//! Velero inventory for the `:velero` view (backups, schedules, restores, storage locations).
//!
//! The point of this view is not to list backups — `velero get backups` already does that — but to
//! answer the only question a backup system is ever asked: *if the cluster burns down right now,
//! what comes back?* That answer is spread across six kinds and two silences, which is why it costs
//! an afternoon:
//!
//! - A `PartiallyFailed` backup is coloured like a success in most dashboards. It is not one: it
//!   ran to completion having failed to capture some items, and nothing tells you which.
//! - A `Schedule` that stops firing says nothing at all. Velero re-computes the next run from
//!   `status.lastBackup` (or the creation stamp) and simply does not create a backup; there is no
//!   Event, no condition, no missed-run counter. The only way to know is to evaluate the cron
//!   yourself and compare — which is what [`Cron`] is for.
//! - A namespace nobody put in a schedule is not backed up, and nothing anywhere says so.
//!
//! Everything the rules need is fetched in one wave — schedules, backups, restores, both location
//! kinds, the file-system repositories, the per-volume backups and the claims that say which
//! namespaces have data to lose — so the diagnosis comes from a single consistent view. The rules
//! ([`analyse`]) are pure functions over that snapshot: no client, no I/O, testable.
//!
//! The writes ([`VelWrite`]) reproduce what the `velero` CLI does, field for field, rather than
//! approximating it: the backup-from-schedule naming and labels come from `pkg/builder`, the
//! deletion goes through a `DeleteBackupRequest` because deleting the `Backup` object is *not* how
//! you delete a backup (see [`VelWrite::DeleteBackup`]).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use k8s_openapi::api::apps::v1::{DaemonSet, Deployment};
use k8s_openapi::api::core::v1::{Namespace, PersistentVolumeClaim};
use kube::api::{Api, DynamicObject, ListParams, Patch, PatchParams, PostParams};
use kube::core::GroupVersionKind;
use kube::{discovery, Client};
use serde_json::{json, Value};

use crate::lang::{fill, Strings};
pub use crate::storage::{Hint, HintLevel};

fn info(text: String) -> Hint {
    Hint { level: HintLevel::Info, text }
}
fn warn(text: String) -> Hint {
    Hint { level: HintLevel::Warn, text }
}
fn danger(text: String) -> Hint {
    Hint { level: HintLevel::Danger, text }
}

// Labels velero puts on the objects it creates, verbatim from `pkg/apis/velero/v1/labels_annotations.go`.
// They are the only link between a backup and the schedule that produced it: there is no owner
// reference, so a backup whose label is gone is an orphan for good.
const L_SCHEDULE: &str = "velero.io/schedule-name";
const L_BACKUP: &str = "velero.io/backup-name";
const L_BACKUP_UID: &str = "velero.io/backup-uid";
// Namespaces (and objects) carrying this are skipped on purpose: not a coverage gap.
const L_EXCLUDE: &str = "velero.io/exclude-from-backup";

const GROUP: &str = "velero.io";
const API_V1: &str = "velero.io/v1";

// A backup still `InProgress` after this long is not progressing, it is stuck.
const STUCK_BACKUP_SECS: i64 = 6 * 3600;
// Same for a deletion, which is usually a few seconds of object-storage calls.
const STUCK_DELETE_SECS: i64 = 3600;
// A kopia/restic repository that has not been compacted in a week keeps growing.
const REPO_MAINTENANCE_SECS: i64 = 7 * 86400;
// Velero re-validates a storage location on a timer; this much silence past the expected interval
// means the check is no longer running, so the phase on screen is stale.
const BSL_VALIDATION_GRACE: i64 = 3;
const BSL_VALIDATION_DEFAULT: i64 = 60;
// Cron granularity is a minute and the controller polls; below this an "overdue" verdict would be
// a rounding error rather than a finding.
const OVERDUE_GRACE_SECS: i64 = 120;
// A backup whose expiry is this close is the last line of defence.
const EXPIRING_SOON_SECS: i64 = 24 * 3600;

// --- Cron ---------------------------------------------------------------------------------------

// A parsed `spec.schedule`, in the dialect velero actually uses: `cron.ParseStandard` from
// robfig/cron v3 — five fields, no seconds, plus the `@` descriptors.
//
// This exists because the alternative is to not answer. Velero recomputes the next run from
// `status.lastBackup` and creates the backup or does not; a schedule that quietly stopped firing
// looks exactly like one that is between runs. Comparing the two requires evaluating the cron the
// same way the controller does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cron {
    // `@every <duration>`: a fixed delay from the previous run, not a wall-clock slot.
    Every(i64),
    Spec(Spec),
}

// Field bitmasks. `dom_star`/`dow_star` are kept apart from the masks because robfig uses them to
// decide whether day-of-month and day-of-week are ANDed or ORed, and losing that flips the meaning
// of every `0 2 * * 1`-shaped expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    minutes: u64,
    hours: u32,
    doms: u32,
    months: u16,
    dows: u8,
    dom_star: bool,
    dow_star: bool,
}

// Parse the expression, or `None` when it is not one velero would accept either. A `None` here is
// what velero's own `parseCronSchedule` reports as a validation error, and the schedule then never
// fires — so the caller turns it into a finding rather than skipping the schedule.
pub fn parse_cron(raw: &str) -> Option<Cron> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Some(rest) = raw.strip_prefix('@') {
        let rest = rest.trim();
        if let Some(dur) = rest.strip_prefix("every ") {
            return parse_go_duration(dur.trim()).map(Cron::Every);
        }
        return match rest {
            "yearly" | "annually" => parse_cron("0 0 1 1 *"),
            "monthly" => parse_cron("0 0 1 * *"),
            "weekly" => parse_cron("0 0 * * 0"),
            "daily" | "midnight" => parse_cron("0 0 * * *"),
            "hourly" => parse_cron("0 * * * *"),
            _ => None,
        };
    }
    let fields: Vec<&str> = raw.split_whitespace().collect();
    if fields.len() != 5 {
        return None;
    }
    let (minutes, _) = parse_field(fields[0], 0, 59, &[])?;
    let (hours, _) = parse_field(fields[1], 0, 23, &[])?;
    let (doms, dom_star) = parse_field(fields[2], 1, 31, &[])?;
    let (months, _) = parse_field(fields[3], 1, 12, MONTH_NAMES)?;
    let (dows, dow_star) = parse_field(fields[4], 0, 6, DAY_NAMES)?;
    Some(Cron::Spec(Spec {
        minutes,
        hours: hours as u32,
        doms: doms as u32,
        months: months as u16,
        // Sunday is both 0 and 7 upstream; fold 7 back onto 0 before the mask narrows to a byte.
        dows: ((dows | (dows >> 7)) & 0x7f) as u8,
        dom_star,
        dow_star,
    }))
}

const MONTH_NAMES: &[&str] = &[
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];
const DAY_NAMES: &[&str] = &["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

// One cron field to a bitmask, plus whether it was an unrestricted `*` (or `?`, which upstream
// accepts as a synonym). Handles lists, ranges and steps in any combination.
fn parse_field(field: &str, min: u64, max: u64, names: &[&str]) -> Option<(u64, bool)> {
    let mut mask = 0u64;
    let mut star = false;
    for part in field.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return None;
        }
        let (range_part, step) = match part.split_once('/') {
            Some((r, s)) => (r, s.parse::<u64>().ok().filter(|s| *s > 0)?),
            None => (part, 1),
        };
        let (lo, hi, is_star) = if range_part == "*" || range_part == "?" {
            (min, max, true)
        } else if let Some((a, b)) = range_part.split_once('-') {
            (parse_value(a, min, max, names)?, parse_value(b, min, max, names)?, false)
        } else {
            let v = parse_value(range_part, min, max, names)?;
            // `5/15` means "from 5 to the end of the field, every 15" upstream, not just "5".
            if step > 1 { (v, max, false) } else { (v, v, false) }
        };
        if lo > hi || hi > max || lo < min {
            return None;
        }
        star = star || (is_star && step == 1);
        let mut v = lo;
        while v <= hi {
            mask |= 1 << v;
            v += step;
        }
    }
    Some((mask, star))
}

fn parse_value(raw: &str, min: u64, max: u64, names: &[&str]) -> Option<u64> {
    let raw = raw.trim();
    if let Ok(v) = raw.parse::<u64>() {
        // Day-of-week 7 is Sunday upstream; let it through here and fold it in `parse_cron`.
        if v >= min && (v <= max || (max == 6 && v == 7)) {
            return Some(v);
        }
        return None;
    }
    let lower = raw.to_lowercase();
    names.iter().position(|n| *n == lower).map(|i| i as u64 + min)
}

// Go's `time.ParseDuration` for the shapes `@every` is used with. Anything more exotic is left
// unparsed rather than guessed at.
fn parse_go_duration(raw: &str) -> Option<i64> {
    let mut total = 0i64;
    let mut num = String::new();
    let mut any = false;
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let value: i64 = num.parse().ok()?;
        num.clear();
        let unit = if c == 'm' && chars.peek() == Some(&'s') {
            chars.next();
            0 // milliseconds: below the granularity of a schedule, and worth nothing here
        } else {
            match c {
                'h' => 3600,
                'm' => 60,
                's' => 1,
                _ => return None,
            }
        };
        total += value * unit;
        any = true;
    }
    if !num.is_empty() || !any {
        return None;
    }
    Some(total)
}

impl Cron {
    // The first firing strictly after `from` (epoch seconds, UTC), the way the controller computes
    // it. `metav1.Time` decodes to UTC, so upstream's `cronSchedule.Next(lastBackupTime)` is a UTC
    // evaluation too — an expression carrying its own `TZ=` prefix never gets here, because
    // `parse_cron` refuses it and the caller abstains rather than answering in the wrong zone.
    pub fn next_after(&self, from: i64) -> Option<i64> {
        match self {
            Cron::Every(secs) => Some(from + secs.max(&1)),
            Cron::Spec(s) => s.next_after(from),
        }
    }

    // How long one period lasts, measured rather than declared: the gap between two consecutive
    // firings. Used to tell whether a TTL outlives the interval that replaces the backup.
    pub fn period(&self, from: i64) -> Option<i64> {
        match self {
            Cron::Every(secs) => Some(*secs),
            Cron::Spec(_) => {
                let a = self.next_after(from)?;
                let b = self.next_after(a)?;
                Some(b - a)
            }
        }
    }
}

impl Spec {
    fn next_after(&self, from: i64) -> Option<i64> {
        use chrono::{Datelike, TimeZone, Timelike, Utc};
        // Start at the top of the next minute: `Next` is strictly after the given instant.
        let mut t = chrono::DateTime::from_timestamp(from - from.rem_euclid(60) + 60, 0)?;
        // Bounded so an expression that can never match (31 February) returns "we cannot say"
        // instead of spinning. The day/hour skips below make the real cost a few hundred steps.
        for _ in 0..100_000 {
            if !self.month_matches(t.month()) || !self.day_matches(t.day(), t.weekday().num_days_from_sunday()) {
                let next = t.date_naive().succ_opt()?;
                t = Utc.from_utc_datetime(&next.and_hms_opt(0, 0, 0)?);
                continue;
            }
            if self.hours & (1 << t.hour()) == 0 {
                t += chrono::Duration::hours(1);
                t = t.with_minute(0)?;
                continue;
            }
            if self.minutes & (1 << t.minute()) != 0 {
                return Some(t.timestamp());
            }
            t += chrono::Duration::minutes(1);
        }
        None
    }

    fn month_matches(&self, month: u32) -> bool {
        self.months & (1 << month) != 0
    }

    // Verbatim from robfig's `dayMatches`: when *both* day fields are restricted the expression
    // matches either of them, which is the Vixie-cron rule and the opposite of what an AND would
    // give. `0 0 1 * 1` fires on the first of the month *and* on every Monday.
    fn day_matches(&self, dom: u32, dow: u32) -> bool {
        let dom_match = self.doms & (1 << dom) != 0;
        let dow_match = self.dows & (1 << dow) != 0;
        if self.dom_star || self.dow_star {
            dom_match && dow_match
        } else {
            dom_match || dow_match
        }
    }
}

// --- Rows ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct VelSchedule {
    pub namespace: String,
    pub name: String,
    pub cron: String,
    pub paused: bool,
    // `Enabled` / `FailedValidation`, or empty before the controller has looked at it.
    pub phase: String,
    pub validation_errors: Vec<String>,
    pub last_backup: Option<i64>,
    pub last_skipped: Option<i64>,
    pub created: i64,
    pub age: String,
    pub ttl: Option<i64>,
    pub included_ns: Vec<String>,
    pub excluded_ns: Vec<String>,
    // A backup-level label selector filters *resources*, not namespaces: the namespace is in scope
    // but only part of what it holds gets captured, which is worth saying out loud.
    pub has_selector: bool,
    pub snapshot_volumes: Option<bool>,
    pub fs_backup_default: bool,
    pub snapshot_move_data: bool,
    pub storage_location: Option<String>,
    // The template a manual run has to reproduce, kept verbatim so the write is a copy and not a
    // re-derivation of a spec with two dozen optional fields.
    pub template: Value,
    pub labels: Vec<(String, String)>,
    pub annotations: Vec<(String, String)>,
    pub tpl_labels: Vec<(String, String)>,
    pub tpl_annotations: Vec<(String, String)>,
    // Computed, not read: the instant the controller would next create a backup.
    pub next_run: Option<i64>,
    pub cron_ok: bool,
    // The GitOps engine that owns this Schedule, if any. `spec.paused` is part of the desired state
    // those engines enforce, so a pause set from here is reverted at their next reconciliation —
    // and velero reports nothing at all when that happens.
    pub gitops: Option<String>,
    pub uid: String,
    pub hints: Vec<Hint>,
}

impl VelSchedule {
    pub fn key(&self) -> String {
        format!("{}/{}", self.namespace, self.name)
    }
}

#[derive(Debug, Clone, Default)]
pub struct VelBackup {
    pub namespace: String,
    pub name: String,
    pub phase: String,
    pub schedule: Option<String>,
    pub storage_location: String,
    pub started: Option<i64>,
    pub completed: Option<i64>,
    pub expiration: Option<i64>,
    pub created: i64,
    pub age: String,
    pub errors: i64,
    pub warnings: i64,
    pub items_backed_up: i64,
    pub total_items: i64,
    pub failure_reason: String,
    pub validation_errors: Vec<String>,
    pub volume_snapshots_attempted: i64,
    pub volume_snapshots_completed: i64,
    pub included_ns: Vec<String>,
    pub excluded_ns: Vec<String>,
    pub ttl: Option<i64>,
    pub snapshot_volumes: Option<bool>,
    pub fs_backup_default: bool,
    // The object's own UID: a `DeleteBackupRequest` carries it so velero can tell a re-created
    // backup of the same name from the one the request was filed against.
    pub k8s_uid: String,
    // A DeleteBackupRequest is already in flight for it.
    pub deleting: bool,
    pub delete_errors: Vec<String>,
    pub pvb_total: usize,
    pub pvb_failed: Vec<String>,
    pub restores: usize,
    pub uid: String,
    pub hints: Vec<Hint>,
}

impl VelBackup {
    // Ran to completion having failed items. Velero has four spellings of it depending on where it
    // gave up, and every one of them means the same thing: this is not a backup you can restore.
    pub fn partially_failed(&self) -> bool {
        matches!(
            self.phase.as_str(),
            "PartiallyFailed"
                | "FinalizingPartiallyFailed"
                | "WaitingForPluginOperationsPartiallyFailed"
        )
    }

    pub fn failed(&self) -> bool {
        matches!(self.phase.as_str(), "Failed" | "FailedValidation")
    }

    pub fn running(&self) -> bool {
        matches!(
            self.phase.as_str(),
            "New" | "Queued" | "ReadyToStart" | "InProgress" | "WaitingForPluginOperations"
                | "Finalizing"
        ) || self.phase.is_empty()
    }

    pub fn usable(&self) -> bool {
        self.phase == "Completed"
    }
}

#[derive(Debug, Clone, Default)]
pub struct VelRestore {
    pub namespace: String,
    pub name: String,
    pub backup: String,
    pub schedule: Option<String>,
    pub phase: String,
    pub started: Option<i64>,
    pub completed: Option<i64>,
    pub created: i64,
    pub age: String,
    pub errors: i64,
    pub warnings: i64,
    pub failure_reason: String,
    pub validation_errors: Vec<String>,
    pub items_restored: i64,
    pub total_items: i64,
    pub existing_policy: String,
    pub uid: String,
    pub hints: Vec<Hint>,
}

impl VelRestore {
    pub fn running(&self) -> bool {
        matches!(self.phase.as_str(), "New" | "InProgress" | "WaitingForPluginOperations")
            || self.phase.is_empty()
    }
}

#[derive(Debug, Clone, Default)]
pub struct VelLocation {
    pub namespace: String,
    pub name: String,
    pub provider: String,
    pub bucket: String,
    pub prefix: String,
    pub phase: String,
    pub default: bool,
    pub access_mode: String,
    pub last_validated: Option<i64>,
    pub validation_frequency: Option<i64>,
    // The object-store endpoint the cluster uses, and the one velero signs download URLs with when
    // it differs. Velero signs on `s3Url` unless `publicUrl` is set, so a cluster-internal `s3Url`
    // with no `publicUrl` produces URLs only the cluster can resolve.
    pub s3_url: String,
    pub public_url: String,
    pub message: String,
    pub created: i64,
    pub age: String,
    pub backups: usize,
    pub uid: String,
    pub hints: Vec<Hint>,
}

impl VelLocation {
    pub fn available(&self) -> bool {
        // An unvalidated location has an empty phase and may well be fine; only an explicit
        // `Unavailable` is a verdict.
        self.phase != "Unavailable"
    }

    pub fn read_only(&self) -> bool {
        self.access_mode == "ReadOnly"
    }
}

#[derive(Debug, Clone, Default)]
pub struct VelSnapLocation {
    pub namespace: String,
    pub name: String,
    pub provider: String,
    pub phase: String,
    pub message: String,
    pub created: i64,
    pub age: String,
    pub uid: String,
    pub hints: Vec<Hint>,
}

#[derive(Debug, Clone, Default)]
pub struct VelRepo {
    pub namespace: String,
    pub name: String,
    pub volume_namespace: String,
    pub repo_type: String,
    pub phase: String,
    pub message: String,
    pub last_maintenance: Option<i64>,
    pub created: i64,
    pub age: String,
    pub uid: String,
    pub hints: Vec<Hint>,
}

// What the velero installation itself looks like. A view about backups that cannot say "the
// controller is not running" would spend its findings blaming the schedules.
#[derive(Debug, Clone, Default)]
pub struct ServerFacts {
    pub namespace: String,
    pub found: bool,
    pub ready: i32,
    pub desired: i32,
    pub version: String,
    // The node-agent DaemonSet, which is what performs file-system backups. `None` when absent.
    pub node_agent: Option<(i32, i32)>,
}

impl ServerFacts {
    pub fn running(&self) -> bool {
        self.found && self.ready > 0
    }
}

#[derive(Default, Debug, Clone)]
pub struct VeleroState {
    pub installed: bool,
    pub server: ServerFacts,
    pub schedules: Vec<VelSchedule>,
    pub backups: Vec<VelBackup>,
    pub restores: Vec<VelRestore>,
    pub locations: Vec<VelLocation>,
    pub snap_locations: Vec<VelSnapLocation>,
    pub repos: Vec<VelRepo>,
    pub cluster_hints: Vec<Hint>,
    // Namespaces holding a PVC that no schedule covers, i.e. data nobody is protecting.
    pub uncovered: Vec<String>,
    // When the last backup that is actually restorable finished. The one number a backup view owes
    // the reader on sight.
    pub last_success: Option<i64>,
    pub error: Option<String>,
    pub loading: bool,
}

impl VeleroState {
    pub fn problems(&self) -> usize {
        let count = |hints: &[Hint]| usize::from(hints.iter().any(|h| h.level >= HintLevel::Warn));
        self.schedules.iter().map(|s| count(&s.hints)).sum::<usize>()
            + self.backups.iter().map(|b| count(&b.hints)).sum::<usize>()
            + self.restores.iter().map(|r| count(&r.hints)).sum::<usize>()
            + self.locations.iter().map(|l| count(&l.hints)).sum::<usize>()
            + self.snap_locations.iter().map(|l| count(&l.hints)).sum::<usize>()
            + self.repos.iter().map(|r| count(&r.hints)).sum::<usize>()
    }
}

pub type SharedVelero = Arc<Mutex<VeleroState>>;

pub fn new_velero_state() -> SharedVelero {
    Arc::new(Mutex::new(VeleroState::default()))
}

// --- Fetch --------------------------------------------------------------------------------------

// Every kind the view reads, with the API versions to try newest-first. Nine kinds is nine
// discovery round-trips; done in sequence on a remote cluster that is ten seconds of blank screen,
// so they are probed as one wave and listed as a second (see the kyverno view for the same shape).
const KINDS: &[(&str, &[&str], &str)] = &[
    (GROUP, &["v1"], "Schedule"),
    (GROUP, &["v1"], "Backup"),
    (GROUP, &["v1"], "Restore"),
    (GROUP, &["v1"], "BackupStorageLocation"),
    (GROUP, &["v1"], "VolumeSnapshotLocation"),
    (GROUP, &["v1"], "BackupRepository"),
    (GROUP, &["v1"], "PodVolumeBackup"),
    (GROUP, &["v1"], "DeleteBackupRequest"),
    ("snapshot.storage.k8s.io", &["v1"], "VolumeSnapshotClass"),
];

pub async fn fetch_velero(client: Client, state: SharedVelero) {
    let st = crate::lang::active();
    {
        let mut s = state.lock().expect("velero poisoned");
        s.loading = true;
        s.error = None;
    }

    let (objects, server, claims, namespaces) = futures::future::join4(
        list_kinds(&client),
        fetch_server(&client),
        list_data_namespaces(&client),
        list_namespaces(&client),
    )
    .await;

    let Listed { mut by_kind, installed, csi_classes } = objects;
    if !installed {
        let mut s = state.lock().expect("velero poisoned");
        *s = VeleroState {
            loading: false,
            installed: false,
            error: Some(st.vel_crds_missing.to_string()),
            ..VeleroState::default()
        };
        return;
    }

    let take = |k: &str, by: &mut HashMap<&'static str, Vec<DynamicObject>>| {
        by.remove(k).unwrap_or_default()
    };
    let schedules_raw = take("Schedule", &mut by_kind);
    let backups_raw = take("Backup", &mut by_kind);
    let restores_raw = take("Restore", &mut by_kind);
    let bsl_raw = take("BackupStorageLocation", &mut by_kind);
    let vsl_raw = take("VolumeSnapshotLocation", &mut by_kind);
    let repos_raw = take("BackupRepository", &mut by_kind);
    let pvb_raw = take("PodVolumeBackup", &mut by_kind);
    let dbr_raw = take("DeleteBackupRequest", &mut by_kind);

    let mut schedules: Vec<VelSchedule> = schedules_raw.iter().map(parse_schedule).collect();
    schedules.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
    let mut backups: Vec<VelBackup> = backups_raw.iter().map(parse_backup).collect();
    // Newest first: on a schedule with a fortnight of retention, the one you came to look at is the
    // last one that ran.
    backups.sort_by(|a, b| b.created.cmp(&a.created).then(a.name.cmp(&b.name)));
    let mut restores: Vec<VelRestore> = restores_raw.iter().map(parse_restore).collect();
    restores.sort_by(|a, b| b.created.cmp(&a.created).then(a.name.cmp(&b.name)));
    let mut locations: Vec<VelLocation> = bsl_raw.iter().map(parse_location).collect();
    locations.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
    let mut snap_locations: Vec<VelSnapLocation> = vsl_raw.iter().map(parse_snap_location).collect();
    snap_locations.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
    let mut repos: Vec<VelRepo> = repos_raw.iter().map(parse_repo).collect();
    repos.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));

    attach_volume_backups(&pvb_raw, &mut backups);
    attach_delete_requests(&dbr_raw, &mut backups);

    let (data_namespaces, opted_out) = match (claims, namespaces) {
        (Some(c), Some(n)) => {
            let excluded: HashSet<&String> = n
                .iter()
                .filter(|(_, opted_out)| *opted_out)
                .map(|(name, _)| name)
                .collect();
            let opted: Vec<String> = excluded.iter().map(|s| (*s).clone()).collect();
            (Some(c.into_iter().filter(|ns| !excluded.contains(ns)).collect()), opted)
        }
        // Without the claims (or the namespaces to read the opt-out label off), the coverage rules
        // have nothing to observe and stay quiet rather than declaring everything unprotected.
        _ => (None, Vec::new()),
    };

    let inv = Inventory {
        schedules,
        backups,
        restores,
        locations,
        snap_locations,
        repos,
        data_namespaces,
        opted_out,
        server,
        csi_snapshot_classes: csi_classes,
    };
    let now = k8s_openapi::jiff::Timestamp::now().as_second();
    let out = analyse(inv, now, st);

    let mut s = state.lock().expect("velero poisoned");
    s.loading = false;
    s.installed = true;
    s.error = None;
    s.last_success = out
        .backups
        .iter()
        .filter(|b| b.usable())
        .filter_map(|b| b.completed.or(Some(b.created)))
        .max();
    s.schedules = out.schedules;
    s.backups = out.backups;
    s.restores = out.restores;
    s.locations = out.locations;
    s.snap_locations = out.snap_locations;
    s.repos = out.repos;
    s.cluster_hints = out.cluster_hints;
    s.uncovered = out.uncovered;
    s.server = out.server;
}

#[derive(Default)]
struct Listed {
    by_kind: HashMap<&'static str, Vec<DynamicObject>>,
    installed: bool,
    // `None` when the snapshot CRDs are absent altogether, which is a different answer from "there
    // are none defined".
    csi_classes: Option<usize>,
}

async fn list_kinds(client: &Client) -> Listed {
    let probes = KINDS.iter().map(|(group, versions, kind)| async move {
        for v in *versions {
            let gvk = GroupVersionKind::gvk(group, v, kind);
            if let Ok((ar, _caps)) = discovery::pinned_kind(client, &gvk).await {
                return Some(ar);
            }
        }
        None
    });
    let resolved = futures::future::join_all(probes).await;

    let mut out = Listed::default();
    let mut listings = Vec::new();
    for ((group, _versions, kind), r) in KINDS.iter().zip(resolved) {
        let Some(ar) = r else { continue };
        if *group == GROUP {
            out.installed = true;
        }
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
        listings.push(async move { (*kind, api.list(&ListParams::default()).await) });
    }

    for (kind, res) in futures::future::join_all(listings).await {
        let Ok(list) = res else { continue };
        if kind == "VolumeSnapshotClass" {
            out.csi_classes = Some(list.items.len());
            continue;
        }
        out.by_kind.insert(kind, list.items);
    }
    out
}

// The velero deployment and its node-agent, found by name rather than by label: the chart, the
// operator and a hand-rolled install do not agree on labels, but they all call it `velero`.
async fn fetch_server(client: &Client) -> ServerFacts {
    let api: Api<Deployment> = Api::all(client.clone());
    let Ok(list) = api.list(&ListParams::default()).await else {
        return ServerFacts::default();
    };
    let Some(d) = list.items.iter().find(|d| {
        d.metadata.name.as_deref() == Some("velero")
            || d.spec
                .as_ref()
                .and_then(|s| s.template.spec.as_ref())
                .map(|s| s.containers.iter().any(|c| c.name == "velero"))
                .unwrap_or(false)
    }) else {
        return ServerFacts::default();
    };
    let namespace = d.metadata.namespace.clone().unwrap_or_default();
    let status = d.status.as_ref();
    let version = d
        .spec
        .as_ref()
        .and_then(|s| s.template.spec.as_ref())
        .and_then(|s| s.containers.first())
        .and_then(|c| c.image.as_ref())
        .and_then(|i| i.rsplit_once(':').map(|(_, tag)| tag.to_string()))
        .unwrap_or_default();

    let node_agent = {
        let api: Api<DaemonSet> = Api::namespaced(client.clone(), &namespace);
        api.list(&ListParams::default()).await.ok().and_then(|l| {
            l.items
                .iter()
                .find(|ds| {
                    matches!(ds.metadata.name.as_deref(), Some("node-agent") | Some("restic"))
                })
                .map(|ds| {
                    let s = ds.status.as_ref();
                    (
                        s.map(|s| s.number_ready).unwrap_or(0),
                        s.map(|s| s.desired_number_scheduled).unwrap_or(0),
                    )
                })
        })
    };

    ServerFacts {
        namespace,
        found: true,
        ready: status.and_then(|s| s.ready_replicas).unwrap_or(0),
        desired: status.and_then(|s| s.replicas).unwrap_or(0),
        version,
        node_agent,
    }
}

// Namespaces holding at least one PVC: the ones with something to lose. `None` when the claims
// cannot be listed, which the coverage rules treat as "we did not look", not "there are none".
async fn list_data_namespaces(client: &Client) -> Option<Vec<String>> {
    let api: Api<PersistentVolumeClaim> = Api::all(client.clone());
    let list = api.list(&ListParams::default()).await.ok()?;
    let mut out: Vec<String> = list
        .items
        .iter()
        .filter(|c| {
            // A claim velero is told to skip is not a coverage gap.
            !c.metadata
                .labels
                .as_ref()
                .and_then(|l| l.get(L_EXCLUDE))
                .map(|v| v == "true")
                .unwrap_or(false)
        })
        .filter_map(|c| c.metadata.namespace.clone())
        .collect();
    out.sort();
    out.dedup();
    Some(out)
}

// `(name, opted out of backup)` for every namespace.
async fn list_namespaces(client: &Client) -> Option<Vec<(String, bool)>> {
    let api: Api<Namespace> = Api::all(client.clone());
    let list = api.list(&ListParams::default()).await.ok()?;
    Some(
        list.items
            .iter()
            .filter_map(|n| {
                let name = n.metadata.name.clone()?;
                let excluded = n
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|l| l.get(L_EXCLUDE))
                    .map(|v| v == "true")
                    .unwrap_or(false);
                Some((name, excluded))
            })
            .collect(),
    )
}

// --- Conversion ---------------------------------------------------------------------------------

fn meta_ts(obj: &DynamicObject) -> i64 {
    obj.metadata
        .creation_timestamp
        .as_ref()
        .map(|t| t.0.as_second())
        .unwrap_or(0)
}

fn pairs(map: Option<&std::collections::BTreeMap<String, String>>) -> Vec<(String, String)> {
    map.map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

fn label_of(obj: &DynamicObject, key: &str) -> Option<String> {
    obj.metadata.labels.as_ref().and_then(|l| l.get(key)).cloned()
}

fn str_at(v: &Value, path: &[&str]) -> String {
    let mut cur = v;
    for p in path {
        match cur.get(p) {
            Some(next) => cur = next,
            None => return String::new(),
        }
    }
    cur.as_str().unwrap_or_default().to_string()
}

fn int_at(v: &Value, path: &[&str]) -> i64 {
    let mut cur = v;
    for p in path {
        match cur.get(p) {
            Some(next) => cur = next,
            None => return 0,
        }
    }
    cur.as_i64().unwrap_or(0)
}

fn bool_at(v: &Value, path: &[&str]) -> Option<bool> {
    let mut cur = v;
    for p in path {
        cur = cur.get(p)?;
    }
    cur.as_bool()
}

fn strings_at(v: &Value, path: &[&str]) -> Vec<String> {
    let mut cur = v;
    for p in path {
        match cur.get(p) {
            Some(next) => cur = next,
            None => return Vec::new(),
        }
    }
    cur.as_array()
        .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

// RFC3339 to epoch seconds. An unparseable or absent stamp is `None`, and every rule reading one
// abstains rather than treating it as the epoch.
fn ts_at(v: &Value, path: &[&str]) -> Option<i64> {
    let raw = str_at(v, path);
    if raw.is_empty() {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(&raw).ok().map(|t| t.timestamp())
}

// Velero writes durations as Go strings ("720h0m0s") through the `metav1.Duration` marshaller.
fn duration_at(v: &Value, path: &[&str]) -> Option<i64> {
    let raw = str_at(v, path);
    if raw.is_empty() {
        return None;
    }
    parse_go_duration(&raw)
}

pub fn age_of(then: i64, now: i64) -> String {
    let secs = (now - then).max(0);
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

// The same span in the width of a table cell. The prose form below is for the detail panel, where
// there is room to read it; here a truncated "12 h 2 min" would show as "12 h 2 m".
pub fn format_span_short(secs: i64) -> String {
    let secs = secs.max(0);
    if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

// A span in the units a human would say it in, for TTLs and cron periods. The units are localised:
// unlike the `s/m/h/d` of the AGE column, this one is read as a sentence.
pub fn format_span(secs: i64, st: &'static Strings) -> String {
    let secs = secs.max(0);
    if secs < 3600 {
        format!("{} {}", secs / 60, st.unit_min)
    } else if secs < 86400 {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        if m == 0 {
            format!("{} {}", h, st.unit_hour)
        } else {
            format!("{} {} {} {}", h, st.unit_hour, m, st.unit_min)
        }
    } else {
        let d = secs / 86400;
        let h = (secs % 86400) / 3600;
        if h == 0 {
            format!("{} {}", d, st.unit_day)
        } else {
            format!("{} {} {} {}", d, st.unit_day, h, st.unit_hour)
        }
    }
}

fn parse_schedule(obj: &DynamicObject) -> VelSchedule {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    let created = meta_ts(obj);
    let template = obj.data.get("spec").and_then(|s| s.get("template")).cloned();
    let tpl = template.clone().unwrap_or(Value::Null);
    let cron = str_at(&obj.data, &["spec", "schedule"]);
    let parsed = parse_cron(&cron);
    let last_backup = ts_at(&obj.data, &["status", "lastBackup"]);
    let last_skipped = ts_at(&obj.data, &["status", "lastSkipped"]);

    // Same base the controller uses: the last run, or the creation stamp when it has never run,
    // and a skip that happened later wins over both (`getNextRunTime`).
    let base = last_backup
        .unwrap_or(created)
        .max(last_skipped.unwrap_or(i64::MIN));
    let next_run = parsed.as_ref().and_then(|c| c.next_after(base));

    VelSchedule {
        uid: format!("vel|sched|{}/{}", namespace, name),
        namespace,
        name,
        cron,
        paused: bool_at(&obj.data, &["spec", "paused"]).unwrap_or(false),
        phase: str_at(&obj.data, &["status", "phase"]),
        validation_errors: strings_at(&obj.data, &["status", "validationErrors"]),
        last_backup,
        last_skipped,
        created,
        age: String::new(),
        ttl: duration_at(&tpl, &["ttl"]),
        included_ns: strings_at(&tpl, &["includedNamespaces"]),
        excluded_ns: strings_at(&tpl, &["excludedNamespaces"]),
        has_selector: tpl.get("labelSelector").is_some() || tpl.get("orLabelSelectors").is_some(),
        snapshot_volumes: bool_at(&tpl, &["snapshotVolumes"]),
        fs_backup_default: bool_at(&tpl, &["defaultVolumesToFsBackup"]).unwrap_or(false),
        snapshot_move_data: bool_at(&tpl, &["snapshotMoveData"]).unwrap_or(false),
        storage_location: Some(str_at(&tpl, &["storageLocation"])).filter(|s| !s.is_empty()),
        template: template.unwrap_or(Value::Null),
        labels: pairs(obj.metadata.labels.as_ref()),
        annotations: pairs(obj.metadata.annotations.as_ref()),
        tpl_labels: tpl
            .get("metadata")
            .and_then(|m| m.get("labels"))
            .and_then(value_pairs)
            .unwrap_or_default(),
        tpl_annotations: tpl
            .get("metadata")
            .and_then(|m| m.get("annotations"))
            .and_then(value_pairs)
            .unwrap_or_default(),
        next_run,
        cron_ok: parsed.is_some(),
        gitops: gitops_owner(obj),
        hints: Vec::new(),
    }
}

// Reuses the detection the delete guard-rails already do, on the same labels and annotations, so
// the two features never disagree about who owns an object.
fn gitops_owner(obj: &DynamicObject) -> Option<String> {
    let meta = json!({
        "metadata": {
            "labels": to_object(&pairs(obj.metadata.labels.as_ref())),
            "annotations": to_object(&pairs(obj.metadata.annotations.as_ref())),
        }
    });
    crate::delete::gitops_owner_of(&meta).map(|(_, detail)| detail)
}

fn value_pairs(v: &Value) -> Option<Vec<(String, String)>> {
    Some(
        v.as_object()?
            .iter()
            .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
            .collect(),
    )
}

fn parse_backup(obj: &DynamicObject) -> VelBackup {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    VelBackup {
        uid: format!("vel|backup|{}/{}", namespace, name),
        k8s_uid: obj.metadata.uid.clone().unwrap_or_default(),
        schedule: label_of(obj, L_SCHEDULE),
        storage_location: str_at(&obj.data, &["spec", "storageLocation"]),
        phase: str_at(&obj.data, &["status", "phase"]),
        started: ts_at(&obj.data, &["status", "startTimestamp"]),
        completed: ts_at(&obj.data, &["status", "completionTimestamp"]),
        expiration: ts_at(&obj.data, &["status", "expiration"]),
        created: meta_ts(obj),
        errors: int_at(&obj.data, &["status", "errors"]),
        warnings: int_at(&obj.data, &["status", "warnings"]),
        items_backed_up: int_at(&obj.data, &["status", "progress", "itemsBackedUp"]),
        total_items: int_at(&obj.data, &["status", "progress", "totalItems"]),
        failure_reason: str_at(&obj.data, &["status", "failureReason"]),
        validation_errors: strings_at(&obj.data, &["status", "validationErrors"]),
        volume_snapshots_attempted: int_at(&obj.data, &["status", "volumeSnapshotsAttempted"]),
        volume_snapshots_completed: int_at(&obj.data, &["status", "volumeSnapshotsCompleted"]),
        included_ns: strings_at(&obj.data, &["spec", "includedNamespaces"]),
        excluded_ns: strings_at(&obj.data, &["spec", "excludedNamespaces"]),
        ttl: duration_at(&obj.data, &["spec", "ttl"]),
        snapshot_volumes: bool_at(&obj.data, &["spec", "snapshotVolumes"]),
        fs_backup_default: bool_at(&obj.data, &["spec", "defaultVolumesToFsBackup"]).unwrap_or(false),
        namespace,
        name,
        age: String::new(),
        deleting: false,
        delete_errors: Vec::new(),
        pvb_total: 0,
        pvb_failed: Vec::new(),
        restores: 0,
        hints: Vec::new(),
    }
}

fn parse_restore(obj: &DynamicObject) -> VelRestore {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    VelRestore {
        uid: format!("vel|restore|{}/{}", namespace, name),
        backup: str_at(&obj.data, &["spec", "backupName"]),
        schedule: Some(str_at(&obj.data, &["spec", "scheduleName"])).filter(|s| !s.is_empty()),
        phase: str_at(&obj.data, &["status", "phase"]),
        started: ts_at(&obj.data, &["status", "startTimestamp"]),
        completed: ts_at(&obj.data, &["status", "completionTimestamp"]),
        created: meta_ts(obj),
        errors: int_at(&obj.data, &["status", "errors"]),
        warnings: int_at(&obj.data, &["status", "warnings"]),
        failure_reason: str_at(&obj.data, &["status", "failureReason"]),
        validation_errors: strings_at(&obj.data, &["status", "validationErrors"]),
        items_restored: int_at(&obj.data, &["status", "progress", "itemsRestored"]),
        total_items: int_at(&obj.data, &["status", "progress", "totalItems"]),
        existing_policy: str_at(&obj.data, &["spec", "existingResourcePolicy"]),
        namespace,
        name,
        age: String::new(),
        hints: Vec::new(),
    }
}

fn parse_location(obj: &DynamicObject) -> VelLocation {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    VelLocation {
        uid: format!("vel|bsl|{}/{}", namespace, name),
        provider: str_at(&obj.data, &["spec", "provider"]),
        bucket: str_at(&obj.data, &["spec", "objectStorage", "bucket"]),
        prefix: str_at(&obj.data, &["spec", "objectStorage", "prefix"]),
        phase: str_at(&obj.data, &["status", "phase"]),
        default: bool_at(&obj.data, &["spec", "default"]).unwrap_or(false),
        access_mode: str_at(&obj.data, &["spec", "accessMode"]),
        last_validated: ts_at(&obj.data, &["status", "lastValidationTime"]),
        validation_frequency: duration_at(&obj.data, &["spec", "validationFrequency"]),
        s3_url: str_at(&obj.data, &["spec", "config", "s3Url"]),
        public_url: str_at(&obj.data, &["spec", "config", "publicUrl"]),
        message: str_at(&obj.data, &["status", "message"]),
        created: meta_ts(obj),
        namespace,
        name,
        age: String::new(),
        backups: 0,
        hints: Vec::new(),
    }
}

fn parse_snap_location(obj: &DynamicObject) -> VelSnapLocation {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    VelSnapLocation {
        uid: format!("vel|vsl|{}/{}", namespace, name),
        provider: str_at(&obj.data, &["spec", "provider"]),
        phase: str_at(&obj.data, &["status", "phase"]),
        message: str_at(&obj.data, &["status", "message"]),
        created: meta_ts(obj),
        namespace,
        name,
        age: String::new(),
        hints: Vec::new(),
    }
}

fn parse_repo(obj: &DynamicObject) -> VelRepo {
    let namespace = obj.metadata.namespace.clone().unwrap_or_default();
    let name = obj.metadata.name.clone().unwrap_or_default();
    VelRepo {
        uid: format!("vel|repo|{}/{}", namespace, name),
        volume_namespace: str_at(&obj.data, &["spec", "volumeNamespace"]),
        repo_type: str_at(&obj.data, &["spec", "repositoryType"]),
        phase: str_at(&obj.data, &["status", "phase"]),
        message: str_at(&obj.data, &["status", "message"]),
        last_maintenance: ts_at(&obj.data, &["status", "lastMaintenanceTime"]),
        created: meta_ts(obj),
        namespace,
        name,
        age: String::new(),
        hints: Vec::new(),
    }
}

// Per-volume file-system backups, folded into the backup they belong to. Only the failures are kept
// verbatim: they carry the one message that says *which* volume did not make it, which the backup's
// own `failureReason` never does.
fn attach_volume_backups(pvbs: &[DynamicObject], backups: &mut [VelBackup]) {
    let mut by_backup: HashMap<String, (usize, Vec<String>)> = HashMap::new();
    for obj in pvbs {
        let Some(backup) = label_of(obj, L_BACKUP) else { continue };
        let entry = by_backup.entry(backup).or_default();
        entry.0 += 1;
        let phase = str_at(&obj.data, &["status", "phase"]);
        if phase == "Failed" {
            let pod = str_at(&obj.data, &["spec", "pod", "name"]);
            let volume = str_at(&obj.data, &["spec", "volume"]);
            let message = str_at(&obj.data, &["status", "message"]);
            entry.1.push(format!("{}:{} — {}", pod, volume, message));
        }
    }
    for b in backups.iter_mut() {
        // The label is truncated to 63 characters, so the join has to be done on the same
        // truncation or a long backup name never matches its own volume backups.
        if let Some((total, failed)) = by_backup.get(&valid_label(&b.name)) {
            b.pvb_total = *total;
            b.pvb_failed = failed.clone();
        }
    }
}

fn attach_delete_requests(requests: &[DynamicObject], backups: &mut [VelBackup]) {
    let mut by_backup: HashMap<String, Vec<String>> = HashMap::new();
    for obj in requests {
        let name = str_at(&obj.data, &["spec", "backupName"]);
        if name.is_empty() {
            continue;
        }
        let entry = by_backup.entry(name).or_default();
        // A deletion that failed leaves the request behind with the reason on it — the only place
        // that reason exists, since the backup itself just stays in `Deleting`.
        for e in strings_at(&obj.data, &["status", "errors"]) {
            entry.push(e);
        }
    }
    for b in backups.iter_mut() {
        if let Some(errors) = by_backup.get(&b.name) {
            b.deleting = true;
            b.delete_errors = errors.clone();
        }
    }
}

// `label.GetValidName`: velero truncates a label value at 63 characters, which is what makes long
// backup names still findable through their labels.
fn valid_label(name: &str) -> String {
    if name.len() <= 63 {
        name.to_string()
    } else {
        name[..63].to_string()
    }
}

// A hostname only the cluster can resolve. Not a heuristic about DNS in general: these are the
// suffixes Kubernetes itself hands out, plus the link-local names cloud metadata services use.
fn internal_endpoint(url: &str) -> bool {
    let authority = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let hostport = authority.split('/').next().unwrap_or("");
    let host = hostport.rsplit_once(':').map(|(h, _)| h).unwrap_or(hostport);
    host.ends_with(".svc")
        || host.ends_with(".svc.cluster.local")
        || host.ends_with(".cluster.local")
        || host.ends_with(".internal")
}

// --- Scope --------------------------------------------------------------------------------------

// Velero matches namespace filters with globs (`gobwas/glob` behind `IncludesExcludes`), not exact
// strings — so `prod-*` really does cover `prod-api`, and reading it as a literal would report a
// covered namespace as unprotected.
pub fn glob_match(pattern: &str, value: &str) -> bool {
    fn walk(p: &[char], v: &[char]) -> bool {
        match p.first() {
            None => v.is_empty(),
            Some('*') => walk(&p[1..], v) || (!v.is_empty() && walk(p, &v[1..])),
            Some('?') => !v.is_empty() && walk(&p[1..], &v[1..]),
            Some(c) => v.first() == Some(c) && walk(&p[1..], &v[1..]),
        }
    }
    walk(&pattern.chars().collect::<Vec<_>>(), &value.chars().collect::<Vec<_>>())
}

// Does this backup spec take in that namespace? An empty include list means every namespace, and
// excludes always win — the same order `IncludesExcludes.ShouldInclude` applies.
pub fn covers_namespace(included: &[String], excluded: &[String], ns: &str) -> bool {
    if excluded.iter().any(|e| glob_match(e, ns)) {
        return false;
    }
    included.is_empty() || included.iter().any(|i| glob_match(i, ns))
}

// --- Rules --------------------------------------------------------------------------------------

pub struct Inventory {
    pub schedules: Vec<VelSchedule>,
    pub backups: Vec<VelBackup>,
    pub restores: Vec<VelRestore>,
    pub locations: Vec<VelLocation>,
    pub snap_locations: Vec<VelSnapLocation>,
    pub repos: Vec<VelRepo>,
    // Namespaces holding a PVC. `None` when they could not be listed: every coverage rule then
    // abstains instead of turning a failed request into a verdict.
    pub data_namespaces: Option<Vec<String>>,
    pub opted_out: Vec<String>,
    pub server: ServerFacts,
    pub csi_snapshot_classes: Option<usize>,
}

pub struct Analysed {
    pub schedules: Vec<VelSchedule>,
    pub backups: Vec<VelBackup>,
    pub restores: Vec<VelRestore>,
    pub locations: Vec<VelLocation>,
    pub snap_locations: Vec<VelSnapLocation>,
    pub repos: Vec<VelRepo>,
    pub cluster_hints: Vec<Hint>,
    pub uncovered: Vec<String>,
    pub server: ServerFacts,
}

// Reads the whole backup picture at once and says what is wrong with it. Pure over its inputs, so
// every rule below can be exercised without a cluster.
pub fn analyse(inv: Inventory, now: i64, st: &'static Strings) -> Analysed {
    let Inventory {
        mut schedules,
        mut backups,
        mut restores,
        mut locations,
        mut snap_locations,
        mut repos,
        data_namespaces,
        opted_out,
        server,
        csi_snapshot_classes,
    } = inv;

    // --- Joins the rules need in both directions ---
    let mut restores_per_backup: HashMap<String, usize> = HashMap::new();
    for r in &restores {
        *restores_per_backup.entry(r.backup.clone()).or_insert(0) += 1;
    }
    let backup_names: HashSet<String> = backups.iter().map(|b| b.name.clone()).collect();
    let counted: Vec<usize> = backups
        .iter()
        .map(|b| restores_per_backup.get(&b.name).copied().unwrap_or(0))
        .collect();
    for (b, n) in backups.iter_mut().zip(counted) {
        b.restores = n;
        b.age = age_of(b.created, now);
    }

    let default_bsl = locations.iter().find(|l| l.default).map(|l| l.name.clone());
    let known_bsl: HashSet<String> = locations.iter().map(|l| l.name.clone()).collect();
    let unavailable_bsl: HashSet<String> = locations
        .iter()
        .filter(|l| !l.available())
        .map(|l| l.name.clone())
        .collect();

    // The newest backup of each schedule that could actually be restored, and the newest of any
    // kind: "expiring soon" only matters for the one that is currently the answer.
    let mut newest_usable: HashMap<String, i64> = HashMap::new();
    for b in backups.iter().filter(|b| b.usable()) {
        let key = b.schedule.clone().unwrap_or_default();
        let stamp = b.completed.unwrap_or(b.created);
        newest_usable
            .entry(key)
            .and_modify(|e| *e = (*e).max(stamp))
            .or_insert(stamp);
    }

    // --- Storage locations ---
    let mut bsl_counts: HashMap<String, usize> = HashMap::new();
    for b in &backups {
        *bsl_counts.entry(b.storage_location.clone()).or_insert(0) += 1;
    }
    for l in locations.iter_mut() {
        l.age = age_of(l.created, now);
        l.backups = bsl_counts.get(&l.name).copied().unwrap_or(0);
        let mut hints = Vec::new();
        if !l.available() {
            hints.push(danger(fill(
                st.vel_bsl_unavailable,
                &[("phase", &l.phase), ("msg", &suffix(&l.message))],
            )));
        } else if l.phase.is_empty() {
            hints.push(info(st.vel_bsl_unvalidated.to_string()));
        }
        if l.read_only() {
            hints.push(warn(st.vel_bsl_readonly.to_string()));
        }
        match l.validation_frequency {
            // `validationFrequency: 0` switches the check off entirely: whatever phase is on screen
            // is whatever it was the last time anyone looked.
            Some(0) => hints.push(info(st.vel_bsl_validation_off.to_string())),
            freq => {
                let interval = freq.unwrap_or(BSL_VALIDATION_DEFAULT * 60);
                if let Some(last) = l.last_validated {
                    if now - last > interval * BSL_VALIDATION_GRACE {
                        hints.push(warn(fill(
                            st.vel_bsl_stale,
                            &[("age", &age_of(last, now)), ("every", &format_span(interval, st))],
                        )));
                    }
                }
            }
        }
        if l.backups == 0 && !l.default {
            hints.push(info(st.vel_bsl_unused.to_string()));
        }
        // Backups still work; what does not is reading a run log from outside the cluster, which is
        // the one thing a `Completed` backup with warnings sends you looking for.
        if internal_endpoint(&l.s3_url) && l.public_url.is_empty() {
            hints.push(info(fill(st.vel_bsl_internal_endpoint, &[("url", &l.s3_url)])));
        }
        hints.sort_by_key(|h| std::cmp::Reverse(h.level));
        l.hints = hints;
    }

    for l in snap_locations.iter_mut() {
        l.age = age_of(l.created, now);
        let mut hints = Vec::new();
        if l.phase == "Unavailable" {
            hints.push(danger(fill(
                st.vel_vsl_unavailable,
                &[("msg", &suffix(&l.message))],
            )));
        }
        l.hints = hints;
    }

    // --- File-system repositories ---
    for r in repos.iter_mut() {
        r.age = age_of(r.created, now);
        let mut hints = Vec::new();
        if r.phase != "Ready" {
            hints.push(danger(fill(
                st.vel_repo_not_ready,
                &[
                    ("phase", if r.phase.is_empty() { "—" } else { &r.phase }),
                    ("msg", &suffix(&r.message)),
                ],
            )));
        }
        match r.last_maintenance {
            Some(t) if now - t > REPO_MAINTENANCE_SECS => hints.push(warn(fill(
                st.vel_repo_maintenance_late,
                &[("age", &age_of(t, now))],
            ))),
            None => hints.push(info(st.vel_repo_no_maintenance.to_string())),
            _ => {}
        }
        hints.sort_by_key(|h| std::cmp::Reverse(h.level));
        r.hints = hints;
    }

    // --- Backups ---
    for b in backups.iter_mut() {
        let mut hints = Vec::new();
        if b.partially_failed() {
            hints.push(danger(fill(
                &st.plural(b.errors.max(0) as usize, st.vel_bk_partial_one, st.vel_bk_partial_many),
                &[("errors", &b.errors.to_string())],
            )));
            for f in b.pvb_failed.iter().take(5) {
                hints.push(danger(fill(st.vel_bk_volume_failed, &[("what", f)])));
            }
            if !b.failure_reason.is_empty() {
                hints.push(danger(fill(st.vel_bk_reason, &[("msg", &b.failure_reason)])));
            }
        } else if b.failed() {
            let reason = if !b.failure_reason.is_empty() {
                b.failure_reason.clone()
            } else {
                b.validation_errors.join(" · ")
            };
            hints.push(danger(fill(
                st.vel_bk_failed,
                &[("phase", &b.phase), ("msg", &suffix(&reason))],
            )));
        } else if b.usable() && b.warnings > 0 {
            hints.push(warn(fill(
                &st.plural(
                    b.warnings.max(0) as usize,
                    st.vel_bk_warnings_one,
                    st.vel_bk_warnings_many,
                ),
                &[("n", &b.warnings.to_string())],
            )));
        }

        if b.running() {
            if let Some(started) = b.started.or(Some(b.created)) {
                if now - started > STUCK_BACKUP_SECS {
                    hints.push(warn(fill(
                        st.vel_bk_stuck,
                        &[("phase", &b.phase), ("age", &age_of(started, now))],
                    )));
                }
            }
        }

        if b.phase == "Deleting" || b.deleting {
            for e in b.delete_errors.iter().take(3) {
                hints.push(warn(fill(st.vel_bk_delete_failed, &[("msg", e)])));
            }
            if b.phase == "Deleting" && now - b.created > STUCK_DELETE_SECS {
                hints.push(warn(st.vel_bk_delete_stuck.to_string()));
            }
        }

        if b.usable() {
            if b.total_items == 0 && b.items_backed_up == 0 {
                hints.push(warn(st.vel_bk_empty.to_string()));
            }
            if b.volume_snapshots_attempted > b.volume_snapshots_completed {
                hints.push(warn(fill(
                    st.vel_bk_snapshots_incomplete,
                    &[
                        ("done", &b.volume_snapshots_completed.to_string()),
                        ("total", &b.volume_snapshots_attempted.to_string()),
                    ],
                )));
            }
            // Metadata-only, said as an observation and not as an inference: this backup captured
            // no volume by any of the three mechanisms, whatever the spec claims it would do.
            let meant_to = b.snapshot_volumes != Some(false) || b.fs_backup_default;
            if meant_to && b.volume_snapshots_attempted == 0 && b.pvb_total == 0 && data_namespaces
                .as_ref()
                .map(|nss| {
                    nss.iter()
                        .any(|ns| covers_namespace(&b.included_ns, &b.excluded_ns, ns))
                })
                .unwrap_or(false)
            {
                hints.push(warn(st.vel_bk_no_volumes.to_string()));
            }
        }

        match b.expiration {
            Some(exp) if exp < now && b.phase != "Deleting" => hints.push(warn(fill(
                st.vel_bk_expired,
                &[("age", &age_of(exp, now))],
            ))),
            Some(exp)
                if b.usable()
                    && exp - now < EXPIRING_SOON_SECS
                    // Only the current answer is worth an alarm: an old backup expiring while a
                    // newer one stands behind it is retention doing its job.
                    && newest_usable
                        .get(&b.schedule.clone().unwrap_or_default())
                        .map(|newest| *newest <= b.completed.unwrap_or(b.created))
                        .unwrap_or(false) =>
            {
                hints.push(warn(fill(
                    st.vel_bk_last_expiring,
                    &[("in", &format_span(exp - now, st))],
                )));
            }
            _ => {}
        }

        if !b.storage_location.is_empty() && !known_bsl.is_empty() {
            if !known_bsl.contains(&b.storage_location) {
                hints.push(danger(fill(
                    st.vel_bk_bsl_missing,
                    &[("name", &b.storage_location)],
                )));
            } else if unavailable_bsl.contains(&b.storage_location) {
                hints.push(warn(fill(
                    st.vel_bk_bsl_unavailable,
                    &[("name", &b.storage_location)],
                )));
            }
        }

        hints.sort_by_key(|h| std::cmp::Reverse(h.level));
        b.hints = hints;
    }

    // --- Restores ---
    for r in restores.iter_mut() {
        r.age = age_of(r.created, now);
        let mut hints = Vec::new();
        match r.phase.as_str() {
            "PartiallyFailed" => hints.push(danger(fill(
                &st.plural(r.errors.max(0) as usize, st.vel_rs_partial_one, st.vel_rs_partial_many),
                &[("errors", &r.errors.to_string()), ("msg", &suffix(&r.failure_reason))],
            ))),
            "Failed" | "FailedValidation" => {
                let reason = if !r.failure_reason.is_empty() {
                    r.failure_reason.clone()
                } else {
                    r.validation_errors.join(" · ")
                };
                hints.push(danger(fill(
                    st.vel_rs_failed,
                    &[("phase", &r.phase), ("msg", &suffix(&reason))],
                )));
            }
            "Completed" if r.warnings > 0 => hints.push(warn(fill(
                &st.plural(
                    r.warnings.max(0) as usize,
                    st.vel_rs_warnings_one,
                    st.vel_rs_warnings_many,
                ),
                &[("n", &r.warnings.to_string())],
            ))),
            _ => {}
        }
        if r.running() {
            if let Some(started) = r.started.or(Some(r.created)) {
                if now - started > STUCK_BACKUP_SECS {
                    hints.push(warn(fill(
                        st.vel_rs_stuck,
                        &[("age", &age_of(started, now))],
                    )));
                }
            }
        }
        if !r.backup.is_empty() && !backup_names.is_empty() && !backup_names.contains(&r.backup)
        {
            hints.push(warn(fill(st.vel_rs_backup_gone, &[("name", &r.backup)])));
        }
        if r.existing_policy == "update" {
            hints.push(info(st.vel_rs_policy_update.to_string()));
        }
        hints.sort_by_key(|h| std::cmp::Reverse(h.level));
        r.hints = hints;
    }

    // --- Schedules ---
    let mut backups_per_schedule: HashMap<&str, Vec<&VelBackup>> = HashMap::new();
    for b in &backups {
        if let Some(s) = b.schedule.as_deref() {
            backups_per_schedule.entry(s).or_default().push(b);
        }
    }

    for s in schedules.iter_mut() {
        s.age = age_of(s.created, now);
        let mut hints = Vec::new();
        let mine: &[&VelBackup] = backups_per_schedule
            .get(s.name.as_str())
            .map(|v| v.as_slice())
            .unwrap_or(&[]);

        let period = parse_cron(&s.cron).and_then(|c| c.period(s.last_backup.unwrap_or(s.created)));
        if !s.cron_ok {
            hints.push(danger(fill(st.vel_sched_cron_invalid, &[("cron", &s.cron)])));
        }
        if s.phase == "FailedValidation" {
            hints.push(danger(fill(
                st.vel_sched_invalid,
                &[("msg", &suffix(&s.validation_errors.join(" · ")))],
            )));
        }

        if s.paused {
            let since = s.last_backup.map(|t| age_of(t, now));
            hints.push(match (&since, newest_of(mine)) {
                // Paused with nothing left behind it is the state where a cluster silently has no
                // backup at all, which is worth more than the neutral "it is paused".
                (_, None) => danger(st.vel_sched_paused_empty.to_string()),
                (Some(age), _) => warn(fill(st.vel_sched_paused, &[("age", age)])),
                (None, _) => warn(fill(st.vel_sched_paused, &[("age", &s.age)])),
            });
        } else if let Some(next) = s.next_run {
            // Velero deliberately skips a run while one of this schedule's backups is still New or
            // InProgress (`checkIfBackupInNewOrProgress`), so an overlapping run is not a miss.
            let overlapping = mine.iter().any(|b| b.running());
            if now - next > OVERDUE_GRACE_SECS && s.phase != "FailedValidation" && !overlapping {
                hints.push(danger(fill(
                    st.vel_sched_overdue,
                    &[("age", &age_of(next, now)), ("cron", &s.cron)],
                )));
            }
        }
        if s.last_backup.is_none()
            && !mine.iter().any(|b| b.usable())
            && !s.paused
            && period.is_some_and(|p| now - s.created > p)
        {
            hints.push(warn(fill(st.vel_sched_never_ran, &[("age", &s.age)])));
        }

        // A TTL shorter than the interval that replaces the backup guarantees a window with nothing
        // in it — the failure mode where retention itself is the outage.
        if let (Some(ttl), Some(period)) = (s.ttl, period) {
            if ttl < period {
                hints.push(danger(fill(
                    st.vel_sched_ttl_short,
                    &[("ttl", &format_span(ttl, st)), ("period", &format_span(period, st))],
                )));
            }
        }

        if let Some(last) = newest_of(mine) {
            if last.partially_failed() || last.failed() {
                hints.push(danger(fill(
                    st.vel_sched_last_failed,
                    &[("name", &last.name), ("phase", &last.phase)],
                )));
            }
        }

        if let Some(loc) = s.storage_location.as_deref() {
            if !known_bsl.is_empty() && !known_bsl.contains(loc) {
                hints.push(danger(fill(st.vel_sched_bsl_missing, &[("name", loc)])));
            }
        } else if default_bsl.is_none() && !locations.is_empty() {
            hints.push(warn(st.vel_sched_no_default_bsl.to_string()));
        }

        if s.has_selector {
            hints.push(info(st.vel_sched_selector.to_string()));
        }
        if let Some(owner) = &s.gitops {
            hints.push(info(fill(st.vel_sched_gitops, &[("owner", owner)])));
        }

        // Volume coverage, in the order of decreasing certainty: what the spec forbids outright,
        // then what nothing in the cluster could perform, and never a guess when a run of this
        // schedule has already demonstrated it captures volumes.
        let covers_data = data_namespaces
            .as_ref()
            .map(|nss| {
                nss.iter()
                    .any(|ns| covers_namespace(&s.included_ns, &s.excluded_ns, ns))
            })
            .unwrap_or(false);
        let observed_volumes = mine
            .iter()
            .any(|b| b.volume_snapshots_attempted > 0 || b.pvb_total > 0);
        if covers_data && !observed_volumes {
            if s.snapshot_volumes == Some(false) && !s.fs_backup_default {
                hints.push(danger(st.vel_sched_volumes_off.to_string()));
            } else if csi_snapshot_classes == Some(0)
                && snap_locations.is_empty()
                && !s.fs_backup_default
                && !s.snapshot_move_data
            {
                hints.push(warn(st.vel_sched_volumes_unclear.to_string()));
            }
        }
        if s.fs_backup_default {
            match server.node_agent {
                None => hints.push(danger(st.vel_sched_no_node_agent.to_string())),
                Some((0, desired)) if desired > 0 => {
                    hints.push(danger(st.vel_sched_node_agent_down.to_string()))
                }
                _ => {}
            }
        }

        // Namespaces the schedule names but that do not exist: a typo in `includedNamespaces` is
        // silent, and the schedule keeps reporting success over an empty selection.
        if let Some(all) = data_namespaces.as_ref() {
            if !s.included_ns.is_empty()
                && !s.included_ns.iter().any(|i| i == "*")
                && !all.is_empty()
                && !covers_data
            {
                hints.push(warn(fill(
                    st.vel_sched_scope_empty,
                    &[("list", &s.included_ns.join(", "))],
                )));
            }
        }

        hints.sort_by_key(|h| std::cmp::Reverse(h.level));
        s.hints = hints;
    }

    // --- Cluster ---
    let mut cluster_hints = Vec::new();
    if !server.found {
        cluster_hints.push(warn(st.vel_server_absent.to_string()));
    } else if !server.running() {
        cluster_hints.push(danger(st.vel_server_down.to_string()));
    }
    if locations.is_empty() {
        cluster_hints.push(danger(st.vel_no_bsl.to_string()));
    } else if default_bsl.is_none() {
        cluster_hints.push(warn(st.vel_no_default_bsl.to_string()));
    }
    if schedules.is_empty() {
        cluster_hints.push(danger(st.vel_no_schedule.to_string()));
    } else if schedules.iter().all(|s| s.paused) {
        cluster_hints.push(danger(st.vel_all_paused.to_string()));
    }

    // The coverage gap: namespaces with a claim in them that no schedule takes in. This is the one
    // finding nothing in velero will ever tell you, because from velero's side nothing happened.
    let mut uncovered: Vec<String> = Vec::new();
    if let Some(nss) = data_namespaces.as_ref() {
        for ns in nss {
            if ns == &server.namespace {
                continue;
            }
            let covered = schedules.iter().any(|s| {
                !s.paused && covers_namespace(&s.included_ns, &s.excluded_ns, ns)
            });
            if !covered {
                uncovered.push(ns.clone());
            }
        }
        if !uncovered.is_empty() {
            cluster_hints.push(danger(fill(
                &st.plural(uncovered.len(), st.vel_ns_uncovered_one, st.vel_ns_uncovered_many),
                &[
                    ("n", &uncovered.len().to_string()),
                    ("list", &uncovered.join(", ")),
                ],
            )));
        }
    }
    if !opted_out.is_empty() {
        let mut list = opted_out.clone();
        list.sort();
        cluster_hints.push(info(fill(st.vel_ns_opted_out, &[("list", &list.join(", "))])));
    }

    match backups.iter().filter(|b| b.usable()).map(|b| b.completed.unwrap_or(b.created)).max() {
        Some(last) => cluster_hints.push(info(fill(st.vel_rpo, &[("age", &age_of(last, now))]))),
        None if !backups.is_empty() => cluster_hints.push(danger(st.vel_no_usable_backup.to_string())),
        None => {}
    }

    let stuck_deletes = backups.iter().filter(|b| b.phase == "Deleting").count();
    if stuck_deletes > 0 && backups.iter().any(|b| !b.delete_errors.is_empty()) {
        cluster_hints.push(warn(fill(
            st.vel_deletes_failing,
            &[("n", &stuck_deletes.to_string())],
        )));
    }

    Analysed {
        schedules,
        backups,
        restores,
        locations,
        snap_locations,
        repos,
        cluster_hints,
        uncovered,
        server,
    }
}

// The most recent backup of a set, whatever became of it.
fn newest_of<'a>(backups: &[&'a VelBackup]) -> Option<&'a VelBackup> {
    backups.iter().copied().max_by_key(|b| b.created)
}

// A message appended to a sentence, or nothing at all — so a rule never renders " — " over an empty
// status field.
fn suffix(msg: &str) -> String {
    let msg = msg.trim();
    if msg.is_empty() {
        String::new()
    } else {
        format!(" — {}", msg)
    }
}

// --- Run log ------------------------------------------------------------------------------------

// The log of one backup or restore run. It is the only place that says *which* item produced the
// warning a `Completed` backup reports — the object itself only carries the count.
#[derive(Default, Debug, Clone)]
pub struct VelLog {
    // "kind|ns/name" of the run the content belongs to: a result whose key no longer matches the
    // selected row is dropped rather than shown under the wrong backup.
    pub key: String,
    pub lines: Vec<String>,
    // Where the lines came from. The two sources do not contain the same thing, and the panel has
    // to say which one the reader is looking at.
    pub source: LogSource,
    pub loading: bool,
    pub error: Option<String>,
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSource {
    #[default]
    None,
    // The real run log, as velero stored it next to the backup in object storage.
    Download,
    // The velero server's own log, filtered on the run's name. A fallback, and a partial one: it
    // holds what the controller printed, only as far back as the pod's current log goes.
    Server,
}

pub type SharedVelLog = Arc<Mutex<VelLog>>;

pub fn new_vel_log() -> SharedVelLog {
    Arc::new(Mutex::new(VelLog::default()))
}

// How long to wait for velero to answer a DownloadRequest with a pre-signed URL.
const DOWNLOAD_POLL_SECS: u64 = 20;

// Fetch the run log, from the authoritative source if it is reachable and from the server's own log
// if it is not.
//
// The fallback is not a nicety. Velero signs the URL against the endpoint *the cluster* uses, which
// on any in-cluster object store (`s3Url: http://minio.velero.svc.cluster.local:9000`, the default
// of every MinIO-based install) is a name that does not resolve outside the cluster. Downloading it
// from a laptop then fails for a reason that has nothing to do with the backup — so the failure is
// reported as context, and the question gets answered from the controller's log instead.
pub async fn fetch_run_log(
    client: Client,
    namespace: String,
    kind: &'static str,
    name: String,
    state: SharedVelLog,
) {
    let st = crate::lang::active();
    let key = format!("{}|{}/{}", kind, namespace, name);
    {
        let mut s = state.lock().expect("velero log poisoned");
        *s = VelLog { key: key.clone(), loading: true, ..VelLog::default() };
    }

    let target = if kind == "Restore" { "RestoreLog" } else { "BackupLog" };
    let (lines, source, error) = match download_run_log(&client, &namespace, target, &name).await {
        Ok(text) => (split_lines(text), LogSource::Download, None),
        Err(download_err) => match server_log(&client, &namespace, &name).await {
            Ok(lines) => (lines, LogSource::Server, Some(download_err)),
            Err(server_err) => (
                Vec::new(),
                LogSource::None,
                Some(format!("{} · {}", download_err, server_err)),
            ),
        },
    };

    let mut s = state.lock().expect("velero log poisoned");
    // A selection that moved on while this was in flight owns the panel now.
    if s.key != key {
        return;
    }
    s.loading = false;
    s.source = source;
    s.error = error;
    s.lines = if lines.is_empty() && s.error.is_none() {
        vec![st.vel_log_empty.to_string()]
    } else {
        lines
    };
}

async fn download_run_log(
    client: &Client,
    namespace: &str,
    target: &str,
    name: &str,
) -> Result<String, String> {
    download_target(client, namespace, target, name).await.map(|b| gunzip(&b))
}

// Ask velero for a pre-signed URL, then read what is behind it. The request object is removed
// afterwards: velero garbage-collects them on expiry, but leaving one per keypress would litter the
// namespace for the ten minutes each URL lives.
//
// `target` is one of the `DownloadTargetKind` values: `BackupLog` and `RestoreLog` for the run logs,
// `BackupResourceList` for the inventory. The bytes come back raw because they are not all text —
// the caller decides between `gunzip` and a JSON parse.
async fn download_target(
    client: &Client,
    namespace: &str,
    target: &str,
    name: &str,
) -> Result<Vec<u8>, String> {
    let st = crate::lang::active();
    let api = crate::yaml::dynamic_api(client, API_V1, "DownloadRequest", namespace).await?;
    let body = json!({
        "apiVersion": API_V1,
        "kind": "DownloadRequest",
        "metadata": { "generateName": format!("{}-", name), "namespace": namespace },
        "spec": { "target": { "kind": target, "name": name } },
    });
    let obj: DynamicObject = serde_json::from_value(body).map_err(|e| e.to_string())?;
    let created = api
        .create(&PostParams::default(), &obj)
        .await
        .map_err(crate::edit::api_error_text)?;
    let request_name = created.metadata.name.clone().unwrap_or_default();

    let mut url = String::new();
    for _ in 0..DOWNLOAD_POLL_SECS {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let Ok(cur) = api.get(&request_name).await else { continue };
        let candidate = str_at(&cur.data, &["status", "downloadURL"]);
        if !candidate.is_empty() {
            url = candidate;
            break;
        }
    }
    let _ = api.delete(&request_name, &Default::default()).await;
    if url.is_empty() {
        return Err(st.vel_log_no_url.to_string());
    }

    // A short connect timeout on purpose: the common failure is a hostname only the cluster can
    // resolve, and waiting the default minute for that would look like a hung view.
    let http = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(4))
        .read_timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = http.get(&url).send().await.map_err(|e| {
        fill(st.vel_log_unreachable, &[("e", &e.to_string())])
    })?;
    if !resp.status().is_success() {
        return Err(fill(st.vel_log_http, &[("code", resp.status().as_str())]));
    }
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    Ok(bytes.to_vec())
}

// Everything velero serves this way is gzipped — but a proxy or a future target that is not would
// otherwise render as mojibake, so the magic number decides rather than the assumption.
fn gunzip(bytes: &[u8]) -> String {
    use std::io::Read;
    if bytes.len() < 2 || bytes[0] != 0x1f || bytes[1] != 0x8b {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let mut out = String::new();
    match flate2::read::GzDecoder::new(bytes).read_to_string(&mut out) {
        Ok(_) => out,
        Err(_) => String::from_utf8_lossy(bytes).into_owned(),
    }
}

fn split_lines(text: String) -> Vec<String> {
    text.lines().map(|l| l.trim_end().to_string()).collect()
}

// The controller's own account of the run, pulled from the velero pod and narrowed to the lines
// naming it. Partial by nature — it only goes back as far as the running pod's log does — which is
// why it is the fallback and never the first choice.
async fn server_log(client: &Client, namespace: &str, name: &str) -> Result<Vec<String>, String> {
    use k8s_openapi::api::core::v1::Pod;
    let st = crate::lang::active();
    let api: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let list = api.list(&ListParams::default()).await.map_err(|e| e.to_string())?;
    let pod = list
        .items
        .iter()
        .filter(|p| {
            p.spec
                .as_ref()
                .map(|s| s.containers.iter().any(|c| c.name == "velero"))
                .unwrap_or(false)
        })
        .filter_map(|p| p.metadata.name.clone())
        .next()
        .ok_or_else(|| st.vel_log_no_server_pod.to_string())?;

    let params = kube::api::LogParams {
        container: Some("velero".to_string()),
        tail_lines: Some(20_000),
        ..Default::default()
    };
    let raw = api.logs(&pod, &params).await.map_err(|e| e.to_string())?;
    let hits: Vec<String> = raw
        .lines()
        .filter(|l| l.contains(name))
        .map(|l| l.trim_end().to_string())
        .collect();
    if hits.is_empty() {
        return Err(fill(st.vel_log_not_in_server, &[("pod", &pod)]));
    }
    Ok(hits)
}

// --- Contents -----------------------------------------------------------------------------------

// What a backup actually captured, as velero wrote it next to the tarball. The `Backup` object only
// ever gives a count (`items 2431 / 2431`); this is the one place that says *which* 2431 — and
// therefore the only way to decide what is worth restoring before restoring it.
//
// Velero serves it as `BackupResourceList`, a gzipped `map[string][]string` keyed by
// `group/version/Kind` and holding `namespace/name` (or a bare `name` for cluster-scoped objects).
#[derive(Default, Debug, Clone)]
pub struct VelContents {
    // "ns/backup" of the backup this belongs to. Same anti-race rule as `VelLog`: a result whose key
    // no longer matches is dropped rather than shown under another backup.
    pub key: String,
    pub namespaces: Vec<VelNsContent>,
    pub total: usize,
    pub loading: bool,
    pub error: Option<String>,
}

// One namespace of the backup. `namespace` is empty for the cluster-scoped objects — an empty string
// cannot collide with a real namespace, which a reserved name like "cluster-wide" could.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VelNsContent {
    pub namespace: String,
    pub kinds: Vec<VelKindContent>,
}

impl VelNsContent {
    pub fn objects(&self) -> usize {
        self.kinds.iter().map(|k| k.names.len()).sum()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VelKindContent {
    pub api_version: String,
    pub kind: String,
    pub names: Vec<String>,
}

pub type SharedVelContents = Arc<Mutex<VelContents>>;

pub fn new_vel_contents() -> SharedVelContents {
    Arc::new(Mutex::new(VelContents::default()))
}

// Fetch the inventory of one backup.
//
// Unlike the run log there is **no fallback**: the list exists only in object storage, and the
// controller's log never held it. So a failure here is reported as a failure and nothing else — an
// unreachable bucket must never render as a backup that captured nothing.
//
// `s3_url` is the location's endpoint, used only to name the usual cause: velero signs the URL
// against the address *the cluster* uses, so an in-cluster MinIO produces a hostname that does not
// resolve from a laptop, and the raw connection error says nothing about why.
pub async fn fetch_contents(
    client: Client,
    namespace: String,
    backup: String,
    s3_url: Option<String>,
    state: SharedVelContents,
) {
    let st = crate::lang::active();
    let key = format!("{}/{}", namespace, backup);
    {
        let mut s = state.lock().expect("velero contents poisoned");
        *s = VelContents { key: key.clone(), loading: true, ..VelContents::default() };
    }

    let outcome = match download_target(&client, &namespace, "BackupResourceList", &backup).await {
        Ok(bytes) => parse_resource_list(&gunzip(&bytes)),
        Err(e) => Err(match s3_url.as_deref() {
            Some(url) if internal_endpoint(url) => {
                fill(st.vel_ct_internal_endpoint, &[("e", &e), ("url", url)])
            }
            _ => e,
        }),
    };

    let mut s = state.lock().expect("velero contents poisoned");
    // A selection that moved on while this was in flight owns the panel now.
    if s.key != key {
        return;
    }
    s.loading = false;
    match outcome {
        Ok(namespaces) => {
            s.total = namespaces.iter().map(|n| n.objects()).sum();
            s.namespaces = namespaces;
        }
        Err(e) => s.error = Some(e),
    }
}

// Turn the `BackupResourceList` document into the tree the view walks. Pure, so the shapes velero
// emits can be pinned down in tests without a cluster.
pub fn parse_resource_list(raw: &str) -> Result<Vec<VelNsContent>, String> {
    let st = crate::lang::active();
    let doc: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    let Some(map) = doc.as_object() else {
        return Err(st.vel_ct_bad_json.to_string());
    };

    // namespace -> (api_version, kind) -> names
    let mut by_ns: HashMap<String, HashMap<(String, String), Vec<String>>> = HashMap::new();
    for (gvk, entries) in map {
        let (api_version, kind) = split_gvk(gvk);
        let Some(entries) = entries.as_array() else { continue };
        for entry in entries {
            let Some(entry) = entry.as_str() else { continue };
            // A namespaced object is `ns/name`; a cluster-scoped one is a bare name. Object names
            // never contain a slash, so the split is unambiguous.
            let (ns, name) = match entry.split_once('/') {
                Some((ns, name)) => (ns.to_string(), name.to_string()),
                None => (String::new(), entry.to_string()),
            };
            by_ns.entry(ns)
                .or_default()
                .entry((api_version.clone(), kind.clone()))
                .or_default()
                .push(name);
        }
    }

    let mut out: Vec<VelNsContent> = by_ns
        .into_iter()
        .map(|(namespace, kinds)| {
            let mut kinds: Vec<VelKindContent> = kinds
                .into_iter()
                .map(|((api_version, kind), mut names)| {
                    names.sort();
                    VelKindContent { api_version, kind, names }
                })
                .collect();
            kinds.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.api_version.cmp(&b.api_version)));
            VelNsContent { namespace, kinds }
        })
        .collect();
    // Alphabetical, with the cluster-scoped group last: it is the one nobody goes looking for first.
    out.sort_by(|a, b| match (a.namespace.is_empty(), b.namespace.is_empty()) {
        (true, false) => std::cmp::Ordering::Greater,
        (false, true) => std::cmp::Ordering::Less,
        _ => a.namespace.cmp(&b.namespace),
    });
    Ok(out)
}

// `group/version/Kind` -> (apiVersion, Kind). Core objects come as `v1/Pod`, and a key velero wrote
// without a version at all still yields a usable Kind rather than being dropped.
fn split_gvk(gvk: &str) -> (String, String) {
    let parts: Vec<&str> = gvk.split('/').collect();
    match parts.as_slice() {
        [group, version, kind] => (format!("{}/{}", group, version), kind.to_string()),
        [version, kind] => (version.to_string(), kind.to_string()),
        [kind] => ("v1".to_string(), kind.to_string()),
        _ => (
            parts[..parts.len() - 1].join("/"),
            parts.last().copied().unwrap_or_default().to_string(),
        ),
    }
}

// --- Writes -------------------------------------------------------------------------------------

// The four operations the view offers, each reproducing what the `velero` CLI does rather than
// approximating it.
#[derive(Debug, Clone)]
pub enum VelWrite {
    // `velero backup create --from-schedule`: a Backup whose spec is the schedule's template, named
    // and labelled the way the schedule controller names and labels its own runs, so a manual run
    // is indistinguishable from a scheduled one — including to the retention that expires it.
    BackupNow(Box<VelSchedule>),
    // `spec.paused`. The controller stops creating backups; nothing existing is touched.
    Pause { namespace: String, name: String, paused: bool },
    // `velero restore create --from-backup`, with whatever the restore form narrowed it to. Left at
    // its default it restores everything into the namespaces it came from, and *skips* the objects
    // that already exist rather than overwriting them — which is what makes it recoverable, and what
    // `RestoreOptions::overwrite_existing` gives up.
    Restore { namespace: String, backup: String, opts: Box<RestoreOptions> },
    // A `DeleteBackupRequest`, and not a delete of the Backup object.
    //
    // Deleting the object deletes nothing: the data stays in object storage, and the backup-sync
    // controller reads it back and *re-creates* the Backup a minute later
    // (`backup_sync_controller.go`, `client.Create` on everything found in the bucket that has no
    // object here). The request is what makes velero remove the snapshots, the object-storage
    // files, the restores and finally the object itself.
    DeleteBackup { namespace: String, backup: String, uid: String },
}

impl VelWrite {
    // What the confirmation line names. The object the write lands on, not the kind it creates.
    pub fn target(&self) -> String {
        match self {
            VelWrite::BackupNow(s) => format!("{}/{}", s.namespace, s.name),
            VelWrite::Pause { namespace, name, .. } => format!("{}/{}", namespace, name),
            VelWrite::Restore { namespace, backup, .. } => format!("{}/{}", namespace, backup),
            VelWrite::DeleteBackup { namespace, backup, .. } => format!("{}/{}", namespace, backup),
        }
    }
}

// The `<name>-20060102150405` stamp velero builds its generated names from (`TimestampedName`,
// and the restore CLI's own `fmt.Sprintf`). Same format for both so a manual run sorts next to the
// scheduled ones instead of standing out.
pub fn timestamped_name(base: &str, now: i64) -> String {
    let stamp = chrono::DateTime::from_timestamp(now, 0)
        .map(|t| t.format("%Y%m%d%H%M%S").to_string())
        .unwrap_or_else(|| now.to_string());
    format!("{}-{}", base, stamp)
}

// The Backup object a manual run of `schedule` produces. Split out from the write so the naming and
// labelling can be tested without a cluster: getting the schedule label wrong would orphan the
// backup from its schedule for good, and nothing would ever say so.
pub fn backup_from_schedule(s: &VelSchedule, now: i64) -> (String, Value) {
    let name = timestamped_name(&s.name, now);
    // Upstream `FromSchedule`: the template's own metadata wins over the schedule's when it sets
    // any, and the schedule-name label is added on top either way.
    let mut labels: Vec<(String, String)> = if s.tpl_labels.is_empty() {
        s.labels.clone()
    } else {
        s.tpl_labels.clone()
    };
    labels.retain(|(k, _)| k != L_SCHEDULE);
    labels.push((L_SCHEDULE.to_string(), s.name.clone()));
    let annotations: Vec<(String, String)> = if s.tpl_annotations.is_empty() {
        s.annotations.clone()
    } else {
        s.tpl_annotations.clone()
    };

    let mut metadata = json!({ "name": name, "namespace": s.namespace });
    metadata["labels"] = to_object(&labels);
    if !annotations.is_empty() {
        metadata["annotations"] = to_object(&annotations);
    }
    // The template carries its own `metadata` block for the generated backup's labels; it is not a
    // spec field and would be rejected by the API server.
    let mut spec = s.template.clone();
    if let Some(map) = spec.as_object_mut() {
        map.remove("metadata");
    }
    if spec.is_null() {
        spec = json!({});
    }
    (
        name.clone(),
        json!({ "apiVersion": API_V1, "kind": "Backup", "metadata": metadata, "spec": spec }),
    )
}

fn to_object(pairs: &[(String, String)]) -> Value {
    Value::Object(pairs.iter().map(|(k, v)| (k.clone(), json!(v))).collect())
}

// How the restore form narrows a restore. Every field is a *narrowing*: left empty it does not
// appear in the spec at all, so `RestoreOptions::default()` produces exactly the whole-backup
// restore the view has always offered.
//
// Note what is deliberately absent — a list of object names. Velero has no such field: a restore
// selects by namespace, by resource and by label, never by name. Offering a per-object tick box
// would be a promise the API cannot keep.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreOptions {
    // `includedNamespaces`. Empty means every namespace the backup holds.
    pub namespaces: Vec<String>,
    // `namespaceMapping`, source -> target: restore somewhere other than where it came from. Velero
    // creates the target namespace if it does not exist.
    pub namespace_mapping: Option<(String, String)>,
    // `includedResources`, already resolved to the `plural.group` form velero expects — see
    // [`resolve_resources`]. Empty means every kind.
    pub resources: Vec<String>,
    // `labelSelector.matchLabels`.
    pub label_selector: Vec<(String, String)>,
    // `existingResourcePolicy: update`. The only setting here that destroys anything: it overwrites
    // live objects instead of stepping around them.
    pub overwrite_existing: bool,
}

pub fn restore_from_backup(
    namespace: &str,
    backup: &str,
    opts: &RestoreOptions,
    now: i64,
) -> (String, Value) {
    let name = timestamped_name(backup, now);
    let mut spec = json!({ "backupName": backup });
    let map = spec.as_object_mut().expect("restore spec is an object");
    if !opts.namespaces.is_empty() {
        map.insert("includedNamespaces".to_string(), json!(opts.namespaces));
    }
    if let Some((from, to)) = &opts.namespace_mapping {
        map.insert("namespaceMapping".to_string(), json!({ from: to }));
    }
    if !opts.resources.is_empty() {
        map.insert("includedResources".to_string(), json!(opts.resources));
    }
    if !opts.label_selector.is_empty() {
        map.insert(
            "labelSelector".to_string(),
            json!({ "matchLabels": to_object(&opts.label_selector) }),
        );
    }
    // `none` is what velero does when the field is absent, so only the other value is ever written:
    // spelling out the default would suggest a choice was made where none was.
    if opts.overwrite_existing {
        map.insert("existingResourcePolicy".to_string(), json!("update"));
    }
    (
        name.clone(),
        json!({
            "apiVersion": API_V1,
            "kind": "Restore",
            "metadata": { "name": name, "namespace": namespace },
            "spec": spec,
        }),
    )
}

// Turn the Kinds the inventory shows into the resource names `includedResources` matches on.
//
// The two are not the same string and the mapping cannot be computed: `Endpoints` is `endpoints`,
// `NetworkPolicy` is `networkpolicies`, `Ingress` is `ingresses`. Only the API server knows, so it
// is asked — the same discovery the YAML and edit flows already go through.
//
// Returns the resolved names and, separately, the Kinds discovery could not place: a CRD deleted
// since the backup was taken resolves to nothing, and dropping it silently would quietly leave its
// objects out of a restore the user asked for.
pub async fn resolve_resources(
    client: &Client,
    kinds: &[(String, String)],
) -> (Vec<String>, Vec<String>) {
    let mut resolved = Vec::new();
    let mut unresolved = Vec::new();
    for (api_version, kind) in kinds {
        match crate::yaml::dynamic_resource(client, api_version, kind, "default").await {
            Ok((_, ar)) => {
                let name = if ar.group.is_empty() {
                    ar.plural.clone()
                } else {
                    format!("{}.{}", ar.plural, ar.group)
                };
                if !resolved.contains(&name) {
                    resolved.push(name);
                }
            }
            Err(_) => unresolved.push(kind.clone()),
        }
    }
    (resolved, unresolved)
}

// `velero backup delete`: a request with a generated name, carrying both the backup's name and its
// UID so velero can refuse to act on a same-named backup that has since been re-created.
pub fn delete_request(namespace: &str, backup: &str, uid: &str) -> Value {
    json!({
        "apiVersion": API_V1,
        "kind": "DeleteBackupRequest",
        "metadata": {
            "generateName": format!("{}-", backup),
            "namespace": namespace,
            "labels": { L_BACKUP: valid_label(backup), L_BACKUP_UID: uid },
        },
        "spec": { "backupName": backup },
    })
}

// Run one write. Returns what to tell the user: the name of the object that now exists, or the new
// state of the one that was patched.
pub async fn apply_write(client: Client, write: VelWrite) -> Result<String, String> {
    let now = k8s_openapi::jiff::Timestamp::now().as_second();
    match write {
        VelWrite::BackupNow(s) => {
            let (name, body) = backup_from_schedule(&s, now);
            create(&client, "Backup", &s.namespace, body).await?;
            Ok(name)
        }
        VelWrite::Restore { namespace, backup, opts } => {
            let (name, body) = restore_from_backup(&namespace, &backup, &opts, now);
            create(&client, "Restore", &namespace, body).await?;
            Ok(name)
        }
        VelWrite::DeleteBackup { namespace, backup, uid } => {
            let body = delete_request(&namespace, &backup, &uid);
            create(&client, "DeleteBackupRequest", &namespace, body).await?;
            // Name the backup, not the request: the request has a generated name nobody asked for,
            // and the confirmation has to be readable as "this is the thing that is going away".
            Ok(backup)
        }
        VelWrite::Pause { namespace, name, paused } => {
            let api = crate::yaml::dynamic_api(&client, API_V1, "Schedule", &namespace).await?;
            let patch = json!({ "spec": { "paused": paused } });
            api.patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
                .await
                .map_err(crate::edit::api_error_text)?;
            Ok(name)
        }
    }
}

async fn create(
    client: &Client,
    kind: &str,
    namespace: &str,
    body: Value,
) -> Result<String, String> {
    let api = crate::yaml::dynamic_api(client, API_V1, kind, namespace).await?;
    let obj: DynamicObject = serde_json::from_value(body).map_err(|e| e.to_string())?;
    let created = api
        .create(&PostParams::default(), &obj)
        .await
        .map_err(crate::edit::api_error_text)?;
    Ok(created.metadata.name.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::{reads_as, FR};

    // 2026-07-30 12:00:00 UTC, so the cron assertions read as wall-clock times.
    const NOW: i64 = 1_785_412_800;

    fn at(spec: &str, from: i64) -> Option<i64> {
        parse_cron(spec)?.next_after(from)
    }

    fn schedule(name: &str, cron: &str) -> VelSchedule {
        let parsed = parse_cron(cron);
        VelSchedule {
            uid: format!("vel|sched|velero/{}", name),
            namespace: "velero".to_string(),
            name: name.to_string(),
            cron: cron.to_string(),
            created: NOW - 30 * 86400,
            phase: "Enabled".to_string(),
            next_run: parsed.as_ref().and_then(|c| c.next_after(NOW - 30 * 86400)),
            cron_ok: parsed.is_some(),
            ..VelSchedule::default()
        }
    }

    fn backup(name: &str, phase: &str, schedule: Option<&str>) -> VelBackup {
        VelBackup {
            uid: format!("vel|backup|velero/{}", name),
            namespace: "velero".to_string(),
            name: name.to_string(),
            phase: phase.to_string(),
            schedule: schedule.map(String::from),
            created: NOW - 3600,
            completed: Some(NOW - 3500),
            storage_location: "default".to_string(),
            total_items: 120,
            items_backed_up: 120,
            ..VelBackup::default()
        }
    }

    fn bsl(name: &str, phase: &str, default: bool) -> VelLocation {
        VelLocation {
            uid: format!("vel|bsl|velero/{}", name),
            namespace: "velero".to_string(),
            name: name.to_string(),
            phase: phase.to_string(),
            default,
            last_validated: Some(NOW - 60),
            created: NOW - 30 * 86400,
            ..VelLocation::default()
        }
    }

    fn inventory() -> Inventory {
        Inventory {
            schedules: Vec::new(),
            backups: Vec::new(),
            restores: Vec::new(),
            locations: vec![bsl("default", "Available", true)],
            snap_locations: Vec::new(),
            repos: Vec::new(),
            data_namespaces: None,
            opted_out: Vec::new(),
            server: ServerFacts {
                namespace: "velero".to_string(),
                found: true,
                ready: 1,
                desired: 1,
                ..ServerFacts::default()
            },
            csi_snapshot_classes: None,
        }
    }

    fn run(inv: Inventory) -> Analysed {
        analyse(inv, NOW, &FR)
    }

    #[test]
    fn cron_matches_the_standard_five_fields() {
        // Daily at 02:00 UTC, asked at noon: tomorrow, not today.
        let next = at("0 2 * * *", NOW).unwrap();
        assert_eq!(next, NOW + 14 * 3600);
        // Steps and lists.
        assert_eq!(at("*/15 * * * *", NOW).unwrap(), NOW + 15 * 60);
        assert_eq!(at("0 0,12 * * *", NOW).unwrap(), NOW + 12 * 3600);
        // Descriptors and intervals.
        assert_eq!(at("@daily", NOW).unwrap(), NOW + 12 * 3600);
        assert_eq!(at("@every 90m", NOW).unwrap(), NOW + 90 * 60);
        // Names, and a weekday-only expression.
        assert!(parse_cron("0 3 * * MON").is_some());
        // What velero would refuse.
        assert!(parse_cron("0 2 * *").is_none());
        assert!(parse_cron("").is_none());
        assert!(parse_cron("0 99 * * *").is_none());
    }

    #[test]
    fn restricted_day_fields_are_ored_not_anded() {
        // Vixie's rule, kept from robfig: with both day fields restricted the expression fires on
        // either — the 1st of the month *and* every Monday. An AND would skip most of them.
        let both = parse_cron("0 0 1 * 1").unwrap();
        let next = both.next_after(NOW).unwrap();
        let day = chrono::DateTime::from_timestamp(next, 0).unwrap();
        use chrono::Datelike;
        assert!(day.day() == 1 || day.weekday().num_days_from_sunday() == 1);
        // Under an AND reading the next firing would be months away; under OR it is within a week.
        assert!(next - NOW < 8 * 86400);
    }

    #[test]
    fn a_schedule_past_its_next_run_is_overdue() {
        let mut s = schedule("daily", "0 2 * * *");
        s.last_backup = Some(NOW - 3 * 86400);
        s.next_run = parse_cron(&s.cron).unwrap().next_after(NOW - 3 * 86400);
        let d = run(Inventory { schedules: vec![s], ..inventory() });
        assert!(d.schedules[0].hints.iter().any(|h| reads_as(&h.text, FR.vel_sched_overdue)));
        assert_eq!(d.schedules[0].hints[0].level, HintLevel::Danger);
    }

    #[test]
    fn an_overlapping_run_is_not_a_missed_one() {
        // Velero skips a run while one of the schedule's backups is still going, so the schedule is
        // late by the clock and correct by its own rules. Reporting it would be a false alarm.
        let mut s = schedule("daily", "0 2 * * *");
        s.last_backup = Some(NOW - 3 * 86400);
        s.next_run = parse_cron(&s.cron).unwrap().next_after(NOW - 3 * 86400);
        let mut running = backup("daily-1", "InProgress", Some("daily"));
        running.completed = None;
        let d = run(Inventory { schedules: vec![s], backups: vec![running], ..inventory() });
        assert!(!d.schedules[0].hints.iter().any(|h| reads_as(&h.text, FR.vel_sched_overdue)));
    }

    #[test]
    fn a_ttl_shorter_than_the_period_leaves_a_hole() {
        let mut s = schedule("weekly", "0 2 * * 0");
        s.ttl = Some(48 * 3600);
        s.last_backup = Some(NOW - 600);
        s.next_run = parse_cron(&s.cron).unwrap().next_after(NOW - 600);
        let d = run(Inventory { schedules: vec![s], ..inventory() });
        assert!(d.schedules[0].hints.iter().any(|h| reads_as(&h.text, FR.vel_sched_ttl_short)));
    }

    #[test]
    fn partially_failed_is_a_danger_not_a_success() {
        let mut b = backup("daily-1", "PartiallyFailed", Some("daily"));
        b.errors = 3;
        b.pvb_failed = vec!["pg-0:data — timeout".to_string()];
        let d = run(Inventory { backups: vec![b], ..inventory() });
        assert_eq!(d.backups[0].hints[0].level, HintLevel::Danger);
        assert!(d.backups[0].hints.iter().any(|h| reads_as(&h.text, FR.vel_bk_partial_many)));
        assert!(d.backups[0].hints.iter().any(|h| h.text.contains("pg-0:data")));
        // A single error is the common case and reads as one: the count comes from the API and
        // lands straight in the sentence.
        let mut one = backup("daily-2", "PartiallyFailed", Some("daily"));
        one.errors = 1;
        let d = run(Inventory { backups: vec![one], ..inventory() });
        assert!(d.backups[0].hints.iter().any(|h| reads_as(&h.text, FR.vel_bk_partial_one)));
    }

    #[test]
    fn namespaces_with_claims_and_no_schedule_are_reported() {
        let s = {
            let mut s = schedule("apps", "0 2 * * *");
            s.included_ns = vec!["prod-*".to_string()];
            s.last_backup = Some(NOW - 600);
            s.next_run = parse_cron(&s.cron).unwrap().next_after(NOW - 600);
            s
        };
        let d = run(Inventory {
            schedules: vec![s],
            // The glob covers `prod-api`; `data` is on its own.
            data_namespaces: Some(vec!["prod-api".to_string(), "data".to_string()]),
            ..inventory()
        });
        assert_eq!(d.uncovered, vec!["data".to_string()]);
        assert!(d.cluster_hints.iter().any(|h| reads_as(&h.text, FR.vel_ns_uncovered_one)));
    }

    #[test]
    fn coverage_abstains_when_the_claims_could_not_be_listed() {
        // Without the claim list there is nothing to compare against, and "no namespace is
        // uncovered" would be an invented answer rather than an observed one.
        let s = schedule("apps", "0 2 * * *");
        let d = run(Inventory { schedules: vec![s], data_namespaces: None, ..inventory() });
        assert!(d.uncovered.is_empty());
        assert!(!d.cluster_hints.iter().any(|h| reads_as(&h.text, FR.vel_ns_uncovered_one)));
    }

    #[test]
    fn an_observed_volume_backup_silences_the_inference() {
        let mut s = schedule("apps", "0 2 * * *");
        s.last_backup = Some(NOW - 600);
        s.next_run = parse_cron(&s.cron).unwrap().next_after(NOW - 600);
        let mut b = backup("apps-1", "Completed", Some("apps"));
        b.volume_snapshots_attempted = 2;
        b.volume_snapshots_completed = 2;
        let inv = Inventory {
            schedules: vec![s.clone()],
            backups: vec![b],
            data_namespaces: Some(vec!["data".to_string()]),
            csi_snapshot_classes: Some(0),
            ..inventory()
        };
        let d = run(inv);
        assert!(!d.schedules[0].hints.iter().any(|h| reads_as(&h.text, FR.vel_sched_volumes_unclear)));
        // Same schedule, no run that ever captured a volume: the doubt is worth raising.
        let d = run(Inventory {
            schedules: vec![s],
            backups: Vec::new(),
            data_namespaces: Some(vec!["data".to_string()]),
            csi_snapshot_classes: Some(0),
            ..inventory()
        });
        assert!(d.schedules[0].hints.iter().any(|h| reads_as(&h.text, FR.vel_sched_volumes_unclear)));
    }

    #[test]
    fn an_unavailable_location_condemns_everything_under_it() {
        let d = run(Inventory {
            locations: vec![bsl("default", "Unavailable", true)],
            backups: vec![backup("daily-1", "Completed", None)],
            ..inventory()
        });
        assert_eq!(d.locations[0].hints[0].level, HintLevel::Danger);
        assert!(d.backups[0].hints.iter().any(|h| reads_as(&h.text, FR.vel_bk_bsl_unavailable)));
    }

    #[test]
    fn an_expired_backup_still_present_means_the_collector_stopped() {
        let mut b = backup("daily-1", "Completed", Some("daily"));
        b.expiration = Some(NOW - 2 * 86400);
        let d = run(Inventory { backups: vec![b], ..inventory() });
        assert!(d.backups[0].hints.iter().any(|h| reads_as(&h.text, FR.vel_bk_expired)));
    }

    #[test]
    fn only_the_last_usable_backup_raises_the_expiry_alarm() {
        let mut old = backup("daily-1", "Completed", Some("daily"));
        old.created = NOW - 7 * 86400;
        old.completed = Some(NOW - 7 * 86400);
        old.expiration = Some(NOW + 3600);
        let mut fresh = backup("daily-2", "Completed", Some("daily"));
        fresh.expiration = Some(NOW + 30 * 86400);
        let d = run(Inventory { backups: vec![old, fresh], ..inventory() });
        let old = d.backups.iter().find(|b| b.name == "daily-1").unwrap();
        assert!(!old.hints.iter().any(|h| reads_as(&h.text, FR.vel_bk_last_expiring)));
    }

    #[test]
    fn a_paused_schedule_with_nothing_behind_it_is_a_danger() {
        let mut s = schedule("daily", "0 2 * * *");
        s.paused = true;
        let d = run(Inventory { schedules: vec![s.clone()], ..inventory() });
        assert!(d.schedules[0].hints.iter().any(|h| h.text == FR.vel_sched_paused_empty));
        // With a backup still standing it is a warning, not a loss.
        let d = run(Inventory {
            schedules: vec![s],
            backups: vec![backup("daily-1", "Completed", Some("daily"))],
            ..inventory()
        });
        assert!(d.schedules[0].hints.iter().any(|h| reads_as(&h.text, FR.vel_sched_paused)));
    }

    #[test]
    fn namespace_globs_follow_upstream() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("prod-*", "prod-api"));
        assert!(!glob_match("prod-*", "staging-api"));
        assert!(covers_namespace(&[], &[], "data"));
        assert!(!covers_namespace(&[], &["data".to_string()], "data"));
        assert!(covers_namespace(&["*".to_string()], &[], "data"));
        assert!(!covers_namespace(&["prod".to_string()], &[], "data"));
    }

    #[test]
    fn a_manual_run_is_labelled_like_a_scheduled_one() {
        // The schedule label is the only link between a backup and its schedule: get it wrong and
        // the backup is an orphan, invisible to retention and to this view's tree.
        let mut s = schedule("daily", "0 2 * * *");
        s.template = json!({ "ttl": "720h0m0s", "includedNamespaces": ["prod"], "metadata": { "labels": { "team": "core" } } });
        s.tpl_labels = vec![("team".to_string(), "core".to_string())];
        let (name, body) = backup_from_schedule(&s, NOW);
        assert!(name.starts_with("daily-"));
        assert_eq!(body["metadata"]["labels"][L_SCHEDULE], json!("daily"));
        assert_eq!(body["metadata"]["labels"]["team"], json!("core"));
        assert_eq!(body["spec"]["includedNamespaces"], json!(["prod"]));
        // The template's own metadata block is not a spec field.
        assert!(body["spec"].get("metadata").is_none());
    }

    #[test]
    fn a_delete_request_carries_the_uid() {
        let req = delete_request("velero", "daily-1", "abc-123");
        assert_eq!(req["spec"]["backupName"], json!("daily-1"));
        assert_eq!(req["metadata"]["generateName"], json!("daily-1-"));
        assert_eq!(req["metadata"]["labels"][L_BACKUP_UID], json!("abc-123"));
    }

    #[test]
    fn a_cluster_internal_endpoint_is_recognised() {
        // The default of every in-cluster MinIO install, and the reason a run log downloaded from a
        // laptop fails for a reason that has nothing to do with the backup.
        assert!(internal_endpoint("http://minio.velero.svc.cluster.local:9000"));
        assert!(internal_endpoint("http://minio.velero.svc:9000"));
        assert!(!internal_endpoint("https://s3.eu-west-3.amazonaws.com"));
        assert!(!internal_endpoint("https://minio.example.com:9000/path"));
        let mut l = bsl("default", "Available", true);
        l.s3_url = "http://minio.velero.svc.cluster.local:9000".to_string();
        let d = run(Inventory { locations: vec![l.clone()], ..inventory() });
        assert!(d.locations[0]
            .hints
            .iter()
            .any(|h| reads_as(&h.text, FR.vel_bsl_internal_endpoint)));
        // With a public URL set, downloads work from outside and there is nothing to report.
        l.public_url = "https://minio.example.com".to_string();
        let d = run(Inventory { locations: vec![l], ..inventory() });
        assert!(!d.locations[0]
            .hints
            .iter()
            .any(|h| reads_as(&h.text, FR.vel_bsl_internal_endpoint)));
    }

    #[test]
    fn go_durations_parse_as_velero_writes_them() {
        assert_eq!(parse_go_duration("720h0m0s"), Some(720 * 3600));
        assert_eq!(parse_go_duration("90m"), Some(5400));
        assert_eq!(parse_go_duration("1h30m"), Some(5400));
        assert_eq!(parse_go_duration("nope"), None);
    }



    // --- Contents -------------------------------------------------------------------------------

    const RESOURCE_LIST: &str = r#"{
        "v1/ConfigMap": ["prod/app-config", "monitoring/grafana"],
        "v1/Pod": ["prod/api-7d9f", "prod/api-5c2a"],
        "apps/v1/Deployment": ["prod/api"],
        "v1/Namespace": ["prod", "monitoring"],
        "rbac.authorization.k8s.io/v1/ClusterRole": ["view"]
    }"#;

    #[test]
    fn the_resource_list_groups_by_namespace() {
        let out = parse_resource_list(RESOURCE_LIST).expect("parses");
        // Namespaces alphabetically, cluster-scoped last — it is the group nobody looks for first.
        let names: Vec<&str> = out.iter().map(|n| n.namespace.as_str()).collect();
        assert_eq!(names, vec!["monitoring", "prod", ""]);

        let prod = &out[1];
        assert_eq!(prod.objects(), 4);
        let kinds: Vec<&str> = prod.kinds.iter().map(|k| k.kind.as_str()).collect();
        assert_eq!(kinds, vec!["ConfigMap", "Deployment", "Pod"]);
        // The apiVersion has to survive the grouping: it is what lets `y` open the live object.
        let dep = prod.kinds.iter().find(|k| k.kind == "Deployment").expect("Deployment");
        assert_eq!(dep.api_version, "apps/v1");
        let cm = prod.kinds.iter().find(|k| k.kind == "ConfigMap").expect("ConfigMap");
        assert_eq!(cm.api_version, "v1");
    }

    #[test]
    fn a_bare_name_is_a_cluster_scoped_object() {
        // Velero writes `ns/name` for a namespaced object and the bare name for a cluster-scoped
        // one. Reading a ClusterRole as a namespace called "view" would invent a namespace that
        // never existed — and offer it in the restore form.
        let out = parse_resource_list(RESOURCE_LIST).expect("parses");
        let cluster = out.last().expect("a cluster-scoped group");
        assert_eq!(cluster.namespace, "");
        assert_eq!(cluster.kinds.len(), 2);
        let cr = cluster.kinds.iter().find(|k| k.kind == "ClusterRole").expect("ClusterRole");
        assert_eq!(cr.names, vec!["view"]);
        assert_eq!(cr.api_version, "rbac.authorization.k8s.io/v1");
    }

    #[test]
    fn an_empty_list_is_not_a_failure() {
        // A backup that captured nothing is a real thing, and a different statement from a backup
        // whose inventory could not be downloaded. The two must not collapse into one.
        assert_eq!(parse_resource_list("{}").expect("parses"), Vec::new());
        assert!(parse_resource_list("not json at all").is_err());
        assert!(parse_resource_list("[\"a\", \"b\"]").is_err());
    }

    // --- Restore options ------------------------------------------------------------------------

    #[test]
    fn a_default_restore_is_the_one_the_view_always_made() {
        // The form is a narrowing of the plain restore, so with nothing narrowed it has to produce
        // byte for byte what `o` → Restaurer has always sent.
        let (name, body) = restore_from_backup("velero", "daily-1", &RestoreOptions::default(), NOW);
        assert!(name.starts_with("daily-1-"));
        assert_eq!(body["spec"], json!({ "backupName": "daily-1" }));
    }

    #[test]
    fn a_narrowed_restore_carries_only_what_was_chosen() {
        let opts = RestoreOptions {
            namespaces: vec!["prod".to_string()],
            namespace_mapping: Some(("prod".to_string(), "prod-restore".to_string())),
            resources: vec!["configmaps".to_string(), "deployments.apps".to_string()],
            label_selector: vec![("app".to_string(), "web".to_string())],
            overwrite_existing: true,
        };
        let (_, body) = restore_from_backup("velero", "daily-1", &opts, NOW);
        let spec = &body["spec"];
        assert_eq!(spec["includedNamespaces"], json!(["prod"]));
        assert_eq!(spec["namespaceMapping"], json!({ "prod": "prod-restore" }));
        assert_eq!(spec["includedResources"], json!(["configmaps", "deployments.apps"]));
        assert_eq!(spec["labelSelector"], json!({ "matchLabels": { "app": "web" } }));
        assert_eq!(spec["existingResourcePolicy"], json!("update"));
    }

    #[test]
    fn skipping_existing_objects_is_written_by_saying_nothing() {
        // `none` is what velero does with the field absent. Spelling it out would read as a decision
        // where none was made, and would break on the velero versions that predate the field.
        let opts = RestoreOptions {
            namespaces: vec!["prod".to_string()],
            overwrite_existing: false,
            ..RestoreOptions::default()
        };
        let (_, body) = restore_from_backup("velero", "daily-1", &opts, NOW);
        assert!(body["spec"].get("existingResourcePolicy").is_none());
    }
}
