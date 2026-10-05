//! Inventaire de la vue `:rancher-backup` (rancher/backup-restore-operator).
//!
//! L'opérateur sauvegarde des objets Kubernetes — ceux que désigne une `ResourceSet` — dans une
//! archive `.tar.gz` (`.enc` si chiffrée) posée sur un PV ou dans un bucket S3, et restaure ces
//! archives. Trois CRD cluster-scoped du groupe `resources.cattle.io/v1` : `Backup`, `Restore`,
//! `ResourceSet`. La vue sert à répondre à « ai-je un backup récent, et la restauration
//! marcherait-elle », ce que l'opérateur dit mal :
//!
//! - **un échec ne fait pas tomber `Ready`.** `setReconcilingCondition` pose `Reconciling=True`
//!   avec l'erreur et réécrit seulement le *message* de `Ready` en `Retrying` : un Backup récurrent
//!   qui échoue depuis une semaine garde `Ready=True` hérité de son dernier succès. Le verdict se
//!   lit donc sur `Reconciling`, jamais sur `Ready`.
//! - **un run manqué ne laisse aucune trace.** `nextSnapshotAt` n'est réécrit qu'au succès ; un
//!   opérateur arrêté laisse simplement passer l'heure. D'où la règle « en retard » calculée ici.
//! - **la rétention ne vaut que pour un Backup récurrent**, `0` y valant 10
//!   (`DefaultRetentionCount`) ; un Backup ponctuel n'est jamais purgé.
//! - **supprimer un Backup ne supprime aucune archive** : aucun finalizer, le contrôleur ignore
//!   l'objet dès sa `deletionTimestamp`.
//! - **sans chiffrement, les Secrets de la ResourceSet sont en clair dans l'archive** : seules les
//!   ressources listées par la configuration de chiffrement passent par un transformer.
//!
//! Tout vient du source de l'opérateur v5.0.4 (`pkg/controllers/backup`, `pkg/controllers/restore`,
//! `pkg/resourcesets/collector.go`, `main.go`), pas de sa documentation.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::jiff::Timestamp;
use kube::api::{Api, DynamicObject, ListParams, PostParams};
use kube::core::GroupVersionKind;
use kube::discovery;
use kube::Client;
use serde_json::{json, Value};

use crate::events::{EventRecord, LineColor};
use crate::lang::{fill, Strings};
use crate::storage::{hints_severity, Hint, HintLevel};

pub const GROUP: &str = "resources.cattle.io";
pub const API_V1: &str = "resources.cattle.io/v1";
// Posé par le chart sur le Deployment de l'opérateur, quelle que soit sa release.
const OPERATOR_LABEL: &str = "resources.cattle.io/operator=backup-restore";
// La clé que `GetEncryptionTransformers` lit dans le Secret nommé par `encryptionConfigSecretName`.
pub const ENCRYPTION_KEY: &str = "encryption-provider-config.yaml";
// `DefaultRetentionCount`, appliqué quand un Backup récurrent ne dit rien.
pub const DEFAULT_RETENTION: i64 = 10;
// Le temps qu'on laisse à un run pour se faire avant de le dire manqué. L'opérateur se réveille à
// l'heure dite (`EnqueueAfter`) et un backup Rancher prend des secondes à quelques minutes : une
// heure couvre un redémarrage de pod sans crier au loup.
pub const OVERDUE_GRACE_SECS: i64 = 3600;

fn info(text: String) -> Hint { Hint { level: HintLevel::Info, text } }
fn warn(text: String) -> Hint { Hint { level: HintLevel::Warn, text } }
fn danger(text: String) -> Hint { Hint { level: HintLevel::Danger, text } }

// --- Modèle -------------------------------------------------------------------------------------

/// Un emplacement S3 tel que l'écrit `spec.storageLocation.s3`.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct S3Location {
    pub endpoint: String,
    pub bucket: String,
    pub folder: String,
    pub region: String,
    pub credential_secret: String,
    pub insecure_tls: bool,
}

impl S3Location {
    pub fn label(&self) -> String {
        let folder = self.folder.trim_matches('/');
        if folder.is_empty() {
            format!("s3://{}", self.bucket)
        } else {
            format!("s3://{}/{}", self.bucket, folder)
        }
    }
}

/// Où l'opérateur range une archive quand le Backup ne le dit pas, lu dans son environnement :
/// `DEFAULT_PERSISTENCE_ENABLED` (un PV monté) ou `DEFAULT_S3_BACKUP_STORAGE_LOCATION` (un Secret
/// du namespace du chart). Ni l'un ni l'autre : chaque Backup doit porter son S3.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DefaultStorage {
    Pv { claim: String },
    S3 { secret: String },
    None,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Operator {
    pub namespace: String,
    pub name: String,
    pub ready: i32,
    pub desired: i32,
    pub version: String,
    pub default_storage: DefaultStorage,
}

impl Operator {
    pub fn up(&self) -> bool {
        self.ready > 0
    }

    pub fn storage_label(&self) -> String {
        match &self.default_storage {
            DefaultStorage::Pv { claim } if claim.is_empty() => "PV".to_string(),
            DefaultStorage::Pv { claim } => format!("PV {claim}"),
            DefaultStorage::S3 { secret } => format!("S3 ({secret})"),
            DefaultStorage::None => "—".to_string(),
        }
    }
}

/// Ce que la vue conclut d'un Backup ou d'une Restore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Completed,
    Failing,
    Pending,
    Overdue,
    Running,
}

impl Phase {
    pub fn label(self) -> &'static str {
        match self {
            Phase::Completed => "Completed",
            Phase::Failing => "Failing",
            Phase::Pending => "Pending",
            Phase::Overdue => "Overdue",
            Phase::Running => "Running",
        }
    }

    pub fn tone(self) -> LineColor {
        match self {
            Phase::Completed => LineColor::Ok,
            Phase::Failing | Phase::Overdue => LineColor::Err,
            Phase::Pending | Phase::Running => LineColor::Warn,
        }
    }
}

/// Le Secret de chiffrement, tel qu'on a pu le lire dans le namespace de l'opérateur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretCheck {
    Present,
    Missing,
    NoKey,
    Unknown,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RbkBackup {
    pub name: String,
    pub schedule: String,
    /// Le nombre d'archives gardées, effectif : `None` pour un Backup ponctuel, que la rétention
    /// ne touche jamais.
    pub retention: Option<i64>,
    pub retention_defaulted: bool,
    pub resource_set: String,
    pub encryption_secret: String,
    pub s3: Option<S3Location>,
    /// `status.storageLocation` : `PV` ou `S3`, écrit au premier succès.
    pub storage: String,
    pub backup_type: String,
    /// La dernière archive *réussie* : un échec ne touche pas ce champ.
    pub filename: String,
    pub last: Option<i64>,
    pub next: Option<i64>,
    pub generation: i64,
    pub observed_generation: i64,
    /// Le message de `Reconciling` quand il est à `True` : l'erreur du dernier essai.
    pub error: Option<String>,
    pub created: i64,
    pub phase: Phase,
    pub hints: Vec<Hint>,
}

impl RbkBackup {
    pub fn recurring(&self) -> bool {
        !self.schedule.is_empty()
    }

    pub fn encrypted(&self) -> bool {
        !self.encryption_secret.is_empty()
    }

    /// La colonne STORAGE : le S3 du Backup, sinon ce que l'opérateur a écrit au premier succès.
    pub fn storage_label(&self) -> String {
        match &self.s3 {
            Some(s3) => s3.label(),
            None if !self.storage.is_empty() => self.storage.clone(),
            None => "default".to_string(),
        }
    }

    pub fn worst(&self) -> Option<HintLevel> {
        self.hints.iter().map(|h| h.level).max()
    }

    /// Le prochain run est-il déjà passé ?
    pub fn late(&self, now: i64) -> bool {
        self.recurring() && self.next.is_some_and(|t| t < now)
    }

    /// La colonne NEXT : l'écart jusqu'au prochain run, ou de combien il est déjà passé.
    pub fn next_text(&self, now: i64) -> String {
        match self.next {
            _ if !self.recurring() => "—".to_string(),
            Some(t) if t >= now => crate::velero::format_span_short(t - now),
            Some(t) => format!("-{}", crate::velero::format_span_short(now - t)),
            None => "—".to_string(),
        }
    }

    /// La colonne KEEP : le nombre d'archives gardées, étoilé quand c'est le défaut de l'opérateur.
    pub fn keep_text(&self) -> String {
        match self.retention {
            Some(n) if self.retention_defaulted => format!("{n}*"),
            Some(n) => n.to_string(),
            None => "—".to_string(),
        }
    }
}

/// Le ton qu'un constat prête à la ligne qui le porte : seul ce qui demande un humain est coloré.
pub fn hint_tone(level: Option<HintLevel>) -> Option<LineColor> {
    match level? {
        HintLevel::Danger => Some(LineColor::Err),
        HintLevel::Warn => Some(LineColor::Warn),
        HintLevel::Info => None,
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RbkRestore {
    pub name: String,
    pub backup_filename: String,
    pub s3: Option<S3Location>,
    /// `spec.prune` absent vaut `true` : « prune by default » dans le contrôleur.
    pub prune: bool,
    pub delete_timeout: i64,
    pub encryption_secret: String,
    pub ignore_errors: bool,
    pub completed: Option<i64>,
    pub backup_source: String,
    pub error: Option<String>,
    pub created: i64,
    pub phase: Phase,
    pub hints: Vec<Hint>,
}

impl RbkRestore {
    pub fn worst(&self) -> Option<HintLevel> {
        self.hints.iter().map(|h| h.level).max()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RbkResourceSet {
    pub name: String,
    /// Un sélecteur par ligne, en clair : `v1 secrets ns=^cattle-` …
    pub selectors: Vec<String>,
    /// Les contrôleurs que la restauration arrête puis relance (`controllerReferences`).
    pub controller_refs: Vec<String>,
    pub selects_secrets: bool,
    /// Les expressions refusées par le moteur d'expressions régulières : chaque Backup qui lit
    /// cette ResourceSet échouera dessus.
    pub bad_regex: Vec<String>,
    pub used_by: Vec<String>,
    pub created: i64,
    pub hints: Vec<Hint>,
}

impl RbkResourceSet {
    pub fn worst(&self) -> Option<HintLevel> {
        self.hints.iter().map(|h| h.level).max()
    }
}

#[derive(Debug, Clone, Default)]
pub struct RbkState {
    /// Les CRD sont-elles servies ? `false` : l'opérateur n'a jamais été installé ici.
    pub installed: bool,
    pub backups: Vec<RbkBackup>,
    pub restores: Vec<RbkRestore>,
    pub resource_sets: Vec<RbkResourceSet>,
    /// `None` quand aucun Deployment ne porte le label de l'opérateur.
    pub operator: Option<Operator>,
    /// `false` quand les Deployments n'ont pas pu être listés : « introuvable », pas « absent ».
    pub operator_known: bool,
    pub cluster_hints: Vec<Hint>,
    /// Le plus récent `lastSnapshotTs` de tous les Backups : l'âge du dernier backup réussi.
    pub last_success: Option<i64>,
    pub error: Option<String>,
    pub loading: bool,
}

impl RbkState {
    /// Le nombre de lignes qui demandent un humain, toutes listes confondues.
    pub fn problems(&self) -> usize {
        let flagged = |l: Option<HintLevel>| l.is_some_and(|l| l >= HintLevel::Warn);
        self.backups.iter().filter(|b| flagged(b.worst())).count()
            + self.restores.iter().filter(|r| flagged(r.worst())).count()
            + self.resource_sets.iter().filter(|r| flagged(r.worst())).count()
    }
}

pub type SharedRbk = Arc<Mutex<RbkState>>;

pub fn new_rbk_state() -> SharedRbk {
    Arc::new(Mutex::new(RbkState::default()))
}

// --- Lignes -------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RbkWorld {
    #[default]
    Backups,
    Restores,
    ResourceSets,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RbkRow {
    Backup(usize),
    Restore(usize),
    ResourceSet(usize),
}

#[derive(Debug, Clone, Default)]
pub struct RbkView {
    pub backups: Vec<RbkBackup>,
    pub restores: Vec<RbkRestore>,
    pub resource_sets: Vec<RbkResourceSet>,
    pub rows: Vec<RbkRow>,
}

impl RbkView {
    pub fn backup_of(&self, row: &RbkRow) -> Option<&RbkBackup> {
        match row {
            RbkRow::Backup(i) => self.backups.get(*i),
            _ => None,
        }
    }

    pub fn restore_of(&self, row: &RbkRow) -> Option<&RbkRestore> {
        match row {
            RbkRow::Restore(i) => self.restores.get(*i),
            _ => None,
        }
    }

    pub fn resource_set_of(&self, row: &RbkRow) -> Option<&RbkResourceSet> {
        match row {
            RbkRow::ResourceSet(i) => self.resource_sets.get(*i),
            _ => None,
        }
    }
}

fn flagged(level: Option<HintLevel>) -> bool {
    level.is_some_and(|l| l >= HintLevel::Warn)
}

/// Les lignes d'un monde. `problems` ne garde que ce qui porte un constat `Warn` ou pire.
pub fn build_rbk_view(state: &RbkState, world: RbkWorld, problems: bool) -> RbkView {
    let mut view = RbkView {
        backups: state.backups.clone(),
        restores: state.restores.clone(),
        resource_sets: state.resource_sets.clone(),
        rows: Vec::new(),
    };
    if problems {
        view.backups.retain(|b| flagged(b.worst()));
        view.restores.retain(|r| flagged(r.worst()));
        view.resource_sets.retain(|r| flagged(r.worst()));
    }
    view.rows = match world {
        RbkWorld::Backups => (0..view.backups.len()).map(RbkRow::Backup).collect(),
        RbkWorld::Restores => (0..view.restores.len()).map(RbkRow::Restore).collect(),
        RbkWorld::ResourceSets => (0..view.resource_sets.len()).map(RbkRow::ResourceSet).collect(),
    };
    view
}

// --- Enregistrements ----------------------------------------------------------------------------

fn record(uid: String, kind: &str, name: &str, reason: &str, hints: &[Hint], message: String) -> EventRecord {
    EventRecord {
        uid,
        time: Timestamp::now(),
        severity: hints_severity(hints),
        reason: reason.to_string(),
        api_version: API_V1.to_string(),
        kind: kind.to_string(),
        namespace: String::new(),
        name: name.to_string(),
        message,
        component: String::new(),
        host: String::new(),
        count: 1,
    }
}

// Le message d'un enregistrement : le constat le plus grave, sinon le résumé de la ligne.
fn headline(hints: &[Hint], fallback: String) -> String {
    hints
        .iter()
        .max_by_key(|h| h.level)
        .filter(|h| h.level >= HintLevel::Warn)
        .map(|h| h.text.clone())
        .unwrap_or(fallback)
}

pub fn backup_record(b: &RbkBackup, st: &'static Strings) -> EventRecord {
    let summary = fill(
        st.rbk_rec_backup,
        &[
            ("type", if b.recurring() { "Recurring" } else { "One-time" }),
            ("file", if b.filename.is_empty() { "—" } else { &b.filename }),
        ],
    );
    record(
        format!("rbk|backup|{}", b.name),
        "Backup",
        &b.name,
        b.phase.label(),
        &b.hints,
        headline(&b.hints, summary),
    )
}

pub fn restore_record(r: &RbkRestore, st: &'static Strings) -> EventRecord {
    let summary = fill(st.rbk_rec_restore, &[("file", &r.backup_filename)]);
    record(
        format!("rbk|restore|{}", r.name),
        "Restore",
        &r.name,
        r.phase.label(),
        &r.hints,
        headline(&r.hints, summary),
    )
}

pub fn resource_set_record(r: &RbkResourceSet, st: &'static Strings) -> EventRecord {
    let summary = st.plural(r.selectors.len(), st.rbk_rec_rs_one, st.rbk_rec_rs_many);
    record(
        format!("rbk|rs|{}", r.name),
        "ResourceSet",
        &r.name,
        "ResourceSet",
        &r.hints,
        headline(&r.hints, summary),
    )
}

pub fn row_record(view: &RbkView, row: &RbkRow, st: &'static Strings) -> Option<EventRecord> {
    match row {
        RbkRow::Backup(i) => view.backups.get(*i).map(|b| backup_record(b, st)),
        RbkRow::Restore(i) => view.restores.get(*i).map(|r| restore_record(r, st)),
        RbkRow::ResourceSet(i) => view.resource_sets.get(*i).map(|r| resource_set_record(r, st)),
    }
}

// --- Lecture ------------------------------------------------------------------------------------

fn str_at(v: &Value, path: &[&str]) -> String {
    let mut cur = v;
    for p in path {
        match cur.get(p) {
            Some(next) => cur = next,
            None => return String::new(),
        }
    }
    cur.as_str().map(String::from).unwrap_or_default()
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

fn ts_at(v: &Value, path: &[&str]) -> Option<i64> {
    let raw = str_at(v, path);
    if raw.is_empty() {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(&raw).ok().map(|t| t.timestamp())
}

fn meta_ts(obj: &DynamicObject) -> i64 {
    obj.metadata
        .creation_timestamp
        .as_ref()
        .map(|t| t.0.as_second())
        .unwrap_or(0)
}

// Le message d'une condition à `True`, ou `None`.
fn condition_true(v: &Value, kind: &str) -> Option<String> {
    let conds = v.get("status")?.get("conditions")?.as_array()?;
    let c = conds.iter().find(|c| c.get("type").and_then(Value::as_str) == Some(kind))?;
    if c.get("status").and_then(Value::as_str) != Some("True") {
        return None;
    }
    Some(c.get("message").and_then(Value::as_str).unwrap_or_default().to_string())
}

fn parse_s3(v: &Value) -> Option<S3Location> {
    let s3 = v.get("spec")?.get("storageLocation")?.get("s3")?;
    if !s3.is_object() {
        return None;
    }
    let secret_ns = str_at(s3, &["credentialSecretNamespace"]);
    let secret = str_at(s3, &["credentialSecretName"]);
    Some(S3Location {
        endpoint: str_at(s3, &["endpoint"]),
        bucket: str_at(s3, &["bucketName"]),
        folder: str_at(s3, &["folder"]),
        region: str_at(s3, &["region"]),
        credential_secret: match (secret_ns.is_empty(), secret.is_empty()) {
            (_, true) => String::new(),
            (true, false) => secret,
            (false, false) => format!("{secret_ns}/{secret}"),
        },
        insecure_tls: bool_at(s3, &["insecureTLSSkipVerify"]).unwrap_or(false),
    })
}

pub fn parse_backup(obj: &DynamicObject) -> RbkBackup {
    let d = &obj.data;
    let schedule = str_at(d, &["spec", "schedule"]);
    let raw_retention = int_at(d, &["spec", "retentionCount"]);
    let (retention, retention_defaulted) = if schedule.is_empty() {
        (None, false)
    } else if raw_retention == 0 {
        (Some(DEFAULT_RETENTION), true)
    } else {
        (Some(raw_retention), false)
    };
    // `Reconciling` porte la raison `Error` quand il signale un échec ; c'est la seule condition que
    // l'opérateur pose en dehors du succès, et il l'efface (`Conditions = {}`) au run suivant réussi.
    let error = condition_true(d, "Reconciling");
    RbkBackup {
        name: obj.metadata.name.clone().unwrap_or_default(),
        schedule,
        retention,
        retention_defaulted,
        resource_set: str_at(d, &["spec", "resourceSetName"]),
        encryption_secret: str_at(d, &["spec", "encryptionConfigSecretName"]),
        s3: parse_s3(d),
        storage: str_at(d, &["status", "storageLocation"]),
        backup_type: str_at(d, &["status", "backupType"]),
        filename: str_at(d, &["status", "filename"]),
        last: ts_at(d, &["status", "lastSnapshotTs"]),
        next: ts_at(d, &["status", "nextSnapshotAt"]),
        generation: obj.metadata.generation.unwrap_or(0),
        observed_generation: int_at(d, &["status", "observedGeneration"]),
        error,
        created: meta_ts(obj),
        phase: Phase::Pending,
        hints: Vec::new(),
    }
}

pub fn parse_restore(obj: &DynamicObject) -> RbkRestore {
    let d = &obj.data;
    RbkRestore {
        name: obj.metadata.name.clone().unwrap_or_default(),
        backup_filename: str_at(d, &["spec", "backupFilename"]),
        s3: parse_s3(d),
        prune: bool_at(d, &["spec", "prune"]).unwrap_or(true),
        delete_timeout: int_at(d, &["spec", "deleteTimeoutSeconds"]),
        encryption_secret: str_at(d, &["spec", "encryptionConfigSecretName"]),
        ignore_errors: bool_at(d, &["spec", "ignoreErrors"]).unwrap_or(false),
        completed: ts_at(d, &["status", "restoreCompletionTs"]),
        backup_source: str_at(d, &["status", "backupSource"]),
        error: condition_true(d, "Reconciling"),
        created: meta_ts(obj),
        phase: Phase::Running,
        hints: Vec::new(),
    }
}

// Ce qu'un sélecteur retient des types d'objets, en clair.
fn selector_kinds(sel: &Value) -> String {
    let kinds = strings_at(sel, &["kinds"]);
    let re = str_at(sel, &["kindsRegexp"]);
    match (kinds.is_empty(), re.is_empty()) {
        (true, true) => "*".to_string(),
        (false, true) => kinds.join(","),
        (true, false) => format!("/{re}/"),
        (false, false) => format!("{} /{re}/", kinds.join(",")),
    }
}

fn selector_summary(sel: &Value) -> String {
    let mut parts = vec![str_at(sel, &["apiVersion"]), selector_kinds(sel)];
    let ns = strings_at(sel, &["namespaces"]);
    let ns_re = str_at(sel, &["namespaceRegexp"]);
    if !ns.is_empty() {
        parts.push(format!("ns={}", ns.join(",")));
    }
    if !ns_re.is_empty() {
        parts.push(format!("ns=/{ns_re}/"));
    }
    let names = strings_at(sel, &["resourceNames"]);
    let name_re = str_at(sel, &["resourceNameRegexp"]);
    if !names.is_empty() {
        parts.push(format!("name={}", names.join(",")));
    }
    if !name_re.is_empty() {
        parts.push(format!("name=/{name_re}/"));
    }
    if sel.get("labelSelectors").is_some_and(|l| !l.is_null()) {
        parts.push("labels".to_string());
    }
    let ex_kinds = strings_at(sel, &["excludeKinds"]);
    if !ex_kinds.is_empty() {
        parts.push(format!("-{}", ex_kinds.join(",")));
    }
    let ex_name = str_at(sel, &["excludeResourceNameRegexp"]);
    if !ex_name.is_empty() {
        parts.push(format!("-name=/{ex_name}/"));
    }
    parts.join(" ")
}

/// Le sélecteur retient-il les Secrets ? Même règle que `filterByKind` : une correspondance sur le
/// `Kind` (`Secret`) ou sur le nom de la ressource (`secrets`), `.` valant tout, une exclusion par
/// l'un ou l'autre l'emportant. Un sélecteur sans aucun filtre de type prend tout le groupe.
pub fn selects_secrets(sel: &Value) -> bool {
    if str_at(sel, &["apiVersion"]) != "v1" {
        return false;
    }
    let excluded = strings_at(sel, &["excludeKinds"]);
    if excluded.iter().any(|k| k == "Secret" || k == "secrets") {
        return false;
    }
    let kinds = strings_at(sel, &["kinds"]);
    let re = str_at(sel, &["kindsRegexp"]);
    if kinds.is_empty() && re.is_empty() {
        return true;
    }
    if kinds.iter().any(|k| k == "Secret" || k == "secrets") {
        return true;
    }
    if re.is_empty() {
        return false;
    }
    if re == "." {
        return true;
    }
    regex::Regex::new(&re).is_ok_and(|r| r.is_match("Secret") || r.is_match("secrets"))
}

pub fn parse_resource_set(obj: &DynamicObject) -> RbkResourceSet {
    let d = &obj.data;
    let selectors: Vec<Value> = d
        .get("resourceSelectors")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut bad_regex = Vec::new();
    for sel in &selectors {
        for key in ["kindsRegexp", "namespaceRegexp", "resourceNameRegexp", "excludeResourceNameRegexp"] {
            let re = str_at(sel, &[key]);
            if !re.is_empty() && regex::Regex::new(&re).is_err() {
                bad_regex.push(re);
            }
        }
    }
    let controller_refs = d
        .get("controllerReferences")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|c| {
                    let ns = str_at(c, &["namespace"]);
                    let res = str_at(c, &["resource"]);
                    let name = str_at(c, &["name"]);
                    if ns.is_empty() { format!("{res}/{name}") } else { format!("{res} {ns}/{name}") }
                })
                .collect()
        })
        .unwrap_or_default();
    RbkResourceSet {
        name: obj.metadata.name.clone().unwrap_or_default(),
        selectors: selectors.iter().map(selector_summary).collect(),
        controller_refs,
        selects_secrets: selectors.iter().any(selects_secrets),
        bad_regex,
        used_by: Vec::new(),
        created: meta_ts(obj),
        hints: Vec::new(),
    }
}

fn parse_operator(d: &Deployment) -> Operator {
    let pod = d.spec.as_ref().and_then(|s| s.template.spec.as_ref());
    let container = pod.and_then(|p| p.containers.first());
    let env = |key: &str| -> String {
        container
            .and_then(|c| c.env.as_ref())
            .and_then(|e| e.iter().find(|v| v.name == key))
            .and_then(|v| v.value.clone())
            .unwrap_or_default()
    };
    let default_storage = if !env("DEFAULT_PERSISTENCE_ENABLED").is_empty() {
        // Le chart monte le PVC sous le volume `pv-storage` ; un autre nom ne nous empêche pas de
        // dire « PV », seulement de nommer le claim.
        let claim = pod
            .and_then(|p| p.volumes.as_ref())
            .and_then(|vs| vs.iter().find(|v| v.name == "pv-storage"))
            .and_then(|v| v.persistent_volume_claim.as_ref())
            .map(|c| c.claim_name.clone())
            .unwrap_or_default();
        DefaultStorage::Pv { claim }
    } else if !env("DEFAULT_S3_BACKUP_STORAGE_LOCATION").is_empty() {
        DefaultStorage::S3 { secret: env("DEFAULT_S3_BACKUP_STORAGE_LOCATION") }
    } else {
        DefaultStorage::None
    };
    let namespace = {
        let chart_ns = env("CHART_NAMESPACE");
        if chart_ns.is_empty() { d.metadata.namespace.clone().unwrap_or_default() } else { chart_ns }
    };
    let status = d.status.as_ref();
    Operator {
        namespace,
        name: d.metadata.name.clone().unwrap_or_default(),
        ready: status.and_then(|s| s.ready_replicas).unwrap_or(0),
        desired: d.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1),
        version: container
            .and_then(|c| c.image.as_ref())
            .and_then(|i| i.rsplit_once(':').map(|(_, tag)| tag.to_string()))
            .unwrap_or_default(),
        default_storage,
    }
}

// --- Diagnostic ---------------------------------------------------------------------------------

/// Tout ce qu'une passe de lecture a ramené, avant diagnostic.
#[derive(Debug, Clone, Default)]
pub struct Observed {
    pub backups: Vec<RbkBackup>,
    pub restores: Vec<RbkRestore>,
    pub resource_sets: Vec<RbkResourceSet>,
    /// `false` quand les ResourceSets n'ont pas pu être listées : « absente » ne se dit alors pas.
    pub resource_sets_known: bool,
    pub operator: Option<Operator>,
    pub operator_known: bool,
    pub secrets: HashMap<String, SecretCheck>,
}

fn secret_hint(name: &str, check: SecretCheck, ns: &str, st: &'static Strings) -> Option<Hint> {
    match check {
        SecretCheck::Missing => Some(danger(fill(st.rbk_h_enc_missing, &[("secret", name), ("ns", ns)]))),
        SecretCheck::NoKey => Some(danger(fill(
            st.rbk_h_enc_nokey,
            &[("secret", name), ("key", ENCRYPTION_KEY)],
        ))),
        SecretCheck::Present | SecretCheck::Unknown => None,
    }
}

/// Les règles, sur une photographie : pas de client, pas d'horloge, testable.
pub fn diagnose(mut obs: Observed, now: i64, st: &'static Strings) -> RbkState {
    let op_ns = obs.operator.as_ref().map(|o| o.namespace.clone()).unwrap_or_default();
    // L'opérateur ne peut pas tourner : soit il n'existe pas, soit aucun pod n'est prêt. `None`
    // quand on n'a pas pu le chercher, et alors aucune règle ne s'appuie dessus.
    let operator_down: Option<bool> = if obs.operator_known {
        Some(obs.operator.as_ref().is_none_or(|o| !o.up()))
    } else {
        None
    };
    let default_storage = obs.operator.as_ref().map(|o| o.default_storage.clone());

    let rs_secrets: HashMap<String, bool> = obs
        .resource_sets
        .iter()
        .map(|r| (r.name.clone(), r.selects_secrets))
        .collect();

    for b in &mut obs.backups {
        let mut hints = Vec::new();
        let overdue_at = b.next.filter(|next| b.recurring() && now > next + OVERDUE_GRACE_SECS);
        b.phase = if b.error.is_some() {
            Phase::Failing
        } else if overdue_at.is_some() {
            Phase::Overdue
        } else if b.last.is_some() {
            Phase::Completed
        } else {
            Phase::Pending
        };

        match b.phase {
            Phase::Failing => {
                let e = b.error.clone().unwrap_or_default();
                hints.push(danger(match b.last {
                    Some(t) => fill(
                        st.rbk_h_failing_since,
                        &[("age", &crate::velero::age_of(t, now)), ("e", &e)],
                    ),
                    None => fill(st.rbk_h_failing, &[("e", &e)]),
                }));
            }
            Phase::Overdue => {
                let when = overdue_at
                    .map(|t| crate::velero::age_of(t, now))
                    .unwrap_or_default();
                let tpl = if operator_down == Some(true) {
                    st.rbk_h_overdue_operator
                } else {
                    st.rbk_h_overdue
                };
                hints.push(danger(fill(tpl, &[("age", &when)])));
            }
            Phase::Pending if operator_down == Some(true) => {
                hints.push(danger(st.rbk_h_pending_no_operator.to_string()));
            }
            Phase::Pending => hints.push(info(st.rbk_h_pending.to_string())),
            Phase::Completed | Phase::Running => {}
        }

        if obs.resource_sets_known && !b.resource_set.is_empty() && !rs_secrets.contains_key(&b.resource_set) {
            hints.push(danger(fill(st.rbk_h_no_resourceset, &[("rs", &b.resource_set)])));
        }
        if b.s3.is_none() && default_storage == Some(DefaultStorage::None) {
            hints.push(danger(st.rbk_h_no_storage.to_string()));
        }
        if b.encrypted() {
            if let Some(h) = obs
                .secrets
                .get(&b.encryption_secret)
                .and_then(|c| secret_hint(&b.encryption_secret, *c, &op_ns, st))
            {
                hints.push(h);
            }
        } else if rs_secrets.get(&b.resource_set).copied().unwrap_or(false) {
            hints.push(warn(fill(st.rbk_h_secrets_clear, &[("rs", &b.resource_set)])));
        }
        if b.generation > 0 && b.observed_generation > 0 && b.generation != b.observed_generation {
            hints.push(info(st.rbk_h_not_observed.to_string()));
        }
        // Un PV vit dans le cluster qu'il sauvegarde, sauf si sa classe le met ailleurs : on le
        // dit, sans en faire une alerte, puisque la classe peut très bien être un NFS externe.
        let on_pv = b.s3.is_none()
            && (b.storage == "PV" || matches!(default_storage, Some(DefaultStorage::Pv { .. })));
        if on_pv {
            hints.push(info(st.rbk_h_on_pv.to_string()));
        }
        hints.sort_by(|a, b| b.level.cmp(&a.level));
        b.hints = hints;
    }

    for r in &mut obs.restores {
        let mut hints = Vec::new();
        r.phase = if r.completed.is_some() {
            Phase::Completed
        } else if r.error.is_some() {
            Phase::Failing
        } else {
            Phase::Running
        };
        match r.phase {
            Phase::Failing => hints.push(danger(fill(
                st.rbk_h_restore_failing,
                &[("e", r.error.as_deref().unwrap_or_default())],
            ))),
            Phase::Running if operator_down == Some(true) => {
                hints.push(danger(st.rbk_h_restore_no_operator.to_string()));
            }
            Phase::Running => hints.push(warn(st.rbk_h_restore_running.to_string())),
            _ => {}
        }
        if r.phase != Phase::Completed {
            if !r.encryption_secret.is_empty() {
                if let Some(h) = obs
                    .secrets
                    .get(&r.encryption_secret)
                    .and_then(|c| secret_hint(&r.encryption_secret, *c, &op_ns, st))
                {
                    hints.push(h);
                }
            }
            if r.prune {
                hints.push(info(st.rbk_h_restore_prune.to_string()));
            }
        }
        hints.sort_by(|a, b| b.level.cmp(&a.level));
        r.hints = hints;
    }

    for rs in &mut obs.resource_sets {
        rs.used_by = obs
            .backups
            .iter()
            .filter(|b| b.resource_set == rs.name)
            .map(|b| b.name.clone())
            .collect();
        let mut hints = Vec::new();
        for re in &rs.bad_regex {
            hints.push(danger(fill(st.rbk_h_rs_bad_regex, &[("re", re)])));
        }
        if rs.used_by.is_empty() {
            hints.push(info(st.rbk_h_rs_unused.to_string()));
        }
        rs.hints = hints;
    }

    obs.backups.sort_by(|a, b| a.name.cmp(&b.name));
    obs.restores.sort_by(|a, b| b.created.cmp(&a.created).then_with(|| a.name.cmp(&b.name)));
    obs.resource_sets.sort_by(|a, b| a.name.cmp(&b.name));

    let last_success = obs.backups.iter().filter_map(|b| b.last).max();
    let mut cluster_hints = Vec::new();
    match (&obs.operator, obs.operator_known) {
        (None, true) => cluster_hints.push(danger(st.rbk_h_no_operator.to_string())),
        (Some(op), _) if !op.up() => cluster_hints.push(danger(fill(
            st.rbk_h_operator_down,
            &[("ns", &op.namespace), ("name", &op.name)],
        ))),
        (None, false) => cluster_hints.push(info(st.rbk_h_operator_unknown.to_string())),
        _ => {}
    }
    if obs.backups.is_empty() {
        cluster_hints.push(warn(st.rbk_h_no_backup.to_string()));
    } else if !obs.backups.iter().any(|b| b.recurring()) {
        cluster_hints.push(warn(st.rbk_h_no_recurring.to_string()));
    }
    // L'âge du dernier succès est déjà dans le titre et dans la barre : le constat ne parle que
    // quand il n'y en a jamais eu.
    if last_success.is_none() && !obs.backups.is_empty() {
        cluster_hints.push(danger(st.rbk_h_never.to_string()));
    }

    RbkState {
        installed: true,
        backups: obs.backups,
        restores: obs.restores,
        resource_sets: obs.resource_sets,
        operator: obs.operator,
        operator_known: obs.operator_known,
        cluster_hints,
        last_success,
        error: None,
        loading: false,
    }
}

// --- Sondes -------------------------------------------------------------------------------------

/// Le côté TUI : l'inventaire, posé dans l'état partagé qu'il redessine.
pub async fn fetch_rbk(client: Client, state: SharedRbk) {
    {
        let mut s = state.lock().expect("rancher-backup poisoned");
        s.loading = true;
        s.error = None;
    }
    let result = rbk_inventory(&client, crate::lang::active()).await;
    let mut s = state.lock().expect("rancher-backup poisoned");
    match result {
        Ok(inv) => *s = inv,
        Err(e) => {
            s.loading = false;
            s.error = Some(e);
        }
    }
}

/// Une passe complète, diagnostiquée. Rend une valeur plutôt que de remplir un état, pour que
/// kdt-web lise exactement ce que lit le TUI ; la langue est un paramètre pour la même raison.
pub async fn rbk_inventory(client: &Client, st: &'static Strings) -> Result<RbkState, String> {
    let gvk = |kind: &str| GroupVersionKind::gvk(GROUP, "v1", kind);
    let Ok((backup_ar, _)) = discovery::pinned_kind(client, &gvk("Backup")).await else {
        return Ok(RbkState::default());
    };
    let restore_ar = discovery::pinned_kind(client, &gvk("Restore")).await.ok().map(|(ar, _)| ar);
    let rs_ar = discovery::pinned_kind(client, &gvk("ResourceSet")).await.ok().map(|(ar, _)| ar);

    let lp = ListParams::default();
    let backups_api: Api<DynamicObject> = Api::all_with(client.clone(), &backup_ar);
    let deploys: Api<Deployment> = Api::all(client.clone());
    let operator_lp = ListParams::default().labels(OPERATOR_LABEL);
    let restores = async {
        match &restore_ar {
            Some(ar) => Api::<DynamicObject>::all_with(client.clone(), ar).list(&lp).await.ok(),
            None => None,
        }
    };
    let rsets = async {
        match &rs_ar {
            Some(ar) => Api::<DynamicObject>::all_with(client.clone(), ar).list(&lp).await.ok(),
            None => None,
        }
    };
    let (backups, restores, rsets, deploys) = tokio::join!(
        backups_api.list(&lp),
        restores,
        rsets,
        deploys.list(&operator_lp),
    );
    // Les Backups sont le sujet de la vue : sans eux il n'y a rien à dire.
    let backups = backups.map_err(|e| e.to_string())?;

    let (operator, operator_known) = match &deploys {
        Ok(list) => (list.items.first().map(parse_operator), true),
        Err(_) => (None, false),
    };

    let mut obs = Observed {
        backups: backups.items.iter().map(parse_backup).collect(),
        restores: restores.map(|l| l.items.iter().map(parse_restore).collect()).unwrap_or_default(),
        resource_sets_known: rsets.is_some(),
        resource_sets: rsets.map(|l| l.items.iter().map(parse_resource_set).collect()).unwrap_or_default(),
        operator,
        operator_known,
        secrets: HashMap::new(),
    };

    // Les Secrets de chiffrement vivent dans le namespace du chart (`util.ChartNamespace`). On ne
    // lit que la présence de la clé ; un refus de lecture laisse la règle muette.
    if let Some(op) = &obs.operator {
        let names: HashSet<String> = obs
            .backups
            .iter()
            .map(|b| b.encryption_secret.clone())
            .chain(obs.restores.iter().map(|r| r.encryption_secret.clone()))
            .filter(|n| !n.is_empty())
            .collect();
        let api: Api<Secret> = Api::namespaced(client.clone(), &op.namespace);
        for name in names {
            let check = match api.get_opt(&name).await {
                Ok(Some(s)) => {
                    if s.data.as_ref().is_some_and(|d| d.contains_key(ENCRYPTION_KEY)) {
                        SecretCheck::Present
                    } else {
                        SecretCheck::NoKey
                    }
                }
                Ok(None) => SecretCheck::Missing,
                Err(_) => SecretCheck::Unknown,
            };
            obs.secrets.insert(name, check);
        }
    }

    Ok(diagnose(obs, Timestamp::now().as_second(), st))
}

// --- Écritures ----------------------------------------------------------------------------------

/// Les deux écritures de la vue. Chacune nomme un Backup, que l'écriture **relit** avant de bâtir
/// l'objet : ce que la page ou l'écran a vu il y a vingt secondes ne décide de rien.
#[derive(Debug, Clone)]
pub enum RbkWrite {
    /// Un Backup ponctuel calqué sur celui-ci : même ResourceSet, même stockage, même chiffrement,
    /// sans `schedule` — donc jamais purgé par la rétention.
    BackupNow { from: String },
    /// Une Restore de la dernière archive réussie de ce Backup, `prune: true` comme le contrôleur
    /// le fait par défaut.
    Restore { from: String },
}

impl RbkWrite {
    pub fn target(&self) -> &str {
        match self {
            RbkWrite::BackupNow { from } | RbkWrite::Restore { from } => from,
        }
    }
}

pub fn timestamped(base: &str, now: i64) -> String {
    let stamp = chrono::DateTime::from_timestamp(now, 0)
        .map(|t| t.format("%Y%m%d%H%M%S").to_string())
        .unwrap_or_else(|| now.to_string());
    // Un nom d'objet tient en 253 caractères ; on garde la marge pour le suffixe.
    let base: String = base.chars().take(230).collect();
    format!("{}-{}", base.trim_end_matches('-'), stamp)
}

// Les champs du Backup que ses dérivés reprennent tels quels.
fn copied_spec(backup: &Value) -> serde_json::Map<String, Value> {
    let mut spec = serde_json::Map::new();
    if let Some(loc) = backup.get("spec").and_then(|s| s.get("storageLocation")).filter(|l| !l.is_null()) {
        spec.insert("storageLocation".to_string(), loc.clone());
    }
    let enc = str_at(backup, &["spec", "encryptionConfigSecretName"]);
    if !enc.is_empty() {
        spec.insert("encryptionConfigSecretName".to_string(), json!(enc));
    }
    spec
}

/// Le Backup ponctuel qu'un « backup maintenant » crée.
pub fn backup_now_body(from: &str, backup: &Value, now: i64) -> (String, Value) {
    let name = timestamped(&format!("{from}-now"), now);
    let mut spec = copied_spec(backup);
    spec.insert("resourceSetName".to_string(), json!(str_at(backup, &["spec", "resourceSetName"])));
    (
        name.clone(),
        json!({ "apiVersion": API_V1, "kind": "Backup", "metadata": { "name": name }, "spec": spec }),
    )
}

/// La Restore de la dernière archive réussie. `Err` quand le Backup n'en a aucune.
pub fn restore_body(from: &str, backup: &Value, now: i64, st: &'static Strings) -> Result<(String, Value), String> {
    let filename = str_at(backup, &["status", "filename"]);
    if filename.is_empty() {
        return Err(fill(st.rbk_no_archive, &[("name", from)]));
    }
    let name = timestamped(&format!("restore-{from}"), now);
    let mut spec = copied_spec(backup);
    spec.insert("backupFilename".to_string(), json!(filename));
    spec.insert("prune".to_string(), json!(true));
    Ok((
        name.clone(),
        json!({ "apiVersion": API_V1, "kind": "Restore", "metadata": { "name": name }, "spec": spec }),
    ))
}

/// Exécute une écriture et rend le nom de l'objet créé.
pub async fn apply_write(client: Client, write: RbkWrite, st: &'static Strings) -> Result<String, String> {
    let backups = crate::yaml::dynamic_api(&client, API_V1, "Backup", "").await?;
    let current = backups
        .get(write.target())
        .await
        .map_err(crate::edit::api_error_text)?;
    let backup = serde_json::to_value(&current).map_err(|e| e.to_string())?;
    let now = Timestamp::now().as_second();
    let (kind, name, body) = match &write {
        RbkWrite::BackupNow { from } => {
            let (name, body) = backup_now_body(from, &backup, now);
            ("Backup", name, body)
        }
        RbkWrite::Restore { from } => {
            let (name, body) = restore_body(from, &backup, now, st)?;
            ("Restore", name, body)
        }
    };
    let api = crate::yaml::dynamic_api(&client, API_V1, kind, "").await?;
    let obj: DynamicObject = serde_json::from_value(body).map_err(|e| e.to_string())?;
    api.create(&PostParams::default(), &obj)
        .await
        .map_err(crate::edit::api_error_text)?;
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st() -> &'static Strings {
        &crate::lang::FR
    }

    fn obj(v: Value) -> DynamicObject {
        serde_json::from_value(v).unwrap()
    }

    fn backup(v: Value) -> RbkBackup {
        parse_backup(&obj(v))
    }

    fn operator(ready: i32, storage: DefaultStorage) -> Operator {
        Operator {
            namespace: "cattle-resources-system".into(),
            name: "rancher-backup".into(),
            ready,
            desired: 1,
            version: "v5.0.4".into(),
            default_storage: storage,
        }
    }

    fn rs(name: &str, secrets: bool) -> RbkResourceSet {
        RbkResourceSet {
            name: name.into(),
            selectors: vec![],
            controller_refs: vec![],
            selects_secrets: secrets,
            bad_regex: vec![],
            used_by: vec![],
            created: 0,
            hints: vec![],
        }
    }

    fn observed(backups: Vec<RbkBackup>) -> Observed {
        Observed {
            backups,
            restores: vec![],
            resource_sets: vec![rs("rancher-resource-set", true)],
            resource_sets_known: true,
            operator: Some(operator(1, DefaultStorage::Pv { claim: "rancher-backup-1".into() })),
            operator_known: true,
            secrets: HashMap::new(),
        }
    }

    const NOW: i64 = 1_791_000_000;

    fn rfc(t: i64) -> String {
        chrono::DateTime::from_timestamp(t, 0).unwrap().to_rfc3339()
    }

    fn recurring(last: i64, next: i64, conditions: Value) -> Value {
        json!({
            "apiVersion": API_V1, "kind": "Backup",
            "metadata": { "name": "daily", "generation": 1 },
            "spec": { "resourceSetName": "rancher-resource-set", "schedule": "0 2 * * *",
                      "encryptionConfigSecretName": "enc" },
            "status": { "lastSnapshotTs": rfc(last), "nextSnapshotAt": rfc(next),
                        "filename": "daily-uid-x.tar.gz.enc", "observedGeneration": 1,
                        "storageLocation": "PV", "conditions": conditions },
        })
    }

    #[test]
    fn un_echec_se_lit_sur_reconciling_meme_quand_ready_reste_vrai() {
        let conds = json!([
            { "type": "Ready", "status": "True", "message": "Retrying" },
            { "type": "Reconciling", "status": "True", "reason": "Error", "message": "secrets \"enc\" not found" },
        ]);
        let b = backup(recurring(NOW - 86_400, NOW + 3600, conds));
        let s = diagnose(observed(vec![b]), NOW, st());
        assert_eq!(s.backups[0].phase, Phase::Failing);
        assert_eq!(s.backups[0].worst(), Some(HintLevel::Danger));
        assert!(s.backups[0].hints[0].text.contains("not found"));
    }

    #[test]
    fn un_run_recurrent_passe_depuis_plus_d_une_heure_est_en_retard() {
        let ok = json!([{ "type": "Ready", "status": "True", "message": "Completed" }]);
        let late = backup(recurring(NOW - 2 * 86_400, NOW - 2 * 3600, ok.clone()));
        let on_time = backup(recurring(NOW - 3600, NOW - 600, ok));
        let s = diagnose(observed(vec![late]), NOW, st());
        assert_eq!(s.backups[0].phase, Phase::Overdue);
        let s = diagnose(observed(vec![on_time]), NOW, st());
        assert_eq!(s.backups[0].phase, Phase::Completed);
    }

    #[test]
    fn le_retard_nomme_l_operateur_quand_il_est_a_terre() {
        let ok = json!([{ "type": "Ready", "status": "True" }]);
        let mut o = observed(vec![backup(recurring(NOW - 2 * 86_400, NOW - 86_400, ok))]);
        o.operator = Some(operator(0, DefaultStorage::Pv { claim: String::new() }));
        let s = diagnose(o, NOW, st());
        let expected = fill(st().rbk_h_overdue_operator, &[("age", "1d")]);
        assert_eq!(s.backups[0].hints[0].text, expected);
        assert!(s.cluster_hints.iter().any(|h| h.level == HintLevel::Danger));
    }

    #[test]
    fn la_retention_ne_vaut_que_pour_un_backup_recurrent_et_zero_vaut_dix() {
        let b = backup(json!({
            "metadata": { "name": "a" },
            "spec": { "resourceSetName": "x", "schedule": "@daily" },
        }));
        assert_eq!(b.retention, Some(DEFAULT_RETENTION));
        assert!(b.retention_defaulted);
        let once = backup(json!({
            "metadata": { "name": "b" },
            "spec": { "resourceSetName": "x", "retentionCount": 3 },
        }));
        assert_eq!(once.retention, None);
    }

    #[test]
    fn sans_chiffrement_les_secrets_de_la_resourceset_partent_en_clair() {
        let b = backup(json!({
            "metadata": { "name": "once" },
            "spec": { "resourceSetName": "rancher-resource-set" },
            "status": { "lastSnapshotTs": rfc(NOW - 60), "filename": "once.tar.gz" },
        }));
        let s = diagnose(observed(vec![b]), NOW, st());
        assert_eq!(s.backups[0].phase, Phase::Completed);
        assert!(s.backups[0].hints.iter().any(|h| h.level == HintLevel::Warn));
    }

    #[test]
    fn une_resourceset_absente_et_un_secret_de_chiffrement_absent_sont_des_pannes() {
        let b = backup(json!({
            "metadata": { "name": "x" },
            "spec": { "resourceSetName": "nope", "encryptionConfigSecretName": "enc" },
        }));
        let mut o = observed(vec![b]);
        o.secrets.insert("enc".into(), SecretCheck::Missing);
        let s = diagnose(o, NOW, st());
        let dangers = s.backups[0].hints.iter().filter(|h| h.level == HintLevel::Danger).count();
        assert_eq!(dangers, 2);
    }

    #[test]
    fn la_resourceset_inconnue_ne_se_dit_pas_absente() {
        let b = backup(json!({ "metadata": { "name": "x" }, "spec": { "resourceSetName": "nope" } }));
        let mut o = observed(vec![b]);
        o.resource_sets.clear();
        o.resource_sets_known = false;
        let s = diagnose(o, NOW, st());
        assert!(!s.backups[0].hints.iter().any(|h| h.text.contains("nope")));
    }

    #[test]
    fn selection_des_secrets_comme_filterbykind() {
        assert!(selects_secrets(&json!({ "apiVersion": "v1", "kindsRegexp": "^secrets$" })));
        assert!(selects_secrets(&json!({ "apiVersion": "v1", "kinds": ["Secret"] })));
        assert!(selects_secrets(&json!({ "apiVersion": "v1" })));
        assert!(selects_secrets(&json!({ "apiVersion": "v1", "kindsRegexp": "." })));
        assert!(!selects_secrets(&json!({ "apiVersion": "v1", "kindsRegexp": "^serviceaccounts$" })));
        assert!(!selects_secrets(&json!({ "apiVersion": "v1", "kindsRegexp": ".", "excludeKinds": ["secrets"] })));
        assert!(!selects_secrets(&json!({ "apiVersion": "apps/v1" })));
    }

    #[test]
    fn une_restore_terminee_ne_se_rejoue_pas_et_une_restore_sans_fin_est_signalee() {
        let done = parse_restore(&obj(json!({
            "metadata": { "name": "r1", "creationTimestamp": rfc(NOW - 100) },
            "spec": { "backupFilename": "f.tar.gz" },
            "status": { "restoreCompletionTs": rfc(NOW - 50) },
        })));
        let failing = parse_restore(&obj(json!({
            "metadata": { "name": "r2", "creationTimestamp": rfc(NOW - 10) },
            "spec": { "backupFilename": "f.tar.gz", "prune": false },
            "status": { "conditions": [{ "type": "Reconciling", "status": "True", "message": "boom" }] },
        })));
        assert!(done.prune);
        assert!(!failing.prune);
        let mut o = observed(vec![]);
        o.restores = vec![done, failing];
        let s = diagnose(o, NOW, st());
        assert_eq!(s.restores[0].name, "r2");
        assert_eq!(s.restores[0].phase, Phase::Failing);
        assert_eq!(s.restores[1].phase, Phase::Completed);
        assert!(s.restores[1].hints.is_empty());
    }

    #[test]
    fn backup_maintenant_reprend_le_stockage_et_le_chiffrement_sans_schedule() {
        let src = recurring(NOW - 60, NOW + 60, json!([]));
        let (name, body) = backup_now_body("daily", &src, NOW);
        assert!(name.starts_with("daily-now-"));
        assert_eq!(body["spec"]["resourceSetName"], "rancher-resource-set");
        assert_eq!(body["spec"]["encryptionConfigSecretName"], "enc");
        assert!(body["spec"].get("schedule").is_none());
        assert!(body["spec"].get("retentionCount").is_none());
    }

    #[test]
    fn la_restore_vise_la_derniere_archive_reussie() {
        let src = recurring(NOW - 60, NOW + 60, json!([]));
        let (name, body) = restore_body("daily", &src, NOW, st()).unwrap();
        assert!(name.starts_with("restore-daily-"));
        assert_eq!(body["spec"]["backupFilename"], "daily-uid-x.tar.gz.enc");
        assert_eq!(body["spec"]["prune"], true);
        let empty = json!({ "spec": {}, "status": {} });
        assert!(restore_body("x", &empty, NOW, st()).is_err());
    }

    #[test]
    fn regex_refusee_dans_une_resourceset() {
        let r = parse_resource_set(&obj(json!({
            "apiVersion": API_V1, "kind": "ResourceSet",
            "metadata": { "name": "bad" },
            "resourceSelectors": [{ "apiVersion": "v1", "kindsRegexp": "(" }],
        })));
        assert_eq!(r.bad_regex, vec!["(".to_string()]);
    }
}
