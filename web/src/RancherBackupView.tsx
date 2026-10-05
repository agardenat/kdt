// La vue rancher-backup : ai-je un backup récent de Rancher, et la restauration marcherait-elle ?
//
// Trois mondes, comme dans le TUI : les Backups, les Restores, les ResourceSets.
//
// Rien n'est jugé ici. La phase d'une ligne et son ton, les constats, les colonnes NEXT et KEEP
// arrivent tout faits de `kdt::rancherbackup`. Ce qui reste au navigateur : la sélection, la
// recherche, et la confirmation d'une écriture.

import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import type { Lang, Strings } from "./i18n";
import { ToastLine, useToastTimeout, type Toast } from "./toast";
import { InspectPanel, PanelToggle, Splitter, ViewBody, type PanelTab } from "./panel";
import { BulkDeletePane, RowMenu, type ObjectTab } from "./objects";
import { RowCheckbox, SelectionBar, SelectionHead, useMultiSelect } from "./selection";
import type {
  EventRecord,
  Hint,
  RbkBackupRow,
  RbkOperator,
  RbkPayload,
  RbkResourceSetRow,
  RbkRestoreRow,
  RbkRow,
  RbkS3,
  RbkWorld,
} from "./types";
import { cols } from "./table";

/** Les colonnes de chaque monde, dans l'ordre du TUI. La première piste porte la case de sélection
 * multiple, la dernière le hamburger de la ligne ; ALERT est la seule piste souple. */
const COLUMNS: Record<RbkWorld, string> = {
  backups:
    "34px fit-content(30ch) fit-content(10ch) fit-content(16ch) 52px 56px 48px fit-content(32ch)" +
    " 48px fit-content(10ch) minmax(24ch,1fr) 34px",
  restores:
    "34px fit-content(30ch) fit-content(48ch) 56px 52px 52px fit-content(10ch) minmax(24ch,1fr) 34px",
  resource_sets: "34px fit-content(30ch) 84px 72px 104px fit-content(40ch) minmax(24ch,1fr) 34px",
};

function matches(row: RbkRow, needle: string): boolean {
  const extra =
    row.row === "backup"
      ? [row.schedule, row.storage_label, row.filename, row.resource_set, row.phase_label]
      : row.row === "restore"
        ? [row.backup_filename, row.phase_label]
        : [...row.selectors, ...row.used_by];
  return [row.name, row.record.message, ...extra, ...row.hints.map((h) => h.text)]
    .join(" ")
    .toLowerCase()
    .includes(needle);
}

function hintTone(h: Hint | undefined): string {
  return !h ? "dim" : h.level === "danger" ? "err" : h.level === "warn" ? "warn" : "dim";
}

export default function RancherBackupView({
  lang,
  st,
  query,
  panelHeight,
  onPanelHeight,
  panelOpen,
  onPanelOpen,
  onNeedsAuth,
}: {
  lang: Lang;
  st: Strings;
  query: string;
  panelHeight: number;
  onPanelHeight: (h: number) => void;
  panelOpen: boolean;
  onPanelOpen: (open: boolean) => void;
  onNeedsAuth: (message: string) => void;
}) {
  const [payload, setPayload] = useState<RbkPayload | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [world, setWorld] = useState<RbkWorld>("backups");
  const [problems, setProblems] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<PanelTab>("detail");
  const [toast, setToast] = useState<Toast>(null);
  const [busy, setBusy] = useState(false);
  const { checked, toggle, clear, setAll } = useMultiSelect();
  const [bulkOpen, setBulkOpen] = useState(false);

  const load = useCallback(async () => {
    try {
      const data = await api.rancherBackup(world, problems, lang);
      setPayload(data);
      setError(null);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else if (e instanceof ApiError) setError(e.message);
      else setError(String(e));
    } finally {
      setLoaded(true);
    }
  }, [world, problems, lang, onNeedsAuth]);

  useEffect(() => {
    void load();
    // Trente secondes, comme le TUI : un backup Rancher tourne au mieux quelques fois par jour, et
    // une écriture relit d'elle-même.
    const timer = window.setInterval(() => void load(), 30000);
    return () => window.clearInterval(timer);
  }, [load]);

  useToastTimeout(toast, setToast);

  const rows = useMemo(() => payload?.rows ?? [], [payload]);
  const needle = query.trim().toLowerCase();
  const display = useMemo(
    () => (needle ? rows.filter((r) => matches(r, needle)) : rows),
    [rows, needle],
  );
  const selectedRow = useMemo(() => rows.find((r) => r.uid === selected) ?? null, [rows, selected]);
  const selectedRecord: EventRecord | null = selectedRow?.record ?? null;
  const selectableKeys = useMemo(() => display.map((r) => r.uid), [display]);

  const switchWorld = (w: RbkWorld) => {
    setWorld(w);
    setSelected(null);
    clear();
  };

  const write = useCallback(
    async (action: "backup-now" | "restore", name: string) => {
      setBusy(true);
      try {
        const { message } = await api.rancherBackupWrite(action, name, lang);
        setToast({ tone: "ok", text: message });
        void load();
      } catch (e) {
        if (e instanceof NeedsAuth) onNeedsAuth(e.message);
        else setToast({ tone: "err", text: String((e as Error).message ?? e) });
      } finally {
        setBusy(false);
      }
    },
    [lang, load, onNeedsAuth],
  );

  const counts = payload?.counts;
  const operator = payload?.operator ?? null;
  const installed = payload?.installed ?? true;

  return (
    <>
      {panelOpen && (
        <>
          <InspectPanel
            record={selectedRecord}
            tab={tab}
            onTab={setTab}
            onClose={() => onPanelOpen(false)}
            height={panelHeight}
            lang={lang}
            st={st}
            detail={{
              label: st.rbkDetail,
              node: selectedRow ? (
                <Detail
                  row={selectedRow}
                  operator={operator}
                  clusterHints={payload?.cluster_hints ?? []}
                  st={st}
                />
              ) : null,
            }}
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds" role="tablist">
        {(
          [
            ["backups", st.rbkBackups, counts?.backups],
            ["restores", st.rbkRestores, counts?.restores],
            ["resource_sets", st.rbkResourceSets, counts?.resource_sets],
          ] as const
        ).map(([id, label, n]) => (
          <button key={id} role="tab" aria-selected={world === id} onClick={() => switchWorld(id)}>
            {label}
            {n !== undefined && <span className="count">{n}</span>}
          </button>
        ))}

        <div className="segmented" role="group">
          {([false, true] as const).map((p) => (
            <button key={String(p)} aria-pressed={problems === p} onClick={() => setProblems(p)}>
              {p ? st.filterProblems : st.filterAll}
            </button>
          ))}
        </div>

        {payload && installed && (
          <div className="tally">
            {/* L'âge du dernier backup réussi : la réponse que la vue existe pour donner, lisible
                sans rien sélectionner. */}
            <span className={payload.last_success_age ? "" : "err"}>
              {st.rbkLast.replace("{age}", payload.last_success_age ?? st.rbkNever)}
            </span>
            {counts && counts.problems > 0 && (
              <span className="warn">
                {counts.problems} {st.rbkProblems}
              </span>
            )}
            {operator && !operator.up && <span className="err">{st.rbkOpDown}</span>}
            {!operator && payload.operator_known && <span className="err">{st.rbkOpAbsent}</span>}
            {!operator && payload.operator_known === false && (
              <span className="warn">{st.rbkOpUnknown}</span>
            )}
          </div>
        )}

        <div className="right">
          {busy && <span>{st.objWorking}</span>}
          <ToastLine toast={toast} onDismiss={() => setToast(null)} lang={lang} />
          <SelectionBar
            keys={selectableKeys}
            checked={checked}
            onSetAll={setAll}
            onClear={clear}
            onBulkDelete={() => setBulkOpen(true)}
            st={st}
          />
          <PanelToggle open={panelOpen} onOpen={onPanelOpen} lang={lang} />
        </div>
      </div>

      {/* Ce qui vaut pour toute l'installation — opérateur, aucun Backup récurrent, âge du dernier
          succès : une ligne à soi sous la barre, visible sans rien sélectionner. */}
      {payload?.cluster_hints?.map((h, i) => (
        <div key={i} className={`vel-band ${h.level === "danger" ? "err" : h.level}`}>
          {h.text}
        </div>
      ))}

      <ViewBody
        tab={tab}
        record={selectedRecord}
        lang={lang}
        st={st}
        onTab={setTab}
        onNeedsAuth={onNeedsAuth}
        hasDetail
        onDeleted={() => {
          setSelected(null);
          void load();
        }}
        bulk={
          bulkOpen
            ? {
                label: st.bulkDeleteTitle,
                count: checked.size,
                node: (
                  <BulkDeletePane
                    records={rows.filter((r) => checked.has(r.uid)).map((r) => r.record)}
                    lang={lang}
                    st={st}
                    onCancel={() => setBulkOpen(false)}
                    onDone={() => {
                      setBulkOpen(false);
                      setSelected(null);
                      clear();
                      void load();
                    }}
                    onNeedsAuth={onNeedsAuth}
                  />
                ),
              }
            : null
        }
        onBulkClose={() => setBulkOpen(false)}
      >
        {!loaded ? (
          <div className="center" />
        ) : !installed ? (
          <div className="center">
            <div className="box">
              <h2>{st.rbkNotInstalled}</h2>
            </div>
          </div>
        ) : display.length === 0 ? (
          <div className="center">
            <div className="box">
              <h2>{needle || problems ? st.emptyTitle : st.rbkEmpty}</h2>
              {error && <p className="err">{error}</p>}
              {payload?.error && <p className="err">{payload.error}</p>}
            </div>
          </div>
        ) : (
          <div className="tbl" style={cols(COLUMNS[world])}>
            <div className="thead">
              <div className="tr">
                <SelectionHead />
                {world === "backups" ? (
                  <>
                    <div className="cell">NAME</div>
                    <div className="cell">TYPE</div>
                    <div className="cell">SCHEDULE</div>
                    <div className="cell num">LAST</div>
                    <div className="cell num">NEXT</div>
                    <div className="cell num">KEEP</div>
                    <div className="cell">STORAGE</div>
                    <div className="cell">ENC</div>
                    <div className="cell">STATE</div>
                  </>
                ) : world === "restores" ? (
                  <>
                    <div className="cell">NAME</div>
                    <div className="cell">ARCHIVE</div>
                    <div className="cell">PRUNE</div>
                    <div className="cell num">AGE</div>
                    <div className="cell num">DONE</div>
                    <div className="cell">STATE</div>
                  </>
                ) : (
                  <>
                    <div className="cell">NAME</div>
                    <div className="cell num">SELECTORS</div>
                    <div className="cell">SECRETS</div>
                    <div className="cell num">CONTROLLERS</div>
                    <div className="cell">USED BY</div>
                  </>
                )}
                <div className="cell">ALERT</div>
                <div className="cell act" />
              </div>
            </div>
            <div className="tbody">
              {display.map((row) => (
                <Line
                  key={row.uid}
                  row={row}
                  lang={lang}
                  st={st}
                  selected={selected === row.uid}
                  onSelect={() => {
                    setSelected(row.uid);
                    setTab("detail");
                  }}
                  onOpenTab={(t) => {
                    setSelected(row.uid);
                    setTab(t);
                  }}
                  onNeedsAuth={onNeedsAuth}
                  onWrite={(action) => void write(action, row.name)}
                  checked={checked.has(row.uid)}
                  onToggleCheck={() => toggle(row.uid)}
                />
              ))}
            </div>
          </div>
        )}
      </ViewBody>

      <div className="statusbar">
        <span>
          {display.length} {st.rows}
        </span>
        {error && <span className="err">{error}</span>}
        <span style={{ marginLeft: "auto" }}>{st.rbkScopeless}</span>
      </div>
    </>
  );
}

function Line({
  row,
  lang,
  st,
  selected,
  onSelect,
  onOpenTab,
  onNeedsAuth,
  onWrite,
  checked,
  onToggleCheck,
}: {
  row: RbkRow;
  lang: Lang;
  st: Strings;
  selected: boolean;
  onSelect: () => void;
  onOpenTab: (tab: ObjectTab) => void;
  onNeedsAuth: (message: string) => void;
  onWrite: (action: "backup-now" | "restore") => void;
  checked: boolean;
  onToggleCheck: () => void;
}) {
  // Le pire constat, s'il demande un humain : un `info` dit la norme, il reste dans le panneau.
  const alert = row.hints.find((h) => h.level !== "info");
  const yesNo = (v: boolean) => (v ? st.rbkYes : st.rbkNo);
  return (
    <div
      className={`tr sev-${row.record.tone}`}
      aria-selected={selected}
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSelect();
      }}
    >
      <RowCheckbox checked={checked} onToggle={onToggleCheck} label={st.selectRow} st={st} />
      <div className={`cell id ${row.name_tone ?? ""}`}>{row.name}</div>
      {row.row === "backup" ? (
        <>
          <div className="cell dim">{row.recurring ? "Recurring" : "One-time"}</div>
          <div className="cell mono">{row.schedule || "—"}</div>
          <div className="cell num dim">{row.last_age ?? "—"}</div>
          <div className={`cell num ${row.late ? "err" : "dim"}`}>{row.next_text}</div>
          <div className="cell num dim">{row.keep_text}</div>
          <div className="cell mono">{row.storage_label}</div>
          <div className="cell dim">{yesNo(row.encrypted)}</div>
          <div className={`cell ${row.phase_tone}`}>{row.phase_label}</div>
        </>
      ) : row.row === "restore" ? (
        <>
          <div className="cell mono dim">{row.backup_filename}</div>
          <div className="cell">{yesNo(row.prune)}</div>
          <div className="cell num dim">{row.age}</div>
          <div className="cell num dim">{row.completed_age ?? "—"}</div>
          <div className={`cell ${row.phase_tone}`}>{row.phase_label}</div>
        </>
      ) : (
        <>
          <div className="cell num">{row.selectors.length}</div>
          <div className="cell">{yesNo(row.selects_secrets)}</div>
          <div className="cell num dim">{row.controller_refs.length}</div>
          <div className="cell">{row.used_by.length ? row.used_by.join(", ") : "—"}</div>
        </>
      )}
      <div className={`cell wrap ${hintTone(alert)}`} title={row.hints.map((h) => h.text).join(" · ")}>
        {alert?.text ?? "—"}
      </div>
      <div className="cell act">
        <RowMenu record={row.record} lang={lang} st={st} onOpen={onOpenTab} onNeedsAuth={onNeedsAuth}>
          {row.row === "backup"
            ? ({ close }) => (
                <WriteMenu
                  row={row}
                  st={st}
                  onWrite={(action) => {
                    close();
                    onWrite(action);
                  }}
                />
              )
            : undefined}
        </RowMenu>
      </div>
    </div>
  );
}

/**
 * Les deux écritures d'un Backup, avec la confirmation du TUI. La restauration n'est offerte que
 * s'il existe une archive réussie ; sinon le menu dit pourquoi.
 */
function WriteMenu({
  row,
  st,
  onWrite,
}: {
  row: RbkBackupRow;
  st: Strings;
  onWrite: (action: "backup-now" | "restore") => void;
}) {
  const [arming, setArming] = useState<"backup-now" | "restore" | null>(null);

  // Posé comme `children` de `RowMenu` : pas de `.pop.menu`/`.pop-hd` à lui.
  if (!arming) {
    return (
      <>
        <button className="menu-item" onClick={() => setArming("backup-now")}>
          <span className="lbl">{st.rbkBackupNow}</span>
          <span className="desc">{st.rbkBackupNowHelp}</span>
        </button>
        {row.can_restore ? (
          <button className="menu-item" onClick={() => setArming("restore")}>
            <span className="lbl">{st.rbkRestore}</span>
            <span className="desc">{st.rbkRestoreHelp.replace("{file}", row.filename)}</span>
          </button>
        ) : (
          <p className="menu-note dim">{st.rbkNoRestore}</p>
        )}
      </>
    );
  }
  const label = arming === "restore" ? st.rbkRestore : st.rbkBackupNow;
  const help =
    arming === "restore" ? st.rbkRestoreHelp.replace("{file}", row.filename) : st.rbkBackupNowHelp;
  return (
    <div className="menu-confirm">
      <p>
        <strong>{label}</strong> — {row.name}
      </p>
      <p className="dim">{help}</p>
      {/* La sortie par défaut est celle qui n'écrit rien : c'est elle qui a le focus. */}
      <div className="menu-buttons">
        <button autoFocus onClick={() => setArming(null)}>
          {st.rbkCancel}
        </button>
        <button className="cta" onClick={() => onWrite(arming)}>
          {st.rbkConfirm}
        </button>
      </div>
    </div>
  );
}

/** Les faits de la ligne, ce que les règles en font, puis l'opérateur — la forme du panneau du TUI. */
function Detail({
  row,
  operator,
  clusterHints,
  st,
}: {
  row: RbkRow;
  operator: RbkOperator | null;
  clusterHints: Hint[];
  st: Strings;
}) {
  return (
    <div className="detail">
      {row.row === "backup" ? (
        <BackupDetail row={row} st={st} />
      ) : row.row === "restore" ? (
        <RestoreDetail row={row} st={st} />
      ) : (
        <ResourceSetDetail row={row} st={st} />
      )}
      <Hints hints={row.hints} title={st.rbkDiagnostic} />
      <div className="sect">{st.rbkOperator}</div>
      {operator ? (
        <>
          <Field label="Deployment" value={`${operator.namespace}/${operator.name}`} mono />
          <Field
            label="ready"
            value={`${operator.ready}/${operator.desired}`}
            tone={operator.up ? undefined : "err"}
          />
          <Field label="version" value={operator.version || "—"} mono />
          <Field label={st.rbkDefaultStorage} value={operator.storage_label} mono />
        </>
      ) : (
        <Field label="Deployment" value="—" />
      )}
      <Hints hints={clusterHints} title={st.rbkCluster} />
    </div>
  );
}

function BackupDetail({ row, st }: { row: RbkBackupRow; st: Strings }) {
  const retention =
    row.retention === null
      ? st.rbkRetentionNone
      : (row.retention_defaulted ? st.rbkRetentionDefault : st.rbkRetentionN).replace(
          "{n}",
          String(row.retention),
        );
  const next = !row.recurring
    ? null
    : row.next === null
      ? "—"
      : row.late
        ? st.rbkLate.replace("{age}", row.next_text.replace(/^-/, ""))
        : st.rbkIn.replace("{age}", row.next_text);
  return (
    <>
      <Field label={st.rbkState} value={row.phase_label} tone={row.phase_tone} />
      <Field label="type" value={row.recurring ? "Recurring" : "One-time"} />
      <Field label="schedule" value={row.schedule || "—"} mono />
      <Field label={st.rbkRetention} value={retention} />
      <Field label="resourceSet" value={row.resource_set || "—"} mono />
      <Field label={st.rbkEncryption} value={row.encrypted ? row.encryption_secret : st.rbkNo} mono={row.encrypted} />
      <Field
        label={st.rbkLastSuccess}
        value={row.last_age ? st.rbkAgo.replace("{age}", row.last_age) : st.rbkNever}
      />
      {next !== null && <Field label={st.rbkNextRun} value={next} tone={row.late ? "err" : undefined} />}
      <Field label={st.rbkArchive} value={row.filename || "—"} mono />
      <div className="sect">{st.rbkStorage}</div>
      {row.s3 ? (
        <S3Fields s3={row.s3} />
      ) : (
        <Field label="storageLocation" value={st.rbkStorageDefault.replace("{loc}", row.storage || "—")} />
      )}
    </>
  );
}

function RestoreDetail({ row, st }: { row: RbkRestoreRow; st: Strings }) {
  const prune =
    row.prune && row.delete_timeout > 0
      ? `${st.rbkYes} (deleteTimeoutSeconds ${row.delete_timeout})`
      : row.prune
        ? st.rbkYes
        : st.rbkNo;
  return (
    <>
      <Field label={st.rbkState} value={row.phase_label} tone={row.phase_tone} />
      <Field label={st.rbkArchive} value={row.backup_filename || "—"} mono />
      <Field label="prune" value={prune} />
      <Field label="ignoreErrors" value={row.ignore_errors ? st.rbkYes : st.rbkNo} />
      <Field
        label={st.rbkEncryption}
        value={row.encryption_secret || st.rbkNo}
        mono={Boolean(row.encryption_secret)}
      />
      <Field label={st.rbkAge} value={row.age} />
      <Field
        label={st.rbkDone}
        value={row.completed_age ? st.rbkAgo.replace("{age}", row.completed_age) : st.rbkNever}
      />
      {row.backup_source && <Field label="backupSource" value={row.backup_source} />}
      {row.s3 && (
        <>
          <div className="sect">{st.rbkStorage}</div>
          <S3Fields s3={row.s3} />
        </>
      )}
    </>
  );
}

function ResourceSetDetail({ row, st }: { row: RbkResourceSetRow; st: Strings }) {
  return (
    <>
      <Field label="Secrets" value={row.selects_secrets ? st.rbkYes : st.rbkNo} />
      <Field label={st.rbkUsedBy} value={row.used_by.length ? row.used_by.join(", ") : "—"} />
      <div className="sect">resourceSelectors</div>
      {row.selectors.map((s, i) => (
        <p key={i} className="mono">
          {s}
        </p>
      ))}
      {row.controller_refs.length > 0 && (
        <>
          <div className="sect">controllerReferences</div>
          {row.controller_refs.map((c) => (
            <p key={c} className="mono">
              {c}
            </p>
          ))}
        </>
      )}
    </>
  );
}

function S3Fields({ s3 }: { s3: RbkS3 }) {
  return (
    <>
      <Field label="endpoint" value={s3.endpoint || "—"} mono />
      <Field label="bucket" value={s3.bucket || "—"} mono />
      {s3.folder && <Field label="folder" value={s3.folder} mono />}
      {s3.region && <Field label="region" value={s3.region} mono />}
      <Field label="credentialSecret" value={s3.credential_secret || "—"} mono />
      {s3.insecure_tls && <Field label="insecureTLSSkipVerify" value="true" mono tone="warn" />}
    </>
  );
}

function Field({ label, value, mono, tone }: { label: string; value: string; mono?: boolean; tone?: string }) {
  return (
    <div className="keys-row">
      <div className="k-col">
        <span className="k">{label}</span>
      </div>
      <span className={`v ${mono ? "mono" : ""} ${tone ?? ""}`}>{value}</span>
    </div>
  );
}

function Hints({ hints, title }: { hints: Hint[]; title: string }) {
  if (hints.length === 0) return null;
  return (
    <>
      <div className="sect">{title}</div>
      {hints.map((h) => (
        <p key={h.text} className={`guard ${h.level}`}>
          <span className="gl">{h.level === "danger" ? "✗" : h.level === "warn" ? "▲" : "·"}</span>{" "}
          {h.text}
        </p>
      ))}
    </>
  );
}
