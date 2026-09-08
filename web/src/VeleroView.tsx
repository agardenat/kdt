// La vue Velero : si le cluster brûle maintenant, qu'est-ce qui revient ?
//
// Ce que cette vue apporte n'est pas la liste des backups mais la réponse à cette question-là, qui
// est éparpillée sur six kinds et deux silences : un backup `PartiallyFailed` peint comme un succès
// alors qu'il n'en est pas un, et un Schedule qui cesse de se déclencher sans rien dire — ni Event,
// ni condition, ni compteur de runs manqués.
//
// Rien n'est jugé ici. Les constats, le ton d'une phase, la prochaine exécution recalculée et les
// namespaces que personne ne sauvegarde arrivent tout faits de `kdt::velero`.

import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import { useDismiss } from "./dismiss";
import type { Lang, Strings } from "./i18n";
import { ToastLine, useToastTimeout, type Toast } from "./toast";
import { InspectPanel, PanelToggle, Splitter, type PanelTab } from "./panel";
import { ObjectActions } from "./objects";
import type {
  EventRecord,
  VelBackupRow,
  VelContentsPayload,
  VeleroPayload,
  VelHint,
  VelLogPayload,
  VelRestoreRequest,
  VelRow,
  VelScheduleRow,
  VelWorld,
} from "./types";

/** Les colonnes du TUI : `NAMESPACE NAME KIND STATE INFO EXPIRE AGE ALERT`, dans le même ordre. */
const COLUMNS =
  "minmax(110px,16ch) minmax(240px,1.1fr) 76px minmax(120px,16ch) minmax(180px,24ch)" +
  " 76px 56px minmax(200px,1.4fr)";

export default function VeleroView({
  lang,
  st,
  query,
  namespaces,
  panelHeight,
  onPanelHeight,
  panelOpen,
  onPanelOpen,
  onNeedsAuth,
}: {
  lang: Lang;
  st: Strings;
  query: string;
  namespaces: string[];
  panelHeight: number;
  onPanelHeight: (h: number) => void;
  panelOpen: boolean;
  onPanelOpen: (open: boolean) => void;
  onNeedsAuth: (message: string) => void;
}) {
  const [payload, setPayload] = useState<VeleroPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [world, setWorld] = useState<VelWorld>("backups");
  const [group, setGroup] = useState(true);
  const [problems, setProblems] = useState(false);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<PanelTab>("detail");
  const [menuOpen, setMenuOpen] = useState(false);
  const [toast, setToast] = useState<Toast>(null);
  const [busy, setBusy] = useState(false);
  // Le contenu d'un backup, téléchargé à la demande : uid du backup → son inventaire.
  const [contents, setContents] = useState<Record<string, VelContentsPayload | "loading">>({});
  const [ctExpanded, setCtExpanded] = useState<Set<string>>(new Set());
  // Le log du run affiché, s'il y en a un. Il appartient à la ligne pour laquelle il a été demandé.
  const [log, setLog] = useState<{ uid: string; payload: VelLogPayload } | null>(null);

  const namespace = namespaces[0] ?? "";

  const load = useCallback(async () => {
    try {
      setPayload(await api.velero(namespace, world, group, problems, lang));
      setError(null);
      setLoaded(true);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else if (e instanceof ApiError) setError(e.message);
      else setError(String(e));
      setLoaded(true);
    }
  }, [namespace, world, group, problems, lang, onNeedsAuth]);

  useEffect(() => {
    void load();
    // La cadence du TUI : un run de backup prend des minutes et un schedule se déclenche au mieux
    // toutes les heures. Une passe liste six kinds plus les PVC du cluster.
    const timer = window.setInterval(() => void load(), 20000);
    return () => window.clearInterval(timer);
  }, [load]);

  useToastTimeout(toast, setToast);

  const closeMenu = useCallback(() => setMenuOpen(false), []);
  const menuRef = useDismiss<HTMLDivElement>(menuOpen, closeMenu);

  const rows = payload?.rows ?? [];
  const needle = query.trim().toLowerCase();

  const filtered = useMemo(
    () => (needle ? rows.filter((r) => matches(r, needle)) : rows),
    [rows, needle],
  );

  /**
   * Les lignes affichées, une fois les plis appliqués et le contenu des backups intercalé.
   *
   * Un pli n'existe que dans le monde des backups groupés : ailleurs il n'y a pas de parent.
   */
  const display = useMemo(() => {
    const grouped = group && world === "backups";
    const out: Array<{ row: VelRow } | ContentsLine> = [];
    let hideUnder: string | null = null;

    for (const row of filtered) {
      if (grouped && hideUnder !== null) {
        if (row.row === "backup") continue;
        hideUnder = null;
      }
      out.push({ row });
      if (grouped && (row.row === "schedule" || row.row === "orphans") && collapsed.has(row.uid)) {
        hideUnder = row.uid;
        continue;
      }
      if (row.row !== "backup") continue;
      const ct = contents[row.uid];
      if (!ct || ct === "loading") continue;
      out.push(...contentsLines(row, ct, ctExpanded, grouped));
    }
    return out;
  }, [filtered, group, world, collapsed, contents, ctExpanded]);

  const selectedRow = useMemo(() => rows.find((r) => r.uid === selected) ?? null, [rows, selected]);
  const selectedRecord: EventRecord | null = useMemo(() => {
    if (selectedRow) return selectedRow.record;
    // Une feuille de contenu est sélectionnable elle aussi : son enregistrement vise l'objet réel,
    // vivant, pas la copie dans le bucket.
    for (const entry of display) {
      if ("item" in entry && entry.uid === selected) return entry.record;
    }
    return null;
  }, [selectedRow, display, selected]);

  const toggleFold = useCallback((uid: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(uid)) next.delete(uid);
      else next.add(uid);
      return next;
    });
  }, []);

  const toggleContents = useCallback(
    async (row: VelBackupRow) => {
      if (contents[row.uid]) {
        setContents((prev) => {
          const next = { ...prev };
          delete next[row.uid];
          return next;
        });
        return;
      }
      setContents((prev) => ({ ...prev, [row.uid]: "loading" }));
      try {
        const payload = await api.veleroContents(row.namespace, row.name, row.uid, lang);
        setContents((prev) => ({ ...prev, [row.uid]: payload }));
        // Pas de repli : un bucket injoignable est une erreur, jamais un backup qui n'aurait rien
        // capturé.
        if (payload.error) setToast({ tone: "err", text: payload.error });
      } catch (e) {
        setContents((prev) => {
          const next = { ...prev };
          delete next[row.uid];
          return next;
        });
        if (e instanceof NeedsAuth) onNeedsAuth(e.message);
        else setToast({ tone: "err", text: String((e as Error).message ?? e) });
      }
    },
    [contents, lang, onNeedsAuth],
  );

  const toggleLog = useCallback(async () => {
    if (!selectedRow || (selectedRow.row !== "backup" && selectedRow.row !== "restore")) {
      setToast({ tone: "err", text: st.velLogsNoRun });
      return;
    }
    if (log?.uid === selectedRow.uid) {
      setLog(null);
      return;
    }
    setBusy(true);
    try {
      const kind = selectedRow.row === "restore" ? "Restore" : "Backup";
      const payload = await api.veleroLogs(selectedRow.namespace, kind, selectedRow.name, lang);
      setLog({ uid: selectedRow.uid, payload });
      setTab("detail");
      onPanelOpen(true);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else setToast({ tone: "err", text: String((e as Error).message ?? e) });
    } finally {
      setBusy(false);
    }
  }, [selectedRow, log, lang, st, onNeedsAuth, onPanelOpen]);

  const run = useCallback(
    async (request: Parameters<typeof api.veleroWrite>[0]) => {
      setMenuOpen(false);
      setBusy(true);
      try {
        const { message } = await api.veleroWrite(request, lang);
        setToast({ tone: "ok", text: message });
        // Relire tout de suite : un run démarre en quelques secondes, et attendre le tick suivant
        // ferait douter que le geste soit passé.
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
  const actionable =
    selectedRow?.row === "schedule" || selectedRow?.row === "backup" ? selectedRow : null;

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
            onNeedsAuth={onNeedsAuth}
            detail={{
              label: st.velDetail,
              node: payload ? (
                <VeleroDetail
                  st={st}
                  payload={payload}
                  row={selectedRow}
                  contents={selectedRow ? contents[selectedRow.uid] : undefined}
                  log={log && selectedRow && log.uid === selectedRow.uid ? log.payload : null}
                />
              ) : null,
            }}
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds" role="tablist">
        {(["backups", "restores", "infra"] as const).map((w) => (
          <button key={w} role="tab" aria-selected={world === w} onClick={() => setWorld(w)}>
            {w === "backups" ? st.velBackups : w === "restores" ? st.velRestores : st.velInfra}
            {counts && (
              <span className="count">
                {w === "backups" ? counts.backups : w === "restores" ? counts.restores : ""}
              </span>
            )}
          </button>
        ))}

        <div className="segmented" role="group">
          <button aria-pressed={!problems} onClick={() => setProblems(false)}>
            {st.filterAll}
          </button>
          <button aria-pressed={problems} onClick={() => setProblems(true)}>
            {st.filterProblems}
          </button>
        </div>

        {world === "backups" && (
          <label className="opt" title={st.velGroupHelp}>
            <input type="checkbox" checked={group} onChange={(e) => setGroup(e.target.checked)} />
            {st.velGroup}
          </label>
        )}

        {payload && <Rpo payload={payload} st={st} />}

        <div className="right">
          {busy && <span>{st.objWorking}</span>}
          <button
            className="panel-toggle"
            disabled={selectedRow?.row !== "backup" && selectedRow?.row !== "restore"}
            title={
              selectedRow?.row === "backup" || selectedRow?.row === "restore"
                ? st.velLogsHelp
                : st.velLogsNoRun
            }
            onClick={() => void toggleLog()}
          >
            {st.velLogs}
          </button>
          <div className="menu-anchor" ref={menuRef}>
            <button
              className="panel-toggle action"
              disabled={!actionable}
              title={actionable ? undefined : st.velNoAction}
              aria-expanded={menuOpen}
              onClick={() => setMenuOpen((v) => !v)}
            >
              {st.velActions} ▾
            </button>
            {menuOpen && actionable && (
              <ActionMenu
                st={st}
                row={actionable}
                contents={contents[actionable.uid]}
                onRun={(r) => void run(r)}
              />
            )}
          </div>
          <ObjectActions
            record={selectedRecord}
            lang={lang}
            st={st}
            onOpen={(t) => {
              setTab(t);
              onPanelOpen(true);
            }}
            onNeedsAuth={onNeedsAuth}
          />
          <PanelToggle open={panelOpen} onOpen={onPanelOpen} lang={lang} />
        </div>
      </div>

      {/* Les namespaces qu'aucun schedule ne couvre. Rien d'autre sur le cluster ne le dit, et
          c'est une phrase sur le cluster, pas sur une ligne. */}
      {payload && payload.uncovered.length > 0 && (
        <div className="vel-band warn" title={st.velUncoveredHelp}>
          {st.velUncovered} : {payload.uncovered.join(", ")}
        </div>
      )}

      <div className="body">
        {!loaded ? (
          <div className="center" />
        ) : display.length === 0 ? (
          <div className="center">
            <div className="box">
              <h2>
                {payload && !payload.installed
                  ? st.velNotInstalled
                  : needle || problems
                    ? st.emptyTitle
                    : st.velEmpty}
              </h2>
              {error && <p className="err">{error}</p>}
              {payload?.error && <p className="err">{payload.error}</p>}
              <p>
                {st.emptyScope} <code>{namespace || st.scopeAll}</code>
              </p>
            </div>
          </div>
        ) : (
          <div className="tbl">
            <div className="thead">
              <div className="tr" style={{ gridTemplateColumns: COLUMNS }}>
                <div className="cell">NAMESPACE</div>
                <div className="cell">NAME</div>
                <div className="cell">KIND</div>
                <div className="cell">STATE</div>
                <div className="cell">INFO</div>
                <div className="cell">EXPIRE</div>
                <div className="cell num">AGE</div>
                <div className="cell">ALERT</div>
              </div>
            </div>
            <div className="tbody">
              {display.map((entry) =>
                "item" in entry ? (
                  <ContentsRow
                    key={entry.uid}
                    entry={entry}
                    st={st}
                    expanded={ctExpanded.has(entry.key)}
                    selected={selected === entry.uid}
                    onSelect={() => setSelected(entry.uid)}
                    onFold={() =>
                      setCtExpanded((prev) => {
                        const next = new Set(prev);
                        if (next.has(entry.key)) next.delete(entry.key);
                        else next.add(entry.key);
                        return next;
                      })
                    }
                  />
                ) : (
                  <Line
                    key={entry.row.uid}
                    row={entry.row}
                    st={st}
                    grouped={group && world === "backups"}
                    collapsed={collapsed.has(entry.row.uid)}
                    contentsOpen={
                      entry.row.row === "backup" ? Boolean(contents[entry.row.uid]) : false
                    }
                    contentsCount={
                      entry.row.row === "backup" && typeof contents[entry.row.uid] === "object"
                        ? (contents[entry.row.uid] as VelContentsPayload).total
                        : null
                    }
                    selected={selected === entry.row.uid}
                    onSelect={() => setSelected(entry.row.uid)}
                    onFold={() => toggleFold(entry.row.uid)}
                    onContents={() =>
                      entry.row.row === "backup" && void toggleContents(entry.row)
                    }
                  />
                ),
              )}
            </div>
          </div>
        )}
      </div>

      <div className="statusbar">
        <span>
          {display.length} {st.rows}
        </span>
        <span>{namespace || (lang === "fr" ? "tout le cluster" : "whole cluster")}</span>
        {payload && <ServerLine server={payload.server} st={st} />}
        {counts && counts.problems > 0 && (
          <span className="warn">
            {counts.problems} {st.velProblems}
          </span>
        )}
        {error && <span className="err">{error}</span>}
        <ToastLine toast={toast} onDismiss={() => setToast(null)} lang={lang} />
        <span style={{ marginLeft: "auto" }}>
          <span className="kbd">/</span> {st.hintFilter} <span className="kbd">Esc</span>{" "}
          {st.hintClose}
        </span>
      </div>
    </>
  );
}

/**
 * Le seul chiffre qu'une vue de sauvegarde doit au lecteur dès l'ouverture : quand le dernier
 * backup **réellement restaurable** s'est terminé. Il appartient au cluster, pas à une ligne.
 */
function Rpo({ payload, st }: { payload: VeleroPayload; st: Strings }) {
  if (payload.last_success === null) {
    return payload.counts.backups > 0 ? (
      <div className="tally">
        <span className="err">{st.velNoBackup}</span>
      </div>
    ) : null;
  }
  const age = ago(payload.last_success);
  return (
    <div className="tally">
      <span className="dim">{st.velRpo}</span>
      <span className="ok">{age}</span>
    </div>
  );
}

function ServerLine({ server, st }: { server: VeleroPayload["server"]; st: Strings }) {
  if (!server.found) return <span className="err">{st.velServerMissing}</span>;
  return (
    <>
      <span className={server.running ? "ok" : "err"}>
        {st.velServer} {server.ready}/{server.desired}
        {server.version && ` v${server.version}`}
      </span>
      {/* Sans node-agent, `fs-backup` ne capture rien et aucun backup ne s'en plaint. */}
      {server.node_agent ? (
        <span className={server.node_agent.ready >= server.node_agent.desired ? "dim" : "warn"}>
          {st.velNodeAgent} {server.node_agent.ready}/{server.node_agent.desired}
        </span>
      ) : (
        <span className="warn">{st.velNodeAgentAbsent}</span>
      )}
    </>
  );
}

function Line({
  row,
  st,
  grouped,
  collapsed,
  contentsOpen,
  contentsCount,
  selected,
  onSelect,
  onFold,
  onContents,
}: {
  row: VelRow;
  st: Strings;
  grouped: boolean;
  collapsed: boolean;
  contentsOpen: boolean;
  contentsCount: number | null;
  selected: boolean;
  onSelect: () => void;
  onFold: () => void;
  onContents: () => void;
}) {
  const foldable = grouped && (row.row === "schedule" || row.row === "orphans");
  const indent = grouped && row.row === "backup" ? 1.15 : 0;

  return (
    <div
      className={`tr ${hintClass(row.hints)}`}
      style={{ gridTemplateColumns: COLUMNS }}
      aria-selected={selected}
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSelect();
        else if (e.key === " " && foldable) {
          e.preventDefault();
          onFold();
        }
      }}
    >
      <div className="cell mono dim">{"namespace" in row ? row.namespace : ""}</div>
      <div className="cell id" style={{ paddingLeft: `${indent}rem` }}>
        {foldable ? (
          <button
            className="fold"
            title={st.velFold}
            aria-expanded={!collapsed}
            onClick={(e) => {
              e.stopPropagation();
              onFold();
            }}
          >
            {collapsed ? "▸" : "▾"}
          </button>
        ) : (
          <span className="fold-gap" />
        )}
        {row.name}
        {/* L'équivalent des touches `+`/`-` du TUI. Le contenu se télécharge depuis le stockage
            objet : il n'est jamais dans la liste. */}
        {row.row === "backup" && (
          <button
            className="inv-pill"
            aria-expanded={contentsOpen}
            title={st.velContentsHelp}
            onClick={(e) => {
              e.stopPropagation();
              onContents();
            }}
          >
            {contentsOpen ? "⊟" : "⊞"} {contentsCount ?? st.velContents}
          </button>
        )}
        {row.row === "schedule" && row.gitops && (
          <span className="badge info" title={st.velGitops.replace("{engine}", row.gitops)}>
            {row.gitops}
          </span>
        )}
      </div>
      <div className="cell dim">{kindLabel(row)}</div>
      <StateCell row={row} st={st} />
      <div className="cell dim" title={infoText(row, st)}>
        {infoText(row, st)}
      </div>
      <div className="cell dim">{expireText(row)}</div>
      <div className="cell num dim">{"age" in row ? row.age : ""}</div>
      <div className={`cell ${hintTone(row.hints)}`} title={row.hints.map((h) => h.text).join(" · ")}>
        {row.hints[0]?.text ?? ""}
      </div>
    </div>
  );
}

function StateCell({ row, st }: { row: VelRow; st: Strings }) {
  if (row.row === "orphans") return <div className="cell" />;
  if (row.row === "schedule" && row.paused) {
    return (
      <div className="cell">
        <span className="st warn">{st.velPaused}</span>
      </div>
    );
  }
  const phase = "phase" in row ? row.phase : "";
  return (
    <div className="cell">
      <span className={`st ${row.phase_tone}`}>{phase || "—"}</span>
    </div>
  );
}

/** Une ligne de contenu intercalée sous son backup. */
interface ContentsLine {
  item: "ns" | "kind" | "object";
  uid: string;
  /** La clé sous laquelle la ligne se déplie. Vide pour une feuille. */
  key: string;
  label: string;
  kind: string;
  info: string;
  depth: number;
  foldable: boolean;
  /** `null` sur une ligne dont le serveur n'a pas d'enregistrement : rien à ouvrir. */
  record: EventRecord | null;
}

function ContentsRow({
  entry,
  st,
  expanded,
  selected,
  onSelect,
  onFold,
}: {
  entry: ContentsLine;
  st: Strings;
  expanded: boolean;
  selected: boolean;
  onSelect: () => void;
  onFold: () => void;
}) {
  return (
    <div
      className="tr vel-contents"
      style={{ gridTemplateColumns: COLUMNS }}
      aria-selected={selected}
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSelect();
        else if (e.key === " " && entry.foldable) {
          e.preventDefault();
          onFold();
        }
      }}
    >
      {/* La colonne NAMESPACE reste vide : ailleurs dans cette table elle nomme le namespace de
          l'objet velero, et un namespace capturé posé là se lirait comme la même chose. */}
      <div className="cell" />
      <div className="cell id" style={{ paddingLeft: `${entry.depth * 1.15}rem` }}>
        {entry.foldable ? (
          <button
            className="fold"
            title={st.velFold}
            aria-expanded={expanded}
            onClick={(e) => {
              e.stopPropagation();
              onFold();
            }}
          >
            {expanded ? "▾" : "▸"}
          </button>
        ) : (
          <span className="fold-gap" />
        )}
        {entry.label}
      </div>
      <div className="cell dim">{entry.kind}</div>
      <div className="cell" />
      <div className="cell dim">{entry.info}</div>
      <div className="cell" />
      <div className="cell" />
      <div className="cell" />
    </div>
  );
}

/** Les trois niveaux du contenu d'un backup, dépliés aussi loin que `expanded` le dit. */
function contentsLines(
  backup: VelBackupRow,
  ct: VelContentsPayload,
  expanded: Set<string>,
  grouped: boolean,
): ContentsLine[] {
  const base = grouped ? 2 : 1;
  const out: ContentsLine[] = [];
  // Les enregistrements viennent du serveur, aux trois niveaux, et se retrouvent par leur uid :
  // en forger un ici reviendrait à décider dans le navigateur ce qu'un geste générique peut ouvrir.
  const byUid = new Map(ct.records.map((r) => [r.uid, r]));
  const record = (uid: string): EventRecord | null => byUid.get(uid) ?? null;

  for (const ns of ct.namespaces) {
    const nsKey = `${backup.uid}|${ns.namespace}`;
    const objects = ns.kinds.reduce((n, k) => n + k.names.length, 0);
    out.push({
      item: "ns",
      uid: `ct|${nsKey}`,
      key: nsKey,
      label: ns.namespace || "(cluster)",
      kind: ns.namespace ? "Namespace" : "Cluster",
      info: `${objects} · ${ns.kinds.length}`,
      depth: base,
      foldable: true,
      record: record(`ct|${nsKey}`),
    });
    if (!expanded.has(nsKey)) continue;

    for (const k of ns.kinds) {
      const kindKey = `${nsKey}|${k.kind}`;
      out.push({
        item: "kind",
        uid: `ct|${kindKey}`,
        key: kindKey,
        label: k.kind,
        kind: "",
        info: String(k.names.length),
        depth: base + 1,
        foldable: true,
        record: record(`ct|${kindKey}`),
      });
      if (!expanded.has(kindKey)) continue;

      for (const name of k.names) {
        out.push({
          item: "object",
          uid: `cto|${k.api_version}|${k.kind}|${ns.namespace}/${name}`,
          key: "",
          label: name,
          kind: k.kind,
          info: "",
          depth: base + 2,
          foldable: false,
          record: record(`cto|${k.api_version}|${k.kind}|${ns.namespace}/${name}`),
        });
      }
    }
  }
  return out;
}

/**
 * Le menu d'action, avec la confirmation de kdt.
 *
 * Rien ici n'est offert sur une ligne où il ne s'appliquerait pas : restaurer depuis un backup qui
 * n'est jamais allé au bout rejouerait une capture partielle comme si elle était entière, donc
 * l'entrée n'existe pas.
 */
function ActionMenu({
  st,
  row,
  contents,
  onRun,
}: {
  st: Strings;
  row: VelScheduleRow | VelBackupRow;
  contents: VelContentsPayload | "loading" | undefined;
  onRun: (r: Parameters<typeof api.veleroWrite>[0]) => void;
}) {
  const [arming, setArming] = useState<{ label: string; desc: string; run: () => void } | null>(
    null,
  );
  const [form, setForm] = useState(false);

  if (form && row.row === "backup") {
    return (
      <RestoreForm
        st={st}
        row={row}
        contents={typeof contents === "object" ? contents : null}
        onCancel={() => setForm(false)}
        onSubmit={(restore) =>
          onRun({ action: "restore", namespace: row.namespace, name: row.name, restore })
        }
      />
    );
  }

  const items: Array<{ label: string; desc: string; run: () => void }> = [];
  if (row.row === "schedule") {
    items.push({
      label: st.velBackupNow,
      desc: st.velBackupNowHelp,
      run: () => onRun({ action: "backup-now", namespace: row.namespace, name: row.name }),
    });
    items.push(
      row.paused
        ? {
            label: st.velResume,
            desc: st.velResumeHelp,
            run: () =>
              onRun({ action: "pause", namespace: row.namespace, name: row.name, paused: false }),
          }
        : {
            label: st.velPause,
            desc: st.velPauseHelp,
            run: () =>
              onRun({ action: "pause", namespace: row.namespace, name: row.name, paused: true }),
          },
    );
  } else {
    if (row.usable || row.partially_failed) {
      items.push({
        label: st.velRestore,
        desc: st.velRestoreHelp,
        run: () =>
          onRun({
            action: "restore",
            namespace: row.namespace,
            name: row.name,
            restore: { namespaces: [], kinds: [], target_ns: "", labels: "", overwrite: false },
          }),
      });
    }
    if (!row.deleting && row.phase !== "Deleting") {
      items.push({
        label: st.velDelete,
        desc: st.velDeleteHelp,
        run: () => onRun({ action: "delete-backup", namespace: row.namespace, name: row.name }),
      });
    }
  }

  return (
    <div className="pop menu" onClick={(e) => e.stopPropagation()}>
      <div className="pop-hd">
        <span>{st.velActions}</span>
      </div>
      <div className="menu-target mono">
        {row.namespace}/{row.name}
      </div>

      {arming ? (
        <div className="menu-confirm">
          <p>{arming.desc}</p>
          <div className="menu-buttons">
            {/* Annuler d'abord et autofocus : la sortie par défaut est celle qui n'écrit rien. */}
            <button autoFocus onClick={() => setArming(null)}>
              {st.fluxCancel}
            </button>
            <button className="cta" onClick={arming.run}>
              {st.fluxConfirm} · {arming.label}
            </button>
          </div>
        </div>
      ) : (
        <div className="menu-list">
          {items.map((a) => (
            <button key={a.label} className="menu-item" onClick={() => setArming(a)}>
              <span className="lbl">{a.label}</span>
              <span className="desc">{a.desc}</span>
            </button>
          ))}
          {/* La restauration à la carte n'est pas une confirmation mais un formulaire : elle ouvre
              son propre écran plutôt que d'armer. */}
          {row.row === "backup" && (row.usable || row.partially_failed) && (
            <button className="menu-item" onClick={() => setForm(true)}>
              <span className="lbl">{st.velRestoreOpts}</span>
              <span className="desc">{st.velRestoreOptsHelp}</span>
            </button>
          )}
          {items.length === 0 && <p className="menu-note">{st.velNoAction}</p>}
        </div>
      )}
    </div>
  );
}

/**
 * Le formulaire de restauration à la carte.
 *
 * Sans inventaire téléchargé les namespaces se **tapent** au lieu de se cocher : le formulaire doit
 * rester utilisable exactement quand le bucket est hors de portée, qui est le cas pour lequel il
 * existe. Une liste vide n'est jamais « tout » — elle est refusée, parce qu'elle restaurerait le
 * backup entier, l'inverse de ce qu'une liste vidée demande.
 */
function RestoreForm({
  st,
  row,
  contents,
  onCancel,
  onSubmit,
}: {
  st: Strings;
  row: VelBackupRow;
  contents: VelContentsPayload | null;
  onCancel: () => void;
  onSubmit: (r: VelRestoreRequest) => void;
}) {
  const available = useMemo(
    () => (contents?.namespaces ?? []).filter((n) => n.namespace).map((n) => n.namespace),
    [contents],
  );
  const kinds = useMemo(() => {
    const out: Array<{ apiVersion: string; kind: string }> = [];
    for (const ns of contents?.namespaces ?? []) {
      for (const k of ns.kinds) {
        if (!out.some((x) => x.kind === k.kind)) out.push({ apiVersion: k.api_version, kind: k.kind });
      }
    }
    return out;
  }, [contents]);

  const manual = available.length === 0;
  const [picked, setPicked] = useState<Set<string>>(() => new Set(available));
  const [pickedKinds, setPickedKinds] = useState<Set<string>>(() => new Set(kinds.map((k) => k.kind)));
  const [nsText, setNsText] = useState("");
  const [targetNs, setTargetNs] = useState("");
  const [labels, setLabels] = useState("");
  const [overwrite, setOverwrite] = useState(false);
  const [typed, setTyped] = useState("");
  const [armed, setArmed] = useState(false);

  const namespaces = manual
    ? nsText
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
    : [...picked];

  // Tous les kinds cochés veut dire « aucun filtre », ce qui est une spec plus courte que d'énumérer
  // chaque kind — et une qui continue de marcher pour un kind que l'inventaire ne mentionne pas.
  const kindFilter =
    kinds.length === 0 || pickedKinds.size === kinds.length
      ? []
      : kinds.filter((k) => pickedKinds.has(k.kind));

  const ready = namespaces.length > 0 && (!overwrite || typed === row.name);

  return (
    <div className="pop menu wide" onClick={(e) => e.stopPropagation()}>
      <div className="pop-hd">
        <span>{st.velRestoreOpts}</span>
      </div>
      <div className="menu-target mono">
        {row.namespace}/{row.name}
      </div>

      <div className="vel-form">
        <div className="sect">{manual ? st.velRoNsManual : st.velRoNamespaces}</div>
        {manual ? (
          <>
            <input
              className="ns-add"
              value={nsText}
              autoFocus
              spellCheck={false}
              onChange={(e) => setNsText(e.target.value)}
            />
            <p className="dim">{st.velRoNsManualHelp}</p>
          </>
        ) : (
          <>
            <div className="vel-pickbar">
              <button onClick={() => setPicked(new Set(available))}>{st.velRoAll}</button>
              <button onClick={() => setPicked(new Set())}>{st.velRoNone}</button>
            </div>
            <div className="vel-picks">
              {available.map((ns) => (
                <label key={ns} className="opt">
                  <input
                    type="checkbox"
                    checked={picked.has(ns)}
                    onChange={(e) =>
                      setPicked((prev) => {
                        const next = new Set(prev);
                        if (e.target.checked) next.add(ns);
                        else next.delete(ns);
                        return next;
                      })
                    }
                  />
                  {ns}
                </label>
              ))}
            </div>
          </>
        )}

        {kinds.length > 0 && (
          <>
            <div className="sect">{st.velRoKinds}</div>
            <div className="vel-pickbar">
              <button onClick={() => setPickedKinds(new Set(kinds.map((k) => k.kind)))}>
                {st.velRoAll}
              </button>
              <button onClick={() => setPickedKinds(new Set())}>{st.velRoNone}</button>
            </div>
            <div className="vel-picks">
              {kinds.map((k) => (
                <label key={k.kind} className="opt">
                  <input
                    type="checkbox"
                    checked={pickedKinds.has(k.kind)}
                    onChange={(e) =>
                      setPickedKinds((prev) => {
                        const next = new Set(prev);
                        if (e.target.checked) next.add(k.kind);
                        else next.delete(k.kind);
                        return next;
                      })
                    }
                  />
                  {k.kind}
                </label>
              ))}
            </div>
          </>
        )}

        <div className="form-row">
          <label>{st.velRoTarget}</label>
          <input
            value={targetNs}
            spellCheck={false}
            // Velero mappe namespace par namespace : avec plusieurs sources il n'y a pas de source
            // unique, et le champ est désactivé plutôt que deviné.
            disabled={namespaces.length !== 1}
            title={st.velRoTargetHelp}
            onChange={(e) => setTargetNs(e.target.value)}
          />
        </div>
        <div className="form-row">
          <label>{st.velRoLabels}</label>
          <input
            value={labels}
            spellCheck={false}
            placeholder="team=a, env=prod"
            title={st.velRoLabelsHelp}
            onChange={(e) => setLabels(e.target.value)}
          />
        </div>
        <label className="opt" title={st.velRoOverwriteHelp}>
          <input
            type="checkbox"
            checked={overwrite}
            onChange={(e) => {
              setOverwrite(e.target.checked);
              setTyped("");
              setArmed(false);
            }}
          />
          {st.velRoOverwrite}
        </label>

        {namespaces.length === 0 && <p className="menu-note err">{st.velRoNoNs}</p>}

        {/* Écraser des objets vivants est sur le même pied qu'une suppression : le nom se retape,
            il ne se confirme pas d'un clic. */}
        {overwrite && armed && (
          <div className="delete-confirm">
            <p>{st.velRoConfirm}</p>
            <input
              className="ns-add"
              value={typed}
              autoFocus
              spellCheck={false}
              onChange={(e) => setTyped(e.target.value)}
            />
          </div>
        )}
      </div>

      <div className="menu-buttons">
        <button autoFocus onClick={onCancel}>
          {st.fluxCancel}
        </button>
        <button
          className={`cta${overwrite ? " danger" : ""}`}
          disabled={namespaces.length === 0 || (overwrite && armed && !ready)}
          onClick={() => {
            if (overwrite && !armed) {
              setArmed(true);
              return;
            }
            if (!ready) return;
            onSubmit({
              namespaces,
              kinds: kindFilter,
              target_ns: targetNs,
              labels,
              overwrite,
            });
          }}
        >
          {st.fluxConfirm} · {st.velRestore}
        </button>
      </div>
    </div>
  );
}

/** Le panneau : ce que la ligne lue dit du backup, du schedule, ou de l'infrastructure. */
function VeleroDetail({
  st,
  payload,
  row,
  contents,
  log,
}: {
  st: Strings;
  payload: VeleroPayload;
  row: VelRow | null;
  contents: VelContentsPayload | "loading" | undefined;
  log: VelLogPayload | null;
}) {
  return (
    <div className="detail">
      {row && <RowFacts st={st} row={row} contents={contents} />}

      {row && row.hints.length > 0 && (
        <>
          <div className="sect">{st.velProblems}</div>
          <ul className="hints">
            {row.hints.map((h, i) => (
              <li key={i} className={h.level === "danger" ? "danger" : h.level}>
                {h.text}
              </li>
            ))}
          </ul>
        </>
      )}

      {payload.cluster_hints.length > 0 && (
        <>
          <div className="sect">cluster</div>
          <ul className="hints">
            {payload.cluster_hints.map((h, i) => (
              <li key={i} className={h.level === "danger" ? "danger" : h.level}>
                {h.text}
              </li>
            ))}
          </ul>
        </>
      )}

      {log && (
        <>
          <div className="sect">
            {log.source === "download" ? st.velLogSourceDownload : st.velLogs}
          </div>
          {/* Le repli n'est pas une commodité : velero signe ses URL contre l'adresse que le
              cluster utilise, qui ne résout pas toujours ailleurs. Dire d'où viennent les lignes
              évite de lire un log partiel comme s'il était complet. */}
          {log.source === "server" && <p className="warn">{st.velLogSourceServer}</p>}
          {log.error && <p className="warn">{log.error}</p>}
          <pre className="logs">{log.lines.length ? log.lines.join("\n") : st.velLogEmpty}</pre>
        </>
      )}
    </div>
  );
}

function RowFacts({
  st,
  row,
  contents,
}: {
  st: Strings;
  row: VelRow;
  contents: VelContentsPayload | "loading" | undefined;
}) {
  const scope = (included: string[], excluded: string[]) => {
    const inc = included.length === 0 || included.includes("*") ? st.velAllNamespaces : included.join(", ");
    return excluded.length === 0 ? inc : `${inc} — ${excluded.join(", ")}`;
  };

  switch (row.row) {
    case "schedule":
      return (
        <dl className="facts">
          <dt>{st.velLblCron}</dt>
          <dd>{row.cron || "—"}</dd>
          <dt>{st.velLblNextRun}</dt>
          <dd className={row.paused ? "warn" : undefined}>
            {row.paused
              ? st.velPaused
              : row.next_run === null
                ? "—"
                : row.next_run > nowSecs()
                  ? inFuture(row.next_run)
                  : `${st.velOverdue} · ${ago(row.next_run)}`}
          </dd>
          <dt>{st.velLblLastBackup}</dt>
          <dd>{row.last_backup === null ? st.velNever : ago(row.last_backup)}</dd>
          {/* `skipImmediately` déplace la prochaine exécution sans rien laisser d'autre : sans
              cette ligne un schedule qui a sauté ressemble à un schedule qui n'a pas encore tiré. */}
          {row.last_skipped !== null && (
            <>
              <dt>{st.velLblLastSkipped}</dt>
              <dd>{ago(row.last_skipped)}</dd>
            </>
          )}
          <dt>{st.velLblTtl}</dt>
          <dd>{row.ttl === null ? "—" : span(row.ttl)}</dd>
          <dt>{st.velLblScope}</dt>
          <dd>{scope(row.included_ns, row.excluded_ns)}</dd>
          <dt>{st.velLblLocation}</dt>
          <dd>{row.storage_location ?? "—"}</dd>
          <dt>age</dt>
          <dd>{row.age}</dd>
        </dl>
      );
    case "backup":
      return (
        <>
          <dl className="facts">
            <dt>{st.velLblPhase}</dt>
            <dd className={row.phase_tone === "err" ? "err" : undefined}>{row.phase || "—"}</dd>
            <dt>{st.velLblSchedule}</dt>
            <dd>{row.schedule ?? "—"}</dd>
            <dt>{st.velLblStarted}</dt>
            <dd>{row.started === null ? "—" : ago(row.started)}</dd>
            {row.started !== null && row.completed !== null && (
              <>
                <dt>{st.velLblDuration}</dt>
                <dd>{span(row.completed - row.started)}</dd>
              </>
            )}
            <dt>{st.velLblItems}</dt>
            <dd>
              {row.items_backed_up} / {row.total_items}
            </dd>
            <dt>{st.velLblCaptured}</dt>
            <dd>
              {row.volume_snapshots_completed} snapshots · {row.pvb_total} fs-backup
            </dd>
            <dt>{st.velLblExpires}</dt>
            <dd>{row.expiration === null ? "—" : inFuture(row.expiration)}</dd>
            <dt>{st.velLblErrors}</dt>
            <dd className={row.errors > 0 ? "err" : row.warnings > 0 ? "warn" : undefined}>
              {row.errors} / {row.warnings}
            </dd>
            <dt>{st.velLblScope}</dt>
            <dd>{scope(row.included_ns, row.excluded_ns)}</dd>
            <dt>{st.velLblLocation}</dt>
            <dd>{row.storage_location || "—"}</dd>
            <dt>{st.velLblRestores}</dt>
            <dd>{row.restores}</dd>
            <dt>{st.velContents}</dt>
            <dd>
              {contents === "loading"
                ? st.velContentsLoading
                : typeof contents === "object"
                  ? contents.error
                    ? contents.error
                    : contents.total === 0
                      ? st.velContentsEmpty
                      : `${contents.total} · ${contents.namespaces.length}`
                  : "—"}
            </dd>
          </dl>
          {/* Les échecs par volume, tels quels : ils portent le seul message qui dise quel volume
              n'est pas passé, ce que le `failureReason` du backup ne dit jamais. */}
          {row.pvb_failed.length > 0 && (
            <>
              <div className="sect">{st.velLblFailedVolumes}</div>
              <ul className="hints">
                {row.pvb_failed.map((v) => (
                  <li key={v} className="danger">
                    {v}
                  </li>
                ))}
              </ul>
            </>
          )}
        </>
      );
    case "restore":
      return (
        <dl className="facts">
          <dt>{st.velLblPhase}</dt>
          <dd className={row.phase_tone === "err" ? "err" : undefined}>{row.phase || "—"}</dd>
          <dt>{st.velLblBackup}</dt>
          <dd>{row.backup || "—"}</dd>
          {row.schedule && (
            <>
              <dt>{st.velLblSchedule}</dt>
              <dd>{row.schedule}</dd>
            </>
          )}
          <dt>{st.velLblStarted}</dt>
          <dd>{row.started === null ? "—" : ago(row.started)}</dd>
          <dt>{st.velLblItems}</dt>
          <dd>
            {row.items_restored} / {row.total_items}
          </dd>
          <dt>{st.velLblErrors}</dt>
          <dd className={row.errors > 0 ? "err" : undefined}>
            {row.errors} / {row.warnings}
          </dd>
        </dl>
      );
    case "location":
      return (
        <dl className="facts">
          <dt>{st.velLblPhase}</dt>
          <dd className={row.available ? undefined : "err"}>{row.phase || "—"}</dd>
          <dt>{st.velLblProvider}</dt>
          <dd>{row.provider || "—"}</dd>
          <dt>{st.velLblBucket}</dt>
          <dd>{row.prefix ? `${row.bucket}/${row.prefix}` : row.bucket || "—"}</dd>
          <dt>{st.velLblAccess}</dt>
          <dd className={row.read_only ? "warn" : undefined}>
            {row.read_only ? "ReadOnly" : "ReadWrite"}
          </dd>
          <dt>{st.velLblValidated}</dt>
          <dd>{row.last_validated === null ? st.velNever : ago(row.last_validated)}</dd>
          <dt>{st.velBackups}</dt>
          <dd>{row.backups}</dd>
        </dl>
      );
    case "snaploc":
      return (
        <dl className="facts">
          <dt>{st.velLblPhase}</dt>
          <dd>{row.phase || "—"}</dd>
          <dt>{st.velLblProvider}</dt>
          <dd>{row.provider || "—"}</dd>
        </dl>
      );
    case "repo":
      return (
        <dl className="facts">
          <dt>{st.velLblPhase}</dt>
          <dd>{row.phase || "—"}</dd>
          <dt>{st.velLblRepoType}</dt>
          <dd>{row.repo_type || "—"}</dd>
          <dt>{st.velLblScope}</dt>
          <dd>{row.volume_namespace || "—"}</dd>
          <dt>{st.velLblMaintenance}</dt>
          <dd>{row.last_maintenance === null ? st.velNever : ago(row.last_maintenance)}</dd>
        </dl>
      );
    default:
      return null;
  }
}

function kindLabel(row: VelRow): string {
  switch (row.row) {
    case "schedule":
      return "Schedule";
    case "backup":
      return "Backup";
    case "restore":
      return "Restore";
    case "location":
      return "BSL";
    case "snaploc":
      return "VSL";
    case "repo":
      return "Repo";
    default:
      return "";
  }
}

function infoText(row: VelRow, st: Strings): string {
  switch (row.row) {
    case "schedule":
      return row.cron;
    case "backup":
      return `${row.items_backed_up} items · ${row.volumes} vol`;
    case "restore":
      return row.backup;
    case "location":
      return row.bucket ? `${row.provider} ${row.bucket}` : row.provider;
    case "snaploc":
      return row.provider;
    case "repo":
      return `${row.repo_type} · ${row.volume_namespace}`;
    case "orphans":
      return `${row.backups} ${st.velBackups}`;
  }
}

function expireText(row: VelRow): string {
  if (row.row === "backup" && row.expiration !== null) return inFuture(row.expiration);
  if (row.row === "schedule" && !row.paused && row.next_run !== null && row.next_run > nowSecs())
    return inFuture(row.next_run);
  return "";
}

function hintClass(hints: VelHint[]): string {
  const worst = hints.reduce<string>(
    (acc, h) => (h.level === "danger" ? "danger" : acc === "danger" ? acc : h.level),
    "",
  );
  return worst === "danger" ? "vel-danger" : worst === "warn" ? "vel-warn" : "vel-plain";
}

function hintTone(hints: VelHint[]): string {
  const worst = hints.reduce<string>(
    (acc, h) => (h.level === "danger" ? "danger" : acc === "danger" ? acc : h.level),
    "",
  );
  return worst === "danger" ? "err" : worst === "warn" ? "warn" : "dim";
}

function nowSecs(): number {
  return Math.floor(Date.now() / 1000);
}

/** « il y a 3h » sous la forme compacte du TUI : `3h`, `2d`, `41d`. */
function ago(epoch: number): string {
  return span(Math.max(0, nowSecs() - epoch));
}

function inFuture(epoch: number): string {
  const delta = epoch - nowSecs();
  return delta <= 0 ? "—" : span(delta);
}

function span(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h`;
  return `${Math.floor(secs / 86400)}d`;
}

function matches(row: VelRow, needle: string): boolean {
  const parts: string[] = [row.row, row.name];
  if ("namespace" in row) parts.push(row.namespace);
  if ("phase" in row) parts.push(row.phase);
  if ("cron" in row) parts.push(row.cron);
  if ("backup" in row) parts.push(row.backup);
  if ("provider" in row) parts.push(row.provider);
  parts.push(...row.hints.map((h) => h.text));
  return parts.join(" ").toLowerCase().includes(needle);
}
