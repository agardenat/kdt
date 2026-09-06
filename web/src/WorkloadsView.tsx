// La vue Workloads : les workloads, leurs pods, et les containers de chaque pod.
//
// Trois niveaux, et donc deux plis. Le TUI les pilote avec `t` (montrer les workloads), `Espace`
// et `→`/`←` (déplier un pod) parce qu'il n'a que des touches ; ici chaque pli a sa cible visible.
// Voir la mémoire `gui-affordances-not-tui-keys`.
//
// Aucun verdict n'est calculé ici : l'état d'un pod, le ton de sa ligne, le `READY` d'un workload
// — qui ne se compte pas pareil selon le kind — et le rattachement d'un pod à son workload
// arrivent tout faits de `kdt::pods`.

import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import type { Lang, Strings } from "./i18n";
import { InspectPanel, Splitter, type PanelTab } from "./panel";
import type { ContainerRow, EventRecord, PodRow, WorkloadRow } from "./types";

/**
 * Les colonnes, dans l'ordre du TUI : le nom, puis ce qui se compte, puis ce qui se consomme.
 *
 * NAME prend la place restante parce que c'est lui qui porte l'indentation des trois niveaux.
 * CPU et MEM restent étroites : ce sont des chiffres courts, et les élargir volerait la place au
 * seul champ qui distingue deux lignes voisines.
 */
const COLUMNS =
  "minmax(260px,1.6fr) 88px minmax(110px,14ch) 64px 56px minmax(110px,16ch) 74px 74px";

/** Une ligne affichée : un des trois niveaux, avec sa profondeur. */
type Row =
  | { level: "workload"; row: WorkloadRow }
  | { level: "pod"; row: PodRow; indent: boolean }
  | { level: "container"; row: ContainerRow };

export default function WorkloadsView({
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
  const [workloads, setWorkloads] = useState<WorkloadRow[]>([]);
  const [pods, setPods] = useState<PodRow[]>([]);
  const [missing, setMissing] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [grouped, setGrouped] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<PanelTab>("status");
  const [menuFor, setMenuFor] = useState<WorkloadRow | null>(null);
  const [toast, setToast] = useState<{ tone: "ok" | "err"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  // La vue est dans la portée, contrairement à l'arbre Flux : elle liste des objets indépendants,
  // pas un graphe qu'un filtre amputerait de ses arêtes. Un seul namespace — la hiérarchie se lit
  // workload par workload, et deux namespaces mêlés n'auraient pas de racine commune.
  const namespace = namespaces[0] ?? "";

  const load = useCallback(async () => {
    try {
      const payload = await api.workloads(namespace);
      setWorkloads(payload.workloads);
      setPods(payload.pods);
      setMissing(payload.missing_kinds);
      setError(null);
      setLoaded(true);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else if (e instanceof ApiError) setError(e.message);
      else setError(String(e));
      setLoaded(true);
    }
  }, [namespace, onNeedsAuth]);

  useEffect(() => {
    void load();
    // Plus lent que les évènements : un tour complet lit les pods, les métriques et quatre kinds
    // de workloads, et résout les owners. Assez pour suivre un rollout, sans marteler l'apiserver.
    const timer = window.setInterval(() => void load(), 10000);
    return () => window.clearInterval(timer);
  }, [load]);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 8000);
    return () => window.clearTimeout(timer);
  }, [toast]);

  useEffect(() => {
    if (!menuFor) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        setMenuFor(null);
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [menuFor]);

  const needle = query.trim().toLowerCase();

  // Le filtre porte sur les pods et les workloads séparément, puis la hiérarchie se reconstruit :
  // un workload dont un pod correspond reste visible, sinon son groupe entier disparaîtrait et on
  // ne saurait plus d'où vient le pod trouvé.
  const rows = useMemo<Row[]>(() => {
    const podMatches = (p: PodRow) =>
      !needle ||
      [p.name, p.namespace, p.status, p.node, p.ip].join(" ").toLowerCase().includes(needle);
    const workloadMatches = (w: WorkloadRow) =>
      !needle ||
      [w.name, w.namespace, w.kind, w.status_label].join(" ").toLowerCase().includes(needle);

    const out: Row[] = [];
    const pushPod = (p: PodRow, indent: boolean) => {
      out.push({ level: "pod", row: p, indent });
      if (expanded.has(p.uid)) {
        for (const c of p.containers) out.push({ level: "container", row: c });
      }
    };

    if (!grouped) {
      for (const p of pods) if (podMatches(p)) pushPod(p, false);
      return out;
    }

    for (const w of workloads) {
      const mine = pods.filter((p) => p.group === w.uid);
      const keptPods = mine.filter(podMatches);
      // Le workload reste si lui-même correspond, ou si l'un de ses pods correspond.
      if (!workloadMatches(w) && keptPods.length === 0) continue;
      out.push({ level: "workload", row: w });
      // Un workload qui correspond garde **tout** son groupe : on cherche un workload pour voir
      // ses pods, pas pour n'en voir que ceux dont le nom répète le sien.
      for (const p of workloadMatches(w) ? mine : keptPods) pushPod(p, true);
    }
    // Les orphelins ferment la marche en gardant leur namespace : un pod nu, ou celui d'un
    // ReplicaSet sans Deployment au-dessus, n'a pas de parent à afficher mais existe bel et bien.
    for (const p of pods) if (p.group === null && podMatches(p)) pushPod(p, false);
    return out;
  }, [grouped, workloads, pods, expanded, needle]);

  const selectedRecord = useMemo<EventRecord | null>(() => {
    for (const entry of rows) if (entry.row.uid === selected) return entry.row.record;
    return null;
  }, [rows, selected]);

  const toggle = useCallback((uid: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(uid)) next.delete(uid);
      else next.add(uid);
      return next;
    });
  }, []);

  const run = useCallback(
    async (action: () => Promise<{ message: string }>) => {
      setMenuFor(null);
      setBusy(true);
      try {
        const { message } = await action();
        setToast({ tone: "ok", text: message });
        void load();
      } catch (e) {
        if (e instanceof NeedsAuth) onNeedsAuth(e.message);
        else setToast({ tone: "err", text: String((e as Error).message ?? e) });
      } finally {
        setBusy(false);
      }
    },
    [load, onNeedsAuth],
  );

  const running = pods.filter((p) => p.status_tone === "ok").length;
  const broken = pods.filter((p) => p.status_tone === "err").length;

  return (
    <>
      {selectedRecord && panelOpen && (
        <>
          <InspectPanel
            record={selectedRecord}
            tab={tab}
            onTab={setTab}
            onClose={() => onPanelOpen(false)}
            height={panelHeight}
            lang={lang}
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds" role="tablist">
        <button role="tab" aria-selected={grouped} onClick={() => setGrouped(true)}>
          {st.wlGrouped}
          <span className="count">{workloads.length}</span>
        </button>
        <button role="tab" aria-selected={!grouped} onClick={() => setGrouped(false)}>
          {st.wlPods}
          <span className="count">{pods.length}</span>
        </button>

        <div className="tally">
          <span className="ok" title={st.wlRunning}>
            ✓{running}
          </span>
          {broken > 0 && (
            <span className="err" title={st.wlBroken}>
              ✗{broken}
            </span>
          )}
        </div>

        <div className="right">
          {busy && <span>{st.wlWorking}</span>}
          {selectedRecord && (
            <button className="panel-toggle" onClick={() => onPanelOpen(!panelOpen)}>
              {panelOpen
                ? lang === "fr"
                  ? "▾ replier"
                  : "▾ collapse"
                : lang === "fr"
                  ? "▸ panneau"
                  : "▸ panel"}
            </button>
          )}
        </div>
      </div>

      <div className="body">
        {!loaded ? (
          <div className="center" />
        ) : rows.length === 0 ? (
          <div className="center">
            <div className="box">
              <h2>{needle ? st.emptyTitle : st.wlEmpty}</h2>
              {error && <p className="err">{error}</p>}
              <p>
                {st.emptyScope} <code>{namespace || st.scopeAll}</code>
              </p>
            </div>
          </div>
        ) : (
          <div className="tbl">
            <div className="thead">
              <div className="tr" style={{ gridTemplateColumns: COLUMNS }}>
                <div className="cell">NAME</div>
                <div className="cell">READY</div>
                <div className="cell">STATUS</div>
                <div className="cell num">RESTARTS</div>
                <div className="cell num">AGE</div>
                <div className="cell">NODE</div>
                <div className="cell num">CPU</div>
                <div className="cell num">MEM</div>
              </div>
            </div>
            <div className="tbody">
              {rows.map((entry) =>
                entry.level === "workload" ? (
                  <WorkloadLine
                    key={entry.row.uid}
                    w={entry.row}
                    st={st}
                    selected={selected === entry.row.uid}
                    menuOpen={menuFor?.uid === entry.row.uid}
                    onSelect={() => {
                      setSelected(entry.row.uid);
                      onPanelOpen(true);
                    }}
                    onMenu={() => setMenuFor((m) => (m?.uid === entry.row.uid ? null : entry.row))}
                    onRun={run}
                  />
                ) : entry.level === "pod" ? (
                  <PodLine
                    key={entry.row.uid}
                    p={entry.row}
                    st={st}
                    indent={entry.indent}
                    expanded={expanded.has(entry.row.uid)}
                    selected={selected === entry.row.uid}
                    onSelect={() => {
                      setSelected(entry.row.uid);
                      onPanelOpen(true);
                    }}
                    onToggle={() => toggle(entry.row.uid)}
                  />
                ) : (
                  <ContainerLine
                    key={entry.row.uid}
                    c={entry.row}
                    selected={selected === entry.row.uid}
                    onSelect={() => {
                      setSelected(entry.row.uid);
                      onPanelOpen(true);
                    }}
                  />
                ),
              )}
            </div>
          </div>
        )}
      </div>

      <div className="statusbar">
        <span>
          {rows.length} {st.rows}
        </span>
        <span>
          {st.scopeLabel}: {namespace || st.scopeAll}
        </span>
        {/* Un kind refusé se dit : sans ça, la vue laisserait croire qu'il n'y a aucun Job. */}
        {missing.length > 0 && (
          <span className="warn" title={st.wlMissingHelp}>
            {st.wlMissing}: {missing.join(" · ")}
          </span>
        )}
        {error && <span className="err">{error}</span>}
        {toast && <span className={toast.tone === "err" ? "err" : "ok"}>{toast.text}</span>}
        <span style={{ marginLeft: "auto" }}>
          <span className="kbd">/</span> {st.hintFilter} <span className="kbd">Esc</span>{" "}
          {st.hintClose}
        </span>
      </div>
    </>
  );
}

function WorkloadLine({
  w,
  st,
  selected,
  menuOpen,
  onSelect,
  onMenu,
  onRun,
}: {
  w: WorkloadRow;
  st: Strings;
  selected: boolean;
  menuOpen: boolean;
  onSelect: () => void;
  onMenu: () => void;
  onRun: (action: () => Promise<{ message: string }>) => void;
}) {
  return (
    <div
      className="tr wl-workload"
      style={{ gridTemplateColumns: COLUMNS }}
      aria-selected={selected}
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSelect();
      }}
    >
      <div className="cell id">
        <span className="kind">{w.kind}</span> {w.name}
        {/* Les actions vivent sur la ligne qu'elles visent, et non dans une barre où il faudrait
            d'abord sélectionner puis chercher : c'est là que la souris est déjà. */}
        {(w.scalable || w.restartable) && (
          <span className="menu-anchor">
            <button
              className="inv-pill"
              aria-expanded={menuOpen}
              title={st.wlActions}
              onClick={(e) => {
                e.stopPropagation();
                onMenu();
              }}
            >
              ⋯
            </button>
            {menuOpen && <WorkloadMenu w={w} st={st} onRun={onRun} />}
          </span>
        )}
      </div>
      <div className="cell mono">{w.ready_label}</div>
      <div className="cell">
        <span className={`st ${w.status_tone}`}>{w.status_label}</span>
      </div>
      <div className="cell num dim" />
      <div className="cell num dim">{w.age}</div>
      <div className="cell dim">{w.namespace}</div>
      <div className="cell num dim" />
      <div className="cell num dim" />
    </div>
  );
}

/**
 * Le menu d'une ligne de workload.
 *
 * `scale` et `recycle` demandent un nombre ; il est saisi dans le menu plutôt que dans une invite
 * séparée, avec la valeur actuelle comme point de départ — on ne demande jamais une saisie sans
 * montrer le champ et la valeur attendue.
 */
function WorkloadMenu({
  w,
  st,
  onRun,
}: {
  w: WorkloadRow;
  st: Strings;
  onRun: (action: () => Promise<{ message: string }>) => void;
}) {
  const [replicas, setReplicas] = useState(w.replicas ?? 1);
  const [arming, setArming] = useState<"scale" | "restart" | "recycle" | null>(null);

  const desc =
    arming === "scale"
      ? st.wlDescScale
      : arming === "restart"
        ? st.wlDescRestart
        : st.wlDescRecycle;

  return (
    <div className="pop menu" onClick={(e) => e.stopPropagation()}>
      <div className="pop-hd">
        <span>{st.wlActions}</span>
      </div>
      <div className="menu-target mono">
        {w.kind} {w.namespace}/{w.name}
      </div>

      {arming ? (
        <div className="menu-confirm">
          <p>{desc}</p>
          {arming !== "restart" && (
            <label className="opt">
              {st.wlReplicas}
              <input
                type="number"
                min={arming === "recycle" ? 1 : 0}
                value={replicas}
                autoFocus
                onChange={(e) => setReplicas(Number(e.target.value))}
              />
            </label>
          )}
          <div className="menu-buttons">
            {/* La sortie par défaut est celle qui n'écrit rien. */}
            <button onClick={() => setArming(null)}>{st.fluxCancel}</button>
            <button
              className="cta"
              onClick={() =>
                onRun(() =>
                  arming === "scale"
                    ? api.scale(w, replicas)
                    : arming === "restart"
                      ? api.restart(w)
                      : api.recycle(w, replicas),
                )
              }
            >
              {st.fluxConfirm}
            </button>
          </div>
        </div>
      ) : (
        <div className="menu-list">
          {w.scalable && (
            <button className="menu-item" onClick={() => setArming("scale")}>
              <span className="lbl">{st.wlScale}</span>
              <span className="desc">{st.wlDescScale}</span>
            </button>
          )}
          {w.restartable && (
            <button className="menu-item" onClick={() => setArming("restart")}>
              <span className="lbl">{st.wlRestart}</span>
              <span className="desc">{st.wlDescRestart}</span>
            </button>
          )}
          {w.scalable && (
            <button className="menu-item" onClick={() => setArming("recycle")}>
              <span className="lbl">{st.wlRecycle}</span>
              <span className="desc">{st.wlDescRecycle}</span>
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function PodLine({
  p,
  st,
  indent,
  expanded,
  selected,
  onSelect,
  onToggle,
}: {
  p: PodRow;
  st: Strings;
  indent: boolean;
  expanded: boolean;
  selected: boolean;
  onSelect: () => void;
  onToggle: () => void;
}) {
  return (
    <div
      className={`tr wl-${p.row_tone}`}
      style={{ gridTemplateColumns: COLUMNS }}
      aria-selected={selected}
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSelect();
        else if (e.key === " " && p.containers.length > 0) {
          e.preventDefault();
          onToggle();
        }
      }}
    >
      <div className="cell id" style={{ paddingLeft: indent ? "1.15rem" : undefined }}>
        {p.containers.length > 0 ? (
          <button
            className="fold"
            title={st.wlContainers}
            aria-expanded={expanded}
            onClick={(e) => {
              e.stopPropagation();
              onToggle();
            }}
          >
            {expanded ? "▾" : "▸"}
          </button>
        ) : (
          <span className="fold-gap" />
        )}
        {p.name}
      </div>
      <div className="cell mono">{p.ready}</div>
      <div className="cell">
        <span className={`st ${p.status_tone}`}>{p.status}</span>
      </div>
      <div className={`cell num ${p.restarts_tone}`}>{p.restarts}</div>
      <div className="cell num dim">{p.age}</div>
      <div className="cell dim" title={p.ip}>
        {p.node}
      </div>
      <div className="cell num">{cpu(p.cpu_milli)}</div>
      <div className="cell num">{mem(p.mem_bytes)}</div>
    </div>
  );
}

function ContainerLine({
  c,
  selected,
  onSelect,
}: {
  c: ContainerRow;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <div
      className="tr wl-container"
      style={{ gridTemplateColumns: COLUMNS }}
      aria-selected={selected}
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSelect();
      }}
    >
      <div className="cell id" style={{ paddingLeft: "2.6rem" }}>
        <span className={`gl ${c.tone}`}>{c.ready ? "✓" : "✗"}</span>
        {c.display_name}
      </div>
      <div className="cell mono dim" title={c.image}>
        {c.image.split("/").pop()}
      </div>
      <div className="cell">
        <span className={`st ${c.tone}`}>{c.state}</span>
      </div>
      <div className={`cell num ${c.restarts_tone}`}>{c.restarts}</div>
      <div className="cell num dim">{c.age}</div>
      <div className="cell" />
      <div className="cell num">{cpu(c.cpu_milli)}</div>
      <div className="cell num">{mem(c.mem_bytes)}</div>
    </div>
  );
}

/** Millicores, dans la forme du TUI : `250m` en dessous du cœur, `1.5` au-dessus. */
function cpu(milli: number | null): string {
  if (milli === null) return "—";
  return milli < 1000 ? `${milli}m` : (milli / 1000).toFixed(1);
}

/** Octets, à l'unité qui tient en trois chiffres. */
function mem(bytes: number | null): string {
  if (bytes === null) return "—";
  const mi = bytes / (1024 * 1024);
  return mi < 1024 ? `${Math.round(mi)}Mi` : `${(mi / 1024).toFixed(1)}Gi`;
}
