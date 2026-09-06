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
import { ObjectActions } from "./objects";
import type { ContainerRow, EventRecord, PodRow, UsagePct, WorkloadRow } from "./types";

/**
 * Les quatorze colonnes du TUI, dans le même ordre :
 * `NAMESPACE NAME READY STATUS RST CPU MEM %CPU/R %CPU/L %MEM/R %MEM/L IP NODE AGE`.
 *
 * Les quatre ratios sont le cœur de la vue et non un supplément : c'est là qu'on voit un container
 * throttlé contre sa limite ou un pod qui a réservé dix fois ce qu'il consomme. Ils restent
 * étroits — quatre chiffres et un `%` — pour laisser NAME porter l'indentation des trois niveaux.
 *
 * La table déborde horizontalement sur un écran étroit ; `.tbl` est déjà en `width: max-content`
 * dans un conteneur qui défile, donc rien ne s'écrase.
 */
const COLUMNS =
  "minmax(110px,16ch) minmax(240px,1.5fr) 78px minmax(104px,13ch) 46px 62px 72px" +
  " 60px 60px 60px 60px minmax(110px,14ch) minmax(120px,16ch) 52px";

/**
 * Ce que consomme un workload : la somme de ses pods.
 *
 * `null` quand aucun pod n'a de mesure — un workload à zéro réplique, ou pas de metrics-server.
 * Somme des valeurs connues, pas des zéros : un pod sans mesure ne compte pas pour rien.
 */
interface Agg {
  cpu: number | null;
  mem: number | null;
}

function aggregate(pods: PodRow[]): Agg {
  const sum = (pick: (p: PodRow) => number | null) => {
    const known = pods.map(pick).filter((v): v is number => v !== null);
    return known.length > 0 ? known.reduce((a, b) => a + b, 0) : null;
  };
  return { cpu: sum((p) => p.cpu_milli), mem: sum((p) => p.mem_bytes) };
}

/** Une ligne affichée : un des trois niveaux, avec sa profondeur. */
type Row =
  | { level: "workload"; row: WorkloadRow; agg: Agg }
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
  const [menuOpen, setMenuOpen] = useState(false);
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
    if (!menuOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        setMenuOpen(false);
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [menuOpen]);

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
      out.push({ level: "workload", row: w, agg: aggregate(mine) });
      // Un workload qui correspond garde **tout** son groupe : on cherche un workload pour voir
      // ses pods, pas pour n'en voir que ceux dont le nom répète le sien.
      for (const p of workloadMatches(w) ? mine : keptPods) pushPod(p, true);
    }
    // Les orphelins ferment la marche en gardant leur namespace : un pod nu, ou celui d'un
    // ReplicaSet sans Deployment au-dessus, n'a pas de parent à afficher mais existe bel et bien.
    for (const p of pods) if (p.group === null && podMatches(p)) pushPod(p, false);
    return out;
  }, [grouped, workloads, pods, expanded, needle]);

  // Un pod ou un container n'a ni `scale` ni `restart` : le menu ne s'ouvre que sur un workload,
  // et le dit plutôt que de proposer des entrées qui échoueraient.
  const selectedWorkload = useMemo(
    () => workloads.find((w) => w.uid === selected) ?? null,
    [workloads, selected],
  );

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
      setMenuOpen(false);
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
            st={st}
            onNeedsAuth={onNeedsAuth}
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
          {/* Les trois gestes de kdt qui portent sur n'importe quel objet — `y`, `e`, `h` dans le
              TUI. Ils vivent dans la barre, comme toutes les actions, et ouvrent le panneau du
              haut sur ce qu'ils montrent. */}
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
          {busy && <span>{st.wlWorking}</span>}
          {/* Les actions vivent dans la barre et portent sur la ligne sélectionnée — la même
              convention que la vue Flux. Ce qui est attaché à l'objet, ce sont les plis. */}
          <div className="menu-anchor">
            <button
              className="panel-toggle action"
              disabled={!selectedWorkload}
              title={selectedWorkload ? undefined : st.wlSelectWorkload}
              aria-expanded={menuOpen}
              onClick={() => setMenuOpen((v) => !v)}
            >
              {st.wlActions} ▾
            </button>
            {menuOpen && selectedWorkload && (
              <WorkloadMenu w={selectedWorkload} st={st} onRun={run} />
            )}
          </div>
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
                <div className="cell">NAMESPACE</div>
                <div className="cell">NAME</div>
                <div className="cell">READY</div>
                <div className="cell">STATUS</div>
                <div className="cell num" title={st.wlRestarts}>
                  RST
                </div>
                <div className="cell num">CPU</div>
                <div className="cell num">MEM</div>
                <div className="cell num" title={st.wlCpuReq}>
                  %CPU/R
                </div>
                <div className="cell num" title={st.wlCpuLim}>
                  %CPU/L
                </div>
                <div className="cell num" title={st.wlMemReq}>
                  %MEM/R
                </div>
                <div className="cell num" title={st.wlMemLim}>
                  %MEM/L
                </div>
                <div className="cell">IP</div>
                <div className="cell">NODE</div>
                <div className="cell num">AGE</div>
              </div>
            </div>
            <div className="tbody">
              {rows.map((entry) =>
                entry.level === "workload" ? (
                  <WorkloadLine
                    key={entry.row.uid}
                    w={entry.row}
                    agg={entry.agg}
                    selected={selected === entry.row.uid}
                    onSelect={() => {
                      setSelected(entry.row.uid);
                      onPanelOpen(true);
                    }}
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
  agg,
  selected,
  onSelect,
}: {
  w: WorkloadRow;
  agg: Agg;
  selected: boolean;
  onSelect: () => void;
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
      <div className="cell mono dim">{w.namespace}</div>
      <div className="cell id">
        <span className="kind">{w.kind}</span> {w.name}
        {/* Les actions vivent sur la ligne qu'elles visent, et non dans une barre où il faudrait
            d'abord sélectionner puis chercher : c'est là que la souris est déjà. */}

      </div>
      <div className="cell mono">{w.ready_label}</div>
      <div className="cell">
        <span className={`st ${w.status_tone}`}>{w.status_label}</span>
      </div>
      <div className="cell num dim" />
      {/* CPU et MEM d'un workload sont la somme de ses pods, agrégée à l'affichage. Les ratios,
          eux, restent vides : additionner des pourcentages de bases différentes ne veut rien
          dire, et le TUI les laisse vides pour la même raison. */}
      <div className="cell num">{cpu(agg.cpu)}</div>
      <div className="cell num">{mem(agg.mem)}</div>
      <div className="cell num dim" />
      <div className="cell num dim" />
      <div className="cell num dim" />
      <div className="cell num dim" />
      <div className="cell dim" />
      <div className="cell dim" />
      <div className="cell num dim">{w.age}</div>
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
      <div className="cell num">{cpu(p.cpu_milli)}</div>
      <div className="cell num">{mem(p.mem_bytes)}</div>
      <Pct v={p.cpu_req_pct} />
      <Pct v={p.cpu_lim_pct} />
      <Pct v={p.mem_req_pct} />
      <Pct v={p.mem_lim_pct} />
      <div className="cell mono dim">{p.ip}</div>
      <div className="cell dim" title={p.node}>
        {p.node}
      </div>
      <div className="cell num dim">{p.age}</div>
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
      <div className="cell" />
      <div className="cell id" style={{ paddingLeft: "2.6rem" }}>
        <span className={`gl ${c.tone}`}>{c.ready ? "✓" : "✗"}</span>
        {c.display_name}
      </div>
      {/* Un container n'a pas de compte `prêts/total` : il est prêt ou non, et le glyphe le dit
          déjà. La colonne porte donc son image, qui est ce qui le distingue de son voisin. */}
      <div className="cell mono dim" title={c.image}>
        {c.image.split("/").pop()}
      </div>
      <div className="cell">
        <span className={`st ${c.tone}`}>{c.state}</span>
      </div>
      <div className={`cell num ${c.restarts_tone}`}>{c.restarts}</div>
      <div className="cell num">{cpu(c.cpu_milli)}</div>
      <div className="cell num">{mem(c.mem_bytes)}</div>
      <Pct v={c.cpu_req_pct} />
      <Pct v={c.cpu_lim_pct} />
      <Pct v={c.mem_req_pct} />
      <Pct v={c.mem_lim_pct} />
      <div className="cell" />
      <div className="cell" />
      <div className="cell num dim">{c.age}</div>
    </div>
  );
}

/**
 * Un ratio d'usage, peint par sa bande de pression.
 *
 * `—` quand il n'y en a pas : pas de metrics-server, ou pas de requête ni de limite déclarée. Un
 * `0 %` se lirait comme une consommation nulle, ce qui est une tout autre nouvelle.
 */
function Pct({ v }: { v: UsagePct | null }) {
  if (!v) return <div className="cell num dim">—</div>;
  return <div className={`cell num pr-${v.pressure}`}>{v.pct}%</div>;
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
