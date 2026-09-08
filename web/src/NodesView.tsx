// La vue Nodes : les machines du cluster, ce qu'elles portent, et les gestes qui les sortent du jeu.
//
// Deux mondes, comme les deux écrans de `:nodes` dans le TUI :
//
// - **Nodes** — l'inventaire : qui est `Ready`, qui est cordonné, quelle condition anormale traîne.
// - **Usage** — le détail par container du node sélectionné, ce que `u` ouvre dans kdt. La table y
//   est trop large pour un panneau : elle prend le corps de la vue, et l'objet reste le node, comme
//   dans le TUI où `i` sur cet écran analyse le node et non un container.
//
// Rien n'est jugé ici. Le ton d'une ligne, la liste des alertes, les constats de dimensionnement
// d'un container, le niveau d'un constat de drain : tout arrive tout fait de `kdt`.
//
// Les trois gestes du menu `o` deviennent un menu de la barre — la convention de toutes les vues.
// Cordon et uncordon passent tout de suite ; le drain ouvre ses garde-fous dans le panneau du haut,
// comme `Ctrl-D` ouvre les siens, parce que c'est là que va tout contenu.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import { useDismiss } from "./dismiss";
import type { Lang, Strings } from "./i18n";
import { ObjectActions } from "./objects";
import { InspectPanel, PanelToggle, Splitter, type PanelTab } from "./panel";
import type {
  DrainPreflight,
  DrainProgress,
  EventRecord,
  NodeRow,
  NodeUsagePayload,
  NodeUsageRow,
  NodeUsageSort,
  UsageBucket,
  UsageRatio,
} from "./types";

/** `NAME READY ROLES VERSION AGE ALERTS`, dans l'ordre du TUI. */
const NODE_COLUMNS =
  "minmax(220px,1fr) 72px minmax(140px,20ch) minmax(110px,14ch) 64px minmax(180px,1.2fr)";

/**
 * Les treize colonnes de la table d'usage, dans l'ordre du TUI.
 *
 * Les six colonnes de quantité portent le même gabarit — `1500m`, `3.9Gi` — donc la même largeur :
 * en donner moins à « use » qu'à « req » couperait la mémoire en plein milieu.
 */
const USAGE_COLUMNS =
  "18px minmax(110px,18ch) minmax(180px,1.4fr) minmax(140px,22ch)" +
  " 78px 78px 78px 78px 78px 78px 28px 44px minmax(200px,max-content)";

type World = "nodes" | "usage";

const SORTS: NodeUsageSort[] = ["mem-req", "cpu-req", "alpha"];

export default function NodesView({
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
  const [nodes, setNodes] = useState<NodeRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [world, setWorld] = useState<World>("nodes");
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<PanelTab>("status");
  const [menuOpen, setMenuOpen] = useState(false);
  const [toast, setToast] = useState<{ tone: "ok" | "err"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  // L'usage du node sélectionné. Il ne se lit que dans son monde : c'est une liste de tous les pods
  // du node plus les métriques du cluster, et la payer pendant qu'on lit l'inventaire serait la
  // payer pour rien.
  const [usage, setUsage] = useState<NodeUsagePayload | null>(null);
  const [usageError, setUsageError] = useState<string | null>(null);
  const [sort, setSort] = useState<NodeUsageSort>("mem-req");

  // Le drain est un overlay du panneau du haut, ouvert depuis le menu : `null` tant qu'on ne l'a
  // pas demandé, et il porte le nom du node visé plutôt que de suivre la sélection — un drain
  // lancé ne doit pas changer de cible parce qu'on a cliqué ailleurs.
  const [draining, setDraining] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const payload = await api.nodes(lang);
      setNodes(payload.nodes);
      setError(null);
      setLoaded(true);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else if (e instanceof ApiError) setError(e.message);
      else setError(String(e));
      setLoaded(true);
    }
  }, [lang, onNeedsAuth]);

  useEffect(() => {
    void load();
    // Dix secondes : un node change d'état lentement, mais un cordon ou un drain doit se voir
    // arriver dans la table sans qu'on la relise à la main.
    const timer = window.setInterval(() => void load(), 10000);
    return () => window.clearInterval(timer);
  }, [load]);

  const selectedNode = useMemo(
    () => nodes.find((n) => n.uid === selected) ?? null,
    [nodes, selected],
  );
  const selectedName = selectedNode?.name ?? null;

  const loadUsage = useCallback(async () => {
    if (!selectedName) return;
    try {
      setUsage(await api.nodeUsage(selectedName, sort, lang));
      setUsageError(null);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else setUsageError(e instanceof Error ? e.message : String(e));
    }
  }, [selectedName, sort, lang, onNeedsAuth]);

  useEffect(() => {
    if (world !== "usage" || !selectedName) return;
    // Ce qui est à l'écran appartient à l'autre node : le garder ferait lire les containers de
    // l'un sous le nom de l'autre le temps de la requête.
    setUsage(null);
    setUsageError(null);
    void loadUsage();
    const timer = window.setInterval(() => void loadUsage(), 30000);
    return () => window.clearInterval(timer);
  }, [world, selectedName, loadUsage]);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 8000);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const closeMenu = useCallback(() => setMenuOpen(false), []);
  const menuRef = useDismiss<HTMLDivElement>(menuOpen, closeMenu);

  const needle = query.trim().toLowerCase();
  const shown = useMemo(
    () =>
      nodes.filter(
        (n) =>
          !needle ||
          [n.name, n.roles, n.version, n.ready, ...n.alerts]
            .join(" ")
            .toLowerCase()
            .includes(needle),
      ),
    [nodes, needle],
  );

  const usageRows = useMemo(
    () =>
      (usage?.rows ?? []).filter(
        (r) =>
          !needle ||
          [r.namespace, r.pod, r.container, ...r.issues.map((i) => i.tag)]
            .join(" ")
            .toLowerCase()
            .includes(needle),
      ),
    [usage, needle],
  );

  const selectedRecord: EventRecord | null = selectedNode?.record ?? null;

  const cordon = useCallback(
    async (unschedulable: boolean) => {
      if (!selectedName) return;
      setMenuOpen(false);
      setBusy(true);
      try {
        const { message } = await api.nodeCordon(selectedName, unschedulable, lang);
        setToast({ tone: "ok", text: message });
        void load();
      } catch (e) {
        if (e instanceof NeedsAuth) onNeedsAuth(e.message);
        else setToast({ tone: "err", text: String((e as Error).message ?? e) });
      } finally {
        setBusy(false);
      }
    },
    [selectedName, lang, load, onNeedsAuth],
  );

  const ready = nodes.filter((n) => n.ready === "True").length;
  const alerting = nodes.filter((n) => n.alerts.length > 0).length;

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
            onDeleted={() => {
              setSelected(null);
              void load();
            }}
            // Le monde Usage montre le node autrement : les cumuls sont un contenu de l'objet, pas
            // une ligne de la table, et c'est ce que le TUI met sous sa table.
            detail={
              world === "usage" && usage
                ? { label: st.ndDiagnostic, node: <Diagnostic usage={usage} st={st} /> }
                : undefined
            }
            // Le drain est un overlay, comme dans kdt : il s'ouvre, il se ferme, et son onglet
            // n'existe que tant qu'on y est.
            overlay={
              draining
                ? {
                    label: `${st.ndDrainTitle} · ${draining}`,
                    node: (
                      <DrainPane
                        key={draining}
                        node={draining}
                        lang={lang}
                        st={st}
                        onCancel={() => setDraining(null)}
                        onFinished={() => void load()}
                        onNeedsAuth={onNeedsAuth}
                      />
                    ),
                  }
                : undefined
            }
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds" role="tablist">
        <button
          role="tab"
          aria-selected={world === "nodes"}
          onClick={() => setWorld("nodes")}
        >
          {st.ndInventory}
          <span className="count">{nodes.length}</span>
        </button>
        <button
          role="tab"
          aria-selected={world === "usage"}
          disabled={!selectedNode}
          title={selectedNode ? undefined : st.ndSelectNode}
          onClick={() => setWorld("usage")}
        >
          {st.ndUsage}
          {selectedNode && <span className="count">{selectedNode.name}</span>}
        </button>

        <div className="tally">
          <span className="ok">✓{ready}</span>
          {alerting > 0 && <span className="err">✗{alerting}</span>}
        </div>

        {world === "usage" && (
          <div className="segmented" role="group" aria-label={st.ndSort}>
            {SORTS.map((s) => (
              <button key={s} aria-pressed={sort === s} onClick={() => setSort(s)}>
                {s === "mem-req"
                  ? st.ndSortMemReq
                  : s === "cpu-req"
                    ? st.ndSortCpuReq
                    : st.ndSortAlpha}
              </button>
            ))}
          </div>
        )}

        <div className="right">
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
          {busy && <span className="dim">{st.objWorking}</span>}
          {/* Les actions vivent dans la barre et portent sur la ligne sélectionnée, comme partout
              ailleurs. Ce qui est attaché à l'objet, ce sont les plis — et un node n'en a pas. */}
          <div className="menu-anchor" ref={menuRef}>
            <button
              className="panel-toggle action"
              disabled={!selectedNode}
              title={selectedNode ? undefined : st.ndSelectNode}
              aria-expanded={menuOpen}
              onClick={() => setMenuOpen((v) => !v)}
            >
              {st.ndActions} ▾
            </button>
            {menuOpen && selectedNode && (
              <NodeMenu
                node={selectedNode}
                st={st}
                onCordon={cordon}
                onDrain={() => {
                  setMenuOpen(false);
                  setDraining(selectedNode.name);
                  setTab("custom");
                  onPanelOpen(true);
                }}
              />
            )}
          </div>
          <PanelToggle open={panelOpen} onOpen={onPanelOpen} lang={lang} />
        </div>
      </div>

      {/* Sans metrics-server, la moitié des constats se tait : le dire une fois dans une bande
          vaut mieux que des tirets qu'on prend pour des zéros. */}
      {world === "usage" && usage && !usage.metrics_available && (
        <div className="sto-band warn">
          <span className="warn">⌁ {st.ndNoMetrics}</span>
        </div>
      )}

      <div className="body">
        {world === "usage" ? (
          !selectedNode ? (
            <div className="center">
              <div className="box">
                <h2>{st.ndSelectNode}</h2>
              </div>
            </div>
          ) : !usage ? (
            <div className="center">{usageError && <p className="err">{usageError}</p>}</div>
          ) : (
            <UsageTable rows={usageRows} st={st} />
          )
        ) : !loaded ? (
          <div className="center" />
        ) : shown.length === 0 ? (
          <div className="center">
            <div className="box">
              <h2>{needle ? st.emptyTitle : st.ndEmpty}</h2>
              {error && <p className="err">{error}</p>}
            </div>
          </div>
        ) : (
          <NodeTable
            rows={shown}
            selected={selected}
            onSelect={(uid) => {
              setSelected(uid);
            }}
          />
        )}
      </div>

      <div className="statusbar">
        <span>
          {world === "usage" ? usageRows.length : shown.length} {st.rows}
        </span>
        {/* Un node n'a pas de namespace : la barre le redit là où le compte pourrait surprendre. */}
        <span>
          {st.scopeLabel}: {st.scopeAll}
        </span>
        {world === "usage" && usage && (
          <span>
            {st.ndAlloc}: cpu {usage.alloc.cpu_text} · mem {usage.alloc.mem_text}
          </span>
        )}
        {error && <span className="err">{error}</span>}
        {usageError && world === "usage" && <span className="err">{usageError}</span>}
        {toast && <span className={toast.tone === "err" ? "err" : "ok"}>{toast.text}</span>}
        <span style={{ marginLeft: "auto" }}>
          <span className="kbd">/</span> {st.hintFilter} <span className="kbd">Esc</span>{" "}
          {st.hintClose}
        </span>
      </div>
    </>
  );
}

function NodeTable({
  rows,
  selected,
  onSelect,
}: {
  rows: NodeRow[];
  selected: string | null;
  onSelect: (uid: string) => void;
}) {
  return (
    <div className="tbl">
      <div className="thead">
        <div className="tr" style={{ gridTemplateColumns: NODE_COLUMNS }}>
          <div className="cell">NAME</div>
          <div className="cell">READY</div>
          <div className="cell">ROLES</div>
          <div className="cell">VERSION</div>
          <div className="cell num">AGE</div>
          <div className="cell">ALERTS</div>
        </div>
      </div>
      <div className="tbody">
        {rows.map((n) => (
          <div
            key={n.uid}
            className={`tr sev-${n.record.tone}`}
            style={{ gridTemplateColumns: NODE_COLUMNS }}
            aria-selected={selected === n.uid}
            tabIndex={0}
            onClick={() => onSelect(n.uid)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onSelect(n.uid);
            }}
          >
            <div className="cell id">{n.name}</div>
            <div className={`cell mono tone-${n.ready_tone}`}>{n.ready}</div>
            <div className="cell mono">{n.roles}</div>
            <div className="cell mono dim">{n.version}</div>
            <div className="cell num dim">{n.age}</div>
            {/* La liste vient du serveur, `Cordoned` en tête quand il y en a un : c'est le seul de
                la liste qui soit un geste, et c'est celui qu'on cherche. */}
            <div className={`cell ${n.alerts.length > 0 ? "tone-err" : "dim"}`}>
              {n.alerts.length > 0 ? n.alerts.join(", ") : "—"}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * Le menu du node sélectionné.
 *
 * Cordon et uncordon passent tout de suite : c'est un champ, c'est réversible depuis ce même menu,
 * et rien n'est détruit. Le drain ouvre ses garde-fous ailleurs — il déplace les workloads de
 * quelqu'un d'autre, et il ne se confirme pas dans un menu déroulant.
 *
 * L'entrée qui ne changerait rien n'est pas offerte : proposer « cordon » sur un node déjà cordonné
 * fait chercher pourquoi il ne se passe rien.
 */
function NodeMenu({
  node,
  st,
  onCordon,
  onDrain,
}: {
  node: NodeRow;
  st: Strings;
  onCordon: (unschedulable: boolean) => void;
  onDrain: () => void;
}) {
  return (
    <div className="pop menu" onClick={(e) => e.stopPropagation()}>
      <div className="pop-hd">
        <span>{st.ndActions}</span>
      </div>
      <div className="menu-target mono">Node {node.name}</div>
      <div className="menu-list">
        {node.schedulable ? (
          <button className="menu-item" onClick={() => onCordon(true)}>
            <span className="lbl">{st.ndCordon}</span>
            <span className="desc">{st.ndDescCordon}</span>
          </button>
        ) : (
          <button className="menu-item" onClick={() => onCordon(false)}>
            <span className="lbl">{st.ndUncordon}</span>
            <span className="desc">{st.ndDescUncordon}</span>
          </button>
        )}
        <button className="menu-item" onClick={onDrain}>
          <span className="lbl">{st.ndDrain}</span>
          <span className="desc">{st.ndDescDrain}</span>
        </button>
      </div>
    </div>
  );
}

/** Une quantité, ou `—` quand elle n'est pas connue. Un zéro se lirait comme une mesure. */
function Qty({ text, tone }: { text: string | null; tone?: string }) {
  if (text === null) return <div className="cell num dim">—</div>;
  return <div className={`cell num ${tone ? `tone-${tone}` : ""}`}>{text}</div>;
}

function UsageTable({ rows, st }: { rows: NodeUsageRow[]; st: Strings }) {
  return (
    <div className="tbl">
      <div className="thead">
        <div className="tr" style={{ gridTemplateColumns: USAGE_COLUMNS }}>
          <div className="cell" />
          <div className="cell">NS</div>
          <div className="cell">POD</div>
          <div className="cell">CONTAINER</div>
          <div className="cell num">CPU req</div>
          <div className="cell num">CPU lim</div>
          <div className="cell num">CPU use</div>
          <div className="cell num">MEM req</div>
          <div className="cell num">MEM lim</div>
          <div className="cell num">MEM use</div>
          <div className="cell num" title={st.ndReadyShort}>
            R
          </div>
          <div className="cell num">RST</div>
          <div className="cell">ISSUES</div>
        </div>
      </div>
      <div className="tbody">
        {rows.map((r) => (
          <div
            key={r.uid}
            className={`tr${r.is_system ? " nd-system" : ""}`}
            style={{ gridTemplateColumns: USAGE_COLUMNS }}
          >
            {/* Le marqueur des containers de la plateforme, comme le `·` du TUI : ils restent en
                dernier au tri, et ce point dit pourquoi. */}
            <div className="cell dim" title={r.is_system ? st.ndSystemRow : undefined}>
              {r.is_system ? "·" : ""}
            </div>
            <div className="cell mono dim">{r.namespace}</div>
            <div className="cell mono">{r.pod}</div>
            <div className="cell id">{r.container}</div>
            <Qty text={r.cpu_req_text} />
            <Qty text={r.cpu_lim_text} />
            <Qty text={r.cpu_use_text} tone={r.cpu_use_tone} />
            <Qty text={r.mem_req_text} />
            <Qty text={r.mem_lim_text} />
            <Qty text={r.mem_use_text} tone={r.mem_use_tone} />
            <div className={`cell num tone-${r.ready ? "ok" : "err"}`}>{r.ready ? "Y" : "N"}</div>
            <div className={`cell num tone-${r.restarts_tone}`}>{r.restarts}</div>
            <div className={`cell tone-${r.issues_tone}`}>
              {r.issues.map((i) => i.tag).join(",") || "—"}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * Le bloc de diagnostic du bas de la vue usage du TUI, dans le panneau du haut.
 *
 * La séparation user/système en est le cœur : un node à 90 % dont 60 % sont des DaemonSets de la
 * plateforme ne se lit pas comme un node à 90 % d'applicatif.
 */
function Diagnostic({ usage, st }: { usage: NodeUsagePayload; st: Strings }) {
  const { totals } = usage;
  return (
    <div className="detail">
      <div className="sect">
        {st.ndUsageOf} {usage.node} · {st.ndAlloc} cpu {usage.alloc.cpu_text} · mem{" "}
        {usage.alloc.mem_text}
      </div>
      <Bucket label={st.ndUser} bucket={totals.user} />
      <Bucket label={st.ndSystem} bucket={totals.system} />
      <Bucket label={st.ndTotal} bucket={totals.total} />
      <div className="keys-row">
        <div className="k-col">
          <span className="k">{st.ndWaste}</span>
        </div>
        <span className="v mono">
          <span className={totals.cpu_waste_pct > 50 ? "warn" : "dim"}>
            cpu {totals.cpu_waste_text} ({totals.cpu_waste_pct}%)
          </span>{" "}
          ·{" "}
          <span className={totals.mem_waste_pct > 50 ? "warn" : "dim"}>
            mem {totals.mem_waste_text} ({totals.mem_waste_pct}%)
          </span>
        </span>
      </div>
      {!usage.metrics_available && <p className="hint-note dim">{st.ndNoMetrics}</p>}
    </div>
  );
}

function Bucket({ label, bucket }: { label: string; bucket: UsageBucket }) {
  return (
    <div className="keys-row">
      <div className="k-col">
        <span className="k">
          {label} <span className="dim">({bucket.count})</span>
        </span>
      </div>
      <span className="v mono">
        cpu <Ratio r={bucket.cpu_req} /> · lim <Ratio r={bucket.cpu_lim} /> · use{" "}
        <Ratio r={bucket.cpu_use} />
        {"  ·  "}
        mem <Ratio r={bucket.mem_req} /> · lim <Ratio r={bucket.mem_lim} /> · use{" "}
        <Ratio r={bucket.mem_use} />
      </span>
    </div>
  );
}

/**
 * Une quantité cumulée et ce qu'elle pèse.
 *
 * Le ton se pose sous son nom nu — `ok`, `warn` — et non en `tone-ok` : ces derniers ne sont
 * définis que sur une cellule de table, et posés dans le panneau ils ne peignent rien. Une valeur
 * « sans couleur » ne se distingue alors pas d'une valeur calme, ce qui est le contraire du but.
 */
function Ratio({ r }: { r: UsageRatio }) {
  return (
    <span className={r.tone}>
      {r.text} ({r.pct}%)
    </span>
  );
}

/**
 * Le panneau de drain : les garde-fous, la confirmation, puis l'avancement.
 *
 * Trois règles reprises de kdt, et une transposée :
 *
 * - **aucun constat ne bloque** — ils décident de ce que la confirmation coûte, pas de ce qui est
 *   permis ;
 * - **un constat grave, ou une vérification qui n'a pas conclu, exige de retaper le nom** — et le
 *   serveur le revérifie, en rejouant les garde-fous juste avant d'évincer ;
 * - **la sortie par défaut ne draine rien** : c'est le bouton d'annulation qui a le focus, et le
 *   bouton qui draine est une cible séparée, à distance ;
 * - la transposition : le TUI arme puis confirme avec deux touches faute de mieux. Ici les deux
 *   issues sont deux boutons visibles côte à côte.
 *
 * Le drain est lu en flux parce qu'il dure : chaque pod qu'un budget retient est réessayé pendant
 * deux minutes, et c'est exactement ce qu'on reste regarder.
 */
function DrainPane({
  node,
  lang,
  st,
  onCancel,
  onFinished,
  onNeedsAuth,
}: {
  node: string;
  lang: Lang;
  st: Strings;
  onCancel: () => void;
  onFinished: () => void;
  onNeedsAuth: (message: string) => void;
}) {
  const [preflight, setPreflight] = useState<DrainPreflight | null>(null);
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<DrainProgress | null>(null);
  const [done, setDone] = useState<{ ok: boolean; message: string } | null>(null);
  const abort = useRef<AbortController | null>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const progressRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    setPreflight(null);
    setError(null);
    setTyped("");
    try {
      setPreflight(await api.nodeDrainPreflight(node, lang));
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else setError(String((e as Error).message ?? e));
    }
  }, [node, lang, onNeedsAuth]);

  useEffect(() => {
    void load();
  }, [load]);

  // La sortie qui ne draine rien prend le focus, mais **sans faire défiler** : le panneau est
  // scrollable, ce bouton est en bas, et un `autoFocus` ordinaire pousse hors de l'écran les
  // constats qu'on ouvre justement le panneau pour lire.
  useEffect(() => {
    if (preflight) cancelRef.current?.focus({ preventScroll: true });
  }, [preflight]);

  // Pendant qu'il tourne, ce qu'on est resté regarder est l'avancement — et il s'écrit sous des
  // constats qui remplissent déjà le panneau. Il se ramène donc sous les yeux à chaque morceau,
  // tant que ça bouge : c'est la version web de l'ancrage en bas du panneau de kdt.
  useEffect(() => {
    if (running) progressRef.current?.scrollIntoView({ block: "nearest" });
  }, [progress, done, running]);

  // Fermer l'overlay pendant que le drain tourne coupe le flux, pas le drain : les évictions déjà
  // envoyées sont à l'apiserver. C'est le comportement du TUI, où quitter le panneau ne rappelle
  // rien non plus.
  useEffect(() => () => abort.current?.abort(), []);

  const run = useCallback(async () => {
    setRunning(true);
    setError(null);
    setDone(null);
    const controller = new AbortController();
    abort.current = controller;
    try {
      await api.nodeDrain({ node, confirm: typed.trim(), lang }, (event) => {
        if (event.type === "progress") setProgress(event.data);
        else if (event.type === "done") setDone({ ok: event.data.ok, message: event.data.message });
      }, controller.signal);
      onFinished();
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else if ((e as Error).name !== "AbortError") setError(String((e as Error).message ?? e));
    } finally {
      setRunning(false);
    }
  }, [node, typed, lang, onFinished, onNeedsAuth]);

  if (error && !preflight) return <p className="pane-err">{error}</p>;
  if (!preflight) return <p className="pane-wait">{st.ndDrainChecking}</p>;

  const strict = preflight.strict;
  const matches = typed.trim() === node;

  return (
    <div className="editor">
      <div className="guards">
        <div className="sect">{st.ndDrainTarget}</div>
        <p className="mono">Node {node}</p>
      </div>

      <div className="guards">
        {/* Une vérification qui n'a pas pu conclure n'est pas un feu vert : elle se dit, et elle
            fait passer la confirmation en mode strict. */}
        {preflight.error && <p className="guard danger">{preflight.error}</p>}
        <p className="guard info">
          {preflight.plan}
          {preflight.skipped_label && ` · ${preflight.skipped_label}`}
        </p>
        {preflight.reasons.length === 0 && !preflight.error ? (
          <p className="guard ok">{preflight.no_finding}</p>
        ) : (
          preflight.reasons.map((r) => (
            <p key={`${r.kind}-${r.text}`} className={`guard ${r.level}`}>
              <span className="gl">
                {r.level === "danger" ? "✗" : r.level === "warn" ? "▲" : "·"}
              </span>{" "}
              {r.text}
            </p>
          ))
        )}
        {preflight.reasons.length > 0 && <p className="dim">{st.ndDrainHelp}</p>}
      </div>

      {progress && (
        <div className="guards" ref={progressRef}>
          <p className="guard info">
            {st.ndDrainEvicted}: {progress.evicted.length}/{progress.to_evict}
          </p>
          {progress.waiting.length > 0 && (
            <p className="guard warn">
              {st.ndDrainWaiting}: <span className="mono">{progress.waiting.join(", ")}</span>
            </p>
          )}
          {progress.failed.map((f) => (
            <p key={f.pod} className="guard danger">
              {st.ndDrainFailed}: <span className="mono">{f.pod}</span> — {f.error}
            </p>
          ))}
        </div>
      )}

      {error && <p className="pane-err">{error}</p>}

      {done ? (
        <p className={done.ok ? "ok" : "err"}>{done.message}</p>
      ) : (
        <div className="delete-confirm">
          {strict && (
            <>
              <p className="warn">{st.ndDrainStrictHelp}</p>
              <input
                className="ns-add"
                value={typed}
                spellCheck={false}
                autoComplete="off"
                disabled={running}
                placeholder={st.ndDrainStrictPlaceholder}
                onChange={(e) => setTyped(e.target.value)}
              />
              {typed.trim() !== "" && !matches && (
                <p className="err">{st.ndDrainStrictMismatch.replace("{name}", node)}</p>
              )}
            </>
          )}
          <div className="menu-buttons">
            {/* La sortie par défaut est celle qui ne draine rien : c'est elle qui a le focus. */}
            <button ref={cancelRef} onClick={onCancel}>
              {st.ndDrainCancel}
            </button>
            <button className="panel-toggle" disabled={running} onClick={() => void load()}>
              {st.ndDrainReload}
            </button>
            <button
              className="cta danger"
              disabled={running || (strict && !matches)}
              onClick={() => void run()}
            >
              {st.ndDrainConfirm}
            </button>
          </div>
          {running && <span className="dim">{st.ndDrainRunning}</span>}
        </div>
      )}
    </div>
  );
}
