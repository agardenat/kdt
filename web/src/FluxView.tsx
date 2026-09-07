// La vue Flux : l'arbre GitOps, son inventaire, et les leviers qui débloquent.
//
// Rien n'est jugé ici. L'arbre arrive résolu, chaque ligne porte son étiquette READY et son ton,
// et le badge `no-prune` vient d'un booléen que kdt calcule — le CSS ne fait que peindre. Ce qui
// reste au navigateur est ce qui le regarde : quels plis sont ouverts, et quelle ligne on lit.

import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import { useDismiss } from "./dismiss";
import type { Lang, Strings } from "./i18n";
import { InspectPanel, PanelToggle, Splitter, type PanelTab } from "./panel";
import { ObjectActions } from "./objects";
import { filterTree, hiddenUnder, revealed, visibleRows, type Hidden } from "./tree";
import type { FluxCounts, FluxRow, InventoryItem, ReconcileScope } from "./types";

/**
 * Les colonnes de l'arbre : mêmes colonnes, même ordre et mêmes proportions que le TUI.
 *
 * Côté Rust : RESOURCE dimensionnée sur son contenu (24 à 80 caractères), puis 10, 18, 6, et le
 * reste au message. Transposées en pistes de grille, avec la colonne RESOURCE en `fr` parce que
 * c'est elle qui porte l'indentation, et le message en second `fr` parce que c'est lui qui dit
 * pourquoi une ligne est rouge.
 */
const TREE_COLUMNS = "minmax(280px,1.3fr) 104px minmax(120px,18ch) 52px minmax(200px,1.6fr)";

/** Les colonnes de la vue à plat, celles de `flux_table_parts`. */
const LIST_COLUMNS =
  "minmax(110px,16ch) minmax(120px,20ch) minmax(160px,1fr) 104px minmax(120px,18ch) 52px minmax(200px,1.6fr)";

/** Une entrée du menu d'action, dans l'ordre et sous les mots du TUI. */
interface Action {
  scope: ReconcileScope | "suspend";
  label: string;
  desc: string;
}

export default function FluxView({
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
  const [rows, setRows] = useState<FluxRow[]>([]);
  const [counts, setCounts] = useState<FluxCounts | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [tree, setTree] = useState(true);
  // Par défaut comme dans kdt : les branches qui mènent à un problème s'ouvrent d'elles-mêmes et
  // se referment quand il est réglé. Les plis manuels ne sont pas touchés — c'est un override.
  const [autoReveal, setAutoReveal] = useState(true);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<PanelTab>("status");
  const [menuOpen, setMenuOpen] = useState(false);
  const [toast, setToast] = useState<{ tone: "ok" | "err"; text: string } | null>(null);
  // Inventaires dépliés : uid de la Kustomization → ses objets appliqués.
  const [inventory, setInventory] = useState<Record<string, InventoryItem[]>>({});

  const load = useCallback(async () => {
    try {
      const payload = await api.fluxTree();
      setRows(payload.rows);
      setCounts(payload.counts);
      // L'erreur du serveur — un kind illisible — accompagne des lignes vraies : elle s'affiche
      // à côté d'elles, pas à leur place.
      setError(payload.error);
      setLoaded(true);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else if (e instanceof ApiError) setError(e.message);
      else setError(String(e));
      setLoaded(true);
    }
  }, [onNeedsAuth]);

  useEffect(() => {
    void load();
    // La même cadence que le TUI sur la vue Flux : une réconciliation se suit à cette vitesse-là,
    // et un `list` de tous les kinds Flux ne se paie pas plus souvent.
    const timer = window.setInterval(() => void load(), 10000);
    return () => window.clearInterval(timer);
  }, [load]);

  // Le message d'une action s'efface tout seul : c'est un accusé de réception, pas un état.
  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 8000);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const needle = query.trim().toLowerCase();

  // L'ordre compte : filtrer d'abord, plier ensuite. Le filtre garde les ancêtres de ce qui
  // correspond, donc la suite reste un arbre valide, et les décomptes d'un pli portent alors sur
  // ce que ce pli cache *ici* — pas sur des lignes que le filtre avait déjà écartées.
  const filtered = useMemo(() => filterTree(rows, needle), [rows, needle]);
  const reveal = useMemo(
    () => (autoReveal ? revealed(filtered, selected) : new Set<string>()),
    [filtered, selected, autoReveal],
  );
  const shown = useMemo(
    () => (tree ? visibleRows(filtered, collapsed, reveal) : filtered),
    [tree, filtered, collapsed, reveal],
  );

  // Les lignes d'inventaire s'intercalent sous leur Kustomization, à la profondeur suivante. Ce
  // sont des lignes d'affichage : elles ne participent ni au pliage ni au filtre de l'arbre.
  const display = useMemo(() => {
    // Le décompte d'un pli se lit sur l'arbre complet, jamais sur ce qui reste à l'écran : les
    // lignes qu'il cache sont précisément celles que `visibleRows` vient de retirer.
    const indexOf = new Map(filtered.map((r, i) => [r.uid, i]));
    const out: Array<{ row: FluxRow; hidden: Hidden } | InventoryRow> = [];
    for (const row of shown) {
      const isCollapsed = tree && row.has_children && collapsed.has(row.uid) && !reveal.has(row.uid);
      const at = indexOf.get(row.uid);
      const hidden =
        isCollapsed && at !== undefined
          ? hiddenUnder(filtered, at)
          : { failed: 0, reconciling: 0 };
      out.push({ row, hidden });
      for (const item of inventory[row.uid] ?? []) {
        out.push({ item, depth: (tree ? row.depth : 0) + 1, parent: row.uid });
      }
    }
    return out;
  }, [filtered, shown, tree, collapsed, reveal, inventory]);

  const selectedRow = useMemo(() => rows.find((r) => r.uid === selected) ?? null, [rows, selected]);
  const selectedRecord = useMemo(() => {
    if (selectedRow) return selectedRow.record;
    // Une feuille d'inventaire est sélectionnable elle aussi : son enregistrement vise l'objet
    // réel, pas la Kustomization qui l'a posé.
    for (const items of Object.values(inventory)) {
      const hit = items.find((it) => it.uid === selected);
      if (hit) return hit.record;
    }
    return null;
  }, [selectedRow, inventory, selected]);

  const toggleFold = useCallback((uid: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(uid)) next.delete(uid);
      else next.add(uid);
      return next;
    });
  }, []);

  const toggleInventory = useCallback(
    async (row: FluxRow) => {
      if (inventory[row.uid]) {
        setInventory((prev) => {
          const next = { ...prev };
          delete next[row.uid];
          return next;
        });
        return;
      }
      try {
        const payload = await api.fluxInventory(row);
        if (payload.error) setToast({ tone: "err", text: payload.error });
        setInventory((prev) => ({ ...prev, [row.uid]: payload.items }));
      } catch (e) {
        if (e instanceof NeedsAuth) onNeedsAuth(e.message);
        else setToast({ tone: "err", text: String((e as Error).message ?? e) });
      }
    },
    [inventory, onNeedsAuth],
  );

  const run = useCallback(
    async (action: Action) => {
      if (!selectedRow) return;
      setMenuOpen(false);
      try {
        if (action.scope === "suspend") {
          const { suspended } = await api.fluxSuspend(selectedRow);
          setToast({
            tone: "ok",
            // La phrase dit ce qui a été écrit, pas ce qui avait été demandé : la direction se
            // décide sur l'objet vivant, et elle peut ne pas être celle que le tableau laissait
            // prévoir.
            text: `${selectedRow.kind} ${selectedRow.name} : ${suspended ? "suspend" : "resume"}`,
          });
        } else {
          const { message } = await api.fluxReconcile(selectedRow, action.scope);
          setToast({ tone: "ok", text: message });
        }
        // Relire tout de suite : une réconciliation change l'état en quelques secondes, et
        // attendre le prochain tick ferait douter que le geste soit passé.
        void load();
      } catch (e) {
        if (e instanceof NeedsAuth) onNeedsAuth(e.message);
        // Un refus n'est pas une panne : c'est l'objet qui repousse le geste, et sa phrase le dit.
        else setToast({ tone: "err", text: String((e as Error).message ?? e) });
      }
    },
    [selectedRow, load, onNeedsAuth],
  );

  const actions = useMemo(() => buildActions(selectedRow, st), [selectedRow, st]);

  // `Échap` ferme le menu avant tout le reste, et un clic à côté aussi : c'est ce qui est ouvert
  // par-dessus. La ref va sur l'ancre — bouton **et** menu — sinon le bouton refermerait puis
  // rouvrirait dans le même geste.
  const closeMenu = useCallback(() => setMenuOpen(false), []);
  const menuRef = useDismiss<HTMLDivElement>(menuOpen, closeMenu);

  return (
    <>
            {/* Le panneau reste en place tant qu'il est déplié, sélection ou pas : le faire apparaître
          avec la sélection décalait la table de 300 px à chaque clic, et on perdait la ligne qu'on
          venait de viser. */}
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
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds" role="tablist">
        <button role="tab" aria-selected={tree} onClick={() => setTree(true)}>
          {st.fluxTree}
        </button>
        <button role="tab" aria-selected={!tree} onClick={() => setTree(false)}>
          {st.fluxList}
          {counts && <span className="count">{counts.total}</span>}
        </button>

        {counts && <FluxTally counts={counts} />}

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
          {tree && (
            // Une case à cocher, et non la bascule du TUI qui nomme la direction qu'elle
            // prendrait. Cette convention-là vaut pour un pied de page qui liste des *touches* :
            // « a → suivi auto » se lit « appuyer sur a pour l'obtenir ». Un bouton posé dans une
            // barre, lui, se lit comme un état, et un libellé qui s'inverse ne dit alors plus si
            // on est dedans ou si on y va. Une case cochée dit les deux à la fois.
            <label className="opt" title={st.fluxRevealHelp}>
              <input
                type="checkbox"
                checked={autoReveal}
                onChange={(e) => setAutoReveal(e.target.checked)}
              />
              {st.fluxReveal}
            </label>
          )}
          <div className="menu-anchor" ref={menuRef}>
            <button
              className="panel-toggle action"
              disabled={!selectedRow}
              title={selectedRow ? undefined : st.fluxSelectRow}
              aria-expanded={menuOpen}
              onClick={() => setMenuOpen((v) => !v)}
            >
              {st.fluxActions} ▾
            </button>
            {menuOpen && selectedRow && (
              <ActionMenu actions={actions} row={selectedRow} st={st} onRun={run} />
            )}
          </div>
          <PanelToggle open={panelOpen} onOpen={onPanelOpen} lang={lang} />
        </div>
      </div>

      <div className="body">
        {!loaded ? (
          <div className="center" />
        ) : display.length === 0 ? (
          <div className="center">
            <div className="box">
              <h2>{needle ? st.emptyTitle : st.fluxEmpty}</h2>
              {error && <p className="err">{error}</p>}
            </div>
          </div>
        ) : (
          <div className="tbl">
            <div className="thead">
              <div
                className="tr"
                style={{ gridTemplateColumns: tree ? TREE_COLUMNS : LIST_COLUMNS }}
              >
                {tree ? (
                  <div className="cell">RESOURCE</div>
                ) : (
                  <>
                    <div className="cell">KIND</div>
                    <div className="cell">NAMESPACE</div>
                    <div className="cell">NAME</div>
                  </>
                )}
                <div className="cell">READY</div>
                <div className="cell">REVISION</div>
                <div className="cell num">AGE</div>
                <div className="cell">MESSAGE</div>
              </div>
            </div>
            <div className="tbody">
              {display.map((entry) =>
                "item" in entry ? (
                  <InventoryLine
                    key={entry.item.uid}
                    entry={entry}
                    tree={tree}
                    selected={selected === entry.item.uid}
                    onSelect={() => {
                      setSelected(entry.item.uid);
                    }}
                  />
                ) : (
                  <ResourceLine
                    key={entry.row.uid}
                    row={entry.row}
                    hidden={entry.hidden}
                    tree={tree}
                    st={st}
                    collapsed={collapsed.has(entry.row.uid) && !reveal.has(entry.row.uid)}
                    inventoryOpen={Boolean(inventory[entry.row.uid])}
                    inventoryCount={inventory[entry.row.uid]?.length ?? null}
                    selected={selected === entry.row.uid}
                    onSelect={() => {
                      setSelected(entry.row.uid);
                    }}
                    onFold={() => toggleFold(entry.row.uid)}
                    onInventory={() => void toggleInventory(entry.row)}
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
        <span title={st.fluxScopeless}>{lang === "fr" ? "tout le cluster" : "whole cluster"}</span>
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

/** Une ligne d'inventaire intercalée sous sa Kustomization. */
interface InventoryRow {
  item: InventoryItem;
  depth: number;
  parent: string;
}

/** Le décompte par état, dans la forme du titre du TUI : `✓a ✗b ↻c ?d ■e`. */
function FluxTally({ counts }: { counts: FluxCounts }) {
  // Seuls les états non nuls sont affichés, sauf `ready` : un cluster sans ressource en échec doit
  // le montrer, et une ligne de zéros ferait chercher où est passé le compteur.
  return (
    <div className="tally">
      <span className="ok" title="ready">
        ✓{counts.ready}
      </span>
      {counts.failed > 0 && (
        <span className="err" title="failed">
          ✗{counts.failed}
        </span>
      )}
      {counts.reconciling > 0 && (
        <span className="info" title="reconciling">
          ↻{counts.reconciling}
        </span>
      )}
      {counts.unknown > 0 && (
        <span className="warn" title="unknown">
          ?{counts.unknown}
        </span>
      )}
      {counts.suspended > 0 && (
        <span className="dim" title="suspended">
          ■{counts.suspended}
        </span>
      )}
    </div>
  );
}

function ResourceLine({
  row,
  hidden,
  tree,
  st,
  collapsed,
  inventoryOpen,
  inventoryCount,
  selected,
  onSelect,
  onFold,
  onInventory,
}: {
  row: FluxRow;
  hidden: { failed: number; reconciling: number };
  tree: boolean;
  st: Strings;
  collapsed: boolean;
  inventoryOpen: boolean;
  inventoryCount: number | null;
  selected: boolean;
  onSelect: () => void;
  onFold: () => void;
  onInventory: () => void;
}) {
  return (
    <div
      className={`tr flux-${row.row_tone}`}
      style={{ gridTemplateColumns: tree ? TREE_COLUMNS : LIST_COLUMNS }}
      aria-selected={selected}
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSelect();
        else if (e.key === " " && tree && row.has_children) {
          e.preventDefault();
          onFold();
        }
      }}
    >
      {tree ? (
        <div className="cell id" style={{ paddingLeft: `${row.depth * 1.15}rem` }}>
          {row.has_children ? (
            <button
              className="fold"
              title={st.fluxFold}
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
          <span className="kind">{row.kind}</span> {row.name}
          {/* L'équivalent des touches `+`/`-` du TUI. Un `⊞` seul se devine mal sur une page :
              la pastille porte le mot, et le compte une fois l'inventaire ouvert. */}
          {row.kind === "Kustomization" && (
            <button
              className="inv-pill"
              aria-expanded={inventoryOpen}
              title={st.fluxInventoryHelp}
              onClick={(e) => {
                e.stopPropagation();
                onInventory();
              }}
            >
              {inventoryOpen ? "⊟" : "⊞"} {inventoryCount ?? st.fluxInventory}
            </button>
          )}
          {/* Ce qu'un pli cache : une branche repliée qui ne dit rien de son contenu est ce qui
              transforme « où est l'erreur » en promenade dans tout l'arbre. */}
          {hidden.failed > 0 && <span className="badge err">✗{hidden.failed}</span>}
          {hidden.reconciling > 0 && <span className="badge info">↻{hidden.reconciling}</span>}
        </div>
      ) : (
        <>
          <div className="cell kind">{row.kind}</div>
          <div className="cell mono">{row.namespace}</div>
          <div className="cell id">{row.name}</div>
        </>
      )}
      <div className="cell">
        <span className={`st ${row.ready_tone}`}>{row.ready_label}</span>
      </div>
      <div className="cell mono dim" title={row.revision}>
        {row.revision}
      </div>
      <div className="cell num dim">{row.age}</div>
      <div className="cell" title={row.message}>
        {row.no_prune && (
          <span className="badge prune" title={st.fluxNoPruneTitle}>
            ⊡ {st.fluxNoPrune}
          </span>
        )}
        {row.message}
      </div>
    </div>
  );
}

function InventoryLine({
  entry,
  tree,
  selected,
  onSelect,
}: {
  entry: InventoryRow;
  tree: boolean;
  selected: boolean;
  onSelect: () => void;
}) {
  const { item, depth } = entry;
  const glyph = item.reconciling ? "↻" : item.ready === true ? "✓" : item.ready === false ? "✗" : "·";
  const nsname = item.namespace ? `${item.namespace}/${item.name}` : item.name;

  return (
    <div
      className="tr flux-inv"
      style={{ gridTemplateColumns: tree ? TREE_COLUMNS : LIST_COLUMNS }}
      aria-selected={selected}
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSelect();
      }}
    >
      <div
        className={`cell id ${item.tone}`}
        style={{ paddingLeft: `${depth * 1.15}rem`, gridColumn: tree ? undefined : "1 / 4" }}
      >
        <span className="fold-gap">{glyph}</span>
        <span className="kind">{item.kind}</span> {nsname}
      </div>
      <div className="cell">
        <span className={`st ${item.tone}`}>{item.ready_label}</span>
      </div>
      <div className="cell" />
      <div className="cell" />
      <div className="cell dim" title={item.msg}>
        {item.msg}
      </div>
    </div>
  );
}

/**
 * Le menu d'action, avec la même confirmation que dans kdt.
 *
 * Rien ici n'est destructif — une réconciliation redemande le travail, un suspend le met en pause
 * sans rien supprimer — mais tout écrit sur le cluster, et le TUI confirme pour la même raison :
 * on ne déclenche pas un déploiement d'un clic à côté. L'annulation est la sortie par défaut.
 */
function ActionMenu({
  actions,
  row,
  st,
  onRun,
}: {
  actions: Action[];
  row: FluxRow;
  st: Strings;
  onRun: (a: Action) => void;
}) {
  const [arming, setArming] = useState<Action | null>(null);

  return (
    <div className="pop menu" onClick={(e) => e.stopPropagation()}>
      <div className="pop-hd">
        <span>{st.fluxActions}</span>
      </div>
      <div className="menu-target mono">
        {row.kind} {row.namespace}/{row.name}
      </div>

      {arming ? (
        <div className="menu-confirm">
          <p>{arming.desc}</p>
          <div className="menu-buttons">
            {/* Annuler d'abord et autofocus : la sortie par défaut est celle qui n'écrit rien. */}
            <button autoFocus onClick={() => setArming(null)}>
              {st.fluxCancel}
            </button>
            <button className="cta" onClick={() => onRun(arming)}>
              {st.fluxConfirm} · {arming.label}
            </button>
          </div>
        </div>
      ) : (
        <div className="menu-list">
          {actions.map((action) => (
            <button key={action.scope} className="menu-item" onClick={() => setArming(action)}>
              <span className="lbl">{action.label}</span>
              <span className="desc">{action.desc}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * Les actions offertes sur cette ligne, dans l'ordre du menu de kdt.
 *
 * `force` et `reset` ne sont proposés que sur une HelmRelease : ce sont des leviers de
 * helm-controller, et ailleurs l'annotation serait écrite sans que personne la lise — un
 * « ✓ » sur une action que rien n'a exécutée est pire qu'une entrée absente.
 */
function buildActions(row: FluxRow | null, st: Strings): Action[] {
  if (!row) return [];
  const actions: Action[] = [
    { scope: "resource", label: st.fluxReconcile, desc: st.fluxDescReconcile },
    { scope: "with-source", label: st.fluxReconcileSrc, desc: st.fluxDescReconcileSrc },
  ];
  if (row.kind === "HelmRelease") {
    actions.push({ scope: "force", label: st.fluxForceUpgrade, desc: st.fluxDescForceUpgrade });
    actions.push({ scope: "reset", label: st.fluxResetFailures, desc: st.fluxDescResetFailures });
  }
  actions.push({ scope: "root-sync", label: st.fluxSyncRoot, desc: st.fluxDescSyncRoot });
  // La bascule nomme la direction qu'elle prendrait sur cette ligne — la lecture vient du tableau,
  // mais l'écriture, elle, décide sur l'objet vivant.
  actions.push(
    row.suspended
      ? { scope: "suspend", label: st.fluxResume, desc: st.fluxDescResume }
      : { scope: "suspend", label: st.fluxSuspend, desc: st.fluxDescSuspend },
  );
  return actions;
}
