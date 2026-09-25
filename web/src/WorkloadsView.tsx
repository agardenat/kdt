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
import { ToastLine, useToastTimeout, type Toast } from "./toast";
import { InspectPanel, PanelToggle, Splitter, ViewBody, type PanelTab } from "./panel";
import { BulkDeletePane, RowMenu, type ObjectTab } from "./objects";
import {
  RowCheckbox,
  SelectionBar,
  SelectionHead,
  TreeCheckbox,
  useMultiSelect,
  withoutSelTrack,
  type Owner,
} from "./selection";
import type { ContainerRow, EventRecord, PodRow, UsagePct, WorkloadRow } from "./types";
import { cols } from "./table";

/**
 * Les quatorze colonnes du TUI, dans le même ordre :
 * `NAMESPACE NAME READY STATUS RST CPU MEM %CPU/R %CPU/L %MEM/R %MEM/L IP NODE AGE`.
 *
 * Les quatre ratios sont le cœur de la vue et non un supplément : c'est là qu'on voit un container
 * throttlé contre sa limite ou un pod qui a réservé dix fois ce qu'il consomme. Ils restent
 * étroits — quatre chiffres et un `%` — pour laisser NAME porter l'indentation des trois niveaux.
 *
 * La table tient dans la largeur : les colonnes se taillent sur leur contenu et NAME, qui porte
 * l'indentation des trois niveaux, prend le mou. Sur un écran vraiment étroit les colonnes de
 * texte élident plutôt que de pousser la table hors champ.
 *
 * La première piste (`34px`) porte la case de sélection multiple et la dernière le hamburger de la
 * ligne, ni l'une ni l'autre mesurée sur le contenu. Groupée, la vue est un arbre et la case passe
 * dans la cellule NAME (`withoutSelTrack`) ; seule la liste des pods à plat garde sa colonne.
 */
const COLUMNS =
  "34px fit-content(16ch) minmax(28ch,1fr) 78px fit-content(13ch) 46px 62px 72px" +
  " 60px 60px 60px 60px fit-content(14ch) fit-content(16ch) 52px 34px";

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
  const [toast, setToast] = useState<Toast>(null);
  const [busy, setBusy] = useState(false);
  const [bulkOpen, setBulkOpen] = useState(false);

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

  useToastTimeout(toast, setToast);

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

  const selectedRecord = useMemo<EventRecord | null>(() => {
    for (const entry of rows) if (entry.row.uid === selected) return entry.row.record;
    return null;
  }, [rows, selected]);

  // La sélection multiple survit à un changement de filtre ou de groupement : une ligne cochée
  // puis sortie de `rows` par le filtre garde son objet, cherché ici plutôt que dans `rows`.
  //
  // Les containers en sont absents, et n'ont pas de case : un container n'est pas un objet de
  // l'API, et son `record` est celui de **son pod** (`synthetic_container_record`). Le cocher
  // reviendrait à cocher le pod sous un autre nom — supprimant le pod entier en croyant viser un
  // container, et deux fois si le pod était coché lui aussi.
  const allRecords = useMemo<{ uid: string; record: EventRecord }[]>(() => {
    const out: { uid: string; record: EventRecord }[] = [];
    for (const w of workloads) out.push({ uid: w.uid, record: w.record });
    for (const p of pods) out.push({ uid: p.uid, record: p.record });
    return out;
  }, [workloads, pods]);

  // Un pod est possédé par son workload (Deployment → ReplicaSet → Pod, résolu par kdt dans
  // `group`) : supprimer le workload l'emporte, en `Background` comme `kubectl delete`. C'est la
  // seule vue où la sélection descend d'une branche à ses feuilles, et elle le fait dans les deux
  // mondes — la possession ne dépend pas de l'affichage.
  const owners = useMemo(() => {
    const byUid = new Map(workloads.map((w) => [w.uid, w]));
    const out = new Map<string, Owner>();
    for (const p of pods) {
      const w = p.group === null ? undefined : byUid.get(p.group);
      if (w) out.set(p.uid, { key: w.uid, label: `${w.kind} ${w.name}` });
    }
    return out;
  }, [workloads, pods]);
  const {
    checked,
    shown: shownChecked,
    partial,
    coveredBy,
    toggle: toggleChecked,
    clear,
    setAll,
  } = useMultiSelect(owners);

  /** Ce que « tout sélectionner » couvre : les lignes adressables **affichées**, containers exclus. */
  const selectableKeys = useMemo(
    () => rows.filter((entry) => entry.level !== "container").map((entry) => entry.row.uid),
    [rows],
  );

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
          <SelectionBar
            keys={selectableKeys}
            checked={shownChecked}
            count={checked.size}
            onSetAll={setAll}
            onClear={clear}
            onBulkDelete={() => setBulkOpen(true)}
            st={st}
          />
          <PanelToggle open={panelOpen} onOpen={onPanelOpen} lang={lang} />
        </div>
      </div>

      <ViewBody
        tab={tab}
        record={selectedRecord}
        lang={lang}
        st={st}
        onTab={setTab}
        onNeedsAuth={onNeedsAuth}
        bulk={
          bulkOpen
            ? {
                label: st.bulkDeleteTitle,
                count: checked.size,
                node: (
                  <BulkDeletePane
                    records={allRecords.filter((r) => checked.has(r.uid)).map((r) => r.record)}
                    lang={lang}
                    st={st}
                    onCancel={() => setBulkOpen(false)}
                    onDone={(message) => {
                      setBulkOpen(false);
                      clear();
                      setToast({ tone: "ok", text: message });
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
          <div className="tbl" style={cols(grouped ? withoutSelTrack(COLUMNS) : COLUMNS)}>
            <div className="thead">
              <div className="tr">
                {!grouped && <SelectionHead />}
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
                <div className="cell act" />
              </div>
            </div>
            <div className="tbody">
              {rows.map((entry) =>
                entry.level === "workload" ? (
                  <WorkloadLine
                    key={entry.row.uid}
                    w={entry.row}
                    agg={entry.agg}
                    lang={lang}
                    st={st}
                    selected={selected === entry.row.uid}
                    onSelect={() => {
                      setSelected(entry.row.uid);
                    }}
                    onOpenTab={(t) => {
                      setSelected(entry.row.uid);
                      setTab(t);
                    }}
                    onRun={run}
                    onNeedsAuth={onNeedsAuth}
                    checked={checked.has(entry.row.uid)}
                    partial={partial.has(entry.row.uid)}
                    onToggleCheck={() => toggleChecked(entry.row.uid)}
                  />
                ) : entry.level === "pod" ? (
                  <PodLine
                    key={entry.row.uid}
                    p={entry.row}
                    st={st}
                    lang={lang}
                    tree={grouped}
                    indent={entry.indent}
                    expanded={expanded.has(entry.row.uid)}
                    selected={selected === entry.row.uid}
                    onSelect={() => {
                      setSelected(entry.row.uid);
                    }}
                    onOpenTab={(t) => {
                      setSelected(entry.row.uid);
                      setTab(t);
                    }}
                    onNeedsAuth={onNeedsAuth}
                    onToggle={() => toggle(entry.row.uid)}
                    checked={checked.has(entry.row.uid)}
                    covered={coveredBy(entry.row.uid)}
                    onToggleCheck={() => toggleChecked(entry.row.uid)}
                  />
                ) : (
                  <ContainerLine
                    key={entry.row.uid}
                    c={entry.row}
                    tree={grouped}
                    lang={lang}
                    st={st}
                    selected={selected === entry.row.uid}
                    onSelect={() => {
                      setSelected(entry.row.uid);
                    }}
                    onOpenTab={(t) => {
                      setSelected(entry.row.uid);
                      setTab(t);
                    }}
                    onNeedsAuth={onNeedsAuth}
                  />
                ),
              )}
            </div>
          </div>
        )}
      </ViewBody>

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
        <ToastLine toast={toast} onDismiss={() => setToast(null)} lang={lang} />
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
  lang,
  st,
  selected,
  onSelect,
  onOpenTab,
  onRun,
  onNeedsAuth,
  checked,
  partial,
  onToggleCheck,
}: {
  w: WorkloadRow;
  agg: Agg;
  lang: Lang;
  st: Strings;
  selected: boolean;
  onSelect: () => void;
  onOpenTab: (tab: ObjectTab) => void;
  onRun: (action: () => Promise<{ message: string }>) => void;
  onNeedsAuth: (message: string) => void;
  checked: boolean;
  partial: boolean;
  onToggleCheck: () => void;
}) {
  return (
    <div
      className="tr wl-workload"
      aria-selected={selected}
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSelect();
      }}
    >
      <div className="cell mono dim">{w.namespace}</div>
      <div className="cell id">
        {/* Pas de pli sur un workload — ses pods sont toujours listés — mais la place du pli, pour
            que sa case s'aligne sur celle d'un pod orphelin, racine comme lui. */}
        <span className="fold-gap" />
        <TreeCheckbox
          checked={checked}
          partial={partial}
          onToggle={onToggleCheck}
          label={st.selectRow}
          st={st}
        />
        <span className="kind">{w.kind}</span> {w.name}
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
      <div className="cell act">
        <RowMenu record={w.record} lang={lang} st={st} onOpen={onOpenTab} onNeedsAuth={onNeedsAuth}>
          {({ close }) => (
            <WorkloadMenu
              w={w}
              st={st}
              onRun={(action) => {
                close();
                onRun(action);
              }}
            />
          )}
        </RowMenu>
      </div>
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

  // Posé comme `children` de `RowMenu` : pas de `.pop.menu`/`.pop-hd`/`.menu-target` à lui, le
  // hamburger de ligne les porte déjà pour l'objet entier.
  return arming ? (
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
    <>
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
    </>
  );
}

function PodLine({
  p,
  lang,
  st,
  tree,
  indent,
  expanded,
  selected,
  onSelect,
  onOpenTab,
  onNeedsAuth,
  onToggle,
  checked,
  covered,
  onToggleCheck,
}: {
  p: PodRow;
  lang: Lang;
  st: Strings;
  tree: boolean;
  indent: boolean;
  expanded: boolean;
  selected: boolean;
  onSelect: () => void;
  onOpenTab: (tab: ObjectTab) => void;
  onNeedsAuth: (message: string) => void;
  onToggle: () => void;
  checked: boolean;
  covered: Owner | undefined;
  onToggleCheck: () => void;
}) {
  return (
    <div
      className={`tr wl-${p.row_tone}`}
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
      {!tree && (
        <RowCheckbox
          checked={checked}
          covered={covered}
          onToggle={onToggleCheck}
          label={st.selectRow}
          st={st}
        />
      )}
      {/* Un pod n'a pas sa propre colonne NAMESPACE — celle de son workload au-dessus suffit —
          mais la piste existe dans `COLUMNS` : sans cellule vide ici, toute la ligne se décale
          d'une colonne vers la gauche (préexistant à ce changement, remarqué en y posant la case
          à cocher). */}
      <div className="cell" />
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
        {tree && (
          <TreeCheckbox
            checked={checked}
            covered={covered}
            onToggle={onToggleCheck}
            label={st.selectRow}
            st={st}
          />
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
      <div className="cell act">
        <RowMenu record={p.record} lang={lang} st={st} onOpen={onOpenTab} onNeedsAuth={onNeedsAuth} />
      </div>
    </div>
  );
}

function ContainerLine({
  c,
  tree,
  lang,
  st,
  selected,
  onSelect,
  onOpenTab,
  onNeedsAuth,
}: {
  c: ContainerRow;
  tree: boolean;
  lang: Lang;
  st: Strings;
  selected: boolean;
  onSelect: () => void;
  onOpenTab: (tab: ObjectTab) => void;
  onNeedsAuth: (message: string) => void;
}) {
  return (
    <div
      className="tr wl-container"
      aria-selected={selected}
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSelect();
      }}
    >
      {/* Pas de case : un container n'est pas un objet à supprimer, son `record` est celui de son
          pod. Le menu, lui, reste — il nomme le pod qu'il vise dans son en-tête. */}
      {!tree && <div className="cell sel" />}
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
      <div className="cell act">
        <RowMenu record={c.record} lang={lang} st={st} onOpen={onOpenTab} onNeedsAuth={onNeedsAuth} />
      </div>
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
