// La vue stockage : PVC, PV et StorageClass, snapshots et attachements CSI — et surtout ce qui ne
// va pas avec eux.
//
// Ce que cette vue apporte n'est pas la liste des volumes, `kubectl get pvc` la donne, mais ce qui
// coûte une après-midi : une claim qui ne se liera jamais et pourquoi, un PV qui tient encore la
// donnée d'une claim disparue, un `reclaimPolicy: Delete` sur ce que personne ne veut perdre, un
// cluster sans classe par défaut — ou avec deux.
//
// Rien n'est jugé ici. Les constats, le ton d'une phase, les octets qui dorment en `Released`
// arrivent tout faits de `kdt::storage`.
//
// # Quatre mondes, quatre formes
//
// Le TUI donne une seule forme de table aux quatre mondes et laisse des colonnes vides. Ici chaque
// monde a la sienne : sur les claims, `KIND` répéterait « PVC » sur chaque ligne et `RECLAIM` serait
// vide partout — deux colonnes qui volent la largeur à celles qui distinguent. Le volume lié, que le
// TUI met dans le panneau, prend leur place.

import { Fragment, useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import type { Lang, Strings } from "./i18n";
import { BulkDeletePane, RowMenu, type ObjectTab } from "./objects";
import {
  RowCheckbox,
  SelectionBar,
  SelectionHead,
  TreeCheckbox,
  useMultiSelect,
} from "./selection";
import { InspectPanel, PanelToggle, Splitter, ViewBody, type PanelTab } from "./panel";
import type {
  EventRecord,
  Hint,
  PvRow,
  PvcRow,
  ScRow,
  StoragePayload,
  StorageRow,
  VaNodeRow,
  VaRow,
  VsClassRow,
  VscRow,
  VsRow,
} from "./types";
import { cols } from "./table";

/** `NAMESPACE NAME PHASE SIZE ACCESS CLASS VOLUME USED BY AGE`. La première piste (`34px`) porte
 * la case de sélection multiple, la dernière le hamburger de la ligne. */
const CLAIM_COLUMNS =
  "34px fit-content(18ch) fit-content(26ch) 84px 72px 72px fit-content(22ch)" +
  " fit-content(32ch) minmax(20ch,1fr) 52px 34px";

/** `NAME KIND PHASE SIZE ACCESS RECLAIM CLAIM / PROVISIONER AGE`. Les volumes se rangent sous leur
 * StorageClass : c'est un arbre, et la case suit l'indentation dans NAME au lieu d'avoir sa piste.
 * Pas de cascade — une StorageClass ne possède pas les PV qu'elle a provisionnés. */
const VOLUME_COLUMNS =
  "fit-content(30ch) fit-content(6ch) 84px 72px 72px 76px minmax(26ch,1fr) 52px 34px";

/** `NAME NAMESPACE KIND READY SIZE CLASS POLICY SOURCE AGE`. Un arbre à trois étages : la
 * classe, ses snapshots, le contenu lié à chacun. Comme pour les volumes, la case suit
 * l'indentation et ne cascade pas — une classe ne possède pas les snapshots pris avec elle. */
const SNAPSHOT_COLUMNS =
  "fit-content(40ch) fit-content(18ch) fit-content(8ch) 84px 72px fit-content(20ch) 76px" +
  " minmax(24ch,1fr) 52px 34px";

/** `NAME KIND PHASE ATTACHED PV / SLOTS AGE`. Les attachements se rangent sous leur nœud, dont
 * l'en-tête porte les emplacements d'attachement comptés contre la limite du CSINode. */
const ATTACH_COLUMNS =
  "fit-content(44ch) fit-content(6ch) 84px 76px minmax(30ch,1fr) 52px 34px";

type World = "claims" | "volumes" | "snapshots" | "attachments";

/** Un groupe du monde des snapshots : une classe (ou le seau « classe absente ») et ses snapshots,
 * chacun avec son contenu lié quand il est listé. */
interface SnapGroup {
  sc: VsClassRow | null;
  snapshots: Array<{ vs: VsRow; content: VscRow | null }>;
}

/** Un nœud et ses attachements. */
interface AttachGroup {
  node: VaNodeRow;
  items: VaRow[];
}
type Filter = "all" | "problems";

/** Un constat au-delà de l'information mérite un regard ; un `info` est du contexte. */
const worse = (hints: Hint[]) => hints.some((h) => h.level !== "info");

export default function StorageView({
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
  const [payload, setPayload] = useState<StoragePayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [world, setWorld] = useState<World>("claims");
  const [filter, setFilter] = useState<Filter>("all");
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<PanelTab>("detail");
  const { checked, toggle: toggleChecked, clear, setAll } = useMultiSelect();
  const [bulkOpen, setBulkOpen] = useState(false);
  // Les classes **repliées**, et non les dépliées : le monde Volumes existe pour montrer les
  // volumes, et l'ouvrir sur trois classes fermées n'en montrerait aucun. C'est le parti de
  // l'arbre Flux — déplié, parce que le pliage est un état de qui regarde, pas du cluster. Le pli
  // vit sur l'objet, pas dans une touche globale : le choix ne vaut que pour la classe qu'on ferme.
  const [folded, setFolded] = useState<Set<string>>(new Set());

  const scope = namespaces[0] ?? "";

  const load = useCallback(async () => {
    try {
      setPayload(await api.storage(scope, lang));
      setError(null);
      setLoaded(true);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else if (e instanceof ApiError) setError(e.message);
      else setError(String(e));
      setLoaded(true);
    }
  }, [scope, lang, onNeedsAuth]);

  useEffect(() => {
    void load();
    // Un volume ne se lie pas à la seconde, mais une claim Pending finit par se lier : trente
    // secondes suffisent à voir la bascule sans marteler l'apiserver.
    const timer = window.setInterval(() => void load(), 30000);
    return () => window.clearInterval(timer);
  }, [load]);

  const needle = query.trim().toLowerCase();
  const keep = useCallback(
    (hints: Hint[], haystack: string[]) => {
      if (filter === "problems" && !worse(hints)) return false;
      if (!needle) return true;
      return haystack.join(" ").toLowerCase().includes(needle);
    },
    [filter, needle],
  );

  const claims = useMemo(
    () =>
      (payload?.pvcs ?? []).filter((c) =>
        keep(c.hints, [
          c.namespace,
          c.name,
          c.phase,
          c.size,
          c.access_modes,
          c.storage_class ?? "",
          c.volume_name ?? "",
          c.mounted_by.join(" "),
        ]),
      ),
    [payload, keep],
  );

  // Les volumes rangés sous leur classe. Le rattachement est un champ — `storageClass` — pas une
  // règle : le regroupement se fait donc ici, et rien n'est déduit.
  const volumeGroups = useMemo(() => {
    const classes = payload?.classes ?? [];
    const volumes = payload?.pvs ?? [];
    const groups = classes.map((sc) => ({
      sc,
      volumes: volumes.filter((v) => v.storage_class === sc.name),
    }));
    // Les volumes dont la classe n'existe pas (ou plus) ne disparaissent pas : ils sont justement
    // ceux qu'on cherche quand une claim ne se lie pas.
    const named = new Set(classes.map((c) => c.name));
    const orphans = volumes.filter((v) => !named.has(v.storage_class));
    return { groups, orphans };
  }, [payload]);

  const visibleVolumes = useMemo(() => {
    const rows: Array<{ sc: ScRow | null; volumes: PvRow[] }> = [];
    const keepVolume = (v: PvRow) =>
      keep(v.hints, [
        v.name,
        v.phase,
        v.capacity,
        v.access_modes,
        v.reclaim_policy,
        v.storage_class,
        v.claim ?? "",
        v.source,
      ]);
    for (const g of volumeGroups.groups) {
      const volumes = g.volumes.filter(keepVolume);
      // Une classe reste visible si elle-même passe le tamis : « quelle est ma classe par défaut »
      // est une question qu'on pose même quand aucun volume ne correspond au filtre.
      const scKept = keep(g.sc.hints, [g.sc.name, g.sc.provisioner, g.sc.binding_mode]);
      if (volumes.length > 0 || scKept) rows.push({ sc: g.sc, volumes });
    }
    const orphans = volumeGroups.orphans.filter(keepVolume);
    if (orphans.length > 0) rows.push({ sc: null, volumes: orphans });
    return rows;
  }, [volumeGroups, keep]);

  // Les snapshots rangés sous leur classe, chacun suivi de son contenu. Ce qui ne se rattache à
  // rien a son propre seau, en fin de liste : les snapshots dont la classe est absente, puis les
  // contenus qu'aucun snapshot listé ne désigne — ceux que le fournisseur facture encore.
  const snapshotWorld = useMemo(() => {
    const classes = payload?.snap_classes ?? [];
    const contents = payload?.contents ?? [];
    const contentOf = (vs: VsRow) => contents.find((c) => c.name === vs.content) ?? null;
    const rows = (payload?.snapshots ?? []).map((vs) => ({ vs, content: contentOf(vs) }));
    const named = new Set(classes.map((c) => c.name));
    const groups: SnapGroup[] = classes.map((sc) => ({
      sc,
      snapshots: rows.filter((r) => r.vs.class === sc.name),
    }));
    const unclassed = rows.filter((r) => !r.vs.class || !named.has(r.vs.class));
    if (unclassed.length > 0) groups.push({ sc: null, snapshots: unclassed });
    const referenced = new Set((payload?.snapshots ?? []).map((v) => v.content).filter(Boolean));
    const loose = contents.filter((c) => !referenced.has(c.name));
    return { groups, loose };
  }, [payload]);

  const visibleSnapshots = useMemo(() => {
    const keepVs = (vs: VsRow) =>
      keep(vs.hints, [vs.namespace, vs.name, vs.phase, vs.class ?? "", vs.source_pvc ?? ""]);
    const keepVsc = (c: VscRow) =>
      keep(c.hints, [c.name, c.phase, c.driver, c.deletion_policy, c.snapshot ?? "", c.handle]);
    const groups: SnapGroup[] = [];
    for (const g of snapshotWorld.groups) {
      // Un snapshot reste si lui ou son contenu passe le tamis : un contenu trouvé sans le
      // snapshot au-dessus serait lu sans ce qui le rend lisible.
      const snapshots = g.snapshots.filter(
        (r) => keepVs(r.vs) || (r.content !== null && keepVsc(r.content)),
      );
      const scKept = g.sc ? keep(g.sc.hints, [g.sc.name, g.sc.driver, g.sc.deletion_policy]) : false;
      if (snapshots.length > 0 || scKept) groups.push({ sc: g.sc, snapshots });
    }
    return { groups, loose: snapshotWorld.loose.filter(keepVsc) };
  }, [snapshotWorld, keep]);

  const visibleAttachments = useMemo(() => {
    const out: AttachGroup[] = [];
    for (const node of payload?.attach_nodes ?? []) {
      const items = (payload?.attachments ?? [])
        .filter((a) => a.node === node.node)
        .filter((a) => keep(a.hints, [a.name, a.phase, a.pv, a.attacher, a.node]));
      if (items.length > 0 || keep(node.hints, [node.node, node.slots_label])) out.push({ node, items });
    }
    return out;
  }, [payload, keep]);

  // Les lignes adressables du monde affiché : les claims, ou les classes (le seau « sans classe »
  // n'est pas un objet) et leurs volumes, repliés ou non — « tout sélectionner » porte sur ce qui
  // est listé, pas seulement sur ce qui est déplié à l'écran.
  const selectableKeys = useMemo(
    () =>
      world === "claims"
        ? claims.map((c) => c.uid)
        : world === "volumes"
          ? visibleVolumes.flatMap((g) => [
              ...(g.sc ? [g.sc.uid] : []),
              ...g.volumes.map((v) => v.uid),
            ])
          : world === "snapshots"
            ? [
                ...visibleSnapshots.groups.flatMap((g) => [
                  ...(g.sc ? [g.sc.uid] : []),
                  ...g.snapshots.flatMap((r) => [r.vs.uid, ...(r.content ? [r.content.uid] : [])]),
                ]),
                ...visibleSnapshots.loose.map((c) => c.uid),
              ]
            : visibleAttachments.flatMap((g) => g.items.map((a) => a.uid)),
    [world, claims, visibleVolumes, visibleSnapshots, visibleAttachments],
  );

  const shownCount =
    world === "claims"
      ? claims.length
      : world === "volumes"
        ? visibleVolumes.reduce((n, g) => n + g.volumes.length + (g.sc ? 1 : 0), 0)
        : world === "snapshots"
          ? visibleSnapshots.groups.reduce(
              (n, g) =>
                n + (g.sc ? 1 : 0) + g.snapshots.reduce((m, r) => m + 1 + (r.content ? 1 : 0), 0),
              0,
            ) + visibleSnapshots.loose.length
          : visibleAttachments.reduce((n, g) => n + 1 + g.items.length, 0);

  const allRows: StorageRow[] = useMemo(
    () => [
      ...(payload?.pvcs ?? []),
      ...(payload?.pvs ?? []),
      ...(payload?.classes ?? []),
      ...(payload?.snap_classes ?? []),
      ...(payload?.snapshots ?? []),
      ...(payload?.contents ?? []),
      ...(payload?.attachments ?? []),
      ...(payload?.attach_nodes ?? []),
    ],
    [payload],
  );
  const selectedRow = allRows.find((r) => r.uid === selected) ?? null;
  const selectedRecord: EventRecord | null = selectedRow?.record ?? null;

  const select = (uid: string) => {
    setSelected(uid);
    setTab("detail");
  };

  const toggle = (uid: string) =>
    setFolded((prev) => {
      const next = new Set(prev);
      if (next.has(uid)) next.delete(uid);
      else next.add(uid);
      return next;
    });

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
            detail={
              selectedRow
                ? { label: st.tabDetail, node: <RowDetail row={selectedRow} st={st} /> }
                : undefined
            }
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds" role="tablist">
        {(
          [
            ["claims", "Claims", payload?.pvcs.length],
            ["volumes", "Volumes", payload?.pvs.length],
            ["snapshots", "Snapshots", payload?.snapshots.length],
            ["attachments", "Attachments", payload?.attachments.length],
          ] as const
        ).map(([id, label, n]) => (
          <button
            key={id}
            role="tab"
            aria-selected={world === id}
            onClick={() => {
              setWorld(id);
              setSelected(null);
              clear();
            }}
          >
            {label}
            {n !== undefined && <span className="count">{n}</span>}
          </button>
        ))}

        <div className="segmented" role="group">
          {(["all", "problems"] as const).map((f) => (
            <button key={f} aria-pressed={filter === f} onClick={() => setFilter(f)}>
              {f === "all" ? st.filterAll : st.filterProblems}
            </button>
          ))}
        </div>

        {payload && payload.classes.length > 0 && (
          <div className="tally">
            <span className="info">{payload.classes.length} class</span>
          </div>
        )}

        <div className="right">
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

      {/* Ce qui appartient au cluster et à aucune ligne : pas de classe par défaut, deux classes
          par défaut, et les octets que plus personne ne peut atteindre. */}
      {payload && (payload.cluster_hints.length > 0 || payload.released_bytes > 0) && (
        <ClusterBand payload={payload} st={st} />
      )}

      <ViewBody
        tab={tab}
        record={selectedRecord}
        lang={lang}
        st={st}
        onTab={setTab}
        onNeedsAuth={onNeedsAuth}
        hasDetail={Boolean(selectedRow)}
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
                    records={allRows.filter((r) => checked.has(r.uid)).map((r) => r.record)}
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
        ) : shownCount === 0 ? (
          <div className="center">
            <div className="box">
              <h2>
                {world === "snapshots" && payload && !payload.snapshots_installed
                  ? st.stoNoSnapshotCrd
                  : st.stoEmpty}
              </h2>
              {error && <p className="err">{error}</p>}
              <p>
                {st.emptyScope} <code>{scope || st.scopeAll}</code>
              </p>
            </div>
          </div>
        ) : world === "claims" ? (
          <ClaimTable
            rows={claims}
            selected={selected}
            lang={lang}
            st={st}
            onSelect={select}
            onOpenTab={(uid, t) => {
              setSelected(uid);
              setTab(t);
            }}
            onNeedsAuth={onNeedsAuth}
            checked={checked}
            onToggleCheck={toggleChecked}
          />
        ) : world === "snapshots" ? (
          <SnapshotTable
            groups={visibleSnapshots.groups}
            loose={visibleSnapshots.loose}
            folded={folded}
            selected={selected}
            lang={lang}
            st={st}
            onSelect={select}
            onOpenTab={(uid, t) => {
              setSelected(uid);
              setTab(t);
            }}
            onNeedsAuth={onNeedsAuth}
            onToggle={toggle}
            checked={checked}
            onToggleCheck={toggleChecked}
          />
        ) : world === "attachments" ? (
          <AttachTable
            groups={visibleAttachments}
            folded={folded}
            selected={selected}
            lang={lang}
            st={st}
            onSelect={select}
            onOpenTab={(uid, t) => {
              setSelected(uid);
              setTab(t);
            }}
            onNeedsAuth={onNeedsAuth}
            onToggle={toggle}
            checked={checked}
            onToggleCheck={toggleChecked}
          />
        ) : (
          <VolumeTable
            groups={visibleVolumes}
            folded={folded}
            selected={selected}
            lang={lang}
            st={st}
            onSelect={select}
            onOpenTab={(uid, t) => {
              setSelected(uid);
              setTab(t);
            }}
            onNeedsAuth={onNeedsAuth}
            onToggle={toggle}
            checked={checked}
            onToggleCheck={toggleChecked}
          />
        )}
      </ViewBody>

      <div className="statusbar">
        <span>
          {shownCount} {st.rows}
        </span>
        <span>
          {st.scopeLabel}: {scope || st.scopeAll}
        </span>
        {/* Un refus sur les pods change ce que la vue peut affirmer : elle le dit plutôt que de
            laisser lire « rien ne monte cette claim » là où la vérité est « je n'ai pas pu voir ». */}
        {payload && !payload.mounts_known && <span className="warn">{st.stoMountsUnknown}</span>}
        {error && <span className="err">{error}</span>}
      </div>
    </>
  );
}

function ClusterBand({ payload, st }: { payload: StoragePayload; st: Strings }) {
  const worstLevel = payload.cluster_hints.some((h) => h.level === "danger")
    ? "danger"
    : payload.cluster_hints.some((h) => h.level === "warn")
      ? "warn"
      : "info";
  return (
    <div className={`sto-band ${worstLevel}`}>
      {payload.released_bytes > 0 && (
        <span className="waste">{st.stoReleased.replace("{size}", payload.released_text)}</span>
      )}
      {payload.cluster_hints.map((h) => (
        <span key={h.text} className={h.level}>
          {h.level === "danger" ? "✗" : h.level === "warn" ? "▲" : "·"} {h.text}
        </span>
      ))}
    </div>
  );
}

interface WorldTableProps {
  lang: Lang;
  st: Strings;
  onOpenTab: (uid: string, tab: ObjectTab) => void;
  onNeedsAuth: (message: string) => void;
  checked: Set<string>;
  onToggleCheck: (key: string) => void;
}

function ClaimTable({
  rows,
  selected,
  lang,
  st,
  onSelect,
  onOpenTab,
  onNeedsAuth,
  checked,
  onToggleCheck,
}: {
  rows: PvcRow[];
  selected: string | null;
  onSelect: (uid: string) => void;
} & WorldTableProps) {
  return (
    <div className="tbl" style={cols(CLAIM_COLUMNS)}>
      <div className="thead">
        <div className="tr">
          <SelectionHead />
          <div className="cell">NAMESPACE</div>
          <div className="cell">NAME</div>
          <div className="cell">PHASE</div>
          <div className="cell num">SIZE</div>
          <div className="cell">ACCESS</div>
          <div className="cell">CLASS</div>
          <div className="cell">VOLUME</div>
          <div className="cell">USED BY</div>
          <div className="cell num">AGE</div>
          <div className="cell act" />
        </div>
      </div>
      <div className="tbody">
        {rows.map((c) => (
          <div
            key={c.uid}
            className={`tr sev-${c.record.tone}`}
            aria-selected={selected === c.uid}
            tabIndex={0}
            onClick={() => onSelect(c.uid)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onSelect(c.uid);
            }}
          >
            <RowCheckbox
              checked={checked.has(c.uid)}
              onToggle={() => onToggleCheck(c.uid)}
              label={st.selectRow}
            />
            <div className="cell mono dim">{c.namespace}</div>
            <div className="cell id">{c.name}</div>
            <div className={`cell ${c.phase_tone}`}>{c.phase}</div>
            <div className="cell num">{c.size || "—"}</div>
            <div className="cell dim">{c.access_modes}</div>
            <div className="cell mono dim">{c.storage_class ?? "—"}</div>
            <div className="cell mono dim">{c.volume_name ?? "—"}</div>
            <div className={`cell wrap ${c.mounted_by.length === 0 ? "dim" : ""}`}>
              {c.mounted_by.length === 0
                ? "—"
                : c.mounted_by.length === 1
                  ? c.mounted_by[0]
                  : `${c.mounted_by[0]} (${c.mounted_by.length})`}
            </div>
            <div className="cell num dim">{c.age}</div>
            <div className="cell act">
              <RowMenu
                record={c.record}
                lang={lang}
                st={st}
                onOpen={(t) => onOpenTab(c.uid, t)}
                onNeedsAuth={onNeedsAuth}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function VolumeTable({
  groups,
  folded: foldedSet,
  selected,
  lang,
  st,
  onSelect,
  onOpenTab,
  onNeedsAuth,
  onToggle,
  checked,
  onToggleCheck,
}: {
  groups: Array<{ sc: ScRow | null; volumes: PvRow[] }>;
  folded: Set<string>;
  selected: string | null;
  onSelect: (uid: string) => void;
  onToggle: (uid: string) => void;
} & WorldTableProps) {
  return (
    <div className="tbl" style={cols(VOLUME_COLUMNS)}>
      <div className="thead">
        <div className="tr">
          <div className="cell">NAME</div>
          <div className="cell">KIND</div>
          <div className="cell">PHASE</div>
          <div className="cell num">SIZE</div>
          <div className="cell">ACCESS</div>
          <div className="cell">RECLAIM</div>
          <div className="cell">CLAIM / PROVISIONER</div>
          <div className="cell num">AGE</div>
          <div className="cell act" />
        </div>
      </div>
      <div className="tbody">
        {groups.map((g) => {
          // Les orphelins n'ont pas de classe à replier : ils s'affichent toujours, parce qu'ils
          // sont précisément ce qu'on cherche quand une claim ne se lie pas.
          const key = g.sc ? g.sc.uid : "sto|orphans";
          const folded = g.sc ? foldedSet.has(key) : false;
          return (
            <div className="grp" key={key}>
              {g.sc ? (
                <div
                  className={`tr sto-class sev-${g.sc.record.tone}`}
                  aria-selected={selected === g.sc.uid}
                  tabIndex={0}
                  onClick={() => onSelect(g.sc!.uid)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") onSelect(g.sc!.uid);
                  }}
                >
                  <div className="cell id">
                    <button
                      className="fold"
                      aria-expanded={!folded}
                      disabled={g.volumes.length === 0}
                      onClick={(e) => {
                        e.stopPropagation();
                        onToggle(key);
                      }}
                    >
                      {g.volumes.length === 0 ? "·" : folded ? "▸" : "▾"}
                    </button>
                    <TreeCheckbox
                      checked={checked.has(g.sc.uid)}
                      onToggle={() => onToggleCheck(g.sc!.uid)}
                      label={st.selectRow}
                      st={st}
                    />
                    {g.sc.name}
                    {g.sc.is_default && <span className="badge-default">{st.stoDefault}</span>}
                    {/* Combien de volumes elle provisionne, à côté d'elle : la colonne SIZE mesure
                        des octets, y poser un compte le ferait lire comme une taille. */}
                    <span className="grp-count">{g.volumes.length}</span>
                  </div>
                  <div className="cell mono dim">SC</div>
                  <div className="cell dim">—</div>
                  <div className="cell num dim">—</div>
                  <div className="cell dim">—</div>
                  <div className="cell dim">{g.sc.reclaim_policy}</div>
                  <div className="cell mono dim">
                    {g.sc.provisioner} · {g.sc.binding_mode}
                  </div>
                  <div className="cell num dim">{g.sc.age}</div>
                  <div className="cell act">
                    <RowMenu
                      record={g.sc.record}
                      lang={lang}
                      st={st}
                      onOpen={(t) => onOpenTab(g.sc!.uid, t)}
                      onNeedsAuth={onNeedsAuth}
                    />
                  </div>
                </div>
              ) : (
                <div className="tr sto-class">
                  <div className="cell id dim">
                    <span className="fold-gap">·</span>
                    <TreeCheckbox checked={false} label={st.selectRow} st={st} />
                    {st.stoNoClass}
                    <span className="grp-count">{g.volumes.length}</span>
                  </div>
                  <div className="cell mono dim" />
                  <div className="cell" />
                  <div className="cell num dim">—</div>
                  <div className="cell" />
                  <div className="cell" />
                  <div className="cell" />
                  <div className="cell" />
                  <div className="cell act" />
                </div>
              )}
              {!folded &&
                g.volumes.map((v) => (
                  <div
                    key={v.uid}
                    className={`tr sto-volume sev-${v.record.tone}`}
                    aria-selected={selected === v.uid}
                    tabIndex={0}
                    onClick={() => onSelect(v.uid)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") onSelect(v.uid);
                    }}
                  >
                    <div className="cell id nested">
                      <span className="fold-gap" />
                      <TreeCheckbox
                        checked={checked.has(v.uid)}
                        onToggle={() => onToggleCheck(v.uid)}
                        label={st.selectRow}
                        st={st}
                      />
                      {v.name}
                    </div>
                    <div className="cell mono dim">PV</div>
                    <div className={`cell ${v.phase_tone}`}>{v.phase}</div>
                    <div className="cell num">{v.capacity}</div>
                    <div className="cell dim">{v.access_modes}</div>
                    {/* `Delete` est la seule politique qui perde la donnée sur un `kubectl delete
                        pvc` : c'est la seule que la table signale. */}
                    <div
                      className={`cell ${v.reclaim_deletes ? "warn" : "dim"}`}
                      title={v.reclaim_deletes ? st.stoDeletes : undefined}
                    >
                      {v.reclaim_policy}
                    </div>
                    <div className="cell mono dim">{v.claim ?? "—"}</div>
                    <div className="cell num dim">{v.age}</div>
                    <div className="cell act">
                      <RowMenu
                        record={v.record}
                        lang={lang}
                        st={st}
                        onOpen={(t) => onOpenTab(v.uid, t)}
                        onNeedsAuth={onNeedsAuth}
                      />
                    </div>
                  </div>
                ))}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function RowDetail({ row, st }: { row: StorageRow; st: Strings }) {
  switch (row.row) {
    case "pvc":
      return <ClaimDetail claim={row} st={st} />;
    case "pv":
      return <VolumeDetail volume={row} st={st} />;
    case "sc":
      return <ClassDetail sc={row} st={st} />;
    case "vsclass":
      return <SnapClassDetail sc={row} st={st} />;
    case "vs":
      return <SnapshotDetail vs={row} st={st} />;
    case "vsc":
      return <ContentDetail vsc={row} st={st} />;
    case "va":
      return <AttachDetail va={row} st={st} />;
    case "vanode":
      return <NodeDetail node={row} st={st} />;
  }
}

function ClaimDetail({ claim, st }: { claim: PvcRow; st: Strings }) {
  return (
    <div className="detail">
      <Line label="phase" value={claim.phase} tone={claim.phase_tone} />
      {/* Demandé et obtenu côte à côte : un volume donne parfois plus que ce qu'on a demandé, et
          c'est en les voyant ensemble qu'on s'en aperçoit. */}
      <Line label="requested" value={claim.requested || "—"} />
      <Line label="capacity" value={claim.capacity || "—"} />
      <Line label="accessModes" value={claim.access_modes || "—"} />
      <Line label="storageClass" value={claim.class_label} mono />
      <Line label="volume" value={claim.volume_name ?? "—"} mono />
      <Line label={st.stoMountedBy} value={claim.mounted_label} />
      <Line label="age" value={claim.age} />
      <Hints hints={claim.hints} st={st} />
    </div>
  );
}

function VolumeDetail({ volume, st }: { volume: PvRow; st: Strings }) {
  return (
    <div className="detail">
      <Line label="phase" value={volume.phase} tone={volume.phase_tone} />
      <Line label="capacity" value={volume.capacity || "—"} />
      <Line label="accessModes" value={volume.access_modes || "—"} />
      <Line
        label="reclaimPolicy"
        value={volume.reclaim_policy}
        tone={volume.reclaim_deletes ? "warn" : undefined}
      />
      <Line label="storageClass" value={volume.storage_class || "—"} mono />
      <Line label="claimRef" value={volume.claim ?? "—"} mono />
      <Line label={st.stoBackend} value={volume.source || "—"} mono />
      {/* La contrainte de placement : la raison habituelle d'une claim qui se lie sur un cluster
          et reste Pending sur un autre. */}
      <Line label="nodeAffinity" value={volume.node_affinity || "—"} mono />
      <Line label="age" value={volume.age} />
      <Hints hints={volume.hints} st={st} />
    </div>
  );
}

function ClassDetail({ sc, st }: { sc: ScRow; st: Strings }) {
  return (
    <div className="detail">
      <Line label="provisioner" value={sc.provisioner} mono />
      <Line label="reclaimPolicy" value={sc.reclaim_policy} />
      <Line label="bindingMode" value={sc.binding_mode} />
      <Line label="allowVolumeExpansion" value={String(sc.allow_expansion)} />
      <Line label={st.stoDefault} value={String(sc.is_default)} />
      <Line label="age" value={sc.age} />
      <Hints hints={sc.hints} st={st} />
    </div>
  );
}

function Line({
  label,
  value,
  mono,
  tone,
}: {
  label: string;
  value: string;
  mono?: boolean;
  tone?: string;
}) {
  return (
    <div className="keys-row">
      <div className="k-col">
        <span className="k">{label}</span>
      </div>
      <span className={`v ${mono ? "mono" : ""} ${tone ?? ""}`}>{value}</span>
    </div>
  );
}

function Hints({ hints, st }: { hints: Hint[]; st: Strings }) {
  if (hints.length === 0) return null;
  return (
    <>
      <div className="sect">{st.sectionHints}</div>
      <ul className="hints">
        {hints.map((h) => (
          <li key={h.text} className={h.level}>
            <span className="gl">{h.level === "danger" ? "✗" : h.level === "warn" ? "▲" : "·"}</span>{" "}
            {h.text}
          </li>
        ))}
      </ul>
    </>
  );
}

/** Un pli d'en-tête : désactivé quand le groupe est vide, pour ne pas promettre un enfant absent. */
function Fold({
  empty,
  folded,
  onToggle,
}: {
  empty: boolean;
  folded: boolean;
  onToggle: () => void;
}) {
  return (
    <button
      className="fold"
      aria-expanded={!folded}
      disabled={empty}
      onClick={(e) => {
        e.stopPropagation();
        onToggle();
      }}
    >
      {empty ? "·" : folded ? "▸" : "▾"}
    </button>
  );
}

/** Une ligne d'objet de l'arbre : sélectionnable, cochable, avec son hamburger en fin de ligne. */
function TreeRow({
  uid,
  record,
  className,
  nested,
  label,
  cells,
  selected,
  lang,
  st,
  onSelect,
  onOpenTab,
  onNeedsAuth,
  checked,
  onToggleCheck,
  fold,
}: {
  uid: string;
  record: EventRecord;
  className: string;
  nested: "" | "nested" | "nested deep";
  label: ReactNode;
  cells: ReactNode;
  selected: string | null;
  onSelect: (uid: string) => void;
  fold?: ReactNode;
} & WorldTableProps) {
  return (
    <div
      className={`tr ${className} sev-${record.tone}`}
      aria-selected={selected === uid}
      tabIndex={0}
      onClick={() => onSelect(uid)}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSelect(uid);
      }}
    >
      <div className={`cell id ${nested}`}>
        {fold ?? <span className="fold-gap" />}
        <TreeCheckbox
          checked={checked.has(uid)}
          onToggle={() => onToggleCheck(uid)}
          label={st.selectRow}
          st={st}
        />
        {label}
      </div>
      {cells}
      <div className="cell act">
        <RowMenu
          record={record}
          lang={lang}
          st={st}
          onOpen={(t) => onOpenTab(uid, t)}
          onNeedsAuth={onNeedsAuth}
        />
      </div>
    </div>
  );
}

/** Un en-tête qui ne désigne aucun objet : rien à cocher, rien à ouvrir. */
function BucketRow({
  label,
  count,
  cells,
  st,
}: {
  label: string;
  count: number;
  cells: number;
  st: Strings;
}) {
  return (
    <div className="tr sto-class">
      <div className="cell id dim">
        <span className="fold-gap">·</span>
        <TreeCheckbox checked={false} label={st.selectRow} st={st} />
        {label}
        <span className="grp-count">{count}</span>
      </div>
      {Array.from({ length: cells }, (_, i) => (
        <div key={i} className="cell" />
      ))}
      <div className="cell act" />
    </div>
  );
}

function SnapshotTable({
  groups,
  loose,
  folded: foldedSet,
  selected,
  onSelect,
  onToggle,
  ...props
}: {
  groups: SnapGroup[];
  loose: VscRow[];
  folded: Set<string>;
  selected: string | null;
  onSelect: (uid: string) => void;
  onToggle: (uid: string) => void;
} & WorldTableProps) {
  const { st } = props;
  const contentCells = (c: VscRow) => (
    <>
      <div className="cell" />
      <div className="cell mono dim">VSC</div>
      <div className={`cell ${c.phase_tone}`}>{c.phase}</div>
      <div className="cell num">{c.restore_size || "—"}</div>
      <div className="cell mono dim">{c.class ?? "—"}</div>
      <div className="cell dim">{c.deletion_policy}</div>
      <div className="cell mono dim">{c.snapshot ?? "—"}</div>
      <div className="cell num dim">{c.age}</div>
    </>
  );
  return (
    <div className="tbl" style={cols(SNAPSHOT_COLUMNS)}>
      <div className="thead">
        <div className="tr">
          <div className="cell">NAME</div>
          <div className="cell">NAMESPACE</div>
          <div className="cell">KIND</div>
          <div className="cell">READY</div>
          <div className="cell num">SIZE</div>
          <div className="cell">CLASS</div>
          <div className="cell">POLICY</div>
          <div className="cell">SOURCE / DRIVER</div>
          <div className="cell num">AGE</div>
          <div className="cell act" />
        </div>
      </div>
      <div className="tbody">
        {groups.map((g) => {
          const key = g.sc ? g.sc.uid : "sto|vs-no-class";
          const folded = g.sc ? foldedSet.has(key) : false;
          return (
            <div className="grp" key={key}>
              {g.sc ? (
                <TreeRow
                  {...props}
                  uid={g.sc.uid}
                  record={g.sc.record}
                  className="sto-class"
                  nested=""
                  selected={selected}
                  onSelect={onSelect}
                  fold={
                    <Fold
                      empty={g.snapshots.length === 0}
                      folded={folded}
                      onToggle={() => onToggle(key)}
                    />
                  }
                  label={
                    <>
                      {g.sc.name}
                      {g.sc.is_default && <span className="badge-default">{st.stoDefault}</span>}
                      <span className="grp-count">{g.snapshots.length}</span>
                    </>
                  }
                  cells={
                    <>
                      <div className="cell" />
                      <div className="cell mono dim">VSClass</div>
                      <div className="cell dim">—</div>
                      <div className="cell num dim">—</div>
                      <div className="cell dim">—</div>
                      <div className="cell dim">{g.sc.deletion_policy}</div>
                      <div className="cell mono dim">
                        {g.sc.driver}
                        {g.sc.velero ? " · velero" : ""}
                      </div>
                      <div className="cell num dim">{g.sc.age}</div>
                    </>
                  }
                />
              ) : (
                <BucketRow label={st.stoNoClass} count={g.snapshots.length} cells={8} st={st} />
              )}
              {!folded &&
                g.snapshots.map(({ vs, content }) => (
                  <Fragment key={vs.uid}>
                    <TreeRow
                      {...props}
                      uid={vs.uid}
                      record={vs.record}
                      className="sto-volume"
                      nested="nested"
                      selected={selected}
                      onSelect={onSelect}
                      label={vs.name}
                      cells={
                        <>
                          <div className="cell mono dim">{vs.namespace}</div>
                          <div className="cell mono dim">VS</div>
                          <div className={`cell ${vs.phase_tone}`}>{vs.phase}</div>
                          <div className="cell num">{vs.restore_size || "—"}</div>
                          <div className="cell mono dim">{vs.class ?? "—"}</div>
                          <div className="cell dim">—</div>
                          <div className="cell mono dim">
                            {vs.source_pvc ? `pvc:${vs.source_pvc}` : vs.content ? `vsc:${vs.content}` : "—"}
                          </div>
                          <div className="cell num dim">{vs.age}</div>
                        </>
                      }
                    />
                    {content && (
                      <TreeRow
                        {...props}
                        uid={content.uid}
                        record={content.record}
                        className="sto-volume"
                        nested="nested deep"
                        selected={selected}
                        onSelect={onSelect}
                        label={content.name}
                        cells={contentCells(content)}
                      />
                    )}
                  </Fragment>
                ))}
            </div>
          );
        })}
        {loose.length > 0 && (
          <div className="grp">
            <BucketRow label={st.stoLooseContents} count={loose.length} cells={8} st={st} />
            {loose.map((c) => (
              <TreeRow
                {...props}
                key={c.uid}
                uid={c.uid}
                record={c.record}
                className="sto-volume"
                nested="nested"
                selected={selected}
                onSelect={onSelect}
                label={c.name}
                cells={contentCells(c)}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function AttachTable({
  groups,
  folded: foldedSet,
  selected,
  onSelect,
  onToggle,
  ...props
}: {
  groups: AttachGroup[];
  folded: Set<string>;
  selected: string | null;
  onSelect: (uid: string) => void;
  onToggle: (uid: string) => void;
} & WorldTableProps) {
  const { st } = props;
  return (
    <div className="tbl" style={cols(ATTACH_COLUMNS)}>
      <div className="thead">
        <div className="tr">
          <div className="cell">NAME</div>
          <div className="cell">KIND</div>
          <div className="cell">PHASE</div>
          <div className="cell">ATTACHED</div>
          <div className="cell">PV / SLOTS</div>
          <div className="cell num">AGE</div>
          <div className="cell act" />
        </div>
      </div>
      <div className="tbody">
        {groups.map(({ node, items }) => {
          const folded = foldedSet.has(node.uid);
          return (
            <div className="grp" key={node.uid}>
              <TreeRow
                {...props}
                uid={node.uid}
                record={node.record}
                className="sto-class"
                nested=""
                selected={selected}
                onSelect={onSelect}
                fold={
                  <Fold empty={items.length === 0} folded={folded} onToggle={() => onToggle(node.uid)} />
                }
                label={
                  <>
                    {node.node}
                    <span className="grp-count">{items.length}</span>
                  </>
                }
                cells={
                  <>
                    <div className="cell mono dim">Node</div>
                    <div className="cell dim">—</div>
                    <div className="cell dim">—</div>
                    {/* Le nœud disparu se dit ici et pas en pastille après le nom : la cellule du
                        nom la couperait dès que le nom est long, et c'est le cas des nœuds AKS. */}
                    <div className={`cell mono ${node.exists ? "dim" : "warn"}`}>
                      {node.exists ? node.slots_label : `${st.stoNodeGone} · ${node.slots_label}`}
                    </div>
                    <div className="cell num dim" />
                  </>
                }
              />
              {!folded &&
                items.map((a) => (
                  <TreeRow
                    {...props}
                    key={a.uid}
                    uid={a.uid}
                    record={a.record}
                    className="sto-volume"
                    nested="nested"
                    selected={selected}
                    onSelect={onSelect}
                    label={a.name}
                    cells={
                      <>
                        <div className="cell mono dim">VA</div>
                        <div className={`cell ${a.phase_tone}`}>{a.phase}</div>
                        <div className="cell dim">{String(a.attached)}</div>
                        <div className="cell mono dim">{a.pv || "—"}</div>
                        <div className="cell num dim">{a.age}</div>
                      </>
                    }
                  />
                ))}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/** La suppression en attente et ce qui la retient : la seule chose qui explique un objet bloqué. */
function Deletion({ since, finalizers }: { since: string | null; finalizers: string[] }) {
  if (!since) return null;
  return (
    <>
      <Line label="deletion" value={since} tone="warn" />
      <Line label="finalizers" value={finalizers.join(", ") || "—"} mono />
    </>
  );
}

function SnapClassDetail({ sc, st }: { sc: VsClassRow; st: Strings }) {
  return (
    <div className="detail">
      <Line label="driver" value={sc.driver || "—"} mono />
      <Line label="deletionPolicy" value={sc.deletion_policy || "—"} />
      <Line label={st.stoDefault} value={String(sc.is_default)} />
      <Line label="velero" value={String(sc.velero)} />
      <Line label="age" value={sc.age} />
      <Hints hints={sc.hints} st={st} />
    </div>
  );
}

function SnapshotDetail({ vs, st }: { vs: VsRow; st: Strings }) {
  return (
    <div className="detail">
      <Line label="phase" value={vs.phase} tone={vs.phase_tone} />
      <Line label="restoreSize" value={vs.restore_size || "—"} />
      <Line label="snapshotClass" value={vs.class ?? "—"} mono />
      <Line label="source" value={vs.source_pvc ?? "—"} mono />
      <Line label="content" value={vs.content ?? "—"} mono />
      {vs.error && <Line label="error" value={vs.error} tone="err" />}
      <Deletion since={vs.deleting_since} finalizers={vs.finalizers} />
      <Line label="age" value={vs.age} />
      <Hints hints={vs.hints} st={st} />
    </div>
  );
}

function ContentDetail({ vsc, st }: { vsc: VscRow; st: Strings }) {
  return (
    <div className="detail">
      <Line label="phase" value={vsc.phase} tone={vsc.phase_tone} />
      <Line label="restoreSize" value={vsc.restore_size || "—"} />
      <Line label="driver" value={vsc.driver || "—"} mono />
      <Line label="deletionPolicy" value={vsc.deletion_policy || "—"} />
      <Line label="snapshotClass" value={vsc.class ?? "—"} mono />
      <Line label="volumeSnapshotRef" value={vsc.snapshot ?? "—"} mono />
      <Line label="snapshotHandle" value={vsc.handle || "—"} mono />
      {vsc.error && <Line label="error" value={vsc.error} tone="err" />}
      <Deletion since={vsc.deleting_since} finalizers={vsc.finalizers} />
      <Line label="age" value={vsc.age} />
      <Hints hints={vsc.hints} st={st} />
    </div>
  );
}

function AttachDetail({ va, st }: { va: VaRow; st: Strings }) {
  return (
    <div className="detail">
      <Line label="phase" value={va.phase} tone={va.phase_tone} />
      <Line label="attacher" value={va.attacher} mono />
      <Line label="node" value={va.node} mono />
      <Line label="persistentVolume" value={va.pv || "—"} mono />
      <Line label="attached" value={String(va.attached)} />
      <Line label="metadata" value={va.metadata || "—"} mono />
      {va.attach_error && <Line label="attachError" value={va.attach_error} tone="err" />}
      {va.detach_error && <Line label="detachError" value={va.detach_error} tone="warn" />}
      <Deletion since={va.deleting_since} finalizers={va.finalizers} />
      <Line label="age" value={va.age} />
      <Hints hints={va.hints} st={st} />
    </div>
  );
}

function NodeDetail({ node, st }: { node: VaNodeRow; st: Strings }) {
  return (
    <div className="detail">
      {node.slots.map((s) => (
        <Line key={s.driver} label={s.driver} value={`${s.used} / ${s.limit ?? "—"}`} mono />
      ))}
      <Hints hints={node.hints} st={st} />
    </div>
  );
}
