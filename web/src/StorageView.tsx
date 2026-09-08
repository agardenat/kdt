// La vue stockage : PVC, PV et StorageClass — et surtout ce qui ne va pas avec eux.
//
// Ce que cette vue apporte n'est pas la liste des volumes, `kubectl get pvc` la donne, mais ce qui
// coûte une après-midi : une claim qui ne se liera jamais et pourquoi, un PV qui tient encore la
// donnée d'une claim disparue, un `reclaimPolicy: Delete` sur ce que personne ne veut perdre, un
// cluster sans classe par défaut — ou avec deux.
//
// Rien n'est jugé ici. Les constats, le ton d'une phase, les octets qui dorment en `Released`
// arrivent tout faits de `kdt::storage`.
//
// # Deux mondes, deux formes
//
// Le TUI donne une seule forme de table aux deux mondes et laisse des colonnes vides. Ici chaque
// monde a la sienne : sur les claims, `KIND` répéterait « PVC » sur chaque ligne et `RECLAIM` serait
// vide partout — deux colonnes qui volent la largeur à celles qui distinguent. Le volume lié, que le
// TUI met dans le panneau, prend leur place.

import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import type { Lang, Strings } from "./i18n";
import { ObjectActions } from "./objects";
import { InspectPanel, PanelToggle, Splitter, type PanelTab } from "./panel";
import type {
  EventRecord,
  Hint,
  PvRow,
  PvcRow,
  ScRow,
  StoragePayload,
  StorageRow,
} from "./types";

/** `NAMESPACE NAME PHASE SIZE ACCESS CLASS VOLUME USED BY AGE`. */
const CLAIM_COLUMNS =
  "minmax(110px,18ch) minmax(150px,26ch) 84px 72px 72px minmax(150px,22ch)" +
  " minmax(180px,1.2fr) minmax(140px,1fr) 52px";

/** `NAME KIND PHASE SIZE ACCESS RECLAIM CLAIM / PROVISIONER AGE`. */
const VOLUME_COLUMNS =
  "minmax(180px,1fr) 44px 84px 72px 72px 76px minmax(200px,1.4fr) 52px";

type World = "claims" | "volumes";
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

  const shownCount =
    world === "claims"
      ? claims.length
      : visibleVolumes.reduce((n, g) => n + g.volumes.length + (g.sc ? 1 : 0), 0);

  const allRows: StorageRow[] = useMemo(
    () => [...(payload?.pvcs ?? []), ...(payload?.pvs ?? []), ...(payload?.classes ?? [])],
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
            onNeedsAuth={onNeedsAuth}
            onDeleted={() => {
              setSelected(null);
              void load();
            }}
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
          ] as const
        ).map(([id, label, n]) => (
          <button
            key={id}
            role="tab"
            aria-selected={world === id}
            onClick={() => {
              setWorld(id);
              setSelected(null);
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

      {/* Ce qui appartient au cluster et à aucune ligne : pas de classe par défaut, deux classes
          par défaut, et les octets que plus personne ne peut atteindre. */}
      {payload && (payload.cluster_hints.length > 0 || payload.released_bytes > 0) && (
        <ClusterBand payload={payload} st={st} />
      )}

      <div className="body">
        {!loaded ? (
          <div className="center" />
        ) : shownCount === 0 ? (
          <div className="center">
            <div className="box">
              <h2>{st.stoEmpty}</h2>
              {error && <p className="err">{error}</p>}
              <p>
                {st.emptyScope} <code>{scope || st.scopeAll}</code>
              </p>
            </div>
          </div>
        ) : world === "claims" ? (
          <ClaimTable rows={claims} selected={selected} onSelect={select} />
        ) : (
          <VolumeTable
            groups={visibleVolumes}
            folded={folded}
            selected={selected}
            st={st}
            onSelect={select}
            onToggle={toggle}
          />
        )}
      </div>

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

function ClaimTable({
  rows,
  selected,
  onSelect,
}: {
  rows: PvcRow[];
  selected: string | null;
  onSelect: (uid: string) => void;
}) {
  return (
    <div className="tbl">
      <div className="thead">
        <div className="tr" style={{ gridTemplateColumns: CLAIM_COLUMNS }}>
          <div className="cell">NAMESPACE</div>
          <div className="cell">NAME</div>
          <div className="cell">PHASE</div>
          <div className="cell num">SIZE</div>
          <div className="cell">ACCESS</div>
          <div className="cell">CLASS</div>
          <div className="cell">VOLUME</div>
          <div className="cell">USED BY</div>
          <div className="cell num">AGE</div>
        </div>
      </div>
      <div className="tbody">
        {rows.map((c) => (
          <div
            key={c.uid}
            className={`tr sev-${c.record.tone}`}
            style={{ gridTemplateColumns: CLAIM_COLUMNS }}
            aria-selected={selected === c.uid}
            tabIndex={0}
            onClick={() => onSelect(c.uid)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onSelect(c.uid);
            }}
          >
            <div className="cell mono dim">{c.namespace}</div>
            <div className="cell id">{c.name}</div>
            <div className={`cell ${c.phase_tone}`}>{c.phase}</div>
            <div className="cell num">{c.size || "—"}</div>
            <div className="cell dim">{c.access_modes}</div>
            <div className="cell mono dim">{c.storage_class ?? "—"}</div>
            <div className="cell mono dim">{c.volume_name ?? "—"}</div>
            <div className={`cell ${c.mounted_by.length === 0 ? "dim" : ""}`}>
              {c.mounted_by.length === 0
                ? "—"
                : c.mounted_by.length === 1
                  ? c.mounted_by[0]
                  : `${c.mounted_by[0]} (${c.mounted_by.length})`}
            </div>
            <div className="cell num dim">{c.age}</div>
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
  st,
  onSelect,
  onToggle,
}: {
  groups: Array<{ sc: ScRow | null; volumes: PvRow[] }>;
  folded: Set<string>;
  selected: string | null;
  st: Strings;
  onSelect: (uid: string) => void;
  onToggle: (uid: string) => void;
}) {
  return (
    <div className="tbl">
      <div className="thead">
        <div className="tr" style={{ gridTemplateColumns: VOLUME_COLUMNS }}>
          <div className="cell">NAME</div>
          <div className="cell">KIND</div>
          <div className="cell">PHASE</div>
          <div className="cell num">SIZE</div>
          <div className="cell">ACCESS</div>
          <div className="cell">RECLAIM</div>
          <div className="cell">CLAIM / PROVISIONER</div>
          <div className="cell num">AGE</div>
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
                  style={{ gridTemplateColumns: VOLUME_COLUMNS }}
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
                </div>
              ) : (
                <div className="tr sto-class" style={{ gridTemplateColumns: VOLUME_COLUMNS }}>
                  <div className="cell id dim">
                    <span className="fold-gap">·</span>
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
                </div>
              )}
              {!folded &&
                g.volumes.map((v) => (
                  <div
                    key={v.uid}
                    className={`tr sto-volume sev-${v.record.tone}`}
                    style={{ gridTemplateColumns: VOLUME_COLUMNS }}
                    aria-selected={selected === v.uid}
                    tabIndex={0}
                    onClick={() => onSelect(v.uid)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") onSelect(v.uid);
                    }}
                  >
                    <div className="cell id nested">{v.name}</div>
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
  if (row.row === "pvc") return <ClaimDetail claim={row} st={st} />;
  if (row.row === "pv") return <VolumeDetail volume={row} st={st} />;
  return <ClassDetail sc={row} st={st} />;
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
