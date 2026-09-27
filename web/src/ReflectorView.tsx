// La vue reflector : pourquoi un miroir n'est pas là, ou ne ressemble plus à sa source.
//
// Trois mondes, comme dans le TUI : l'arbre des sources et de leurs destinations, les miroirs à plat
// pour aligner les versions, les orphelins qu'aucune source ne réclame plus.
//
// Rien n'est jugé ici. Le statut d'une destination et son ton, le score d'une source, le filtre qui
// garde une source au-dessus d'une destination en échec, et le plan d'un forçage arrivent tout faits
// de `kdt::reflector`. Ce qui reste au navigateur : le pli, la sélection, la recherche.

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
} from "./selection";
import type {
  EventRecord,
  Hint,
  ReflMirror,
  ReflOrphanRow,
  ReflPayload,
  ReflRow,
  ReflSourceRow,
  ReflTargetRow,
  ReflWorld,
} from "./types";
import { cols } from "./table";

/** `NAMESPACE NAME KIND ROLE STATE VERSION AGE ALERT`. La première piste porte la case de sélection
 * multiple des mondes à plat, la dernière le hamburger de la ligne. */
const COLUMNS =
  "34px fit-content(24ch) fit-content(40ch) fit-content(10ch) fit-content(12ch) fit-content(12ch)" +
  " fit-content(10ch) 52px minmax(24ch,1fr) 34px";

/** Une ligne désigne un objet qui existe. Une destination vide nomme ce qui *devrait* être là : ni
 * YAML ni suppression n'y ont de sens — sauf quand le nom est pris, et c'est l'occupant qu'on ouvre. */
function usable(row: ReflRow): boolean {
  if (!row.record.kind || !row.record.name) return false;
  return row.row !== "target" || row.target.mirror !== null || row.target.blocker !== null;
}

function matches(row: ReflRow, needle: string): boolean {
  return [row.namespace, row.name, row.kind, row.role, row.state, row.record.message, ...row.hints.map((h) => h.text)]
    .join(" ")
    .toLowerCase()
    .includes(needle);
}

function hintTone(h: Hint | undefined): string {
  return !h ? "dim" : h.level === "danger" ? "err" : h.level === "warn" ? "warn" : "dim";
}

/** La source qu'une ligne reflète : celle d'une destination, ou celle qu'un orphelin nomme encore. */
function sourceOf(row: ReflRow | null): { namespace: string; name: string } | null {
  if (!row) return null;
  if (row.row === "target") return { namespace: row.source.namespace, name: row.source.name };
  if (row.row === "orphan" && row.orphan.props.reflects) {
    const [namespace, name] = row.orphan.props.reflects;
    return { namespace, name };
  }
  return null;
}

export default function ReflectorView({
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
  const [payload, setPayload] = useState<ReflPayload | null>(null);
  // Le monde et le filtre pour lesquels `payload` a été lu : un saut vers une source ne conclut à
  // son absence que sur l'arbre complet, pas sur la réponse du monde qu'on vient de quitter.
  const [loadedFor, setLoadedFor] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [world, setWorld] = useState<ReflWorld>("sources");
  const [problems, setProblems] = useState(false);
  // Les plis posés à la main. Ils gagnent toujours sur `fold_default`, qui vient de kdt.
  const [folds, setFolds] = useState<Map<string, boolean>>(new Map());
  const [selected, setSelected] = useState<string | null>(null);
  const [focus, setFocus] = useState<string | null>(null);
  const [tab, setTab] = useState<PanelTab>("detail");
  const [toast, setToast] = useState<Toast>(null);
  const [busy, setBusy] = useState(false);
  const { checked, toggle, clear, setAll } = useMultiSelect();
  const [bulkOpen, setBulkOpen] = useState(false);

  const load = useCallback(async () => {
    try {
      const data = await api.reflector(world, problems, lang);
      setPayload(data);
      setLoadedFor(`${world}|${problems}`);
      setError(null);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else if (e instanceof ApiError) setError(e.message);
      else setError(String(e));
      setLoadedFor(`${world}|${problems}`);
    }
  }, [world, problems, lang, onNeedsAuth]);

  useEffect(() => {
    void load();
    // Vingt secondes, comme le TUI : les objets réfléchis bougent lentement, et une passe relit tous
    // les Secrets, ConfigMaps et pods du cluster. Un forçage relit de lui-même.
    const timer = window.setInterval(() => void load(), 20000);
    return () => window.clearInterval(timer);
  }, [load]);

  useToastTimeout(toast, setToast);

  const rows = useMemo(() => payload?.rows ?? [], [payload]);
  const needle = query.trim().toLowerCase();

  const isFolded = useCallback(
    (row: ReflRow) => (folds.has(row.uid) ? Boolean(folds.get(row.uid)) : row.fold_default),
    [folds],
  );

  /**
   * Les lignes affichées. La recherche garde la source au-dessus d'une destination retenue — un
   * miroir sans sa source n'a rien contre quoi se lire — et déplie ce qu'elle trouve.
   */
  const display = useMemo(() => {
    if (needle) {
      const hit = new Set(rows.filter((r) => matches(r, needle)).map((r) => r.uid));
      for (const r of rows) if (hit.has(r.uid) && r.parent) hit.add(r.parent);
      return rows.filter((r) => hit.has(r.uid));
    }
    const folded = new Set(rows.filter((r) => r.foldable && isFolded(r)).map((r) => r.uid));
    return rows.filter((r) => !r.parent || !folded.has(r.parent));
  }, [rows, needle, isFolded]);

  // Le saut vers une source : sélectionnée dès qu'elle apparaît, et si l'arbre complet ne la
  // contient pas, le dire — se taire se lirait « le bouton ne fait rien ».
  useEffect(() => {
    if (!focus) return;
    if (rows.some((r) => r.uid === focus)) {
      setSelected(focus);
      setTab("detail");
      setFocus(null);
    } else if (loadedFor === "sources|false") {
      const [namespace, name] = focus.replace(/^refl\|src\|/, "").split("/");
      setToast({
        tone: "err",
        text: st.reflSourceGone.replace("{ns}", namespace).replace("{name}", name ?? ""),
      });
      setFocus(null);
    }
  }, [rows, focus, loadedFor, st]);

  const selectedRow = useMemo(() => rows.find((r) => r.uid === selected) ?? null, [rows, selected]);
  const selectedRecord: EventRecord | null = selectedRow?.record ?? null;
  const target = sourceOf(selectedRow);

  const selectableKeys = useMemo(
    () => display.filter(usable).map((r) => r.uid),
    [display],
  );

  const toggleFold = useCallback(
    (row: ReflRow) => {
      setFolds((prev) => new Map(prev).set(row.uid, !isFolded(row)));
    },
    [isFolded],
  );

  const switchWorld = (w: ReflWorld) => {
    setWorld(w);
    setSelected(null);
    clear();
  };

  const gotoSource = () => {
    if (!target) return;
    const uid = `refl|src|${target.namespace}/${target.name}`;
    // Comme le `s` du TUI : l'arbre complet, toutes les autres sources repliées, celle-ci ouverte.
    setFolds(new Map([[uid, false]]));
    setProblems(false);
    setWorld("sources");
    clear();
    setFocus(uid);
  };

  const force = useCallback(
    async (uid: string) => {
      setBusy(true);
      try {
        const { message } = await api.reflectorForce(uid, lang);
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
  const tree = world === "sources";

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
              label: st.reflDetail,
              node: selectedRow ? (
                <Detail row={selectedRow} consumersKnown={payload?.consumers_known ?? true} st={st} />
              ) : null,
            }}
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds" role="tablist">
        {(
          [
            ["sources", st.reflSources, counts?.sources],
            ["mirrors", st.reflMirrors, counts?.mirrors],
            ["orphans", st.reflOrphans, counts?.orphans],
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

        {payload && (
          <div className="tally">
            {counts && counts.problems > 0 && (
              <span className="warn">
                {counts.problems} {st.reflProblems}
              </span>
            )}
            {/* L'absence du contrôleur explique toutes les lignes à la fois : c'est la raison
                d'ouvrir cette vue quand rien ne bouge, d'où sa place dans la barre. */}
            {payload.controller_present === false && (
              <span className="err" title={st.reflCtrlAbsentHelp}>
                {st.reflCtrlAbsent}
              </span>
            )}
            {payload.controller_present === null && (
              <span className="warn" title={st.reflCtrlUnknownHelp}>
                {st.reflCtrlUnknown}
              </span>
            )}
          </div>
        )}

        <div className="right">
          {busy && <span>{st.objWorking}</span>}
          {/* Le `s` du TUI : une navigation, pas une action sur l'objet — sa place est la barre. */}
          {target && (
            <button className="panel-toggle" onClick={gotoSource}>
              {st.reflGotoSource}
            </button>
          )}
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

      {/* Ce qui ne tient à aucune source — contrôleur, pods en attente d'un nom publié ailleurs :
          une ligne à soi sous la barre, visible sans rien sélectionner. */}
      {payload?.cluster_hints?.map((h, i) => (
        <div key={i} className={`vel-band ${h.level === "danger" ? "err" : h.level}`}>
          {h.text}
        </div>
      ))}

      <ViewBody
        tab={tab}
        record={selectedRow && usable(selectedRow) ? selectedRecord : null}
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
        {loadedFor === null ? (
          <div className="center" />
        ) : display.length === 0 ? (
          <div className="center">
            <div className="box">
              <h2>{needle || problems ? st.emptyTitle : st.reflEmpty}</h2>
              {error && <p className="err">{error}</p>}
              {payload?.error && <p className="err">{payload.error}</p>}
            </div>
          </div>
        ) : (
          <div className="tbl" style={cols(tree ? withoutSelTrack(COLUMNS) : COLUMNS)}>
            <div className="thead">
              <div className="tr">
                {!tree && <SelectionHead />}
                <div className="cell">NAMESPACE</div>
                <div className="cell">NAME</div>
                <div className="cell">KIND</div>
                <div className="cell">ROLE</div>
                <div className="cell">STATE</div>
                <div className="cell">VERSION</div>
                <div className="cell num">AGE</div>
                <div className="cell">ALERT</div>
                <div className="cell act" />
              </div>
            </div>
            <div className="tbody">
              {display.map((row) => (
                <Line
                  key={row.uid}
                  row={row}
                  tree={tree}
                  lang={lang}
                  st={st}
                  folded={row.foldable && !needle && isFolded(row)}
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
                  onFold={() => toggleFold(row)}
                  onForce={() => void force(row.uid)}
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
        <span style={{ marginLeft: "auto" }}>{st.reflScopeless}</span>
      </div>
    </>
  );
}

function Line({
  row,
  tree,
  lang,
  st,
  folded,
  selected,
  onSelect,
  onOpenTab,
  onNeedsAuth,
  onFold,
  onForce,
  checked,
  onToggleCheck,
}: {
  row: ReflRow;
  tree: boolean;
  lang: Lang;
  st: Strings;
  folded: boolean;
  selected: boolean;
  onSelect: () => void;
  onOpenTab: (tab: ObjectTab) => void;
  onNeedsAuth: (message: string) => void;
  onFold: () => void;
  onForce: () => void;
  checked: boolean;
  onToggleCheck: () => void;
}) {
  const rowUsable = usable(row);
  const alert = row.hints[0];

  return (
    <div
      className={`tr sev-${row.record.tone}`}
      aria-selected={selected}
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSelect();
        else if (e.key === " " && row.foldable) {
          e.preventDefault();
          onFold();
        }
      }}
    >
      {!tree &&
        (rowUsable ? (
          <RowCheckbox checked={checked} onToggle={onToggleCheck} label={st.selectRow} st={st} />
        ) : (
          <div className="cell sel" />
        ))}
      <div className="cell dim">{row.namespace}</div>
      <div
        className={`cell id ${row.name_tone ?? ""}`}
        style={tree ? { paddingLeft: `${row.depth * 1.15}rem` } : undefined}
      >
        {tree &&
          (row.foldable ? (
            <button
              className="fold"
              title={st.reflFold}
              aria-expanded={!folded}
              onClick={(e) => {
                e.stopPropagation();
                onFold();
              }}
            >
              {folded ? "▸" : "▾"}
            </button>
          ) : (
            <span className="fold-gap" />
          ))}
        {tree && (
          <TreeCheckbox
            checked={checked}
            onToggle={rowUsable ? onToggleCheck : undefined}
            label={st.selectRow}
            st={st}
          />
        )}
        {row.name}
      </div>
      <div className="cell dim">{row.kind}</div>
      <div className={`cell ${row.row === "source" ? "info" : row.row === "orphan" ? "err" : "dim"}`}>
        {row.role}
      </div>
      <div className={`cell ${row.state_tone ?? ""}`}>{row.state}</div>
      <div className="cell mono dim">{row.version}</div>
      <div className="cell num dim">{row.age}</div>
      <div className={`cell wrap ${hintTone(alert)}`} title={row.hints.map((h) => h.text).join(" · ")}>
        {alert?.text ?? "—"}
      </div>
      <div className="cell act">
        {rowUsable && (
          <RowMenu record={row.record} lang={lang} st={st} onOpen={onOpenTab} onNeedsAuth={onNeedsAuth}>
            {({ close }) => (
              <ForceMenu
                row={row}
                st={st}
                onForce={() => {
                  close();
                  onForce();
                }}
              />
            )}
          </RowMenu>
        )}
      </div>
    </div>
  );
}

/**
 * Forcer une re-réflexion, avec la confirmation du TUI. Offert seulement quand un forçage peut
 * bouger quelque chose ; sinon le menu dit pourquoi, au lieu d'une écriture qui n'aboutirait à rien.
 */
function ForceMenu({ row, st, onForce }: { row: ReflRow; st: Strings; onForce: () => void }) {
  const [arming, setArming] = useState(false);

  // Posé comme `children` de `RowMenu` : pas de `.pop.menu`/`.pop-hd` à lui.
  if (!row.force) {
    return <p className="menu-note dim">{row.no_force}</p>;
  }
  if (!arming) {
    return (
      <button className="menu-item" onClick={() => setArming(true)}>
        <span className="lbl">{st.reflForce}</span>
        <span className="desc">{st.reflForceHelp}</span>
      </button>
    );
  }
  return (
    <div className="menu-confirm">
      <p>
        <strong>{st.reflForce}</strong> — {row.namespace}/{row.name}
      </p>
      <p>{st.reflForceMirrors.replace("{n}", String(row.force.mirrors))}</p>
      {row.force.stamps_source && <p className="dim">{st.reflStampsSource}</p>}
      {/* La sortie par défaut est celle qui n'écrit rien : c'est elle qui a le focus. */}
      <div className="menu-buttons">
        <button autoFocus onClick={() => setArming(false)}>
          {st.reflCancel}
        </button>
        <button className="cta" onClick={onForce}>
          {st.reflConfirm}
        </button>
      </div>
    </div>
  );
}

/** Les faits de la ligne, puis ce que les règles en font — la forme du panneau du TUI. Les
 * annotations sont montrées telles qu'écrites : elles sont l'entrée de chaque verdict. */
function Detail({ row, consumersKnown, st }: { row: ReflRow; consumersKnown: boolean; st: Strings }) {
  return (
    <div className="detail">
      {row.row === "source" ? (
        <SourceDetail row={row} st={st} />
      ) : row.row === "target" ? (
        <TargetDetail row={row} consumersKnown={consumersKnown} st={st} />
      ) : (
        <OrphanDetail row={row} consumersKnown={consumersKnown} st={st} />
      )}
      <Hints hints={row.hints} title={st.reflDiagnostic} />
    </div>
  );
}

function SourceDetail({ row, st }: { row: ReflSourceRow; st: Strings }) {
  const s = row.source;
  // Une liste vide n'est pas une absence : chez reflector elle vaut « tous les namespaces ».
  const all = (v: string) => (v === "" ? st.reflAllNs : v);
  return (
    <>
      <Field label="kind" value={row.kind} />
      {s.type && <Field label="type" value={s.type} />}
      <Field label="resourceVersion" value={s.resource_version || "—"} mono />
      <Field label={st.reflProvenance} value={s.provenance_label} />
      <Field label={st.reflAge} value={s.age} />

      <div className="sect">{st.reflAnnotations}</div>
      <Field label="allowed" value={String(s.props.allowed)} mono />
      <Field label="allowed-namespaces" value={all(s.props.allowed_ns)} mono />
      {s.props.allowed_selector && <Field label="allowed-selector" value={s.props.allowed_selector} mono />}
      <Field label="auto-enabled" value={String(s.props.auto_enabled)} mono />
      <Field label="auto-namespaces" value={all(s.props.auto_ns)} mono />
      {s.props.auto_selector && <Field label="auto-selector" value={s.props.auto_selector} mono />}

      <div className="sect">{st.reflScopeTitle}</div>
      {!s.scope_known ? (
        <Field label={st.reflDestinations} value={st.reflDestUnknown} />
      ) : s.targets.length === 0 ? (
        <Field label={st.reflDestinations} value={st.reflDestNone} />
      ) : (
        <>
          <Field
            label="auto"
            value={st.reflDestUptodate
              .replace("{synced}", String(s.synced))
              .replace("{expected}", String(s.expected))}
          />
          {s.targets.map((t) => (
            <div className="keys-row" key={t.namespace}>
              <div className="k-col">
                <span className={`k ${t.tone}`}>{t.status_label}</span>
              </div>
              <span className="v">
                {t.namespace}
                {!t.auto && <span className="dim"> ({st.reflOutOfAuto})</span>}
              </span>
            </div>
          ))}
        </>
      )}
    </>
  );
}

function TargetDetail({
  row,
  consumersKnown,
  st,
}: {
  row: ReflTargetRow;
  consumersKnown: boolean;
  st: Strings;
}) {
  const t = row.target;
  return (
    <>
      <Field label={st.reflState} value={t.status_label} tone={row.state_tone ?? undefined} />
      <Field label="source" value={`${row.source.namespace}/${row.source.name}`} mono />
      <Field label="kind" value={row.kind} />
      <Field label={st.reflScope} value={t.auto ? st.reflScopeAuto : st.reflScopeManual} />
      {t.mirror ? (
        <MirrorFields mirror={t.mirror} expected={row.source.resource_version} st={st} />
      ) : (
        <>
          <Field label={st.reflObject} value={st.reflObjectAbsent} />
          {t.blocker && <Field label={st.reflOccupied} value={t.blocker} tone="err" />}
        </>
      )}
      <Consumers consumers={t.consumers} known={consumersKnown} st={st} />
    </>
  );
}

function OrphanDetail({
  row,
  consumersKnown,
  st,
}: {
  row: ReflOrphanRow;
  consumersKnown: boolean;
  st: Strings;
}) {
  const o = row.orphan;
  const reflects = o.props.reflects ? `${o.props.reflects[0]}/${o.props.reflects[1]}` : "—";
  return (
    <>
      <Field label="kind" value={row.kind} />
      <Field label="reflects" value={reflects} mono />
      <MirrorFields mirror={o.mirror} st={st} />
      <Consumers consumers={o.consumers} known={consumersKnown} st={st} />
    </>
  );
}

function MirrorFields({ mirror: m, expected, st }: { mirror: ReflMirror; expected?: string; st: Strings }) {
  return (
    <>
      <Field label={st.reflCreatedBy} value={m.auto ? st.reflYes : st.reflCreatedManual} />
      <Field label="reflected-version" value={m.reflected_version || "—"} mono />
      {expected !== undefined && <Field label={st.reflExpected} value={expected || "—"} mono />}
      <Field label="reflected-at" value={m.reflected_at || "—"} mono />
      {m.reflected_age && <Field label={st.reflLastPass} value={st.reflAgo.replace("{age}", m.reflected_age)} />}
      <Field label={st.reflProvenance} value={m.provenance_label} />
      <Field label={st.reflAge} value={m.age} />
      <Field label={st.reflKeys} value={m.keys.length ? m.keys.join(", ") : "—"} mono />
    </>
  );
}

/** Personne ne réclame l'objet, ou on n'a pas pu le savoir : les deux ne se confondent pas. */
function Consumers({ consumers, known, st }: { consumers: string[]; known: boolean; st: Strings }) {
  const value = consumers.length ? consumers.join(", ") : known ? "—" : st.reflConsumersUnknown;
  return <Field label={st.reflClaimedBy} value={value} tone={!known && !consumers.length ? "dim" : undefined} />;
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
