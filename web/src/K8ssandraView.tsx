// La vue k8ssandra : sur une base, qu'est-ce qui est restaurable ?
//
// Trois mondes sur une seule lecture — le ring, les sauvegardes Medusa, les opérations. Le chiffre
// que la vue doit sans qu'on sélectionne rien est l'âge de la dernière sauvegarde qui couvre tous
// les nodes : un run partiel se restaure comme s'il était entier, et les trois surfaces qui
// devraient le dire (le `status` du schedule, le CronJob de purge, le catalogue) mentent par
// omission.
//
// Rien n'est jugé ici. Les lignes, leurs états et leurs tons, la couverture d'un run, les actions
// qu'une ligne offre et leurs libellés arrivent tout faits de `kdt::k8ssandra`. Le navigateur ne
// garde que l'état de qui regarde : le pliage, la sélection, le filtre, et la lecture ouverte.

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import type { Lang, Strings } from "./i18n";
import { ToastLine, useToastTimeout, type Toast } from "./toast";
import { InspectPanel, PanelToggle, Splitter, ViewBody, type PanelTab } from "./panel";
import { BulkDeletePane, RowMenu, type ObjectTab } from "./objects";
import { SelectionBar, TreeCheckbox, useMultiSelect } from "./selection";
import type {
  EventRecord,
  K8cActionItem,
  K8cHint,
  K8cLinesPayload,
  K8cMetricsPayload,
  K8cRepairsPayload,
  K8cRow,
  K8cSnapshotsPayload,
  K8cWorld,
  K8ssandraPayload,
} from "./types";
import { cols } from "./table";

/** Les colonnes du TUI : `NAMESPACE NAME KIND STATE INFO DUR AGE ALERT`, dans le même ordre. La
 * case de sélection n'a pas de piste : la vue est un arbre, elle suit l'indentation dans NAME. Et
 * pas de cascade — un schedule ne possède pas ses runs au sens où les supprimer ensemble serait
 * voulu, et un en-tête de section ne désigne aucun objet. La dernière piste porte le hamburger. */
const COLUMNS =
  "fit-content(16ch) fit-content(44ch) 84px fit-content(14ch) fit-content(26ch)" +
  " 64px 56px minmax(24ch,1fr) 34px";

/** Même liste blanche que `kdt::nodetool::command_char_allowed`. Le serveur la rejoue sur la ligne
 * entière ; ici elle ne sert qu'à dire tout de suite ce qui serait refusé. */
const NODETOOL_ALLOWED = /^[A-Za-z0-9 \-_.,:/=+*@]*$/;
const NODETOOL_MAX = 200;

/** Une lecture à la demande : aucune n'est dans la liste, chacune a sa route. */
type ReadingKind = "log" | "output" | "metrics" | "snapshots" | "repairs";

type Reading =
  | { kind: "log" | "output"; data: K8cLinesPayload }
  | { kind: "metrics"; data: K8cMetricsPayload }
  | { kind: "snapshots"; data: K8cSnapshotsPayload }
  | { kind: "repairs"; data: K8cRepairsPayload };

/** La lecture ouverte appartient à une ligne : elle se referme quand la sélection en change. */
interface OpenReading {
  uid: string;
  kind: ReadingKind;
  label: string;
  state: "loading" | Reading | { error: string };
}

/** Une ligne sans objet à elle — un en-tête de section — n'a ni case ni hamburger. */
function usable(record: EventRecord | null): boolean {
  return Boolean(record && record.kind && record.name);
}

export default function K8ssandraView({
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
  const [payload, setPayload] = useState<K8ssandraPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [world, setWorld] = useState<K8cWorld>("cluster");
  const [problems, setProblems] = useState(false);
  // Les plis posés à la main. Ils gagnent toujours sur `fold_default`, qui vient de kdt.
  const [folds, setFolds] = useState<Map<string, boolean>>(new Map());
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<PanelTab>("detail");
  const [toast, setToast] = useState<Toast>(null);
  const [busy, setBusy] = useState(false);
  const { checked, toggle, clear, setAll } = useMultiSelect();
  const [bulkOpen, setBulkOpen] = useState(false);
  const [reading, setReading] = useState<OpenReading | null>(null);
  // La ligne qu'un `nodetool` vient de créer : elle apparaît une lecture plus tard, et le curseur
  // s'y pose à ce moment-là.
  const [focus, setFocus] = useState<string | null>(null);

  const namespace = namespaces[0] ?? "";

  const load = useCallback(async () => {
    try {
      setPayload(await api.k8ssandra(namespace, world, problems, lang));
      setError(null);
      setLoaded(true);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else if (e instanceof ApiError) setError(e.message);
      else setError(String(e));
      setLoaded(true);
    }
  }, [namespace, world, problems, lang, onNeedsAuth]);

  useEffect(() => {
    void load();
    // La cadence du TUI : un run prend des minutes, un schedule se déclenche au mieux toutes les
    // heures, et une passe coûte onze sondes de découverte plus une lecture de ring par datacenter.
    const timer = window.setInterval(() => void load(), 20000);
    return () => window.clearInterval(timer);
  }, [load]);

  useToastTimeout(toast, setToast);

  const rows = useMemo(() => payload?.rows ?? [], [payload]);
  const needle = query.trim().toLowerCase();

  useEffect(() => {
    if (!focus || !rows.some((r) => r.uid === focus)) return;
    setSelected(focus);
    setFocus(null);
  }, [rows, focus]);

  // Une lecture répond sur un node, un run : sous la ligne d'à côté, ce serait la mauvaise réponse.
  useEffect(() => {
    if (reading && reading.uid !== selected) setReading(null);
  }, [reading, selected]);

  const isFolded = useCallback(
    (row: K8cRow) => (folds.has(row.uid) ? Boolean(folds.get(row.uid)) : row.fold_default),
    [folds],
  );

  /**
   * Les lignes affichées. La recherche garde les ancêtres de ce qu'elle retient — un node trouvé
   * sans son datacenter et son cluster n'a rien contre quoi se lire — puis les plis s'appliquent.
   * Une recherche en cours déplie ce qu'elle trouve.
   */
  const display = useMemo(() => {
    if (needle) {
      const keep = rows.map((r) => matches(r, needle));
      const lastAt: number[] = [];
      rows.forEach((r, i) => {
        if (keep[i]) for (let d = 0; d < r.depth; d++) if (lastAt[d] !== undefined) keep[lastAt[d]] = true;
        lastAt[r.depth] = i;
        lastAt.length = r.depth + 1;
      });
      return rows.filter((_, i) => keep[i]);
    }
    const out: K8cRow[] = [];
    let hideBelow: number | null = null;
    for (const row of rows) {
      if (hideBelow !== null) {
        if (row.depth > hideBelow) continue;
        hideBelow = null;
      }
      out.push(row);
      if (row.foldable && isFolded(row)) hideBelow = row.depth;
    }
    return out;
  }, [rows, needle, isFolded]);

  const selectableKeys = useMemo(
    () => display.filter((r) => usable(r.record)).map((r) => r.uid),
    [display],
  );

  const selectedRow = useMemo(() => rows.find((r) => r.uid === selected) ?? null, [rows, selected]);
  const selectedRecord: EventRecord | null = selectedRow?.record ?? null;

  const toggleFold = useCallback(
    (row: K8cRow) => {
      setFolds((prev) => {
        const next = new Map(prev);
        next.set(row.uid, !isFolded(row));
        return next;
      });
    },
    [isFolded],
  );

  const openReading = useCallback(
    async (row: K8cRow, kind: ReadingKind, label: string) => {
      setReading({ uid: row.uid, kind, label, state: "loading" });
      setTab("detail");
      onPanelOpen(true);
      try {
        let result: Reading;
        const target = row.log_target;
        if ((kind === "log" || kind === "output") && target) {
          result =
            target.kind === "nodetool"
              ? { kind: "output", data: await api.k8ssandraOutput(target.namespace, target.job, lang) }
              : {
                  kind: "log",
                  data: await api.k8ssandraLog(target.namespace, target.pod, target.container),
                };
        } else if (kind === "metrics") {
          result = { kind, data: await api.k8ssandraMetrics(row.namespace, row.name) };
        } else if (kind === "snapshots") {
          result = { kind, data: await api.k8ssandraSnapshots(row.namespace, row.name, lang) };
        } else {
          result = { kind: "repairs", data: await api.k8ssandraRepairs(row.namespace, row.name, lang) };
        }
        // La réponse d'une ligne qu'on a quittée entre-temps ne s'affiche pas sous une autre.
        setReading((cur) => (cur && cur.uid === row.uid && cur.kind === kind ? { ...cur, state: result } : cur));
      } catch (e) {
        if (e instanceof NeedsAuth) onNeedsAuth(e.message);
        const message = String((e as Error).message ?? e);
        setReading((cur) =>
          cur && cur.uid === row.uid && cur.kind === kind ? { ...cur, state: { error: message } } : cur,
        );
      }
    },
    [lang, onNeedsAuth, onPanelOpen],
  );

  const run = useCallback(
    async (request: Parameters<typeof api.k8ssandraWrite>[0]) => {
      setBusy(true);
      try {
        const { message, focus: created } = await api.k8ssandraWrite(request, lang);
        setToast({ tone: "ok", text: message });
        // Un `nodetool` se lit dans les opérations : c'est là que sa ligne apparaîtra.
        if (created) {
          setWorld("ops");
          setSelected(null);
          setFocus(created);
        }
        // Relire tout de suite : l'objet que l'écriture vient de créer est ce qu'on cherche.
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
              label: st.k8cDetail,
              node: payload ? (
                <K8cDetail
                  st={st}
                  payload={payload}
                  row={selectedRow}
                  reading={reading && selectedRow && reading.uid === selectedRow.uid ? reading : null}
                  onRead={(kind, label) => selectedRow && void openReading(selectedRow, kind, label)}
                  onCloseReading={() => setReading(null)}
                />
              ) : null,
            }}
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds" role="tablist">
        {(["cluster", "backups", "ops"] as const).map((w) => (
          <button
            key={w}
            role="tab"
            aria-selected={world === w}
            onClick={() => {
              setWorld(w);
              setSelected(null);
            }}
          >
            {w === "cluster" ? st.k8cCluster : w === "backups" ? st.k8cBackups : st.k8cOps}
            {counts && (
              <span className="count">
                {w === "cluster"
                  ? counts.nodes
                  : w === "backups"
                    ? counts.jobs + counts.backups + counts.restores
                    : counts.ops}
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

        {payload && payload.installed && <Rpo payload={payload} st={st} />}

        <div className="right">
          {busy && <span>{st.objWorking}</span>}
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

      {/* Ce qui vaut pour tout le cluster — aucune sauvegarde restaurable, schémas divergents, ring
          non lu : une phrase sur l'installation, pas sur une ligne, d'où sa ligne à elle. */}
      {payload &&
        payload.cluster_hints.map((h, i) => (
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
        hasDetail={Boolean(payload)}
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
        ) : display.length === 0 ? (
          <div className="center">
            <div className="box">
              <h2>
                {payload && !payload.installed
                  ? st.k8cNotInstalled
                  : needle || problems
                    ? st.emptyTitle
                    : st.k8cEmpty}
              </h2>
              {error && <p className="err">{error}</p>}
              {payload?.error && <p className="err">{payload.error}</p>}
              <p>
                {st.emptyScope} <code>{namespace || st.scopeAll}</code>
              </p>
            </div>
          </div>
        ) : (
          <div className="tbl" style={cols(COLUMNS)}>
            <div className="thead">
              <div className="tr">
                <div className="cell">NAMESPACE</div>
                <div className="cell">NAME</div>
                <div className="cell">KIND</div>
                <div className="cell">STATE</div>
                <div className="cell">INFO</div>
                <div className="cell num">DUR</div>
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
                  lang={lang}
                  st={st}
                  folded={row.foldable && !needle && isFolded(row)}
                  selected={selected === row.uid}
                  onSelect={() => setSelected(row.uid)}
                  onOpenTab={(t) => {
                    setSelected(row.uid);
                    setTab(t);
                  }}
                  onNeedsAuth={onNeedsAuth}
                  onFold={() => toggleFold(row)}
                  onRun={run}
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
        <span>{namespace || (lang === "fr" ? "tout le cluster" : "whole cluster")}</span>
        {counts && counts.problems > 0 && (
          <span className="warn">
            {counts.problems} {st.k8cProblems}
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
 * L'âge de la dernière sauvegarde qui couvre tous les nodes, et l'état du ring. C'est ce que le
 * titre du TUI porte : la réponse que la vue doit sans qu'on sélectionne rien.
 */
function Rpo({ payload, st }: { payload: K8ssandraPayload; st: Strings }) {
  return (
    <div className="tally" title={st.k8cRpoHelp}>
      {payload.last_restorable !== null ? (
        <>
          <span className="dim">{st.k8cRpo}</span>
          <span>{ago(payload.last_restorable)}</span>
        </>
      ) : payload.counts.schedules > 0 || payload.counts.backups > 0 ? (
        <span className="err">{st.k8cNoRestorable}</span>
      ) : null}
      {!payload.ring_known && (
        <span className="warn" title={st.k8cRingUnreadHelp}>
          {st.k8cRingUnread}
        </span>
      )}
    </div>
  );
}

function Line({
  row,
  lang,
  st,
  folded,
  selected,
  onSelect,
  onOpenTab,
  onNeedsAuth,
  onFold,
  onRun,
  checked,
  onToggleCheck,
}: {
  row: K8cRow;
  lang: Lang;
  st: Strings;
  folded: boolean;
  selected: boolean;
  onSelect: () => void;
  onOpenTab: (tab: ObjectTab) => void;
  onNeedsAuth: (message: string) => void;
  onFold: () => void;
  onRun: (request: Parameters<typeof api.k8ssandraWrite>[0]) => void;
  checked: boolean;
  onToggleCheck: () => void;
}) {
  const rowUsable = usable(row.record);
  const actionMenu =
    row.actions.length > 0
      ? ({ close }: { close: () => void }) => (
          <ActionMenu
            st={st}
            row={row}
            onRun={(r) => {
              close();
              onRun(r);
            }}
          />
        )
      : undefined;

  return (
    <div
      className={`tr ${hintClass(row.hints)}${row.foldable ? " k8c-parent" : ""}`}
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
      <div className="cell mono dim">{row.namespace}</div>
      <div className="cell id" style={{ paddingLeft: `${row.depth * 1.15}rem` }}>
        {row.foldable ? (
          <button
            className="fold"
            title={st.k8cFold}
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
        )}
        <TreeCheckbox
          checked={checked}
          onToggle={rowUsable ? onToggleCheck : undefined}
          label={st.selectRow}
          st={st}
        />
        {row.name}
      </div>
      <div className="cell dim">{row.kind_label}</div>
      <div className="cell">
        {row.state && <span className={`st ${row.state_tone}`}>{row.state}</span>}
      </div>
      <div className="cell" title={row.info}>
        {row.info}
      </div>
      <div className="cell num dim">{row.row === "group" ? "" : row.span}</div>
      <div className="cell num dim">{row.created > 0 ? ago(row.created) : "—"}</div>
      <div className={`cell wrap ${hintTone(row.hints)}`} title={row.hints.map((h) => h.text).join(" · ")}>
        {row.hints[0]?.text ?? ""}
      </div>
      <div className="cell act">
        {rowUsable && (
          <RowMenu record={row.record} lang={lang} st={st} onOpen={onOpenTab} onNeedsAuth={onNeedsAuth}>
            {actionMenu}
          </RowMenu>
        )}
      </div>
    </div>
  );
}

/**
 * Le menu d'action, avec les confirmations de kdt.
 *
 * Trois formes : une confirmation simple (la sortie par défaut n'écrit rien), le nom du backup à
 * retaper pour une restauration — elle arrête le datacenter —, et la ligne de commande d'un
 * `nodetool`, montrée telle qu'elle partira et contre quel node avant d'être lancée.
 */
function ActionMenu({
  st,
  row,
  onRun,
}: {
  st: Strings;
  row: K8cRow;
  onRun: (r: Parameters<typeof api.k8ssandraWrite>[0]) => void;
}) {
  const [arming, setArming] = useState<K8cActionItem | null>(null);
  const [typed, setTyped] = useState("");

  // Posé comme `children` de `RowMenu` : pas de `.pop.menu`/`.pop-hd` à lui.
  if (!arming) {
    return (
      <>
        {row.actions.map((a) => (
          <button
            key={a.id}
            className="menu-item"
            onClick={() => {
              setTyped("");
              setArming(a);
            }}
          >
            <span className="lbl">{a.label}</span>
            <span className="desc">{a.desc}</span>
          </button>
        ))}
      </>
    );
  }

  const cancel = (
    <button autoFocus={arming.id !== "nodetool" && arming.id !== "restore"} onClick={() => setArming(null)}>
      {st.fluxCancel}
    </button>
  );

  if (arming.id === "nodetool") {
    const valid = NODETOOL_ALLOWED.test(typed) && typed.length <= NODETOOL_MAX;
    const ready = valid && typed.trim().length > 0;
    const send = () => ready && onRun({ uid: row.uid, action: arming.id, command: typed.trim() });
    return (
      <div className="menu-confirm">
        {row.actions_note && <p>{row.actions_note}</p>}
        <input
          className="ns-add mono"
          value={typed}
          autoFocus
          spellCheck={false}
          placeholder={st.k8cNodetoolPrompt}
          maxLength={NODETOOL_MAX}
          onChange={(e) => setTyped(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") send();
          }}
        />
        {!valid ? (
          <p className="menu-note err">{st.k8cNodetoolInvalid}</p>
        ) : (
          ready && (
            <p className="mono">
              nodetool {typed.trim()} → {row.name}
            </p>
          )
        )}
        <p className="menu-note">{st.k8cNodetoolHelp}</p>
        <div className="menu-buttons">
          {cancel}
          <button className="cta" disabled={!ready} onClick={send}>
            {st.k8cNodetoolRun}
          </button>
        </div>
      </div>
    );
  }

  if (arming.id === "restore") {
    return (
      <div className="menu-confirm">
        <p>{arming.desc}</p>
        {row.actions_note && <p className="menu-note err">{row.actions_note}</p>}
        <p>{st.k8cRestoreRetype}</p>
        <input
          className="ns-add mono"
          value={typed}
          autoFocus
          spellCheck={false}
          onChange={(e) => setTyped(e.target.value)}
        />
        <div className="menu-buttons">
          {cancel}
          <button
            className="cta danger"
            disabled={typed !== row.name}
            onClick={() => onRun({ uid: row.uid, action: arming.id, confirm_name: typed })}
          >
            {st.fluxConfirm} · {arming.label}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="menu-confirm">
      <p>{arming.desc}</p>
      {row.actions_note && <p>{row.actions_note}</p>}
      <div className="menu-buttons">
        {/* Annuler d'abord et au focus : la sortie par défaut est celle qui n'écrit rien. */}
        {cancel}
        <button className="cta" onClick={() => onRun({ uid: row.uid, action: arming.id })}>
          {st.fluxConfirm} · {arming.label}
        </button>
      </div>
    </div>
  );
}

/** Les lectures qu'une ligne offre : `l`, `m` et `S` du TUI, avec leur mot. */
function readingsOf(row: K8cRow, st: Strings): Array<{ kind: ReadingKind; label: string }> {
  const out: Array<{ kind: ReadingKind; label: string }> = [];
  if (row.log_target) {
    out.push(
      row.log_target.kind === "nodetool"
        ? { kind: "output", label: st.k8cReadOutput }
        : { kind: "log", label: `${st.k8cReadLog} ${row.log_target.container}` },
    );
  }
  if (row.row === "node") {
    out.push({ kind: "metrics", label: st.k8cReadMetrics });
    out.push({ kind: "snapshots", label: st.k8cReadSnapshots });
  }
  if (row.row === "reaper") out.push({ kind: "repairs", label: st.k8cReadRepairs });
  return out;
}

/** Le panneau : les faits de la ligne, ses constats, ceux du cluster, et la lecture ouverte. */
function K8cDetail({
  st,
  payload,
  row,
  reading,
  onRead,
  onCloseReading,
}: {
  st: Strings;
  payload: K8ssandraPayload;
  row: K8cRow | null;
  reading: OpenReading | null;
  onRead: (kind: ReadingKind, label: string) => void;
  onCloseReading: () => void;
}) {
  const reads = row ? readingsOf(row, st) : [];
  return (
    <div className="detail">
      {row && <RowFacts st={st} row={row} />}

      {row && row.hints.length > 0 && <Hints title={st.velProblems} hints={row.hints} />}
      {payload.cluster_hints.length > 0 && <Hints title="cluster" hints={payload.cluster_hints} />}

      {reads.length > 0 && (
        <>
          <div className="sect">{st.k8cReadings}</div>
          {/* Le contenu que la ligne peut révéler, et les commandes qui le révèlent : le même geste
              referme. Aucune de ces lectures n'est relue au rafraîchissement. */}
          <div className="k8c-reads">
            {reads.map((r) => (
              <button
                key={r.kind}
                className="inv-pill"
                aria-pressed={reading?.kind === r.kind}
                onClick={() => (reading?.kind === r.kind ? onCloseReading() : onRead(r.kind, r.label))}
              >
                {r.label}
              </button>
            ))}
            {reading && reading.state !== "loading" && (
              <button className="inv-pill" onClick={() => onRead(reading.kind, reading.label)}>
                {st.k8cReadReload}
              </button>
            )}
          </div>
        </>
      )}

      {reading && <ReadingView st={st} reading={reading} />}
    </div>
  );
}

function Hints({ title, hints }: { title: string; hints: K8cHint[] }) {
  return (
    <>
      <div className="sect">{title}</div>
      <ul className="hints">
        {hints.map((h, i) => (
          <li key={i} className={h.level}>
            {h.text}
          </li>
        ))}
      </ul>
    </>
  );
}

function ReadingView({ st, reading }: { st: Strings; reading: OpenReading }) {
  // La lecture arrive sous les faits de la ligne, souvent hors du panneau visible : elle se ramène
  // sous les yeux à son arrivée, comme la progression d'un drain.
  const ref = useRef<HTMLDivElement>(null);
  const arrived = reading.state !== "loading";
  useEffect(() => {
    ref.current?.scrollIntoView({ block: "nearest" });
  }, [reading.uid, reading.kind, arrived]);
  return (
    <div ref={ref}>
      <ReadingBody st={st} reading={reading} />
    </div>
  );
}

function ReadingBody({ st, reading }: { st: Strings; reading: OpenReading }) {
  const state = reading.state;
  if (state === "loading") return <p className="dim">{st.k8cReadLoading}</p>;
  if ("error" in state) return <p className="err">{state.error}</p>;
  const r = state;

  switch (r.kind) {
    case "log":
    case "output":
      return (
        <>
          <div className="sect">{reading.label}</div>
          {r.data.error && <p className="err">{r.data.error}</p>}
          <pre className="logs">{r.data.lines.length ? r.data.lines.join("\n") : st.k8cReadEmpty}</pre>
        </>
      );
    case "metrics": {
      const m = r.data;
      return (
        <>
          {m.error && <p className="err">{m.error}</p>}
          {m.pools && (
            <>
              <div className="sect">{st.k8cPools}</div>
              {m.pools.length === 0 ? (
                <p className="dim">{st.k8cReadEmpty}</p>
              ) : (
                <dl className="facts">
                  {m.pools.map((p) => (
                    <Fact key={p.name} k={p.name} tone={p.pressured ? "warn" : undefined}>
                      active {p.active} · pending {p.pending} · blocked {p.blocked}
                    </Fact>
                  ))}
                </dl>
              )}
            </>
          )}
          {m.dropped && m.dropped.length > 0 && (
            <>
              <div className="sect">{st.k8cDropped}</div>
              <dl className="facts">
                {m.dropped.map((d) => (
                  <Fact key={d.kind} k={d.kind} tone="warn">
                    {d.count}
                  </Fact>
                ))}
              </dl>
            </>
          )}
          {m.pools && (
            <>
              <div className="sect">{st.k8cCompactions}</div>
              <dl className="facts">
                <Fact k="pending">{m.pending_compactions ?? "—"}</Fact>
                <Fact k="completed">{m.completed_compactions ?? "—"}</Fact>
                <Fact k="bytes compacted">{m.bytes_compacted ?? "—"}</Fact>
              </dl>
            </>
          )}
          <div className="sect">{st.k8cStreams}</div>
          {/* Une liste de sessions vide est une réponse, pas un échec : rien ne streame. */}
          {m.streams.length === 0 ? (
            <p className="dim">{st.k8cNoStreams}</p>
          ) : (
            m.streams.map((session, i) => (
              <dl className="facts" key={i}>
                {session.map(([k, v]) => (
                  <Fact key={k} k={k}>
                    {v}
                  </Fact>
                ))}
              </dl>
            ))
          )}
        </>
      );
    }
    case "snapshots": {
      const s = r.data;
      return (
        <>
          <div className="sect">{st.k8cSnapshots}</div>
          {s.error && <p className="err">{s.error}</p>}
          {!s.error && s.tags.length === 0 && <p className="dim">{st.k8cNoSnapshots}</p>}
          {s.tags.map((t) => (
            <div className="k8c-snap" key={t.tag}>
              <div className="mono">{t.tag}</div>
              {/* Les deux tailles côte à côte : un snapshot est un répertoire de liens durs, et
                  seule la première revient quand on l'efface. */}
              <div className="dim">
                {t.reclaimable} {st.k8cSnapReclaimable} · {t.on_disk} {st.k8cSnapShared} · {t.tables}{" "}
                {st.k8cSnapTables} · {t.created !== null ? ago(t.created) : st.k8cSnapNoDate}
              </div>
              {t.keyspaces.length > 0 && <div className="dim">{t.keyspaces.join(", ")}</div>}
              {t.origin && <div className="warn">{t.origin}</div>}
            </div>
          ))}
          {s.tags.length > 0 && s.total && (
            <p>
              <span className="mono">{s.total}</span> <span className="dim">{st.k8cSnapTotal}</span>
            </p>
          )}
          {s.partial && <p className="dim">{st.k8cSnapPartial}</p>}
        </>
      );
    }
    case "repairs": {
      const rp = r.data;
      return (
        <>
          <div className="sect">{st.k8cRepairs}</div>
          {rp.error && <p className="err">{rp.error}</p>}
          {!rp.error && rp.rows.length === 0 && <p className="dim">{st.k8cReadEmpty}</p>}
          <dl className="facts">
            {rp.rows.map((x, i) => (
              <Fact key={`${x.keyspace}-${i}`} k={x.keyspace}>
                {x.state || "—"} · {x.interval || "—"} · {x.tables || "—"}
              </Fact>
            ))}
          </dl>
        </>
      );
    }
  }
}

function Fact({
  k,
  tone,
  children,
}: {
  k: string;
  tone?: "ok" | "warn" | "err" | "dim";
  children: ReactNode;
}) {
  return (
    <>
      <dt>{k}</dt>
      <dd className={tone}>{children}</dd>
    </>
  );
}

/** Les faits de la ligne, dans l'ordre et sous les noms du panneau de détail du TUI. */
function RowFacts({ st, row }: { st: Strings; row: K8cRow }) {
  const dash = (v: string) => v || "—";
  const nodes = (names: string[]) =>
    names.length === 0
      ? "—"
      : names.length <= 4
        ? names.join(", ")
        : `${names.slice(0, 4).join(", ")}, … (+${names.length - 4})`;
  const stamp = (t: number | null) =>
    t === null
      ? st.k8cNever
      : t > nowSecs()
        ? st.k8cIn.replace("{age}", span(t - nowSecs()))
        : st.k8cAgo.replace("{age}", ago(t));
  const conditions = (list: [string, string][]) =>
    list.length > 0 && (
      <>
        <div className="sect">{st.k8cLblConditions}</div>
        <dl className="facts">
          {list.map(([k, v]) => (
            <Fact key={k} k={k}>
              {v}
            </Fact>
          ))}
        </dl>
      </>
    );

  switch (row.row) {
    case "cluster":
      return (
        <>
          <dl className="facts">
            <Fact k="serverType">{dash(row.server_type)}</Fact>
            <Fact k="serverVersion">{dash(row.server_version)}</Fact>
            <Fact k="auth">{row.auth === null ? st.k8cUnknown : String(row.auth)}</Fact>
            <Fact k="datacenters">{nodes(row.datacenters)}</Fact>
            <Fact k="reaper">{String(row.reaper_enabled)}</Fact>
            <Fact k="stargate">{String(row.stargate_enabled)}</Fact>
          </dl>
          <div className="sect">{st.k8cLblMedusa}</div>
          {row.medusa ? (
            <dl className="facts">
              <Fact k="storageProvider">{dash(row.medusa.provider)}</Fact>
              <Fact k="bucketName">{dash(row.medusa.bucket)}</Fact>
              <Fact k="prefix">{dash(row.medusa.prefix)}</Fact>
              <Fact k="region">{dash(row.medusa.region)}</Fact>
              <Fact k="storageSecretRef">{dash(row.medusa.secret)}</Fact>
              <Fact k="maxBackupAge">{row.medusa.max_backup_age ?? "—"}</Fact>
              <Fact k="maxBackupCount">{row.medusa.max_backup_count ?? "—"}</Fact>
            </dl>
          ) : (
            <p className="warn">{st.k8cNoMedusa}</p>
          )}
          {conditions(row.conditions)}
        </>
      );
    case "datacenter":
      return (
        <>
          <dl className="facts">
            <Fact k="clusterName">{dash(row.cluster_name)}</Fact>
            <Fact k="serverType">{dash(row.server_type)}</Fact>
            <Fact k="serverVersion">{dash(row.server_version)}</Fact>
            <Fact k="size">{row.size}</Fact>
            <Fact k="racks">{nodes(row.racks)}</Fact>
            <Fact k="stopped" tone={row.stopped ? "err" : undefined}>
              {String(row.stopped)}
            </Fact>
            <Fact k="operatorProgress">{dash(row.progress)}</Fact>
            <Fact k="storageClassName">{dash(row.storage_class)}</Fact>
            <Fact k="declaredStorage">{dash(row.declared_storage)}</Fact>
          </dl>
          {conditions(row.conditions)}
        </>
      );
    case "remote_dc":
      return (
        <>
          <dl className="facts">
            <Fact k="k8sContext">{row.context}</Fact>
            <Fact k="K8ssandraCluster">{row.cluster}</Fact>
            <Fact k="clusterName">{dash(row.cluster_name)}</Fact>
            {row.ring_name !== row.name && <Fact k="datacenterName">{row.ring_name}</Fact>}
            <Fact k="size">{row.size}</Fact>
            <Fact k="operatorProgress">{dash(row.progress)}</Fact>
          </dl>
          {row.node_statuses.length > 0 && (
            <>
              <div className="sect">nodeStatuses</div>
              <dl className="facts">
                {row.node_statuses.map(([pod, id]) => (
                  <Fact key={pod} k={pod}>
                    {dash(id)}
                  </Fact>
                ))}
              </dl>
            </>
          )}
          {conditions(row.conditions)}
        </>
      );
    case "remote_node":
      return (
        <>
          <dl className="facts">
            <Fact k="datacenter">{dash(row.datacenter)}</Fact>
            <Fact k="rack">{dash(row.rack)}</Fact>
            <Fact k="hostID">{dash(row.host_id)}</Fact>
          </dl>
          <div className="sect">{st.k8cLblRing}</div>
          <dl className="facts">
            <Fact k="status" tone={row.state_tone === "ok" ? "ok" : "err"}>
              {row.ring.status_code}
            </Fact>
            <Fact k="state">{dash(row.ring.state)}</Fact>
            <Fact k="address">{dash(row.ring.ip)}</Fact>
            <Fact k="load">{row.load_text}</Fact>
            <Fact k="tokens">{row.ring.tokens}</Fact>
            <Fact k="schema">{dash(row.ring.schema)}</Fact>
          </dl>
        </>
      );
    case "node":
      return (
        <>
          <dl className="facts">
            <Fact k="cluster">{dash(row.cluster)}</Fact>
            <Fact k="datacenter">{dash(row.datacenter)}</Fact>
            <Fact k="rack">{dash(row.rack)}</Fact>
            <Fact k="phase">{dash(row.phase)}</Fact>
            <Fact k="ready" tone={row.ready ? undefined : "err"}>
              {String(row.ready)}
            </Fact>
            <Fact k="restarts">{row.restarts}</Fact>
            <Fact k="nodeName">{dash(row.node_name)}</Fact>
            <Fact k="hostID">{dash(row.host_id)}</Fact>
            <Fact k="node-state">{dash(row.node_state)}</Fact>
          </dl>
          <div className="sect">{st.k8cLblRing}</div>
          {row.ring ? (
            <dl className="facts">
              <Fact k="status" tone={row.state_tone === "ok" ? "ok" : "err"}>
                {row.ring.status_code}
              </Fact>
              <Fact k="state">{dash(row.ring.state)}</Fact>
              <Fact k="address">{dash(row.ring.ip)}</Fact>
              <Fact k="podIP">{dash(row.pod_ip)}</Fact>
              <Fact k="load">{row.load_text}</Fact>
              <Fact k="tokens">{row.ring.tokens}</Fact>
              <Fact k="schema">{dash(row.ring.schema)}</Fact>
            </dl>
          ) : (
            // Pas « down » : c'est l'API de management qui n'a pas été jointe.
            <p className="dim">{st.k8cRingNotRead}</p>
          )}
          {row.streaming && (
            <>
              <div className="sect">{st.k8cStreams}</div>
              <dl className="facts">
                <Fact k="operation">{dash(row.streaming.operation)}</Fact>
                <Fact k="open sessions">{row.streaming_text}</Fact>
                <Fact k="files">{row.streaming.files_to_receive}</Fact>
                <Fact k="peers">{row.streaming.peers}</Fact>
                <Fact k="load">{row.load_text}</Fact>
              </dl>
            </>
          )}
          {row.claims.length > 0 && (
            <>
              <div className="sect">{st.k8cLblVolumes}</div>
              <dl className="facts">
                {row.claims.map(([claim, size]) => (
                  <Fact key={claim} k={claim}>
                    {dash(size)}
                  </Fact>
                ))}
              </dl>
            </>
          )}
        </>
      );
    case "schedule":
      return (
        <dl className="facts">
          <Fact k="cronSchedule">{dash(row.cron)}</Fact>
          <Fact k="backupType">{dash(row.backup_type)}</Fact>
          <Fact k="cassandraDatacenter">{dash(row.datacenter)}</Fact>
          <Fact k="disabled">{String(row.disabled)}</Fact>
          <Fact k="lastExecution">{stamp(row.last_execution)}</Fact>
          <Fact k="nextSchedule">{stamp(row.next_schedule)}</Fact>
          <Fact k={st.k8cLblRuns}>{row.runs.length}</Fact>
        </dl>
      );
    case "job":
      return (
        <>
          <dl className="facts">
            <Fact k="backupType">{dash(row.backup_type)}</Fact>
            <Fact k="cassandraDatacenter">{dash(row.datacenter)}</Fact>
            <Fact k="startTime">{stamp(row.start)}</Fact>
            <Fact k="finishTime">{stamp(row.finish)}</Fact>
            <Fact k={st.k8cLblDuration}>{row.span}</Fact>
          </dl>
          {/* La couverture, que Medusa n'écrit nulle part : c'est elle qui dit si le run se
              restaure. */}
          <div className="sect">{st.k8cLblCoverage}</div>
          <dl className="facts">
            <Fact k={st.k8cLblExpected}>{row.expected ?? st.k8cUnknown}</Fact>
            <Fact k={st.k8cLblFinished}>
              {row.finished.length} · {nodes(row.finished)}
            </Fact>
            <Fact k={st.k8cLblFailed} tone={row.failed.length > 0 ? "err" : undefined}>
              {row.failed.length} · {nodes(row.failed)}
            </Fact>
            {row.in_progress.length > 0 && <Fact k={st.k8cLblInProgress}>{nodes(row.in_progress)}</Fact>}
            <Fact k={st.k8cLblCatalogued}>{String(row.in_catalogue)}</Fact>
          </dl>
        </>
      );
    case "backup":
      return (
        <dl className="facts">
          <Fact k="backupType">{dash(row.backup_type)}</Fact>
          <Fact k="cassandraDatacenter">{dash(row.datacenter)}</Fact>
          <Fact k="startTime">{stamp(row.start)}</Fact>
          <Fact k="finishTime">{stamp(row.finish)}</Fact>
          <Fact k={st.k8cLblDuration}>{row.span}</Fact>
          {/* Seulement quand l'API les porte : jusqu'à l'operator 1.9 ils n'existent pas, et un
              « 0/0 » serait un fait inventé. */}
          {row.total_nodes !== null && (
            <Fact k={st.k8cLblCoverage}>
              {row.finished_nodes ?? 0}/{row.total_nodes}
            </Fact>
          )}
          {row.status && <Fact k="status">{row.status}</Fact>}
        </dl>
      );
    case "restore":
      return (
        <dl className="facts">
          <Fact k="backup">{dash(row.backup)}</Fact>
          <Fact k="cassandraDatacenter">{dash(row.datacenter)}</Fact>
          <Fact k="startTime">{stamp(row.start)}</Fact>
          <Fact k="finishTime">{stamp(row.finish)}</Fact>
          <Fact k={st.k8cLblDuration}>{row.span}</Fact>
          <Fact k="restoreKey">{dash(row.restore_key)}</Fact>
          <Fact k="restorePrepared">{String(row.restore_prepared)}</Fact>
          {/* Le champ qui fait d'une restauration une panne : le datacenter a été arrêté pour elle. */}
          <Fact k="datacenterStopped">{stamp(row.datacenter_stopped)}</Fact>
          {row.failed.length > 0 && (
            <Fact k={st.k8cLblFailed} tone="err">
              {nodes(row.failed)}
            </Fact>
          )}
          {row.in_progress.length > 0 && <Fact k={st.k8cLblInProgress}>{nodes(row.in_progress)}</Fact>}
        </dl>
      );
    case "task":
      return (
        <dl className="facts">
          <Fact k="operation">{dash(row.operation)}</Fact>
          <Fact k="cassandraDatacenter">{dash(row.datacenter)}</Fact>
          <Fact k="startTime">{stamp(row.start)}</Fact>
          <Fact k="finishTime">{stamp(row.finish)}</Fact>
          <Fact k={st.k8cLblDuration}>{row.span}</Fact>
          <Fact k={st.k8cLblFinished}>{nodes(row.finished)}</Fact>
          {row.failed.length > 0 && (
            <Fact k={st.k8cLblFailed} tone="err">
              {nodes(row.failed)}
            </Fact>
          )}
          {row.in_progress.length > 0 && <Fact k={st.k8cLblInProgress}>{nodes(row.in_progress)}</Fact>}
        </dl>
      );
    case "ctask":
      return (
        <>
          <dl className="facts">
            <Fact k="commands">{nodes(row.commands)}</Fact>
            <Fact k="datacenter">{dash(row.datacenter)}</Fact>
            {row.source_dc && <Fact k="source_datacenter">{row.source_dc}</Fact>}
            <Fact k="startTime">{stamp(row.start)}</Fact>
            <Fact k="completionTime">{stamp(row.finish)}</Fact>
            <Fact k={st.k8cLblDuration}>{row.span}</Fact>
            <Fact k="active">{row.active}</Fact>
            <Fact k="succeeded">{row.succeeded}</Fact>
            <Fact k="failed" tone={row.failed > 0 ? "err" : undefined}>
              {row.failed}
            </Fact>
          </dl>
          {/* Le parcours pod par pod : cass-operator les traite un à un, et un DC en rebuild reste
              Ready de bout en bout — c'est ici seulement qu'on voit où il en est. */}
          {row.pods.length > 0 && (
            <>
              <div className="sect">pods</div>
              <dl className="facts">
                {row.progress && <Fact k={st.k8cLblCoverage}>{row.progress}</Fact>}
                {row.pods.map(([pod, phase]) => (
                  <Fact key={pod} k={pod} tone={phase === "ERROR" ? "err" : phase === "COMPLETED" ? "ok" : undefined}>
                    {phase}
                  </Fact>
                ))}
              </dl>
            </>
          )}
        </>
      );
    case "nodetool":
      return (
        <dl className="facts">
          <Fact k="kdt.io/nodetool-command">{dash(row.command)}</Fact>
          <Fact k="kdt.io/nodetool-target">{dash(row.target)}</Fact>
          <Fact k="kdt.io/nodetool-line">{dash(row.line)}</Fact>
          <Fact k="startTime">{stamp(row.start)}</Fact>
          <Fact k="completionTime">{stamp(row.finish)}</Fact>
          <Fact k={st.k8cLblDuration}>{row.span}</Fact>
          <Fact k="active">{row.active}</Fact>
          <Fact k="succeeded">{row.succeeded}</Fact>
          <Fact k="failed" tone={row.failed > 0 ? "err" : undefined}>
            {row.failed}
          </Fact>
          {row.reason && <Fact k="reason">{row.reason}</Fact>}
        </dl>
      );
    case "reaper":
      return (
        <dl className="facts">
          <Fact k="datacenterRef">{dash(row.datacenter)}</Fact>
          <Fact k="progress">{dash(row.progress)}</Fact>
          <Fact k="ready" tone={row.ready ? undefined : "warn"}>
            {String(row.ready)}
          </Fact>
          <Fact k="uiUserSecretRef">{dash(row.ui_secret)}</Fact>
          <Fact k={st.k8cLblService}>{dash(row.service)}</Fact>
        </dl>
      );
    case "group":
      return (
        <dl className="facts">
          <Fact k={st.k8cLblObjects}>{row.info}</Fact>
        </dl>
      );
  }
}

const RANK: Record<K8cHint["level"], number> = { info: 1, warn: 2, danger: 3 };

function worst(hints: K8cHint[]): K8cHint["level"] | "" {
  return hints.reduce<K8cHint["level"] | "">(
    (acc, h) => (acc === "" || RANK[h.level] > RANK[acc] ? h.level : acc),
    "",
  );
}

function hintClass(hints: K8cHint[]): string {
  const w = worst(hints);
  return w === "danger" ? "vel-danger" : w === "warn" ? "vel-warn" : "vel-plain";
}

function hintTone(hints: K8cHint[]): string {
  const w = worst(hints);
  return w === "danger" ? "err" : w === "warn" ? "warn" : "dim";
}

function nowSecs(): number {
  return Math.floor(Date.now() / 1000);
}

/** « il y a 3h » sous la forme compacte du TUI : `3h`, `2d`, `41d`. */
function ago(epoch: number): string {
  return span(Math.max(0, nowSecs() - epoch));
}

function span(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h`;
  return `${Math.floor(secs / 86400)}d`;
}

function matches(row: K8cRow, needle: string): boolean {
  const parts = [row.name, row.namespace, row.kind_label, row.state, row.info, ...row.hints.map((h) => h.text)];
  return parts.join(" ").toLowerCase().includes(needle);
}
