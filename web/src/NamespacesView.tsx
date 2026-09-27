// La vue Namespaces : chaque namespace comme un objet — phase, provenance, âge — avec ses labels et
// ses annotations dans le panneau.
//
// Les quatre colonnes du TUI, dans son ordre : `NAME STATUS ORIGIN AGE`. La phase et son ton, la
// provenance et l'enregistrement viennent de `kdt::namespaces`. L'`Entrée` du TUI — restreindre la
// portée à ce namespace et revenir aux évènements — devient un item du hamburger ; sa copie `c` du
// manifeste est celle de l'overlay YAML.

import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import type { Lang, Strings } from "./i18n";
import { InspectPanel, PanelToggle, Splitter, ViewBody, type PanelTab } from "./panel";
import { BulkDeletePane, RowMenu, type ObjectTab } from "./objects";
import { RowCheckbox, SelectionBar, SelectionHead, useMultiSelect } from "./selection";
import type { NamespaceRow } from "./types";
import { cols } from "./table";

/** `NAME STATUS ORIGIN AGE`, entre la case de sélection et le hamburger. NAME est la piste souple :
 * c'est lui qui distingue les lignes. */
const COLUMNS = "34px minmax(24ch,1fr) fit-content(14ch) fit-content(36ch) 6ch 34px";

function matches(ns: NamespaceRow, needle: string): boolean {
  return [ns.name, ns.phase, ...ns.labels.flat()].join(" ").toLowerCase().includes(needle);
}

export default function NamespacesView({
  lang,
  st,
  query,
  panelHeight,
  onPanelHeight,
  panelOpen,
  onPanelOpen,
  onNeedsAuth,
  onOpenEvents,
}: {
  lang: Lang;
  st: Strings;
  query: string;
  panelHeight: number;
  onPanelHeight: (h: number) => void;
  panelOpen: boolean;
  onPanelOpen: (open: boolean) => void;
  onNeedsAuth: (message: string) => void;
  /** Le `Entrée` du TUI : la portée sur ce namespace, et retour aux évènements. */
  onOpenEvents: (namespace: string) => void;
}) {
  const [items, setItems] = useState<NamespaceRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<PanelTab>("detail");
  const { checked, toggle, clear, setAll } = useMultiSelect();
  const [bulkOpen, setBulkOpen] = useState(false);

  const load = useCallback(async () => {
    try {
      const data = await api.namespacesView(lang);
      setItems(data.namespaces);
      setError(null);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else if (e instanceof ApiError) setError(e.message);
      else setError(String(e));
      // Un refus n'est pas un cluster sans namespace : ce qui a été lu reste, l'erreur le dit.
      setItems((prev) => prev ?? []);
    }
  }, [lang, onNeedsAuth]);

  useEffect(() => {
    void load();
    // Soixante secondes, comme le TUI : les namespaces se créent et se suppriment rarement.
    const timer = window.setInterval(() => void load(), 60000);
    return () => window.clearInterval(timer);
  }, [load]);

  const rows = useMemo(() => items ?? [], [items]);
  const needle = query.trim().toLowerCase();
  const display = useMemo(
    () => (needle ? rows.filter((n) => matches(n, needle)) : rows),
    [rows, needle],
  );
  const selectedRow = useMemo(() => rows.find((n) => n.uid === selected) ?? null, [rows, selected]);
  const terminating = rows.filter((n) => n.phase === "Terminating").length;

  return (
    <>
      {panelOpen && (
        <>
          <InspectPanel
            record={selectedRow?.record ?? null}
            tab={tab}
            onTab={setTab}
            onClose={() => onPanelOpen(false)}
            height={panelHeight}
            lang={lang}
            st={st}
            detail={{
              label: st.nsDetail,
              node: selectedRow ? <Detail ns={selectedRow} st={st} /> : null,
            }}
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds">
        {items && (
          <div className="tally">
            <span>{rows.length} namespaces</span>
            {/* L'écart seul se compte : un namespace qui ne finit pas de partir. */}
            {terminating > 0 && <span className="warn">{terminating} Terminating</span>}
          </div>
        )}
        <div className="right">
          <SelectionBar
            keys={display.map((n) => n.uid)}
            checked={checked}
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
        record={selectedRow?.record ?? null}
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
                    records={rows.filter((n) => checked.has(n.uid)).map((n) => n.record)}
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
        {items === null ? (
          <div className="center" />
        ) : display.length === 0 ? (
          <div className="center">
            <div className="box">
              {/* Un refus n'est pas un cluster sans namespace : il prend la place du titre. */}
              {error && !needle ? (
                <p className="err">{error}</p>
              ) : (
                <h2>{needle ? st.emptyTitle : st.nsEmpty}</h2>
              )}
            </div>
          </div>
        ) : (
          <div className="tbl" style={cols(COLUMNS)}>
            <div className="thead">
              <div className="tr">
                <SelectionHead />
                <div className="cell">NAME</div>
                <div className="cell">STATUS</div>
                <div className="cell">ORIGIN</div>
                <div className="cell num">AGE</div>
                <div className="cell act" />
              </div>
            </div>
            <div className="tbody">
              {display.map((ns) => (
                <Line
                  key={ns.uid}
                  ns={ns}
                  lang={lang}
                  st={st}
                  selected={selected === ns.uid}
                  onSelect={() => {
                    setSelected(ns.uid);
                    setTab("detail");
                  }}
                  onOpenTab={(t) => {
                    setSelected(ns.uid);
                    setTab(t);
                  }}
                  onNeedsAuth={onNeedsAuth}
                  onOpenEvents={() => onOpenEvents(ns.name)}
                  checked={checked.has(ns.uid)}
                  onToggleCheck={() => toggle(ns.uid)}
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
        <span style={{ marginLeft: "auto" }}>{st.nsScopeless}</span>
      </div>
    </>
  );
}

function Line({
  ns,
  lang,
  st,
  selected,
  onSelect,
  onOpenTab,
  onNeedsAuth,
  onOpenEvents,
  checked,
  onToggleCheck,
}: {
  ns: NamespaceRow;
  lang: Lang;
  st: Strings;
  selected: boolean;
  onSelect: () => void;
  onOpenTab: (tab: ObjectTab) => void;
  onNeedsAuth: (message: string) => void;
  onOpenEvents: () => void;
  checked: boolean;
  onToggleCheck: () => void;
}) {
  return (
    <div
      className={`tr sev-${ns.record.tone}`}
      aria-selected={selected}
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSelect();
      }}
    >
      <RowCheckbox checked={checked} onToggle={onToggleCheck} label={st.selectRow} st={st} />
      <div className="cell id wrap">{ns.name}</div>
      <div className={`cell tone-${ns.phase_tone}`}>{ns.phase || "—"}</div>
      <div className="cell dim">{ns.provenance_label}</div>
      <div className="cell num dim">{ns.age}</div>
      <div className="cell act">
        <RowMenu record={ns.record} lang={lang} st={st} onOpen={onOpenTab} onNeedsAuth={onNeedsAuth}>
          {({ close }) => (
            <button
              className="menu-item"
              onClick={() => {
                close();
                onOpenEvents();
              }}
            >
              <span className="lbl">{st.nsOpenEvents}</span>
              <span className="desc">{st.nsOpenEventsHelp}</span>
            </button>
          )}
        </RowMenu>
      </div>
    </div>
  );
}

/** La forme du panneau du TUI : phase, origine, âge, puis labels et annotations tels qu'écrits. */
function Detail({ ns, st }: { ns: NamespaceRow; st: Strings }) {
  return (
    <div className="detail">
      <dl className="facts">
        <dt>{st.nsPhase}</dt>
        <dd className={ns.phase_tone === "dim" ? undefined : ns.phase_tone}>{ns.phase || "—"}</dd>
        <dt>{st.nsOrigin}</dt>
        <dd>{ns.provenance_label}</dd>
        <dt>{st.nsAge}</dt>
        <dd>{ns.age}</dd>
      </dl>
      <KeyValues title="Labels" kv={ns.labels} />
      <KeyValues title="Annotations" kv={ns.annotations} />
    </div>
  );
}

function KeyValues({ title, kv }: { title: string; kv: Array<[string, string]> }) {
  if (kv.length === 0) return null;
  return (
    <>
      <div className="sect">{title}</div>
      <dl className="facts kv">
        {kv.map(([k, v]) => (
          <Fragment key={k}>
            <dt>{k}</dt>
            <dd className="wrap">{v}</dd>
          </Fragment>
        ))}
      </dl>
    </>
  );
}
