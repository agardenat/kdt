// La vue évènements : le flux du cluster dans la portée choisie.
//
// Extraite de `App.tsx` quand une deuxième vue est arrivée — la coquille (barre de portée, rail,
// filtre) est partagée, mais chaque vue tient son propre chargement, sa sélection et sa ligne
// d'état. Le contenu n'a pas bougé au passage.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import type { Lang, Strings } from "./i18n";
import { InspectPanel, Splitter, type PanelTab } from "./panel";
import { ObjectActions } from "./objects";
import { age, toneLabel, type EventRecord } from "./types";

/**
 * Les colonnes de la vue évènements : mêmes colonnes, même ordre et mêmes proportions que le TUI.
 *
 * Côté Rust les largeurs sont en caractères — 5, 4, 20, 14, 40, 22, 4, puis le reste pour le
 * message. Transposées ici en pistes de grille, avec un minimum pour que rien ne s'écrase et un
 * `fr` sur les deux colonnes qui méritent la place restante.
 */
const COLUMNS =
  "52px 46px minmax(120px,20ch) minmax(96px,14ch) minmax(180px,1.4fr) minmax(150px,22ch) 40px minmax(240px,2fr)";

type Filter = "all" | "warnings";

export default function EventsView({
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
  const [filter, setFilter] = useState<Filter>("all");
  const [rows, setRows] = useState<EventRecord[]>([]);
  const [selected, setSelected] = useState<EventRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshedAt, setRefreshedAt] = useState<number | null>(null);
  const [tab, setTab] = useState<PanelTab>("status");
  const bodyRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    try {
      const payload = await api.events(namespaces);
      setRows(payload.rows);
      setError(null);
      setRefreshedAt(Date.now());
    } catch (e) {
      if (e instanceof NeedsAuth) {
        onNeedsAuth(e.message);
      } else if (e instanceof ApiError) {
        // Un refus de l'apiserver — le RBAC, le plus souvent. La liste précédente reste à
        // l'écran : la vider ferait croire à un cluster qui s'est tu.
        setError(e.message);
      } else {
        setError(String(e));
      }
    }
  }, [namespaces, onNeedsAuth]);

  useEffect(() => {
    void load();
    // Même cadence que le TUI pour les évènements : assez pour suivre, assez peu pour ne pas
    // marteler l'apiserver avec un `list` complet.
    const timer = window.setInterval(() => void load(), 5000);
    return () => window.clearInterval(timer);
  }, [load]);

  // Le flux se lit par le bas : tant qu'aucune ligne n'est retenue, la vue suit la plus récente,
  // comme le curseur du TUI qui reste sur `last`. Dès qu'une ligne est sélectionnée, la vue
  // s'ancre — sinon on perdrait de vue ce qu'on est en train d'examiner à chaque rafraîchissement.
  useEffect(() => {
    if (selected) return;
    const body = bodyRef.current;
    if (body) body.scrollTop = body.scrollHeight;
  }, [rows, selected]);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return rows.filter((r) => {
      if (filter === "warnings" && r.tone === "ok") return false;
      if (!needle) return true;
      return [r.reason, r.kind, r.namespace, r.name, r.message, r.component]
        .join(" ")
        .toLowerCase()
        .includes(needle);
    });
  }, [rows, query, filter]);

  const warnings = rows.filter((r) => r.tone !== "ok").length;

  return (
    <>
      {selected && panelOpen && (
        <>
          <InspectPanel
            record={selected}
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
        <button role="tab" aria-selected={filter === "all"} onClick={() => setFilter("all")}>
          {lang === "fr" ? "Tous" : "All"}
          <span className="count">{rows.length}</span>
        </button>
        <button
          role="tab"
          aria-selected={filter === "warnings"}
          onClick={() => setFilter("warnings")}
        >
          Warnings
          <span className="count">{warnings}</span>
        </button>
        <div className="right">
          {/* Les trois gestes de kdt qui portent sur n'importe quel objet — `y`, `e`, `h` dans le
              TUI. Ils vivent dans la barre, comme toutes les actions, et ouvrent le panneau du
              haut sur ce qu'ils montrent. */}
          <ObjectActions
            record={selected}
            lang={lang}
            st={st}
            onOpen={(t) => {
              setTab(t);
              onPanelOpen(true);
            }}
            onNeedsAuth={onNeedsAuth}
          />
          {selected && (
            <button
              className="panel-toggle"
              onClick={() => onPanelOpen(!panelOpen)}
              title={lang === "fr" ? "Panneau d'inspection" : "Inspection panel"}
            >
              {panelOpen
                ? lang === "fr"
                  ? "▾ replier"
                  : "▾ collapse"
                : lang === "fr"
                  ? "▸ panneau"
                  : "▸ panel"}
            </button>
          )}
          {refreshedAt && <span>{st.refreshed.replace("{age}", age(new Date(refreshedAt).toISOString()))}</span>}
        </div>
      </div>

      <div className="body" ref={bodyRef}>
        {visible.length === 0 ? (
          <div className="center">
            <div className="box">
              <h2>{st.emptyTitle}</h2>
              {error && <p className="err">{error}</p>}
              <p>
                {st.emptyScope}{" "}
                <code>{namespaces.length ? namespaces.join(", ") : st.scopeAll}</code>
              </p>
            </div>
          </div>
        ) : (
          <EventTable
            rows={visible}
            selected={selected}
            onSelect={(r) => {
              setSelected(r);
              onPanelOpen(true);
            }}
          />
        )}
      </div>

      <div className="statusbar">
        <span>
          {visible.length} {st.rows}
        </span>
        <span>
          {st.scopeLabel}: {namespaces.length ? namespaces.join(",") : st.scopeAll}
        </span>
        {error && <span className="err">{error}</span>}
        <span style={{ marginLeft: "auto" }}>
          <span className="kbd">/</span> {st.hintFilter} <span className="kbd">Esc</span>{" "}
          {st.hintClose}
        </span>
      </div>
    </>
  );
}

function EventTable({
  rows,
  selected,
  onSelect,
}: {
  rows: EventRecord[];
  selected: EventRecord | null;
  onSelect: (r: EventRecord) => void;
}) {
  return (
    <div className="tbl">
      <div className="thead">
        <div className="tr" style={{ gridTemplateColumns: COLUMNS }}>
          <div className="cell num">AGE</div>
          <div className="cell">SEV</div>
          <div className="cell">NS</div>
          <div className="cell">KIND</div>
          <div className="cell">NAME</div>
          <div className="cell">REASON</div>
          <div className="cell num">CNT</div>
          <div className="cell">MESSAGE</div>
        </div>
      </div>
      <div className="tbody">
        {rows.map((r) => (
          <div
            key={r.uid || `${r.namespace}/${r.name}/${r.time}`}
            className={`tr sev-${r.tone}`}
            style={{ gridTemplateColumns: COLUMNS }}
            aria-selected={selected?.uid === r.uid}
            tabIndex={0}
            onClick={() => onSelect(r)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onSelect(r);
            }}
          >
            <div className="cell num">{age(r.time)}</div>
            <div className="cell">
              <span className={`st ${r.tone}`}>{toneLabel(r.tone)}</span>
            </div>
            <div className="cell mono">{r.namespace}</div>
            <div className="cell mono">{r.kind}</div>
            <div className="cell id">{r.name}</div>
            <div className={`cell reason-${r.tone}`}>{r.reason}</div>
            <div className="cell num">x{r.count}</div>
            <div className="cell">{r.message}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
