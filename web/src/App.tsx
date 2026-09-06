// L'ossature validée sur maquette : barre de portée persistante, rail des vues, onglets de
// monde, drawer de détail.
//
// Une seule vue répond pour l'instant — les évènements. Les autres sont dans le rail, désactivées,
// parce que la longueur du rail est une décision d'ergonomie qu'on ne peut juger qu'en la voyant
// entière.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import { storedLang, storeLang, strings, type Lang } from "./i18n";
import { apply as applyTheme, stored as storedTheme, toggled, type Theme } from "./theme";
import {
  age,
  toneLabel,
  type EventRecord,
  type Identity,
  type PodLogs,
  type RelatedSection,
  type StatusPayload,
} from "./types";

/** Les vues, dans l'ordre du rail. `ready` dit celles qui répondent aujourd'hui. */
const VIEWS: Array<{ id: string; label: string; key: string; ready?: boolean }> = [
  { id: "events", label: "Events", key: "e", ready: true },
  { id: "workloads", label: "Workloads", key: "w" },
  { id: "flux", label: "Flux", key: "f" },
  { id: "argocd", label: "Argo CD", key: "a" },
  { id: "velero", label: "Velero", key: "v" },
  { id: "capacity", label: "Capacity", key: "c" },
  { id: "storage", label: "Storage", key: "s" },
  { id: "certs", label: "Certs", key: "t" },
  { id: "rbac", label: "RBAC", key: "r" },
  { id: "kyverno", label: "Kyverno", key: "k" },
  { id: "identity", label: "Identity", key: "i" },
  { id: "netpol", label: "NetPol", key: "n" },
  { id: "diagnostic", label: "Diagnostic", key: "d" },
];

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

/** Hauteur du panneau au premier affichage, et celle que le double-clic sur la poignée rétablit. */
const DEFAULT_PANEL_HEIGHT = 300;

/**
 * Bornes du panneau, calculées à chaque fois plutôt que figées.
 *
 * Le plancher garde les onglets et deux lignes lisibles ; le plafond garde toujours quelques
 * lignes de table sous les yeux, sans quoi le double panneau ne servirait plus à rien.
 */
function clampPanelHeight(height: number): number {
  const ceiling = Math.max(160, window.innerHeight - 260);
  return Math.min(Math.max(height, 120), ceiling);
}

export default function App() {
  const [lang, setLang] = useState<Lang>(storedLang);
  const [theme, setTheme] = useState<Theme>(storedTheme);
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [booting, setBooting] = useState(true);

  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [rows, setRows] = useState<EventRecord[]>([]);
  const [selected, setSelected] = useState<EventRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [needsAuth, setNeedsAuth] = useState(false);
  const [refreshedAt, setRefreshedAt] = useState<number | null>(null);

  const [tab, setTab] = useState<PanelTab>("status");
  // Hauteur du panneau, en pixels et retenue d'une session à l'autre. Lire des logs et lire une
  // table ne demandent pas le même partage de l'écran, et ce partage est affaire de goût — donc
  // il se règle plutôt qu'il ne se décrète.
  const [panelHeight, setPanelHeight] = useState(() => {
    try {
      const stored = Number(localStorage.getItem("kdt-panel-h"));
      if (Number.isFinite(stored) && stored > 0) return stored;
    } catch {
      // Stockage bloqué : la hauteur par défaut fait l'affaire.
    }
    return DEFAULT_PANEL_HEIGHT;
  });
  // Replié, le panneau laisse toute la hauteur à la table. Le choix est retenu, comme le
  // `hide_top_panel` que kdt écrit dans sa configuration.
  const [panelOpen, setPanelOpen] = useState(() => {
    try {
      return localStorage.getItem("kdt-panel") !== "closed";
    } catch {
      return true;
    }
  });
  const [scopeOpen, setScopeOpen] = useState(false);
  const filterRef = useRef<HTMLInputElement>(null);
  const bodyRef = useRef<HTMLDivElement>(null);
  const st = strings(lang);

  useEffect(() => applyTheme(theme), [theme]);

  useEffect(() => {
    try {
      localStorage.setItem("kdt-panel", panelOpen ? "open" : "closed");
    } catch {
      // Stockage bloqué : le choix vaut pour l'onglet ouvert, ce n'est pas une erreur.
    }
  }, [panelOpen]);

  useEffect(() => {
    try {
      localStorage.setItem("kdt-panel-h", String(panelHeight));
    } catch {
      // Idem : sans persistance, la hauteur vaut pour l'onglet ouvert.
    }
  }, [panelHeight]);

  // Une fenêtre rétrécie peut rendre la hauteur retenue plus grande que ce qui tient : la
  // ramener dans les bornes évite un panneau qui recouvre toute la table au redimensionnement.
  useEffect(() => {
    const onResize = () => setPanelHeight((h) => clampPanelHeight(h));
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  // Qui est connecté. Tant qu'on ne le sait pas, on n'affiche ni l'application ni l'invitation à
  // se connecter : montrer l'une puis l'autre ferait clignoter la page à chaque chargement.
  useEffect(() => {
    api
      .identity()
      .then(setIdentity)
      .catch(() => setIdentity(null))
      .finally(() => setBooting(false));
  }, []);

  const load = useCallback(async () => {
    try {
      const payload = await api.events(namespaces);
      setRows(payload.rows);
      setError(null);
      setNeedsAuth(false);
      setRefreshedAt(Date.now());
    } catch (e) {
      if (e instanceof NeedsAuth) {
        setNeedsAuth(true);
        setError(e.message);
      } else if (e instanceof ApiError) {
        // Un refus de l'apiserver — le RBAC, le plus souvent. La liste précédente reste à
        // l'écran : la vider ferait croire à un cluster qui s'est tu.
        setError(e.message);
      } else {
        setError(String(e));
      }
    }
  }, [namespaces]);

  useEffect(() => {
    if (!identity) return;
    void load();
    // Même cadence que le TUI pour les évènements : assez pour suivre, assez peu pour ne pas
    // marteler l'apiserver avec un `list` complet.
    const timer = window.setInterval(() => void load(), 5000);
    return () => window.clearInterval(timer);
  }, [identity, load]);

  // `/` met le focus sur le filtre, `Échap` ferme ce qui est ouvert. Deux gestes du TUI qui
  // survivent au changement de média parce qu'ils ne coûtent rien à qui les ignore.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "/" && document.activeElement !== filterRef.current) {
        e.preventDefault();
        filterRef.current?.focus();
      } else if (e.key === "Escape") {
        if (scopeOpen) setScopeOpen(false);
        else if (document.activeElement === filterRef.current) filterRef.current?.blur();
        else if (panelOpen && selected) setPanelOpen(false);
        else if (selected) setSelected(null);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [scopeOpen, selected, panelOpen]);

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

  if (booting) return <div className="center" />;

  if (!identity) {
    return (
      <div className="center">
        <div className="box">
          <h2>kdt</h2>
          <p>
            Cette interface utilise <strong>votre</strong> identité sur le cluster : elle ne voit
            que ce que vos droits vous permettent de voir.
          </p>
          <button className="cta" onClick={() => api.login()}>
            Se connecter
          </button>
        </div>
      </div>
    );
  }

  const warnings = rows.filter((r) => r.tone !== "ok").length;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="name">kdt</span>
        </div>

        <div className="scope">
          <button
            className="scope-btn"
            aria-expanded={scopeOpen}
            onClick={() => setScopeOpen((v) => !v)}
          >
            <span className="lbl">{st.scopeLabel}</span>
            <span className="val">
              {namespaces.length === 0
                ? st.scopeAll
                : namespaces.length === 1
                  ? namespaces[0]
                  : `${namespaces[0]} +${namespaces.length - 1}`}
            </span>
            <span className="chev">▾</span>
          </button>
          {scopeOpen && (
            <ScopePicker
              namespaces={namespaces}
              onChange={setNamespaces}
              onClose={() => setScopeOpen(false)}
              labels={{ title: st.scopeTitle, all: st.scopeAll }}
            />
          )}
        </div>

        <div className="filter">
          <span className="slash">/</span>
          <input
            ref={filterRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={st.filterPlaceholder}
            autoComplete="off"
            spellCheck={false}
          />
          {query && (
            <button className="clear" aria-label={st.filterClear} onClick={() => setQuery("")}>
              ✕
            </button>
          )}
        </div>

        <div className="spacer" />
        <div className="who">
          <span className="sub">{identity.subject}</span>
          {identity.groups.map((g) => (
            <span className="grp" key={g}>
              {g}
            </span>
          ))}
        </div>
        <button
          className="icon-btn"
          title={st.langToggle}
          onClick={() => {
            const next: Lang = lang === "fr" ? "en" : "fr";
            setLang(next);
            storeLang(next);
          }}
        >
          {lang.toUpperCase()}
        </button>
        <button
          className="icon-btn"
          title={st.themeToggle}
          onClick={() => setTheme(toggled(theme))}
        >
          ◐
        </button>
        <button className="icon-btn" title="Se déconnecter" onClick={() => void api.logout()}>
          ⏻
        </button>
      </header>

      <div className="chrome">
        <nav className="rail">
          <div className="rail-hd">{st.views}</div>
          {VIEWS.map((v) => (
            <button
              key={v.id}
              aria-current={v.id === "events"}
              disabled={!v.ready}
              title={v.ready ? undefined : st.notMockedTitle}
            >
              <span>{v.label}</span>
              <span className="k">{v.key}</span>
            </button>
          ))}
        </nav>

        <section className="pane">
          {selected && panelOpen && (
            <>
              <InspectPanel
                record={selected}
                tab={tab}
                onTab={setTab}
                onClose={() => setPanelOpen(false)}
                height={panelHeight}
                lang={lang}
              />
              <Splitter height={panelHeight} onHeight={setPanelHeight} lang={lang} />
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
              {selected && (
                <button
                  className="panel-toggle"
                  onClick={() => setPanelOpen((v) => !v)}
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
              {refreshedAt && <span>{st.refreshed}</span>}
            </div>
          </div>

          <div className="body" ref={bodyRef}>
            {needsAuth ? (
              <div className="center">
                <div className="box">
                  <h2>{lang === "fr" ? "Votre accès a expiré" : "Your access has expired"}</h2>
                  <p>{error}</p>
                  <button className="cta" onClick={() => api.login()}>
                    {lang === "fr" ? "Se reconnecter" : "Sign in again"}
                  </button>
                </div>
              </div>
            ) : visible.length === 0 ? (
              <div className="center">
                <div className="box">
                  <h2>{error ? st.emptyTitle : st.emptyTitle}</h2>
                  {error && <p className="err">{error}</p>}
                  <p>
                    {st.emptyScope} <code>{namespaces.length ? namespaces.join(", ") : st.scopeAll}</code>
                  </p>
                </div>
              </div>
            ) : (
              <EventTable
                rows={visible}
                selected={selected}
                onSelect={(r) => {
                  setSelected(r);
                  setPanelOpen(true);
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
            {error && !needsAuth && <span className="err">{error}</span>}
            <span style={{ marginLeft: "auto" }}>
              <span className="kbd">/</span> {st.hintFilter} <span className="kbd">Esc</span>{" "}
              {st.hintClose}
            </span>
          </div>
        </section>

      </div>
    </div>
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

/**
 * Les onglets du panneau, dans l'ordre et sous les noms du TUI.
 *
 * `DetailTab { Logs, Status, Related }` côté Rust : mêmes trois, même ordre. Un onglet « Détail »
 * en plus n'existerait que sur le web, et les deux interfaces ne se ressembleraient plus.
 */
type PanelTab = "logs" | "status" | "related";

/**
 * Le panneau d'inspection, **au-dessus** de la table comme dans le TUI.
 *
 * Un panneau latéral paraissait plus moderne ; il est surtout trop étroit pour ce qu'on y met.
 * Des logs sur 390 px se lisent en accordéon, alors que la largeur entière de l'écran les rend
 * comme un terminal. C'est aussi la disposition que kdt a déjà, donc celle que quelqu'un qui
 * passe de l'un à l'autre n'a pas à réapprendre.
 */
function InspectPanel({
  record,
  tab,
  onTab,
  onClose,
  height,
  lang,
}: {
  record: EventRecord;
  tab: PanelTab;
  onTab: (t: PanelTab) => void;
  onClose: () => void;
  height: number;
  lang: Lang;
}) {
  // Les logs ne sont à une requête que sur un Pod : y remonter depuis un Deployment demande de
  // choisir quels pods lire, et ce choix a des règles qu'on ne réinvente pas ici.
  const isPod = record.kind === "Pod" && record.namespace !== "" && record.name !== "";

  return (
    <section className="panel" style={{ height }}>
      <div className="phd">
        <div className="ptabs" role="tablist">
          <button
            role="tab"
            aria-selected={tab === "logs"}
            disabled={!isPod}
            title={
              isPod
                ? undefined
                : lang === "fr"
                  ? "Les logs ne sont lisibles que sur un Pod"
                  : "Logs are only available on a Pod"
            }
            onClick={() => onTab("logs")}
          >
            Logs
          </button>
          <button role="tab" aria-selected={tab === "status"} onClick={() => onTab("status")}>
            Status
          </button>
          <button role="tab" aria-selected={tab === "related"} onClick={() => onTab("related")}>
            Related
          </button>
        </div>

        <div className="pid">
          <span className={`st ${record.tone}`}>{toneLabel(record.tone)}</span>
          <span className="mono">
            {record.kind} {record.namespace ? `${record.namespace}/${record.name}` : record.name}
          </span>
          <span className="reason">{record.reason}</span>
        </div>

        <button
          className="pclose"
          title={lang === "fr" ? "Replier le panneau" : "Collapse the panel"}
          onClick={onClose}
        >
          ▾
        </button>
      </div>

      <div className="pbody">
        {tab === "logs" &&
          (isPod ? (
            <LogsPane namespace={record.namespace} pod={record.name} lang={lang} />
          ) : (
            <p className="pane-wait">
              {lang === "fr"
                ? "Cet évènement ne porte pas sur un Pod."
                : "This event is not about a Pod."}
            </p>
          ))}
        {tab === "status" && <StatusPane record={record} lang={lang} />}
        {tab === "related" && <RelatedPane record={record} lang={lang} />}
      </div>
    </section>
  );
}

/**
 * La poignée entre le panneau et la table.
 *
 * `setPointerCapture` plutôt que des écouteurs sur `window` : le glissement continue de suivre le
 * curseur même s'il sort de la poignée ou passe au-dessus d'une iframe, et il s'arrête tout seul
 * quand le bouton est relâché n'importe où.
 *
 * Elle est aussi au clavier — c'est un `separator` focusable — parce qu'une poignée qui n'existe
 * qu'à la souris exclut ceux qui n'en utilisent pas.
 */
function Splitter({
  height,
  onHeight,
  lang,
}: {
  height: number;
  onHeight: (h: number) => void;
  lang: Lang;
}) {
  const [dragging, setDragging] = useState(false);

  return (
    <div
      className={dragging ? "splitter dragging" : "splitter"}
      role="separator"
      aria-orientation="horizontal"
      aria-label={lang === "fr" ? "Hauteur du panneau" : "Panel height"}
      aria-valuenow={Math.round(height)}
      tabIndex={0}
      title={
        lang === "fr"
          ? "Glisser pour redimensionner, double-clic pour réinitialiser"
          : "Drag to resize, double-click to reset"
      }
      onPointerDown={(e) => {
        e.preventDefault();
        e.currentTarget.setPointerCapture(e.pointerId);
        setDragging(true);
      }}
      onPointerMove={(e) => {
        if (!dragging) return;
        // La hauteur se lit sur la position du curseur, pas sur un cumul de deltas : un cumul
        // dérive dès que la valeur est bornée, et la poignée finit décalée du curseur.
        const top = e.currentTarget.parentElement?.getBoundingClientRect().top ?? 0;
        onHeight(clampPanelHeight(e.clientY - top));
      }}
      onPointerUp={(e) => {
        e.currentTarget.releasePointerCapture(e.pointerId);
        setDragging(false);
      }}
      onDoubleClick={() => onHeight(DEFAULT_PANEL_HEIGHT)}
      onKeyDown={(e) => {
        const step = e.shiftKey ? 60 : 16;
        if (e.key === "ArrowUp") {
          e.preventDefault();
          onHeight(clampPanelHeight(height - step));
        } else if (e.key === "ArrowDown") {
          e.preventDefault();
          onHeight(clampPanelHeight(height + step));
        } else if (e.key === "Home") {
          e.preventDefault();
          onHeight(DEFAULT_PANEL_HEIGHT);
        }
      }}
    />
  );
}

/** L'état de l'objet, mis en forme par kdt et peint avec le ton de chaque ligne. */
function StatusPane({ record, lang }: { record: EventRecord; lang: Lang }) {
  const [payload, setPayload] = useState<StatusPayload | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setPayload(null);
    setError(null);
    api
      .status(record)
      .then((r) => live && setPayload(r))
      .catch((e) => live && setError(String(e.message ?? e)));
    return () => {
      live = false;
    };
  }, [record]);

  if (error) return <p className="pane-err">{error}</p>;
  if (!payload) return <p className="pane-wait">{lang === "fr" ? "Lecture…" : "Reading…"}</p>;
  if (payload.error) return <p className="pane-err">{payload.error}</p>;

  return (
    <pre className="statuslines">
      {payload.lines.map((line, i) => (
        <div key={i} className={`ln ${line.tone}`}>
          {line.text || "\u00a0"}
        </div>
      ))}
    </pre>
  );
}

/**
 * Le contexte autour de l'évènement, tel que `gather_extra_context` le rassemble côté serveur.
 *
 * Les sondes partent avec l'identité de la personne connectée : une section absente veut souvent
 * dire « pas le droit de la lire », pas « rien à voir ».
 */
function RelatedPane({ record, lang }: { record: EventRecord; lang: Lang }) {
  const [sections, setSections] = useState<RelatedSection[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setSections(null);
    setError(null);
    api
      .related(record)
      .then((r) => live && setSections(r.sections))
      .catch((e) => live && setError(String(e.message ?? e)));
    return () => {
      live = false;
    };
  }, [record]);

  if (error) return <p className="pane-err">{error}</p>;
  if (!sections) return <p className="pane-wait">{lang === "fr" ? "Recherche…" : "Gathering…"}</p>;
  if (sections.length === 0)
    return (
      <p className="pane-wait">
        {lang === "fr"
          ? "Aucun objet lié trouvé, ou aucun que vos droits laissent lire."
          : "No related object found, or none your rights allow reading."}
      </p>
    );

  return (
    <div className="relgrid">
      {sections.map((section) => (
        <details key={section.title} className="related">
          <summary>{section.title}</summary>
          <pre className="json">{prettyJson(section.body)}</pre>
        </details>
      ))}
    </div>
  );
}

/** Le JSON compact du serveur, ré-indenté pour la lecture. Illisible, il est rendu tel quel. */
function prettyJson(body: string): string {
  try {
    return JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    return body;
  }
}

function LogsPane({ namespace, pod, lang }: { namespace: string; pod: string; lang: Lang }) {
  const [logs, setLogs] = useState<PodLogs | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [container, setContainer] = useState<string>("");
  const [previous, setPrevious] = useState(false);

  // Le pod change : le choix de container ne vaut plus, celui-ci n'existe pas forcément ailleurs.
  useEffect(() => setContainer(""), [namespace, pod]);

  useEffect(() => {
    let live = true;
    setLogs(null);
    setError(null);
    api
      .logs(namespace, pod, { container, previous })
      .then((r) => live && setLogs(r))
      .catch((e) => live && setError(String(e.message ?? e)));
    return () => {
      live = false;
    };
  }, [namespace, pod, container, previous]);

  return (
    <>
      <div className="logbar">
        <select value={container} onChange={(e) => setContainer(e.target.value)}>
          <option value="">{lang === "fr" ? "tous les containers" : "all containers"}</option>
          {(logs?.containers ?? []).map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <label>
          <input
            type="checkbox"
            checked={previous}
            onChange={(e) => setPrevious(e.target.checked)}
          />
          {lang === "fr" ? "run précédent" : "previous run"}
        </label>
      </div>

      {error ? (
        <p className="pane-err">{error}</p>
      ) : !logs ? (
        <p className="pane-wait">{lang === "fr" ? "Lecture…" : "Reading…"}</p>
      ) : (
        <pre className="logs">{logs.lines.join("\n")}</pre>
      )}
    </>
  );
}

/** Choix de la portée : plusieurs namespaces, ou tout le cluster. */
function ScopePicker({
  namespaces,
  onChange,
  onClose,
  labels,
}: {
  namespaces: string[];
  onChange: (next: string[]) => void;
  onClose: () => void;
  labels: { title: string; all: string };
}) {
  const [draft, setDraft] = useState("");

  return (
    <div className="pop" onClick={(e) => e.stopPropagation()}>
      <div className="pop-hd">
        <span>namespaces</span>
        <button
          onClick={() => {
            onChange([]);
            onClose();
          }}
        >
          {labels.title}
        </button>
      </div>

      {/* Saisi plutôt que choisi dans une liste : lister les namespaces demande un droit que
          tout le monde n'a pas, et le refus se verrait ici au lieu de se voir sur la donnée. */}
      <input
        className="ns-add"
        value={draft}
        placeholder="namespace + Entrée"
        autoFocus
        spellCheck={false}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key !== "Enter") return;
          const name = draft.trim();
          if (name && !namespaces.includes(name)) onChange([...namespaces, name]);
          setDraft("");
        }}
      />

      <div className="ns-list">
        {namespaces.length === 0 && (
          <div className="ns-item">
            <span style={{ opacity: 0.6 }}>{labels.all}</span>
          </div>
        )}
        {namespaces.map((ns) => (
          <div className="ns-item" key={ns}>
            <span>{ns}</span>
            <button
              aria-label={`retirer ${ns}`}
              onClick={() => onChange(namespaces.filter((n) => n !== ns))}
            >
              ✕
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
