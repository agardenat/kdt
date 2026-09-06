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
import { age, toneOf, type EventRecord, type Identity } from "./types";

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

/** Les colonnes de la vue évènements, et leur piste de grille. */
const COLUMNS = "64px 96px 150px 120px minmax(160px,.9fr) minmax(280px,2fr) 54px";

type Filter = "all" | "warnings";

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

  const [scopeOpen, setScopeOpen] = useState(false);
  const filterRef = useRef<HTMLInputElement>(null);
  const st = strings(lang);

  useEffect(() => applyTheme(theme), [theme]);

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
        else if (selected) setSelected(null);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [scopeOpen, selected]);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return rows.filter((r) => {
      if (filter === "warnings" && r.severity !== "warning") return false;
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
          <h2>kdt-web</h2>
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

  const warnings = rows.filter((r) => r.severity === "warning").length;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="name">kdt-web</span>
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

      <div className={selected ? "chrome open" : "chrome"}>
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
              {refreshedAt && <span>{st.refreshed}</span>}
            </div>
          </div>

          <div className="body">
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
              <EventTable rows={visible} selected={selected} onSelect={setSelected} />
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

        {selected && (
          <Detail record={selected} onClose={() => setSelected(null)} labels={st} lang={lang} />
        )}
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
          <div className="cell">TYPE</div>
          <div className="cell">REASON</div>
          <div className="cell">KIND</div>
          <div className="cell">OBJECT</div>
          <div className="cell">MESSAGE</div>
          <div className="cell num">CNT</div>
        </div>
      </div>
      <div className="tbody">
        {rows.map((r) => (
          <div
            key={r.uid || `${r.namespace}/${r.name}/${r.time}`}
            className={`tr sev-${toneOf(r.severity)}`}
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
              <span className={`st ${toneOf(r.severity)}`}>{r.severity}</span>
            </div>
            <div className="cell id">{r.reason}</div>
            <div className="cell mono">{r.kind}</div>
            <div className="cell mono">
              {r.namespace ? `${r.namespace}/${r.name}` : r.name}
            </div>
            <div className="cell">{r.message}</div>
            <div className="cell num">{r.count}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function Detail({
  record,
  onClose,
  labels,
  lang,
}: {
  record: EventRecord;
  onClose: () => void;
  labels: ReturnType<typeof strings>;
  lang: Lang;
}) {
  return (
    <aside className="drawer">
      <div className="dhd">
        <div className="top">
          <div>
            <h2>{record.namespace ? `${record.namespace}/${record.name}` : record.name}</h2>
            <p className="sub">
              {record.kind} · {record.api_version || "v1"}
            </p>
          </div>
          <button className="close" aria-label={labels.detailClose} onClick={onClose}>
            ✕
          </button>
        </div>
      </div>
      <div className="dbody">
        <div className="sect">Message</div>
        <p className="message">{record.message}</p>

        <div className="sect">{labels.sectionFields}</div>
        <dl className="facts">
          <dt>Reason</dt>
          <dd>{record.reason}</dd>
          <dt>{lang === "fr" ? "Type" : "Type"}</dt>
          <dd>{record.severity}</dd>
          <dt>{lang === "fr" ? "Horodatage" : "Timestamp"}</dt>
          <dd>{record.time}</dd>
          <dt>{lang === "fr" ? "Occurrences" : "Count"}</dt>
          <dd>{record.count}</dd>
          {record.component && (
            <>
              <dt>{lang === "fr" ? "Émis par" : "Reported by"}</dt>
              <dd>{record.component}</dd>
            </>
          )}
          {record.host && (
            <>
              <dt>Node</dt>
              <dd>{record.host}</dd>
            </>
          )}
        </dl>
      </div>
    </aside>
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
