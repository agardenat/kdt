// Secrets et ConfigMaps : deux mondes d'une même vue, comme le TUI les voisine.
//
// Tout les oppose sur un point, et c'est celui qui structure ce fichier. Une ConfigMap est du texte
// en clair : ses valeurs arrivent avec la ligne et s'affichent. Un Secret ne montre rien tant qu'on
// ne le demande pas — ses valeurs ne sont même pas dans la réponse, il faut une requête nommée pour
// les obtenir (voir `crates/web/src/config_secrets.rs`).
//
// Deux règles du TUI valent ici mot pour mot : **masqué par défaut**, et **remis à masqué dès que
// la sélection change**, pour qu'une valeur ne traîne jamais sous les yeux du suivant.

import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import type { Lang, Strings } from "./i18n";
import { InspectPanel, Splitter, type PanelTab } from "./panel";
import type { ConfigMapRow, EventRecord, SecretRow, SecretValue } from "./types";

const SECRET_COLUMNS =
  "minmax(220px,1.4fr) minmax(120px,18ch) minmax(140px,20ch) 72px minmax(150px,1fr) 56px";
const CM_COLUMNS = "minmax(240px,1.6fr) minmax(120px,18ch) 64px 80px minmax(150px,1fr) 56px";

type World = "secrets" | "configmaps";

export default function DataView({
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
  const [world, setWorld] = useState<World>("secrets");
  const [secrets, setSecrets] = useState<SecretRow[]>([]);
  const [counts, setCounts] = useState({ total: 0, tls: 0, expired: 0, expiring: 0 });
  const [configmaps, setConfigmaps] = useState<ConfigMapRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<PanelTab>("status");
  const [expanded, setExpanded] = useState<string | null>(null);

  const namespace = namespaces[0] ?? "";

  const load = useCallback(async () => {
    try {
      if (world === "secrets") {
        const payload = await api.secrets(namespace);
        setSecrets(payload.secrets);
        setCounts(payload.counts);
      } else {
        const payload = await api.configmaps(namespace);
        setConfigmaps(payload.configmaps);
      }
      setError(null);
      setLoaded(true);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else if (e instanceof ApiError) setError(e.message);
      else setError(String(e));
      setLoaded(true);
    }
  }, [world, namespace, onNeedsAuth]);

  useEffect(() => {
    setLoaded(false);
    void load();
    // Lent à dessein : ni un Secret ni une ConfigMap ne bougent pendant qu'on les regarde, et
    // relister tous les Secrets d'un cluster est une requête qu'on ne répète pas pour rien.
    const timer = window.setInterval(() => void load(), 30000);
    return () => window.clearInterval(timer);
  }, [load]);

  // Le monde change : ce qui était ouvert ne l'est plus. Sans ça, une clé dépliée d'un Secret
  // resterait ouverte au retour, et ce n'est pas ce qu'on attend d'un panneau qu'on a quitté.
  useEffect(() => {
    setExpanded(null);
    setSelected(null);
  }, [world]);

  const needle = query.trim().toLowerCase();

  const visibleSecrets = useMemo(
    () =>
      secrets.filter(
        (s) =>
          !needle ||
          [s.name, s.namespace, s.type_, s.tls?.subject_cn ?? "", s.data_keys.join(" ")]
            .join(" ")
            .toLowerCase()
            .includes(needle),
      ),
    [secrets, needle],
  );

  const visibleConfigmaps = useMemo(
    () =>
      configmaps.filter(
        (c) =>
          !needle ||
          [c.name, c.namespace, c.keys.join(" ")].join(" ").toLowerCase().includes(needle),
      ),
    [configmaps, needle],
  );

  const selectedRecord = useMemo<EventRecord | null>(() => {
    const rows: Array<{ uid: string; record: EventRecord }> =
      world === "secrets" ? visibleSecrets : visibleConfigmaps;
    return rows.find((r) => r.uid === selected)?.record ?? null;
  }, [world, visibleSecrets, visibleConfigmaps, selected]);

  const rowCount = world === "secrets" ? visibleSecrets.length : visibleConfigmaps.length;

  return (
    <>
      {selectedRecord && panelOpen && (
        <>
          <InspectPanel
            record={selectedRecord}
            tab={tab}
            onTab={setTab}
            onClose={() => onPanelOpen(false)}
            height={panelHeight}
            lang={lang}
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds" role="tablist">
        <button
          role="tab"
          aria-selected={world === "secrets"}
          onClick={() => setWorld("secrets")}
        >
          Secrets
          <span className="count">{counts.total}</span>
        </button>
        <button
          role="tab"
          aria-selected={world === "configmaps"}
          onClick={() => setWorld("configmaps")}
        >
          ConfigMaps
          <span className="count">{configmaps.length}</span>
        </button>

        {world === "secrets" && counts.tls > 0 && (
          <div className="tally">
            <span className="dim" title={st.secTls}>
              ⛨{counts.tls}
            </span>
            {counts.expired > 0 && (
              <span className="err" title={st.secExpired}>
                ✗{counts.expired}
              </span>
            )}
            {counts.expiring > 0 && (
              <span className="warn" title={st.secExpiring}>
                ⚠{counts.expiring}
              </span>
            )}
          </div>
        )}

        <div className="right">
          {selectedRecord && (
            <button className="panel-toggle" onClick={() => onPanelOpen(!panelOpen)}>
              {panelOpen
                ? lang === "fr"
                  ? "▾ replier"
                  : "▾ collapse"
                : lang === "fr"
                  ? "▸ panneau"
                  : "▸ panel"}
            </button>
          )}
        </div>
      </div>

      <div className="body">
        {!loaded ? (
          <div className="center" />
        ) : rowCount === 0 ? (
          <div className="center">
            <div className="box">
              <h2>{needle ? st.emptyTitle : st.dataEmpty}</h2>
              {error && <p className="err">{error}</p>}
              <p>
                {st.emptyScope} <code>{namespace || st.scopeAll}</code>
              </p>
            </div>
          </div>
        ) : world === "secrets" ? (
          <div className="tbl">
            <div className="thead">
              <div className="tr" style={{ gridTemplateColumns: SECRET_COLUMNS }}>
                <div className="cell">NAME</div>
                <div className="cell">NAMESPACE</div>
                <div className="cell">TYPE</div>
                <div className="cell num">KEYS</div>
                <div className="cell">EXPIRY</div>
                <div className="cell num">AGE</div>
              </div>
            </div>
            <div className="tbody">
              {visibleSecrets.map((s) => (
                <SecretLine
                  key={s.uid}
                  s={s}
                  st={st}
                  lang={lang}
                  open={expanded === s.uid}
                  selected={selected === s.uid}
                  onSelect={() => {
                    setSelected(s.uid);
                    onPanelOpen(true);
                  }}
                  onToggle={() => setExpanded((u) => (u === s.uid ? null : s.uid))}
                />
              ))}
            </div>
          </div>
        ) : (
          <div className="tbl">
            <div className="thead">
              <div className="tr" style={{ gridTemplateColumns: CM_COLUMNS }}>
                <div className="cell">NAME</div>
                <div className="cell">NAMESPACE</div>
                <div className="cell num">KEYS</div>
                <div className="cell num">SIZE</div>
                <div className="cell">SOURCE</div>
                <div className="cell num">AGE</div>
              </div>
            </div>
            <div className="tbody">
              {visibleConfigmaps.map((c) => (
                <ConfigMapLine
                  key={c.uid}
                  c={c}
                  st={st}
                  open={expanded === c.uid}
                  selected={selected === c.uid}
                  onSelect={() => {
                    setSelected(c.uid);
                    onPanelOpen(true);
                  }}
                  onToggle={() => setExpanded((u) => (u === c.uid ? null : c.uid))}
                />
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="statusbar">
        <span>
          {rowCount} {st.rows}
        </span>
        <span>
          {st.scopeLabel}: {namespace || st.scopeAll}
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

function SecretLine({
  s,
  st,
  lang,
  open,
  selected,
  onSelect,
  onToggle,
}: {
  s: SecretRow;
  st: Strings;
  lang: Lang;
  open: boolean;
  selected: boolean;
  onSelect: () => void;
  onToggle: () => void;
}) {
  return (
    <>
      <div
        className={`tr sec-${s.expiry_tone ?? "plain"}`}
        style={{ gridTemplateColumns: SECRET_COLUMNS }}
        aria-selected={selected}
        tabIndex={0}
        onClick={onSelect}
        onKeyDown={(e) => {
          if (e.key === "Enter") onSelect();
        }}
      >
        <div className="cell id">
          {s.data_keys.length > 0 ? (
            <button
              className="fold"
              title={st.secKeys}
              aria-expanded={open}
              onClick={(e) => {
                e.stopPropagation();
                onToggle();
              }}
            >
              {open ? "▾" : "▸"}
            </button>
          ) : (
            <span className="fold-gap" />
          )}
          {s.name}
        </div>
        <div className="cell mono dim">{s.namespace}</div>
        <div className="cell mono dim" title={s.type_}>
          {s.type_.replace("kubernetes.io/", "")}
        </div>
        <div className="cell num dim">{s.data_keys.length}</div>
        <div className="cell">
          {s.tls ? (
            <span className={`st ${s.expiry_tone}`}>
              {s.tls.days_remaining < 0
                ? st.secExpiredSince.replace("{n}", String(-s.tls.days_remaining))
                : st.secDays.replace("{n}", String(s.tls.days_remaining))}
            </span>
          ) : s.tls_error ? (
            <span className="st warn" title={s.tls_error}>
              {st.secUndecodable}
            </span>
          ) : null}
        </div>
        <div className="cell num dim">{s.age}</div>
      </div>
      {open && <SecretKeys s={s} st={st} lang={lang} />}
    </>
  );
}

/**
 * Les clés d'un secret, et la révélation à la demande.
 *
 * L'état part **masqué** et repart masqué dès qu'on referme : c'est la règle du TUI, et elle vaut
 * davantage ici — une page web se partage à l'écran, se capture et se laisse ouverte.
 */
function SecretKeys({ s, st, lang }: { s: SecretRow; st: Strings; lang: Lang }) {
  const [values, setValues] = useState<SecretValue[] | null>(null);
  const [mode, setMode] = useState<"hidden" | "text" | "base64">("hidden");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Un autre secret, un autre contenu : rien ne se reporte d'une ligne à l'autre.
  useEffect(() => {
    setValues(null);
    setMode("hidden");
    setError(null);
  }, [s.uid]);

  const revealAs = async (next: "text" | "base64") => {
    if (mode === next) {
      // Le même geste referme, comme `b`/`d` dans le TUI. Les valeurs sont **jetées**, pas juste
      // cachées : les garder en mémoire pour un éventuel second coup d'œil n'apporte rien.
      setMode("hidden");
      setValues(null);
      return;
    }
    setMode(next);
    if (values) return;
    setLoading(true);
    try {
      const payload = await api.revealSecret(s.namespace, s.name);
      setValues(payload.values);
      setError(null);
    } catch (e) {
      setError(String((e as Error).message ?? e));
      setMode("hidden");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="keys">
      <div className="keys-bar">
        <span className="dim">{st.secKeys}</span>
        <button
          className="inv-pill"
          aria-pressed={mode === "text"}
          onClick={() => void revealAs("text")}
        >
          {st.secShowText}
        </button>
        <button
          className="inv-pill"
          aria-pressed={mode === "base64"}
          onClick={() => void revealAs("base64")}
        >
          base64
        </button>
        {loading && <span className="dim">{lang === "fr" ? "lecture…" : "reading…"}</span>}
        {mode !== "hidden" && <span className="warn">{st.secVisible}</span>}
      </div>

      {error && <p className="pane-err">{error}</p>}

      <div className="keys-list">
        {s.data_keys.map((key) => {
          const v = values?.find((x) => x.key === key);
          return (
            <div className="keys-row" key={key}>
              <span className="k mono">{key}</span>
              {mode === "hidden" || !v ? (
                <span className="v masked">••••••••</span>
              ) : mode === "base64" ? (
                <span className="v mono">{v.base64}</span>
              ) : v.text === null ? (
                // Une valeur binaire n'a pas de forme texte : le dire plutôt que d'afficher des
                // remplaçants Unicode qu'on prendrait pour le contenu.
                <span className="v dim">{st.secBinary.replace("{n}", String(v.bytes))}</span>
              ) : (
                <span className="v mono">{v.text}</span>
              )}
            </div>
          );
        })}
      </div>

      {s.tls && <TlsDetail s={s} st={st} />}
    </div>
  );
}

/** Ce que le certificat dit de lui-même. La clé privée n'est ni lue ni transmise. */
function TlsDetail({ s, st }: { s: SecretRow; st: Strings }) {
  const c = s.tls;
  if (!c) return null;
  return (
    <dl className="facts tls">
      <dt>CN</dt>
      <dd>{c.subject_cn || "—"}</dd>
      <dt>{st.secIssuer}</dt>
      <dd>
        {c.issuer_cn || "—"}
        {c.self_signed && <span className="badge info"> {st.secSelfSigned}</span>}
      </dd>
      {c.sans.length > 0 && (
        <>
          <dt>SAN</dt>
          <dd>{c.sans.join(", ")}</dd>
        </>
      )}
      <dt>{st.secValidity}</dt>
      <dd>
        {c.not_before} → {c.not_after}
      </dd>
      {s.cert_manager && (
        <>
          <dt>cert-manager</dt>
          <dd>{s.cert_manager}</dd>
        </>
      )}
      {s.ingress_refs.length > 0 && (
        <>
          <dt>{st.secUsedBy}</dt>
          <dd>{s.ingress_refs.join(", ")}</dd>
        </>
      )}
    </dl>
  );
}

function ConfigMapLine({
  c,
  st,
  open,
  selected,
  onSelect,
  onToggle,
}: {
  c: ConfigMapRow;
  st: Strings;
  open: boolean;
  selected: boolean;
  onSelect: () => void;
  onToggle: () => void;
}) {
  return (
    <>
      <div
        className="tr"
        style={{ gridTemplateColumns: CM_COLUMNS }}
        aria-selected={selected}
        tabIndex={0}
        onClick={onSelect}
        onKeyDown={(e) => {
          if (e.key === "Enter") onSelect();
        }}
      >
        <div className="cell id">
          {c.keys.length > 0 ? (
            <button
              className="fold"
              title={st.secKeys}
              aria-expanded={open}
              onClick={(e) => {
                e.stopPropagation();
                onToggle();
              }}
            >
              {open ? "▾" : "▸"}
            </button>
          ) : (
            <span className="fold-gap" />
          )}
          {c.name}
        </div>
        <div className="cell mono dim">{c.namespace}</div>
        <div className="cell num dim">{c.keys.length}</div>
        <div className="cell num dim">{size(c.total_bytes)}</div>
        <div className="cell dim">{c.provenance_label}</div>
        <div className="cell num dim">{c.age}</div>
      </div>
      {open && (
        <div className="keys">
          {/* Pas de bascule : une ConfigMap est du texte en clair, et la masquer laisserait croire
              qu'elle contient quelque chose à protéger. */}
          {c.data.map(([key, value]) => (
            <details className="related" key={key} open={c.data.length === 1}>
              <summary>
                <span className="mono">{key}</span>{" "}
                <span className="dim">{size(value.length)}</span>
              </summary>
              <pre className="json">{value}</pre>
            </details>
          ))}
          {c.binary_keys.map((key) => (
            <div className="keys-row" key={key}>
              <span className="k mono">{key}</span>
              <span className="v dim">{st.secBinaryKey}</span>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

/** Une taille à l'unité qui tient en trois chiffres. */
function size(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  const ki = bytes / 1024;
  return ki < 1024 ? `${Math.round(ki)}Ki` : `${(ki / 1024).toFixed(1)}Mi`;
}
