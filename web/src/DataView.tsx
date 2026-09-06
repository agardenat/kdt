// Secrets et ConfigMaps : deux mondes d'une même vue, comme le TUI les voisine.
//
// **Le contenu d'un objet se lit dans le panneau du haut**, pas sous sa ligne : c'est là que kdt
// met `secret_detail_lines` et `configmap_detail_lines`, et c'est là que se trouvent les deux
// boutons de révélation — l'équivalent de `b` et `d`. La ligne ne se déplie pas : un Secret n'a
// pas d'enfant, il n'y a rien à plier.
//
// Tout oppose les deux mondes sur un point. Une ConfigMap est du texte en clair : ses valeurs
// arrivent avec la ligne et s'affichent. Un Secret ne montre rien tant qu'on ne le demande pas —
// ses valeurs ne sont même pas dans la réponse (voir `crates/web/src/config_secrets.rs`).
//
// Deux règles du TUI valent ici mot pour mot : **masqué par défaut**, et **remis à masqué dès que
// la sélection change**, pour qu'une valeur ne traîne jamais sous les yeux du suivant.

import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import type { Lang, Strings } from "./i18n";
import { CopyButton } from "./copy";
import { InspectPanel, Splitter, type PanelTab } from "./panel";
import { ObjectActions } from "./objects";
import type { ConfigMapRow, EventRecord, SecretFilter, SecretRow, SecretValue } from "./types";

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
  focusSecret,
  onFocusConsumed,
  onOpenCert,
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
  /** Un Secret sur lequel atterrir, quand une autre vue passe la main — le `s` de la vue certs. */
  focusSecret?: { namespace: string; name: string } | null;
  onFocusConsumed?: () => void;
  /**
   * Passe la main à la vue certs sur le Certificate qui produit ce Secret — le `o` du TUI.
   *
   * Absente quand ce cluster n'a pas cert-manager : la vue de destination n'existe alors pas, et
   * proposer le saut mènerait à un onglet que le rail ne montre pas.
   */
  onOpenCert?: (namespace: string, certificate: string) => void;
}) {
  const [world, setWorld] = useState<World>("secrets");
  const [secrets, setSecrets] = useState<SecretRow[]>([]);
  const [counts, setCounts] = useState({ total: 0, tls: 0, expired: 0, expiring: 0 });
  const [configmaps, setConfigmaps] = useState<ConfigMapRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  // Le détail est ce qu'on vient lire ici : c'est lui qui s'ouvre, pas `Status`.
  const [tab, setTab] = useState<PanelTab>("detail");
  // Le filtre `f` du TUI, qui y cycle sur une touche. Ici les trois états tiennent côte à côte :
  // on voit lequel est actif sans avoir à appuyer pour le découvrir.
  const [filter, setFilter] = useState<SecretFilter>("all");

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

  useEffect(() => setSelected(null), [world]);

  // Le saut d'une autre vue atterrit dès que sa cible apparaît dans la liste : la lecture peut ne
  // pas être finie quand le geste est fait. Il ne change pas la portée — comme dans kdt, où `s`
  // déplace le curseur sans toucher au namespace courant : si le Secret n'y est pas, la vue
  // demandée s'ouvre quand même et le curseur reste où il est.
  useEffect(() => {
    if (!focusSecret) return;
    setWorld("secrets");
    const hit = secrets.find(
      (s) => s.namespace === focusSecret.namespace && s.name === focusSecret.name,
    );
    if (!hit) return;
    setSelected(hit.uid);
    setTab("detail");
    onPanelOpen(true);
    onFocusConsumed?.();
  }, [focusSecret, secrets, onPanelOpen, onFocusConsumed]);

  const needle = query.trim().toLowerCase();

  const visibleSecrets = useMemo(
    () =>
      secrets.filter((s) => {
        // `expiring` ne retient que ce qui porte un certificat **et** dont l'échéance n'est pas
        // saine : un secret TLS illisible n'y figure pas, puisqu'on ignore quand il expire.
        if (filter === "tls" && !s.is_tls) return false;
        if (filter === "expiring" && (!s.tls || s.expiry_tone === "ok")) return false;
        return (
          !needle ||
          [s.name, s.namespace, s.type_, s.tls?.subject_cn ?? "", s.data_keys.join(" ")]
            .join(" ")
            .toLowerCase()
            .includes(needle)
        );
      }),
    [secrets, needle, filter],
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

  const selectedSecret = useMemo(
    () => (world === "secrets" ? (visibleSecrets.find((s) => s.uid === selected) ?? null) : null),
    [world, visibleSecrets, selected],
  );
  const selectedConfigmap = useMemo(
    () =>
      world === "configmaps" ? (visibleConfigmaps.find((c) => c.uid === selected) ?? null) : null,
    [world, visibleConfigmaps, selected],
  );
  const selectedRecord: EventRecord | null =
    selectedSecret?.record ?? selectedConfigmap?.record ?? null;

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
            st={st}
            onNeedsAuth={onNeedsAuth}
            detail={{
              label: st.secDetail,
              node: selectedSecret ? (
                // `key` sur l'uid : changer de secret **démonte** le panneau, donc la révélation
                // repart de zéro. C'est la règle du TUI — ne jamais reporter une valeur révélée
                // d'un objet sur un autre — obtenue par la structure plutôt que par un `useEffect`
                // qu'on pourrait oublier.
                <SecretDetail key={selectedSecret.uid} s={selectedSecret} st={st} lang={lang} />
              ) : selectedConfigmap ? (
                <ConfigMapDetail c={selectedConfigmap} st={st} />
              ) : null,
            }}
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds" role="tablist">
        <button role="tab" aria-selected={world === "secrets"} onClick={() => setWorld("secrets")}>
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

        {world === "secrets" && (
          <div className="segmented" role="group" aria-label={st.secFilter}>
            {(["all", "tls", "expiring"] as const).map((f) => (
              <button
                key={f}
                aria-pressed={filter === f}
                onClick={() => setFilter(f)}
                title={st.secFilterHelp}
              >
                {f === "all" ? st.secFilterAll : f === "tls" ? "TLS" : st.secFilterExpiring}
              </button>
            ))}
          </div>
        )}

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
          {/* Le retour de « voir le Secret » : d'un Secret vers la chaîne qui l'émet. Le lien est
              celui que kdt a déjà posé sur la ligne (`cert_manager`), pas une jointure refaite
              ici — un Secret TLS qui ne vient pas de cert-manager n'a pas d'origine à ouvrir. */}
          {onOpenCert && world === "secrets" && (
            <button
              className="panel-toggle"
              disabled={!selectedSecret?.cert_manager}
              title={selectedSecret?.cert_manager ? st.secOpenChainHelp : st.secNoOrigin}
              onClick={() =>
                selectedSecret?.cert_manager &&
                onOpenCert(selectedSecret.namespace, selectedSecret.cert_manager)
              }
            >
              {st.secOpenChain}
            </button>
          )}
          {/* Les trois gestes de kdt qui portent sur n'importe quel objet — `y`, `e`, `h` dans le
              TUI. Ils vivent dans la barre, comme toutes les actions, et ouvrent le panneau du
              haut sur ce qu'ils montrent. */}
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
              <h2>{needle || filter !== "all" ? st.emptyTitle : st.dataEmpty}</h2>
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
                  selected={selected === s.uid}
                  onSelect={() => {
                    setSelected(s.uid);
                    setTab("detail");
                    onPanelOpen(true);
                  }}
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
                  selected={selected === c.uid}
                  onSelect={() => {
                    setSelected(c.uid);
                    setTab("detail");
                    onPanelOpen(true);
                  }}
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
  selected,
  onSelect,
}: {
  s: SecretRow;
  st: Strings;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
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
      <div className="cell id">{s.name}</div>
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
  );
}

function ConfigMapLine({
  c,
  selected,
  onSelect,
}: {
  c: ConfigMapRow;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
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
      <div className="cell id">{c.name}</div>
      <div className="cell mono dim">{c.namespace}</div>
      <div className="cell num dim">{c.keys.length}</div>
      <div className="cell num dim">{size(c.total_bytes)}</div>
      <div className="cell dim">{c.provenance_label}</div>
      <div className="cell num dim">{c.age}</div>
    </div>
  );
}

/**
 * Le détail d'un Secret dans le panneau du haut, dans l'ordre de `secret_detail_lines` : ce qu'il
 * est, son certificat s'il en porte un, qui le consomme, et enfin ses valeurs — si on les demande.
 */
function SecretDetail({ s, st, lang }: { s: SecretRow; st: Strings; lang: Lang }) {
  const [values, setValues] = useState<SecretValue[] | null>(null);
  const [mode, setMode] = useState<"hidden" | "text" | "base64">("hidden");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

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
    <div className="detail">
      <dl className="facts">
        <dt>type</dt>
        <dd>{s.type_}</dd>
        <dt>{st.secOrigin}</dt>
        <dd>{s.provenance_label}</dd>
        <dt>{st.secKeys}</dt>
        <dd>{s.data_keys.length > 0 ? s.data_keys.join(", ") : "—"}</dd>
        <dt>{st.secAge}</dt>
        <dd>{s.age}</dd>
      </dl>

      {s.tls && (
        <>
          <div className="sect">{st.secCertificate}</div>
          <dl className="facts">
            <dt>subject CN</dt>
            <dd>{s.tls.subject_cn || "—"}</dd>
            <dt>issuer (CA)</dt>
            <dd>
              {s.tls.issuer_cn || "—"}
              {s.tls.self_signed && <span className="badge info"> {st.secSelfSigned}</span>}
            </dd>
            {s.tls.is_ca && (
              <>
                <dt>{st.secConstraint}</dt>
                <dd>CA:TRUE</dd>
              </>
            )}
            <dt>{st.secKey}</dt>
            <dd>{s.tls.key_algo}</dd>
            <dt>serial</dt>
            <dd className="wrap">{s.tls.serial}</dd>
            <dt>{st.secIssuedOn}</dt>
            <dd>{s.tls.not_before}</dd>
            <dt>{st.secExpiresOn}</dt>
            <dd className={s.expiry_tone ?? undefined}>
              {s.tls.not_after}{" "}
              {s.tls.days_remaining < 0
                ? `(${st.secExpiredSince.replace("{n}", String(-s.tls.days_remaining))})`
                : `(${st.secDays.replace("{n}", String(s.tls.days_remaining))})`}
            </dd>
            {s.tls.ca_bundle && (
              <>
                <dt>ca.crt</dt>
                <dd>
                  {s.tls.ca_bundle.subject_cn} · {s.tls.ca_bundle.not_after} (
                  {s.tls.ca_bundle.days_remaining} j)
                </dd>
              </>
            )}
          </dl>

          <div className="sect">SAN (Subject Alternative Names)</div>
          {s.tls.sans.length === 0 ? (
            <p className="pane-wait">({lang === "fr" ? "aucun" : "none"})</p>
          ) : (
            <ul className="sans">
              {s.tls.sans.map((san) => (
                <li key={san}>{san}</li>
              ))}
            </ul>
          )}
        </>
      )}

      {s.tls_error && (
        <p className="pane-err">
          {st.secUndecodable} : {s.tls_error}
        </p>
      )}

      <div className="sect">{st.secConsumers}</div>
      <dl className="facts">
        {s.cert_manager && (
          <>
            <dt>cert-manager</dt>
            <dd>Certificate {s.cert_manager}</dd>
          </>
        )}
        <dt>ingress</dt>
        <dd>{s.ingress_refs.length > 0 ? s.ingress_refs.join(", ") : st.secNoIngress}</dd>
      </dl>

      <div className="sect">{st.secContent}</div>
      <div className="keys-bar">
        {/* Les deux boutons de `b` et `d`. Le même geste referme, et la valeur est alors jetée. */}
        <button
          className="inv-pill"
          aria-pressed={mode === "base64"}
          onClick={() => void revealAs("base64")}
        >
          base64
        </button>
        <button
          className="inv-pill"
          aria-pressed={mode === "text"}
          onClick={() => void revealAs("text")}
        >
          {st.secShowText}
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
              {/* La commande vit sous le nom de la clé : une valeur longue se replie sur plusieurs
                  lignes, et un bouton posé à sa suite finit à l'autre bout du panneau, loin de ce
                  qu'il copie. La copie ne porte que sur ce qui est déjà à l'écran : copier une
                  valeur masquée reviendrait à la sortir sans l'avoir demandée. */}
              <div className="k-col">
                <span className="k mono">{key}</span>
                {mode !== "hidden" && v && (
                  <CopyButton
                    text={mode === "base64" ? v.base64 : (v.text ?? v.base64)}
                    label={st.secCopy}
                    done={st.secCopied}
                  />
                )}
              </div>
              {mode === "hidden" || !v ? (
                <span className="v masked">••••••••</span>
              ) : (
                <span className="v">
                  {mode === "base64" ? (
                    <span className="mono">{v.base64}</span>
                  ) : v.text === null ? (
                    // Une valeur binaire n'a pas de forme texte : le dire plutôt que d'afficher
                    // des remplaçants Unicode qu'on prendrait pour le contenu.
                    <span className="dim">{st.secBinary.replace("{n}", String(v.bytes))}</span>
                  ) : (
                    <span className="mono">{v.text}</span>
                  )}
                </span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/** Le détail d'une ConfigMap : les mêmes champs, et les valeurs directement — c'est du texte. */
function ConfigMapDetail({ c, st }: { c: ConfigMapRow; st: Strings }) {
  return (
    <div className="detail">
      <dl className="facts">
        <dt>{st.secOrigin}</dt>
        <dd>{c.provenance_label}</dd>
        <dt>{st.secKeys}</dt>
        <dd>
          {c.data.length} {st.cmText} · {c.binary_keys.length} {st.cmBinary}
        </dd>
        <dt>{st.cmSize}</dt>
        <dd>{size(c.total_bytes)}</dd>
        <dt>{st.secAge}</dt>
        <dd>{c.age}</dd>
      </dl>

      {c.data.map(([key, value]) => (
        <details className="related" key={key} open={c.data.length === 1}>
          <summary>
            <span className="mono">{key}</span> <span className="dim">{size(value.length)}</span>{" "}
            <CopyButton text={value} label={st.secCopy} done={st.secCopied} />
          </summary>
          <pre className="json">{value}</pre>
        </details>
      ))}

      {c.binary_keys.length > 0 && (
        <>
          <div className="sect">{st.secBinaryKey}</div>
          <div className="keys-list">
            {c.binary_keys.map((key) => (
              <div className="keys-row" key={key}>
                <span className="k mono">{key}</span>
                <span className="v dim">—</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

/** Une taille à l'unité qui tient en trois chiffres. */
function size(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  const ki = bytes / 1024;
  return ki < 1024 ? `${Math.round(ki)}Ki` : `${(ki / 1024).toFixed(1)}Mi`;
}
