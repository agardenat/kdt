// La vue cert-manager : la chaîne d'émission, du point d'ancrage jusqu'au Secret servi.
//
// Ce que cette vue apporte n'est pas la liste des Certificates mais la **chaîne** :
// Issuer → Certificate → CertificateRequest → Order → Challenge, puis le Secret produit et ceux qui
// le référencent. Un certificat qui expire ne dit pas pourquoi ; la chaîne, si.
//
// Rien n'est jugé ici. La lisibilité d'une ligne, son libellé READY, le ton d'une échéance, les
// constats de la chaîne et le refus de relancer sous quota ACME arrivent tout faits de
// `kdt::certmanager`. Ce qui reste au navigateur est ce qui le regarde : quels plis sont ouverts,
// quelle ligne on lit, et quel monde on affiche.

import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import { useDismiss } from "./dismiss";
import type { Lang, Strings } from "./i18n";
import { InspectPanel, PanelToggle, Splitter, type PanelTab } from "./panel";
import { ObjectActions } from "./objects";
import { visibleRows } from "./tree";
import type {
  CertActionTarget,
  CertFilter,
  CertHint,
  CertKeystore,
  CertResourceRow,
  CertRow,
  CertsPayload,
  EventRecord,
  ProducedSecret,
} from "./types";

/**
 * Les colonnes de l'arbre : celles du TUI, dans le même ordre.
 *
 * Côté Rust : RESOURCE dimensionnée sur son contenu (28 à 72 caractères), puis 10, 28, 8, 6, et le
 * reste au message. RESOURCE est en `fr` parce que c'est elle qui porte l'indentation de la lignée,
 * et MESSAGE en second `fr` parce que c'est lui qui dit pourquoi une ligne est rouge.
 */
const TREE_COLUMNS =
  "minmax(280px,1.3fr) 104px minmax(180px,28ch) 76px 52px minmax(200px,1.4fr)";

/** Les colonnes de la vue à plat : `KIND NAMESPACE NAME READY TARGET EXPIRE AGE MESSAGE`. */
const LIST_COLUMNS =
  "minmax(110px,14ch) minmax(120px,20ch) minmax(160px,1fr) 104px minmax(180px,28ch) 76px 52px" +
  " minmax(200px,1.4fr)";

export default function CertsView({
  lang,
  st,
  query,
  namespaces,
  panelHeight,
  onPanelHeight,
  panelOpen,
  onPanelOpen,
  onNeedsAuth,
  onOpenSecret,
  focusCert,
  onFocusConsumed,
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
  /** Passe la main à la vue Secrets sur le Secret produit — le `s` du TUI. */
  onOpenSecret: (namespace: string, name: string) => void;
  /** Un Certificate sur lequel atterrir, quand la vue Secrets passe la main — le `o` du TUI. */
  focusCert?: { namespace: string; name: string } | null;
  onFocusConsumed?: () => void;
}) {
  const [payload, setPayload] = useState<CertsPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [tree, setTree] = useState(true);
  const [filter, setFilter] = useState<CertFilter>("all");
  const [selected, setSelected] = useState<string | null>(null);
  // Le détail est ce qu'on vient lire ici : la chaîne, pas le status de la ligne.
  const [tab, setTab] = useState<PanelTab>("detail");
  // Les plis posés à la main. Ils gagnent toujours sur le pliage automatique — voir `collapsed`.
  const [toggled, setToggled] = useState<Record<string, boolean>>({});
  const [menuOpen, setMenuOpen] = useState(false);
  const [toast, setToast] = useState<{ tone: "ok" | "err"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  // La portée est un namespace, comme pour les autres vues qui listent. Elle ne coupe pas la
  // chaîne : le serveur garde les kinds cluster — un ClusterIssuer n'a pas de namespace et c'est
  // précisément ce que pointe le Certificate de celui-ci.
  const namespace = namespaces[0] ?? "";

  const load = useCallback(async () => {
    try {
      setPayload(await api.certs(namespace, filter, lang));
      setError(null);
      setLoaded(true);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else if (e instanceof ApiError) setError(e.message);
      else setError(String(e));
      setLoaded(true);
    }
  }, [namespace, filter, lang, onNeedsAuth]);

  useEffect(() => {
    void load();
    // Une émission ACME se joue en dizaines de secondes ; lire six CRD plus les Secrets de la
    // portée ne se paie pas plus souvent que ça.
    const timer = window.setInterval(() => void load(), 15000);
    return () => window.clearInterval(timer);
  }, [load]);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 8000);
    return () => window.clearTimeout(timer);
  }, [toast]);

  // `Échap` ferme le menu avant tout le reste, et un clic à côté aussi : c'est ce qui est ouvert
  // par-dessus. La ref va sur l'ancre — bouton **et** menu — sinon le bouton refermerait puis
  // rouvrirait dans le même geste.
  const closeMenu = useCallback(() => setMenuOpen(false), []);
  const menuRef = useDismiss<HTMLDivElement>(menuOpen, closeMenu);

  const rows = payload?.rows ?? [];
  const needle = query.trim().toLowerCase();

  /**
   * L'atterrissage d'un saut depuis la vue Secrets.
   *
   * Il attend que sa cible apparaisse : la lecture peut ne pas être finie quand le geste est fait.
   * Et il **ouvre la chaîne visée**, même saine, comme le fait kdt — sans quoi le saut se poserait
   * sur une ligne repliée. Pour la même raison il ramène l'arbre et le filtre à ce qui montre la
   * cible : un filtre qui la cacherait ferait d'un geste explicite un geste sans effet.
   */
  useEffect(() => {
    if (!focusCert) return;
    setTree(true);
    setFilter("all");
    const uid = `Certificate|${focusCert.namespace}/${focusCert.name}`;
    if (!rows.some((r) => r.uid === uid)) return;
    setToggled((p) => ({ ...p, [uid]: false }));
    setSelected(uid);
    setTab("detail");
    onPanelOpen(true);
    onFocusConsumed?.();
  }, [focusCert, rows, onPanelOpen, onFocusConsumed]);

  /**
   * Le pliage : la chaîne d'un Certificate sain est du bruit, celle d'un Certificate en panne est
   * la réponse. C'est la règle de kdt (`apply_certs_autofold`), et elle ne touche jamais un pli
   * posé à la main — sinon la branche qu'on vient d'ouvrir se refermerait au rafraîchissement.
   */
  const collapsed = useMemo(() => {
    const out = new Set<string>();
    for (const row of rows) {
      if (row.row !== "resource" || row.kind !== "Certificate") continue;
      const manual = toggled[row.uid];
      if (manual !== undefined) {
        if (manual) out.add(row.uid);
      } else if (row.ready === "ready") {
        out.add(row.uid);
      }
    }
    // Les plis manuels sur autre chose qu'un Certificate comptent aussi.
    for (const [uid, folded] of Object.entries(toggled)) {
      if (folded) out.add(uid);
      else out.delete(uid);
    }
    return out;
  }, [rows, toggled]);

  /**
   * Le filtre du champ de recherche garde les **ancêtres** de ce qu'il retient.
   *
   * Filtrer un arbre ligne à ligne le casse : les enfants d'une ligne écartée se rattachent à
   * n'importe quoi et la profondeur ne veut plus rien dire. C'est la même règle que l'arbre Flux.
   */
  const filtered = useMemo(() => {
    if (!needle) return rows;
    const keep = new Set<number>();
    rows.forEach((row, i) => {
      if (!matches(row, needle)) return;
      keep.add(i);
      let want = row.depth - 1;
      for (let k = i - 1; k >= 0 && want >= 0; k -= 1) {
        if (rows[k].depth === want) {
          keep.add(k);
          want -= 1;
        }
      }
    });
    return rows.filter((_, i) => keep.has(i));
  }, [rows, needle]);

  const shown = useMemo(() => {
    if (!tree) {
      // La vue à plat est celle du TUI : les objets cert-manager seuls, dans l'ordre de kdt —
      // problèmes d'abord, puis l'échéance la plus proche. Pas de feuille Secret : elle n'a de sens
      // que sous le Certificate qui la produit.
      return filtered
        .filter((r): r is CertResourceRow => r.row === "resource")
        .slice()
        .sort((a, b) => a.rank - b.rank);
    }
    return visibleRows(filtered, collapsed, new Set<string>());
  }, [tree, filtered, collapsed]);

  const selectedRow = useMemo(
    () => rows.find((r) => r.uid === selected) ?? null,
    [rows, selected],
  );
  const selectedRecord: EventRecord | null = selectedRow?.record ?? null;

  // Le Certificate qui commande la ligne lue, quel que soit l'étage de la chaîne où l'on est :
  // c'est kdt qui le désigne (`owning_certificate`), pas une remontée refaite ici.
  const owningCert = useMemo(() => {
    const uid =
      selectedRow?.row === "resource"
        ? selectedRow.cert_uid
        : selectedRow?.row === "secret"
          ? certOfSecret(rows, selectedRow.uid)
          : null;
    if (!uid) return null;
    const hit = rows.find((r) => r.uid === uid);
    return hit && hit.row === "resource" ? hit : null;
  }, [rows, selectedRow]);

  const run = useCallback(
    async (action: () => Promise<{ message: string }>) => {
      setMenuOpen(false);
      setBusy(true);
      try {
        const { message } = await action();
        setToast({ tone: "ok", text: message });
        // Relire tout de suite : une ré-émission change l'état en quelques secondes, et attendre le
        // tick suivant ferait douter que le geste soit passé.
        void load();
      } catch (e) {
        if (e instanceof NeedsAuth) onNeedsAuth(e.message);
        else setToast({ tone: "err", text: String((e as Error).message ?? e) });
      } finally {
        setBusy(false);
      }
    },
    [load, onNeedsAuth],
  );

  // Le Secret que la ligne lue produit, s'il y en a un : c'est ce que « voir le Secret » ouvre.
  const secretTarget = useMemo(() => {
    if (selectedRow?.row === "secret") {
      return { namespace: selectedRow.namespace, name: selectedRow.name };
    }
    const produced = owningCert?.produced;
    return produced ? { namespace: produced.namespace, name: produced.secret_name } : null;
  }, [selectedRow, owningCert]);

  const counts = payload?.counts;

  return (
    <>
            {/* Le panneau reste en place tant qu'il est déplié, sélection ou pas : le faire apparaître
          avec la sélection décalait la table de 300 px à chaque clic, et on perdait la ligne qu'on
          venait de viser. */}
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
            detail={{
              label: st.certDetail,
              node: selectedRow ? (
                // La chaîne complète, pas celle que le filtre laisse à l'écran : on la lit pour
                // savoir d'où vient la ligne, et une lignée amputée par une recherche dirait le
                // contraire de ce qu'on vient chercher. C'est ce que fait le TUI.
                <ChainDetail
                  rows={rows}
                  row={selectedRow}
                  cert={owningCert}
                  st={st}
                  lang={lang}
                />
              ) : null,
            }}
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds" role="tablist">
        <button role="tab" aria-selected={tree} onClick={() => setTree(true)}>
          {st.certTree}
        </button>
        <button role="tab" aria-selected={!tree} onClick={() => setTree(false)}>
          {st.certList}
          {counts && <span className="count">{counts.total}</span>}
        </button>

        {/* Le filtre `f` du TUI, qui y cycle sur une touche. Ici les trois états tiennent côte à
            côte : on voit lequel est actif sans avoir à appuyer pour le découvrir. */}
        <div className="segmented" role="group" aria-label={st.certFilterHelp}>
          {(["all", "problems", "in-flight"] as const).map((f) => (
            <button
              key={f}
              aria-pressed={filter === f}
              title={st.certFilterHelp}
              onClick={() => setFilter(f)}
            >
              {f === "all"
                ? st.certFilterAll
                : f === "problems"
                  ? st.certFilterProblems
                  : st.certFilterFlight}
            </button>
          ))}
        </div>

        {counts && (
          <div className="tally">
            <span className="ok" title="ready">
              ✓{counts.ready}
            </span>
            {counts.failed > 0 && (
              <span className="err" title="failed">
                ✗{counts.failed}
              </span>
            )}
            {counts.in_flight > 0 && (
              <span className="info" title="issuing">
                ↻{counts.in_flight}
              </span>
            )}
            {counts.expiring > 0 && (
              <span className="warn" title="< 30 j">
                ⚠{counts.expiring}
              </span>
            )}
            {/* Un cluster qui n'émet que depuis une CA ou un selfSigned n'installe pas le groupe
                ACME : le dire évite de chercher des Orders qui n'existeront jamais. */}
            {payload && !payload.acme_installed && <span className="dim">{st.certNoAcme}</span>}
          </div>
        )}

        <div className="right">
          {busy && <span>{st.objWorking}</span>}
          <button
            className="panel-toggle"
            disabled={!secretTarget}
            title={secretTarget ? st.certOpenSecretHelp : st.certSelectRow}
            onClick={() => secretTarget && onOpenSecret(secretTarget.namespace, secretTarget.name)}
          >
            {st.certOpenSecret}
          </button>
          <div className="menu-anchor" ref={menuRef}>
            <button
              className="panel-toggle action"
              disabled={!owningCert}
              title={owningCert ? undefined : st.certSelectRow}
              aria-expanded={menuOpen}
              onClick={() => setMenuOpen((v) => !v)}
            >
              {st.certActions} ▾
            </button>
            {menuOpen && owningCert && (
              <CertMenu cert={owningCert} st={st} lang={lang} onRun={run} />
            )}
          </div>
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

      <div className="body">
        {!loaded ? (
          <div className="center" />
        ) : shown.length === 0 ? (
          <div className="center">
            <div className="box">
              <h2>
                {payload && !payload.installed
                  ? st.certNotInstalled
                  : needle || filter !== "all"
                    ? st.emptyTitle
                    : st.certEmpty}
              </h2>
              {error && <p className="err">{error}</p>}
              {payload?.error && <p className="err">{payload.error}</p>}
              <p>
                {st.emptyScope} <code>{namespace || st.scopeAll}</code>
              </p>
            </div>
          </div>
        ) : (
          <div className="tbl">
            <div className="thead">
              <div
                className="tr"
                style={{ gridTemplateColumns: tree ? TREE_COLUMNS : LIST_COLUMNS }}
              >
                {tree ? (
                  <div className="cell">RESOURCE</div>
                ) : (
                  <>
                    <div className="cell">KIND</div>
                    <div className="cell">NAMESPACE</div>
                    <div className="cell">NAME</div>
                  </>
                )}
                <div className="cell">READY</div>
                <div className="cell">TARGET</div>
                <div className="cell num">EXPIRE</div>
                <div className="cell num">AGE</div>
                <div className="cell">MESSAGE</div>
              </div>
            </div>
            <div className="tbody">
              {shown.map((row) =>
                row.row === "resource" ? (
                  <ResourceLine
                    key={row.uid}
                    row={row}
                    tree={tree}
                    st={st}
                    collapsed={collapsed.has(row.uid)}
                    selected={selected === row.uid}
                    onSelect={() => {
                      setSelected(row.uid);
                      setTab("detail");
                    }}
                    onFold={() => setToggled((p) => ({ ...p, [row.uid]: !collapsed.has(row.uid) }))}
                  />
                ) : (
                  <SecretLine
                    key={row.uid}
                    row={row}
                    st={st}
                    selected={selected === row.uid}
                    onSelect={() => {
                      setSelected(row.uid);
                      setTab("detail");
                    }}
                  />
                ),
              )}
            </div>
          </div>
        )}
      </div>

      <div className="statusbar">
        <span>
          {shown.length} {st.rows}
        </span>
        <span>
          {st.scopeLabel}: {namespace || st.scopeAll}
        </span>
        {/* Les Secrets illisibles ne rendent pas la chaîne fausse : ils rendent muettes les règles
            qui portent sur le Secret produit. Le dire vaut mieux qu'un silence qu'on prendrait
            pour un « tout va bien ». */}
        {payload?.secrets_error && <span className="warn">{st.certSecretsUnreadable}</span>}
        {error && <span className="err">{error}</span>}
        {payload?.error && <span className="err">{payload.error}</span>}
        {toast && <span className={toast.tone === "err" ? "err" : "ok"}>{toast.text}</span>}
        <span style={{ marginLeft: "auto" }}>
          <span className="kbd">/</span> {st.hintFilter} <span className="kbd">Esc</span>{" "}
          {st.hintClose}
        </span>
      </div>
    </>
  );
}

/** Le Certificate au-dessus d'une feuille Secret : la ligne qui la précède immédiatement. */
function certOfSecret(rows: CertRow[], uid: string): string | null {
  const at = rows.findIndex((r) => r.uid === uid);
  for (let k = at - 1; k >= 0; k -= 1) {
    const row = rows[k];
    if (row.row === "resource") return row.uid;
  }
  return null;
}

function matches(row: CertRow, needle: string): boolean {
  const parts =
    row.row === "resource"
      ? [row.kind, row.namespace, row.name, row.message, row.target, row.ready_label]
      : ["Secret", row.namespace, row.name];
  return parts.join(" ").toLowerCase().includes(needle);
}

function ResourceLine({
  row,
  tree,
  st,
  collapsed,
  selected,
  onSelect,
  onFold,
}: {
  row: CertResourceRow;
  tree: boolean;
  st: Strings;
  collapsed: boolean;
  selected: boolean;
  onSelect: () => void;
  onFold: () => void;
}) {
  return (
    <div
      className={`tr cert-${row.ready}`}
      style={{ gridTemplateColumns: tree ? TREE_COLUMNS : LIST_COLUMNS }}
      aria-selected={selected}
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSelect();
        else if (e.key === " " && tree && row.has_children) {
          e.preventDefault();
          onFold();
        }
      }}
    >
      {tree ? (
        <div className="cell id" style={{ paddingLeft: `${row.depth * 1.15}rem` }}>
          {row.has_children ? (
            <button
              className="fold"
              title={st.certFold}
              aria-expanded={!collapsed}
              onClick={(e) => {
                e.stopPropagation();
                onFold();
              }}
            >
              {collapsed ? "▸" : "▾"}
            </button>
          ) : (
            <span className="fold-gap" />
          )}
          <span className="kind">{row.kind_short}</span> {row.name}
          <Keystores formats={row.keystore_formats} />
        </div>
      ) : (
        <>
          <div className="cell kind">{row.kind_short}</div>
          <div className="cell mono dim">{row.namespace}</div>
          <div className="cell id">
            {row.name}
            <Keystores formats={row.keystore_formats} />
          </div>
        </>
      )}
      <div className="cell">
        <span className={`st ${row.ready_tone}`}>
          {row.ready_glyph} {row.ready_label}
        </span>
      </div>
      <div className="cell dim" title={row.target}>
        {row.target}
      </div>
      <Expiry days={row.days_remaining} tone={row.expiry_tone} st={st} />
      <div className="cell num dim">{row.age}</div>
      <div className={`cell ${row.ready === "failed" ? "err" : "dim"}`} title={row.message}>
        {row.message}
      </div>
    </div>
  );
}

/** La feuille TLS : le Secret produit, joint depuis la vue Secrets et jamais relu deux fois. */
function SecretLine({
  row,
  st,
  selected,
  onSelect,
}: {
  row: Extract<CertRow, { row: "secret" }>;
  st: Strings;
  selected: boolean;
  onSelect: () => void;
}) {
  const consumers =
    row.ingress_refs === 0
      ? st.certConsumersNone
      : row.ingress_refs === 1
        ? st.certConsumersOne
        : st.certConsumersMany.replace("{n}", String(row.ingress_refs));

  return (
    <div
      className="tr cert-leaf"
      style={{ gridTemplateColumns: TREE_COLUMNS }}
      aria-selected={selected}
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSelect();
      }}
    >
      <div className="cell id" style={{ paddingLeft: `${row.depth * 1.15}rem` }}>
        <span className="fold-gap">→</span>
        <span className="kind">Secret</span> {row.name}
      </div>
      <div className="cell">
        <span className="st leaf">TLS</span>
      </div>
      <div className="cell dim">{consumers}</div>
      <Expiry days={row.days_remaining} tone={row.expiry_tone} st={st} />
      <div className="cell" />
      <div className="cell" />
    </div>
  );
}

/** L'échéance, peinte par la bande d'urgence de kdt — la même que dans la vue Secrets. */
function Expiry({
  days,
  tone,
  st,
}: {
  days: number | null;
  tone: string | null;
  st: Strings;
}) {
  if (days === null) return <div className="cell num dim">—</div>;
  return (
    <div className={`cell num ${tone ?? ""}`}>{st.certDays.replace("{n}", String(days))}</div>
  );
}

/** Les keystores demandés, en suffixe du nom : de quoi retrouver les certificats côté Java. */
function Keystores({ formats }: { formats: string[] }) {
  if (formats.length === 0) return null;
  return <span className="badge info"> [{formats.join("+")}]</span>;
}

/**
 * La chaîne, du point d'ancrage jusqu'aux consommateurs, puis ce que les règles en disent.
 *
 * C'est la réponse à « pourquoi ce certificat n'est pas émis », et elle se lit la même quelle que
 * soit la ligne de la chaîne sur laquelle on est.
 */
function ChainDetail({
  rows,
  row,
  cert,
  st,
  lang,
}: {
  rows: CertRow[];
  row: CertRow;
  cert: CertResourceRow | null;
  st: Strings;
  lang: Lang;
}) {
  const at = rows.findIndex((r) => r.uid === row.uid);
  // Les ancêtres viennent des profondeurs décroissantes au-dessus, les descendants des lignes
  // plus profondes en dessous. Les arêtes sont celles que kdt a résolues : on ne fait que les lire
  // dans l'ordre où elles arrivent.
  const chain: CertRow[] = [];
  let want = row.depth - 1;
  for (let k = at - 1; k >= 0 && want >= 0; k -= 1) {
    if (rows[k].depth === want) {
      chain.unshift(rows[k]);
      want -= 1;
    }
  }
  chain.push(row);
  for (let k = at + 1; k < rows.length && rows[k].depth > row.depth; k += 1) chain.push(rows[k]);

  const signed =
    row.row === "resource" && (row.kind === "Issuer" || row.kind === "ClusterIssuer")
      ? chain.filter((r) => r.row === "resource" && r.kind === "Certificate").length
      : null;

  const hints: CertHint[] = row.row === "resource" ? row.hints : (cert?.hints ?? []);
  const produced = cert?.produced ?? null;

  return (
    <div className="detail">
      <div className="sect">{st.certChain}</div>
      <ul className="chain">
        {chain.map((r) => (
          <li
            key={r.uid}
            className={r.uid === row.uid ? "here" : undefined}
            style={{ paddingLeft: `${Math.max(0, r.depth - chain[0].depth) * 1.15}rem` }}
          >
            {r.row === "resource" ? (
              <>
                <span className="kind">{r.kind_short}</span> <span className="mono">{r.name}</span>{" "}
                <span className={`st ${r.ready_tone}`}>
                  {r.ready_glyph} {r.ready_label}
                </span>
                {r.issuer_type && <span className="dim"> · {r.issuer_type}</span>}
                {r.challenge && r.challenge.dns_name && (
                  <span className="dim">
                    {" "}
                    · {r.challenge.type_} {r.challenge.dns_name}
                  </span>
                )}
                {r.message && r.ready !== "ready" && <div className="dim wrap">{r.message}</div>}
              </>
            ) : (
              <>
                <span className="kind">Secret</span> <span className="mono">{r.name}</span>
              </>
            )}
          </li>
        ))}
      </ul>
      {signed !== null && (
        <p className="dim">{st.certSignedBy.replace("{n}", String(signed))}</p>
      )}

      {produced && <Produced produced={produced} st={st} lang={lang} />}

      {hints.length > 0 && (
        <>
          <div className="sect">{lang === "fr" ? "Diagnostic" : "Findings"}</div>
          <ul className="hints">
            {hints.map((h) => (
              <li key={h.text} className={h.level}>
                <span className="gl">
                  {h.level === "danger" ? "✗" : h.level === "warn" ? "▲" : "·"}
                </span>{" "}
                {h.text}
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

/** Le Secret produit, ses consommateurs, et les keystores qu'on lui a demandés. */
function Produced({
  produced,
  st,
  lang,
}: {
  produced: ProducedSecret;
  st: Strings;
  lang: Lang;
}) {
  const consumers =
    produced.ingress_refs === null
      ? null
      : produced.ingress_refs === 0
        ? st.certConsumersNone
        : produced.ingress_refs === 1
          ? st.certConsumersOne
          : st.certConsumersMany.replace("{n}", String(produced.ingress_refs));

  return (
    <>
      <div className="sect">{st.certProduced}</div>
      {produced.found === false ? (
        // Un Certificate `Ready` dont le Secret est absent est la seule panne que rien d'autre ne
        // signale : le certificat est prêt, et rien ne le sert.
        <p className="pane-err">
          {st.certSecretAbsent
            .replace("{ns}", produced.namespace)
            .replace("{name}", produced.secret_name)}
        </p>
      ) : (
        <dl className="facts">
          <dt>Secret</dt>
          <dd className="mono">
            {produced.namespace}/{produced.secret_name}
            {produced.days_remaining !== null && (
              <span className="dim">
                {" "}
                ·{" "}
                {produced.days_remaining < 0
                  ? st.certExpiredSince.replace("{n}", String(-produced.days_remaining))
                  : st.certExpiresIn.replace("{n}", String(produced.days_remaining))}
              </span>
            )}
          </dd>
          {consumers !== null && (
            <>
              <dt>ingress</dt>
              <dd>{consumers}</dd>
            </>
          )}
          {!produced.known && (
            <>
              <dt>{lang === "fr" ? "état" : "state"}</dt>
              <dd className="dim">{st.certSecretUnknown}</dd>
            </>
          )}
          {produced.renewal_time && (
            <>
              <dt>{st.certRenewalOn}</dt>
              <dd>{produced.renewal_time.slice(0, 10)}</dd>
            </>
          )}
          {produced.not_after && (
            <>
              <dt>{st.certExpiresOn}</dt>
              <dd>{produced.not_after.slice(0, 10)}</dd>
            </>
          )}
        </dl>
      )}

      {produced.keystores.length > 0 && (
        <>
          <div className="sect">{st.certKeystores}</div>
          {produced.keystores.map((ks) => (
            <Keystore key={ks.format} ks={ks} st={st} />
          ))}
        </>
      )}
    </>
  );
}

/**
 * Un keystore demandé, et les fichiers que cert-manager doit écrire dans le Secret.
 *
 * Un fichier dont on ne connaît pas le sort reste `—` : ni présent, ni absent. C'est ce que le TUI
 * fait quand les clés du Secret ne sont pas connues, et l'inverse — l'afficher manquant — ferait
 * ouvrir un incident sur une lecture qui n'a jamais eu lieu.
 */
function Keystore({ ks, st }: { ks: CertKeystore; st: Strings }) {
  const detail: string[] = [];
  if (ks.alias) detail.push(st.certKeystoreAlias.replace("{alias}", ks.alias));
  if (ks.password_ref) {
    const ok = ks.password_ref.secret_found && ks.password_ref.key_found;
    detail.push(
      `${st.certKeystorePwRef
        .replace("{name}", ks.password_ref.name)
        .replace("{key}", ks.password_ref.key)}${ok === false ? " ✗" : ok ? " ✓" : ""}`,
    );
  } else {
    detail.push(st.certKeystorePwInline);
  }

  return (
    <div className="keystore">
      <span className="badge info">{ks.format}</span>
      {ks.files.map((f) => (
        <span
          key={f.key}
          className={f.present === null ? "dim" : f.present ? "ok" : "err"}
        >
          {f.key} {f.present === null ? "—" : f.present ? "✓" : "✗"}
        </span>
      ))}
      <span className="dim">{detail.join(" · ")}</span>
    </div>
  );
}

/**
 * Les deux leviers, avec la confirmation de kdt.
 *
 * `renouveler` redemande une émission ; `relancer ACME` supprime la demande en cours pour en faire
 * repartir une neuve. Aucune n'est destructrice au sens d'une perte, mais les deux écrivent sur le
 * cluster, et on ne déclenche pas une émission d'un clic à côté. L'annulation est la sortie par
 * défaut.
 */
function CertMenu({
  cert,
  st,
  lang,
  onRun,
}: {
  cert: CertResourceRow;
  st: Strings;
  lang: Lang;
  onRun: (action: () => Promise<{ message: string }>) => void;
}) {
  const [arming, setArming] = useState<"renew" | "retry" | null>(null);
  const actions = cert.actions;
  const renewTarget: CertActionTarget = {
    apiVersion: cert.api_version,
    namespace: cert.namespace,
    name: cert.name,
  };

  return (
    <div className="pop menu" onClick={(e) => e.stopPropagation()}>
      <div className="pop-hd">
        <span>{st.certActions}</span>
      </div>
      <div className="menu-target mono">
        Certificate {cert.namespace}/{cert.name}
      </div>

      {arming ? (
        <div className="menu-confirm">
          <p>{arming === "renew" ? st.certDescRenew : st.certDescAcmeRetry}</p>
          <div className="menu-buttons">
            <button autoFocus onClick={() => setArming(null)}>
              {st.fluxCancel}
            </button>
            <button
              className="cta"
              onClick={() =>
                onRun(() =>
                  arming === "renew"
                    ? api.certRenew(renewTarget, lang)
                    : api.certAcmeRetry(actions!.acme_retry!, lang),
                )
              }
            >
              {st.fluxConfirm}
            </button>
          </div>
        </div>
      ) : (
        <div className="menu-list">
          <button className="menu-item" onClick={() => setArming("renew")}>
            <span className="lbl">{st.certRenew}</span>
            <span className="desc">{st.certDescRenew}</span>
          </button>
          {/* La relance n'est offerte que s'il y a une demande vivante à relancer — et jamais sous
              quota ACME, où réessayer ne fait que brûler ce qui reste. C'est kdt qui tranche. */}
          {actions?.acme_retry && (
            <button className="menu-item" onClick={() => setArming("retry")}>
              <span className="lbl">{st.certAcmeRetry}</span>
              <span className="desc">{st.certDescAcmeRetry}</span>
            </button>
          )}
          {actions?.rate_limited && <p className="menu-note err">{st.certRateLimited}</p>}
        </div>
      )}
    </div>
  );
}
