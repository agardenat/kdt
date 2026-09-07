// La vue Kyverno : les policies, ce qu'elles appliquent vraiment, et ce qu'elles rejettent.
//
// Ce que cette vue apporte n'est pas la liste des ClusterPolicies mais la **jointure** : une
// policy, ses règles — y compris les `autogen-*` que Kyverno a dérivées et que les rapports sont
// seuls à nommer — et les ressources qui échouent dessus. Un `PolicyReport` ne désigne la policy et
// la règle que par des chaînes, et refaire ce rapprochement à la main coûte une après-midi.
//
// Rien n'est jugé ici. Le repli par défaut, la posture d'une règle, le ton d'une ligne, le verdict
// de santé et les refus d'admission arrivent tout faits de `kdt::kyverno`. Ce qui reste au
// navigateur est ce qui le regarde : quels plis sont ouverts, quelle ligne on lit, quel axe on
// affiche.

import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import { useDismiss } from "./dismiss";
import type { Lang, Strings } from "./i18n";
import { InspectPanel, PanelToggle, Splitter, type PanelTab } from "./panel";
import { ObjectActions } from "./objects";
import { visibleRows } from "./tree";
import type {
  KyCounts,
  KyDenial,
  KyFilter,
  KyPolicyRow,
  KyRow,
  KyvernoPayload,
  KyViolationRow,
} from "./types";

/**
 * Les colonnes de l'axe par policy : celles du TUI, dans le même ordre.
 *
 * Côté Rust : RESOURCE dimensionnée sur son contenu (30 à 64 caractères), puis 9, 11, 26, et le
 * reste au détail. RESOURCE est en `fr` parce que c'est elle qui porte l'indentation, et DETAIL en
 * second `fr` parce que c'est lui qui dit pourquoi une ligne est rouge.
 */
const POLICY_COLUMNS =
  "minmax(300px,1.3fr) 92px minmax(104px,12ch) minmax(180px,26ch) minmax(220px,1.5fr)";

/** Les colonnes de l'axe par ressource : `RESOURCE RESULT POLICY/RULE MESSAGE`. */
const RESOURCE_COLUMNS =
  "minmax(300px,1.2fr) minmax(90px,10ch) minmax(220px,34ch) minmax(220px,1.6fr)";

export default function KyvernoView({
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
  const [payload, setPayload] = useState<KyvernoPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [axis, setAxis] = useState<"policy" | "resource">("policy");
  const [filter, setFilter] = useState<KyFilter>("all");
  const [selected, setSelected] = useState<string | null>(null);
  // Le détail est ce qu'on vient lire ici : la policy et ce qu'elle rejette, pas le status d'un objet.
  const [tab, setTab] = useState<PanelTab>("detail");
  // Les plis posés à la main. Ils gagnent toujours sur le pli que kdt propose — voir `collapsed`.
  const [toggled, setToggled] = useState<Record<string, boolean>>({});
  const [menuOpen, setMenuOpen] = useState(false);
  const [toast, setToast] = useState<{ tone: "ok" | "err"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setPayload(await api.kyverno(axis, filter, lang));
      setError(null);
      setLoaded(true);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else if (e instanceof ApiError) setError(e.message);
      else setError(String(e));
      setLoaded(true);
    }
  }, [axis, filter, lang, onNeedsAuth]);

  useEffect(() => {
    void load();
    // La cadence du TUI sur cette vue : les policies ne bougent pas, mais les rapports derrière
    // elles sont réécrits à chaque admission — et c'est cela qu'on attend en la regardant. Plus
    // lent que la vue certs parce qu'une passe liste tous les PolicyReports du cluster.
    const timer = window.setInterval(() => void load(), 15000);
    return () => window.clearInterval(timer);
  }, [load]);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 8000);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const closeMenu = useCallback(() => setMenuOpen(false), []);
  const menuRef = useDismiss<HTMLDivElement>(menuOpen, closeMenu);

  const rows = payload?.rows ?? [];
  const needle = query.trim().toLowerCase();

  /**
   * Le pliage : les règles d'une policy saine sont du bruit, celles d'une policy en peine sont la
   * réponse. Le verdict vient du serveur (`fold_default`), et un pli posé à la main gagne toujours
   * — sinon la branche qu'on vient d'ouvrir se refermerait au rafraîchissement suivant.
   */
  const collapsed = useMemo(() => {
    const out = new Set<string>();
    for (const row of rows) {
      if (!row.has_children) continue;
      const manual = toggled[row.uid];
      if (manual === undefined ? row.fold_default : manual) out.add(row.uid);
    }
    return out;
  }, [rows, toggled]);

  /**
   * Le filtre du champ de recherche garde les **ancêtres** de ce qu'il retient.
   *
   * Filtrer un arbre ligne à ligne le casse : les enfants d'une ligne écartée se rattachent à
   * n'importe quoi et la profondeur ne veut plus rien dire.
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

  const shown = useMemo(
    () => visibleRows(filtered, collapsed, new Set<string>()),
    [filtered, collapsed],
  );

  const selectedRow = useMemo(() => rows.find((r) => r.uid === selected) ?? null, [rows, selected]);
  const selectedRecord = selectedRow?.record ?? null;

  // La policy que le panneau décrit : celle sous le curseur, ou celle qui possède la règle, le
  // constat ou l'exception sous le curseur. C'est le partage de `ky_selected_policy` dans kdt.
  const owningPolicy = useMemo(() => {
    if (!selectedRow) return null;
    const uid =
      selectedRow.row === "policy"
        ? selectedRow.uid
        : selectedRow.row === "rule" || selectedRow.row === "exception"
          ? selectedRow.policy_uid
          : selectedRow.row === "violation"
            ? selectedRow.policy_uid
            : null;
    if (!uid) return null;
    const hit = rows.find((r) => r.row === "policy" && r.uid === uid);
    return (hit as KyPolicyRow | undefined) ?? null;
  }, [rows, selectedRow]);

  const toggleFold = useCallback((uid: string, folded: boolean) => {
    setToggled((prev) => ({ ...prev, [uid]: !folded }));
  }, []);

  const purge = useCallback(async () => {
    setMenuOpen(false);
    setBusy(true);
    try {
      const { message } = await api.kyvernoPurge(lang);
      setToast({ tone: "ok", text: message });
      // Relire tout de suite : la file se vide en quelques secondes, et attendre le tick suivant
      // ferait douter que le geste soit passé.
      void load();
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else setToast({ tone: "err", text: String((e as Error).message ?? e) });
    } finally {
      setBusy(false);
    }
  }, [lang, load, onNeedsAuth]);

  const counts = payload?.counts;
  const columns = axis === "policy" ? POLICY_COLUMNS : RESOURCE_COLUMNS;

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
            detail={{
              label: st.kyDetail,
              node: selectedRow ? (
                <KyvernoDetail
                  st={st}
                  rows={rows}
                  row={selectedRow}
                  policy={owningPolicy}
                  denials={payload?.denials ?? {}}
                  denialsError={payload?.denials_error ?? null}
                />
              ) : null,
            }}
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds" role="tablist">
        <button
          role="tab"
          aria-selected={axis === "policy"}
          title={st.kyAxisHelp}
          onClick={() => setAxis("policy")}
        >
          {st.kyByPolicy}
          {counts && <span className="count">{counts.policies}</span>}
        </button>
        <button
          role="tab"
          aria-selected={axis === "resource"}
          title={st.kyAxisHelp}
          onClick={() => setAxis("resource")}
        >
          {st.kyByResource}
          {counts && <span className="count">{counts.violations}</span>}
        </button>

        {/* Le filtre `f` du TUI, qui y cycle sur une touche. Ici les trois états tiennent côte à
            côte : on voit lequel est actif sans avoir à appuyer pour le découvrir. */}
        <div className="segmented" role="group" aria-label={st.kyFilterHelp}>
          {(["all", "problems", "enforce"] as const).map((f) => (
            <button
              key={f}
              aria-pressed={filter === f}
              title={st.kyFilterHelp}
              onClick={() => setFilter(f)}
            >
              {f === "all" ? st.filterAll : f === "problems" ? st.filterProblems : st.kyFilterEnforce}
            </button>
          ))}
        </div>

        {counts && (
          <div className="tally">
            {counts.error > 0 && (
              <span className="err" title="error">
                ×{counts.error}
              </span>
            )}
            {counts.fail > 0 && (
              <span className="err" title="fail">
                ✗{counts.fail}
              </span>
            )}
            {counts.warn > 0 && (
              <span className="warn" title="warn">
                !{counts.warn}
              </span>
            )}
            {counts.not_ready > 0 && (
              <span className="warn" title={st.kyNotReady}>
                {counts.not_ready} {st.kyNotReady}
              </span>
            )}
            <span className="dim">
              {counts.enforce} {st.kyEnforcing}
            </span>
          </div>
        )}

        <div className="right">
          {busy && <span>{st.objWorking}</span>}
          <div className="menu-anchor" ref={menuRef}>
            <button
              className="panel-toggle action"
              // Le levier n'existe que s'il y a une file à vider : proposer une purge qui ne
              // supprimerait rien ferait chercher pourquoi il ne se passe rien.
              disabled={!payload?.backlog.stuck}
              title={payload?.backlog.stuck ? st.kyPurgeHelp : st.kyPurgeNone}
              aria-expanded={menuOpen}
              onClick={() => setMenuOpen((v) => !v)}
            >
              {st.kyPurge} ▾
            </button>
            {menuOpen && payload && payload.backlog.stuck > 0 && (
              <PurgeMenu stuck={payload.backlog.stuck} st={st} onRun={() => void purge()} />
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

      {/* La bande de santé sur sa propre ligne, et non dans la barre d'actions : elle ne dépend ni
          de la ligne lue ni du geste qu'on prépare, elle décrit l'installation. Serrée entre les
          onglets et les boutons, elle les repoussait hors du cadre. */}
      {payload && <HealthBand payload={payload} st={st} />}

      <div className="body">
        {!loaded ? (
          <div className="center" />
        ) : shown.length === 0 ? (
          <div className="center">
            <div className="box">
              <h2>
                {payload && !payload.installed
                  ? st.kyNotInstalled
                  : needle || filter !== "all"
                    ? st.emptyTitle
                    : st.kyEmpty}
              </h2>
              {error && <p className="err">{error}</p>}
              {payload?.error && <p className="err">{payload.error}</p>}
            </div>
          </div>
        ) : (
          <div className="tbl">
            <div className="thead">
              <div className="tr" style={{ gridTemplateColumns: columns }}>
                <div className="cell">RESOURCE</div>
                {axis === "policy" ? (
                  <>
                    <div className="cell">ACTION</div>
                    <div className="cell">STATE</div>
                    <div className="cell">SCOPE</div>
                    <div className="cell">DETAIL</div>
                  </>
                ) : (
                  <>
                    <div className="cell">RESULT</div>
                    <div className="cell">POLICY / RULE</div>
                    <div className="cell">MESSAGE</div>
                  </>
                )}
              </div>
            </div>
            <div className="tbody">
              {shown.map((row) => (
                <Line
                  key={row.uid}
                  row={row}
                  axis={axis}
                  columns={columns}
                  st={st}
                  collapsed={collapsed.has(row.uid)}
                  selected={selected === row.uid}
                  onSelect={() => setSelected(row.uid)}
                  onFold={() => toggleFold(row.uid, collapsed.has(row.uid))}
                />
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="statusbar">
        <span>
          {shown.length} {st.rows}
        </span>
        <span title={st.kyScopeless}>{lang === "fr" ? "tout le cluster" : "whole cluster"}</span>
        {payload && !payload.cel_installed && <span className="dim">{st.kyNoCel}</span>}
        {error && <span className="err">{error}</span>}
        {toast && <span className={toast.tone === "err" ? "err" : "ok"}>{toast.text}</span>}
        <span style={{ marginLeft: "auto" }}>
          <span className="kbd">/</span> {st.hintFilter} <span className="kbd">Esc</span>{" "}
          {st.hintClose}
        </span>
      </div>
    </>
  );
}

/**
 * « Kyverno fait-il seulement quelque chose ? »
 *
 * Le compte de webhooks est la partie porteuse : tous les controllers peuvent être verts alors
 * qu'aucune policy n'intercepte quoi que ce soit, et rien d'autre sur le cluster ne le dit. Le
 * verdict vient de kdt (`KyHealth::state`), la barre ne fait que le peindre.
 */
function HealthBand({ payload, st }: { payload: KyvernoPayload; st: Strings }) {
  const { health, backlog } = payload;
  const label =
    health.state === "ok"
      ? st.kyHealthOk
      : health.state === "degraded"
        ? st.kyHealthDegraded
        : health.state === "inactive"
          ? st.kyHealthInactive
          : st.kyHealthUnknown;

  return (
    <div className="ky-health" title={health.state === "inactive" ? st.kyNoWebhook : undefined}>
      <span className={`ky-badge ${health.state}`}>{label}</span>
      {health.version && <span className="dim">v{health.version}</span>}
      {health.controllers.length === 0 && <span className="warn">{st.kyNoControllers}</span>}
      {health.controllers.map((c) => (
        <span key={c.name} className={c.up ? "ok" : "err"}>
          {c.name} {c.ready}/{c.desired}
        </span>
      ))}
      {/* Zéro webhook enregistré n'est pas un compte : c'est la panne que rien d'autre ne signale.
          `webhooks_known` à faux veut dire que la lecture n'a pas eu lieu, pas qu'il y en a zéro. */}
      {/* Les deux comptes sont posés à plat, chacun avec son ton : imbriqués dans une étiquette
          éteinte ils se lisaient éteints eux aussi, alors que le zéro est précisément ce qu'il faut
          voir. */}
      {health.webhooks_known && <span className="dim">{st.kyWebhooks}</span>}
      {health.webhooks_known && (
        <span className={health.validating_webhooks === 0 ? "warn" : "ok"}>
          validating {health.validating_webhooks}
        </span>
      )}
      {health.webhooks_known && (
        <span className={health.mutating_webhooks === 0 ? "warn" : "ok"}>
          mutating {health.mutating_webhooks}
        </span>
      )}
      {health.state === "inactive" && <span className="warn">{st.kyNoWebhook}</span>}

      {(backlog.total > 0 || backlog.ephemeral_reports > 0) && (
        <span
          className={backlog.pileup ? "err" : "dim"}
          title={
            backlog.oldest_stuck
              ? st.kyRequestsOldest.replace("{age}", backlog.oldest_stuck)
              : undefined
          }
        >
          {st.kyRequests} {backlog.total}
          {backlog.pending > 0 && ` · ${backlog.pending} ${st.kyRequestsPending}`}
          {backlog.failed > 0 && ` · ${backlog.failed} ${st.kyRequestsFailed}`}
          {backlog.oldest_stuck && ` · ${st.kyRequestsOldest.replace("{age}", backlog.oldest_stuck)}`}
        </span>
      )}
      {/* On ne nomme les policies qui tiennent la file que lorsqu'elle ne se draine plus : le
          correctif est de débloquer ces règles-là, et les nommer est le chemin le plus court. */}
      {backlog.pileup && backlog.by_policy.length > 0 && (
        <span className="warn">
          {st.kyRequestsTop}{" "}
          {backlog.by_policy
            .slice(0, 3)
            .map(([name, n]) => `${name} ${n}`)
            .join(" · ")}
        </span>
      )}
      {backlog.ephemeral_reports > 0 && (
        <span className="dim">
          {st.kyEphemeral.replace("{n}", String(backlog.ephemeral_reports))}
        </span>
      )}
    </div>
  );
}

/** Une ligne de l'arbre, quelle que soit ce qu'elle désigne. */
function Line({
  row,
  axis,
  columns,
  st,
  collapsed,
  selected,
  onSelect,
  onFold,
}: {
  row: KyRow;
  axis: "policy" | "resource";
  columns: string;
  st: Strings;
  collapsed: boolean;
  selected: boolean;
  onSelect: () => void;
  onFold: () => void;
}) {
  return (
    <div
      className={`tr ${rowClass(row)}`}
      style={{ gridTemplateColumns: columns }}
      aria-selected={selected}
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSelect();
        else if (e.key === " " && row.has_children) {
          e.preventDefault();
          onFold();
        }
      }}
    >
      <div className="cell id" style={{ paddingLeft: `${row.depth * 1.15}rem` }}>
        {row.has_children ? (
          <button
            className="fold"
            title={st.kyFold}
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
        <Label row={row} axis={axis} />
      </div>
      {axis === "policy" ? <PolicyCells row={row} st={st} /> : <ResourceCells row={row} />}
    </div>
  );
}

/** L'identité de la ligne, dans la colonne qui porte l'indentation. */
function Label({ row, axis }: { row: KyRow; axis: "policy" | "resource" }) {
  switch (row.row) {
    case "policy":
      return (
        <>
          <span className="kind">{row.kind_short}</span> {row.name}
          {row.namespace && <span className="dim"> · {row.namespace}</span>}
        </>
      );
    case "rule":
      return <>{row.name}</>;
    case "exception":
      return (
        <>
          <span className="kind">polex</span> {row.name}
        </>
      );
    case "namespace":
      return (
        <>
          <span className="kind">ns</span> {row.name || "(cluster)"}
        </>
      );
    case "resource":
      return (
        <>
          <span className="kind">{row.kind}</span> {row.name}
        </>
      );
    case "violation":
      // Dans l'axe par ressource, l'identité de la feuille est le **verdict** : l'objet est la
      // ligne au-dessus. Dans l'axe par policy, c'est l'objet fautif — la policy est au-dessus.
      return axis === "resource" ? (
        <>
          <span className="gl">{row.result_glyph}</span>
          {row.result_label}
          {row.severity && <span className="dim"> · {row.severity}</span>}
        </>
      ) : (
        <>
          <span className="gl">{row.result_glyph}</span>
          {row.target}
        </>
      );
  }
}

/** Les quatre colonnes de l'axe par policy. Leur sens change avec le type de ligne. */
function PolicyCells({ row, st }: { row: KyRow; st: Strings }) {
  switch (row.row) {
    case "policy":
      return (
        <>
          <div className={`cell tone-${row.action_tone}`}>{row.action_label}</div>
          <div className="cell">
            <span className={`st ${row.ready_tone}`}>{row.ready_label}</span>
          </div>
          <div className="cell dim" title={row.scope}>
            {row.scope}
          </div>
          <div className="cell" title={row.ready_message || row.title}>
            {row.ready_message ? (
              <span className="err">{row.ready_message}</span>
            ) : total(row.counts) === 0 ? (
              <span className="dim">{row.title}</span>
            ) : (
              row.summary
            )}
          </div>
        </>
      );
    case "rule":
      return (
        <>
          <div className="cell dim">{row.verb}</div>
          {/* Le marqueur autogen est là où une policy montre sa lisibilité : ces règles sont celles
              de Kyverno, et ce sont elles que les rapports nomment. */}
          <div className="cell dim">{row.autogen ? `(${st.kyAutogen})` : ""}</div>
          <div className="cell info" title={row.match_summary}>
            {row.match_summary}
          </div>
          <div className="cell" title={row.message}>
            {total(row.counts) === 0 ? <span className="dim">{row.message}</span> : row.summary}
          </div>
        </>
      );
    case "violation":
      return (
        <>
          <div className="cell">{row.result_label}</div>
          <div className="cell dim">{row.kind}</div>
          <div className="cell dim">{row.severity}</div>
          <div className="cell" title={row.message}>
            {row.message}
          </div>
        </>
      );
    case "exception":
      return (
        <>
          <div className="cell">{st.kyExceptions}</div>
          <div className="cell" />
          <div className="cell dim" title={row.match_summary}>
            {row.match_summary}
          </div>
          <div className="cell dim">
            {row.rules.length === 0 ? st.kyAllRules : row.rules.join(", ")}
          </div>
        </>
      );
    default:
      return (
        <>
          <div className="cell">{"summary" in row ? row.summary : ""}</div>
          <div className="cell" />
          <div className="cell" />
          <div className="cell" />
        </>
      );
  }
}

/** Les trois colonnes de l'axe par ressource. */
function ResourceCells({ row }: { row: KyRow }) {
  if (row.row === "violation") {
    return (
      <>
        <div className="cell" />
        <div className="cell info" title={`${row.policy}/${row.rule}`}>
          {row.policy}/{row.rule}
        </div>
        <div className="cell" title={row.message}>
          {row.message}
        </div>
      </>
    );
  }
  return (
    <>
      <div className="cell">{"summary" in row ? row.summary : ""}</div>
      <div className="cell" />
      <div className="cell" />
    </>
  );
}

/**
 * Le panneau : ce que la ligne lue veut dire, et ce qu'il faut en faire.
 *
 * Une policy y montre sa posture, ses règles, ses exceptions, ce qu'elle fait échouer et ce qu'elle
 * a refusé à l'admission — cette dernière section n'existant nulle part ailleurs sur le cluster.
 */
function KyvernoDetail({
  st,
  rows,
  row,
  policy,
  denials,
  denialsError,
}: {
  st: Strings;
  rows: KyRow[];
  row: KyRow;
  policy: KyPolicyRow | null;
  denials: Record<string, KyDenial[]>;
  denialsError: string | null;
}) {
  if (row.row === "violation") {
    return <ViolationDetail st={st} row={row} policy={policy} />;
  }
  if (row.row === "namespace") {
    return (
      <div className="detail">
        <dl className="facts">
          <dt>namespace</dt>
          <dd>{row.name || "(cluster)"}</dd>
        </dl>
        <CountsFacts st={st} counts={row.counts} />
      </div>
    );
  }
  if (row.row === "resource") {
    // Les constats de cette ressource sont déjà dans l'arbre, sous elle : on les relit plutôt que
    // de les redemander.
    const mine = childrenOf(rows, row).filter((r): r is KyViolationRow => r.row === "violation");
    return (
      <div className="detail">
        <dl className="facts">
          <dt>kind</dt>
          <dd>{row.kind}</dd>
          <dt>namespace</dt>
          <dd>{row.namespace || "(cluster)"}</dd>
        </dl>
        <div className="sect">{st.kyViolated}</div>
        <ul className="hints">
          {mine.map((v) => (
            <li key={v.uid} className={v.result === "fail" || v.result === "error" ? "danger" : "warn"}>
              <span className="gl">{v.result_glyph}</span>
              {v.policy} / {v.rule} — {v.message}
            </li>
          ))}
        </ul>
        <p className="dim">{st.kyRetrigger}</p>
      </div>
    );
  }
  if (!policy) return null;
  return (
    <PolicyDetail
      st={st}
      rows={rows}
      policy={policy}
      denials={denials[policy.name] ?? []}
      denialsError={denialsError}
    />
  );
}

function PolicyDetail({
  st,
  rows,
  policy,
  denials,
  denialsError,
}: {
  st: Strings;
  rows: KyRow[];
  policy: KyPolicyRow;
  denials: KyDenial[];
  denialsError: string | null;
}) {
  // Ce que la policy fait échouer, relu dans l'arbre : les constats sont ses descendants.
  const failing = childrenOf(rows, policy).filter(
    (r): r is KyViolationRow => r.row === "violation",
  );

  return (
    <div className="detail">
      {/* Une policy qui ne peut pas s'évaluer ne protège rien, quoi que disent ses règles. Ça passe
          avant tout le reste. */}
      {policy.ready === "not-ready" && (
        <p className="err">
          {st.kyNotReadyNote} {policy.ready_message}
        </p>
      )}
      {policy.title && <p className="dim">{policy.title}</p>}

      <div className="sect">{st.kyPosture}</div>
      <dl className="facts">
        <dt>action</dt>
        <dd className={policy.action === "enforce" ? "warn" : undefined}>{policy.action_label}</dd>
        <dt>{st.kyAdmission}</dt>
        <dd>{policy.admission ? "oui" : st.kyBackgroundOnly}</dd>
        <dt>{st.kyBackground}</dt>
        <dd>{policy.background ? "oui" : st.kyNoBackground}</dd>
        {policy.schedule && (
          <>
            <dt>{st.kySchedule}</dt>
            <dd>{policy.schedule}</dd>
          </>
        )}
        <dt>age</dt>
        <dd>{policy.age}</dd>
      </dl>
      {/* Sans cette ligne la colonne ACTION ment sur tous les clusters qui passent en Enforce
          namespace par namespace. */}
      {policy.overrides.map((o, i) => (
        <p key={i} className="warn">
          {st.kyOverride} : {o.action} — {o.namespaces.join(", ")}
        </p>
      ))}

      {policy.rules.length > 0 && (
        <>
          <div className="sect">{st.kyRules}</div>
          <ul className="hints">
            {policy.rules.map((r) => (
              <li key={r.name} className="info">
                <strong>{r.name}</strong> <span className="dim">{r.verb}</span>
                {r.autogen && <span className="warn"> ({st.kyAutogen})</span>}
                {r.action !== policy.action && <span className="info"> {r.action}</span>}
                <div className="dim">
                  {st.kyAppliesTo} {r.match_summary}
                </div>
                {r.message && <div className="dim">« {r.message} »</div>}
              </li>
            ))}
          </ul>
        </>
      )}

      {policy.exceptions.length > 0 && (
        <>
          <div className="sect">{st.kyExceptions}</div>
          <ul className="hints">
            {policy.exceptions.map((e) => (
              <li key={`${e.namespace}/${e.name}`} className="info">
                {e.namespace}/{e.name} <span className="dim">{st.kyExcludes} {e.match_summary}</span>
                {e.rules.length > 0 && (
                  <div className="dim">
                    {st.kyForRules} {e.rules.join(", ")}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </>
      )}

      {failing.length > 0 && (
        <>
          <div className="sect">{st.kyFailing}</div>
          <ul className="hints">
            {failing.slice(0, 12).map((v) => (
              <li key={v.uid} className={v.result === "warn" ? "warn" : "danger"}>
                <span className="gl">{v.result_glyph}</span>
                <span className="dim">{v.kind}</span> {v.target}
                <span className="dim"> {v.rule}</span>
              </li>
            ))}
          </ul>
        </>
      )}

      {/* Ces refus-là n'apparaissent dans aucun rapport : la ressource a été refusée, donc elle
          n'existe pas, donc rien ne la décrit. L'Event est la seule trace. */}
      <div className="sect">{st.kyDenials}</div>
      {denialsError ? (
        <p className="warn">{st.kyDenialsDenied}</p>
      ) : denials.length === 0 ? (
        <p className="dim">{st.kyNoDenial}</p>
      ) : (
        <ul className="hints">
          {denials.map((d, i) => (
            <li key={i} className="danger">
              <span className="dim">{d.age}</span> {d.target}
              {d.rule && <span className="dim"> [{d.rule}]</span>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ViolationDetail({
  st,
  row,
  policy,
}: {
  st: Strings;
  row: KyViolationRow;
  policy: KyPolicyRow | null;
}) {
  const rule = policy?.rules.find((r) => r.name === row.rule) ?? null;
  return (
    <div className="detail">
      <dl className="facts">
        <dt>{st.kyResourceLabel}</dt>
        <dd>{row.target}</dd>
        {row.api_version && (
          <>
            <dt>apiVersion</dt>
            <dd>{row.api_version}</dd>
          </>
        )}
        <dt>policy</dt>
        <dd>
          {row.policy} / {row.rule}
        </dd>
        {row.severity && (
          <>
            <dt>{st.kySeverity}</dt>
            <dd>{row.severity}</dd>
          </>
        )}
        {row.category && (
          <>
            <dt>{st.kyCategory}</dt>
            <dd>{row.category}</dd>
          </>
        )}
        {row.process && (
          <>
            <dt>{st.kyOrigin}</dt>
            <dd>{row.process}</dd>
          </>
        )}
        {row.age && (
          <>
            <dt>{st.kyEvaluated}</dt>
            <dd>{row.age}</dd>
          </>
        )}
      </dl>

      <div className="sect">message</div>
      <p className={row.result === "warn" ? "warn" : "err"}>{row.message}</p>

      {/* Un `error` est la policy qui n'arrive pas à tourner, pas la ressource qui échoue à la
          policy — autre problème, autre correctif, et la nuance se perd dans un mur de rouge. */}
      {row.result === "error" && <p className="warn">{st.kyErrorNote}</p>}

      {rule && (
        <>
          <div className="sect">{st.kyRules}</div>
          <dl className="facts">
            <dt>{st.kyAppliesTo}</dt>
            <dd>{rule.match_summary}</dd>
            <dt>action</dt>
            <dd>{rule.action}</dd>
          </dl>
          {rule.message && <p className="dim">« {rule.message} »</p>}
        </>
      )}

      <p className="dim">{st.kyRetrigger}</p>
    </div>
  );
}

function CountsFacts({ st, counts }: { st: Strings; counts: KyCounts }) {
  return (
    <dl className="facts">
      <dt>error</dt>
      <dd className={counts.error > 0 ? "err" : undefined}>{counts.error}</dd>
      <dt>fail</dt>
      <dd className={counts.fail > 0 ? "err" : undefined}>{counts.fail}</dd>
      <dt>warn</dt>
      <dd className={counts.warn > 0 ? "warn" : undefined}>{counts.warn}</dd>
      <dt>pass</dt>
      <dd>{counts.pass}</dd>
      <dt>skip</dt>
      <dd className="dim">
        {counts.skip} <span className="dim">{st.kyNoViolation}</span>
      </dd>
    </dl>
  );
}

/**
 * La confirmation, comme dans kdt : la purge écrit sur le cluster, et l'annulation est la sortie
 * par défaut — c'est elle qui prend le focus.
 */
function PurgeMenu({
  stuck,
  st,
  onRun,
}: {
  stuck: number;
  st: Strings;
  onRun: () => void;
}) {
  const [arming, setArming] = useState(false);

  return (
    <div className="pop menu" onClick={(e) => e.stopPropagation()}>
      <div className="pop-hd">
        <span>{st.kyPurge}</span>
      </div>
      {arming ? (
        <div className="menu-confirm">
          <p>{st.kyPurgeConfirm.replace("{n}", String(stuck))}</p>
          <p>{st.kyPurgeHelp}</p>
          <div className="menu-buttons">
            <button autoFocus onClick={() => setArming(false)}>
              {st.fluxCancel}
            </button>
            <button className="cta" onClick={onRun}>
              {st.fluxConfirm} · {st.kyPurge}
            </button>
          </div>
        </div>
      ) : (
        <div className="menu-list">
          <button className="menu-item" onClick={() => setArming(true)}>
            <span className="lbl">{st.kyPurge}</span>
            <span className="desc">{st.kyPurgeHelp}</span>
          </button>
        </div>
      )}
    </div>
  );
}

/** Les descendants d'une ligne, en parcours préfixe : les suivantes plus profondes qu'elle. */
function childrenOf(rows: KyRow[], row: KyRow): KyRow[] {
  const start = rows.indexOf(row);
  if (start < 0) return [];
  const out: KyRow[] = [];
  for (let i = start + 1; i < rows.length && rows[i].depth > row.depth; i += 1) out.push(rows[i]);
  return out;
}

function total(counts: KyCounts): number {
  return counts.pass + counts.fail + counts.warn + counts.error + counts.skip;
}

/**
 * Le ton d'une ligne.
 *
 * `error` et `fail` ne partagent pas la même couleur, et c'est voulu : une règle qui n'a pas pu
 * s'évaluer est une policy cassée, une règle qui échoue est une ressource non conforme. Les deux
 * ne se corrigent pas au même endroit.
 */
function rowClass(row: KyRow): string {
  switch (row.row) {
    case "policy":
      return row.alarming ? "ky-alarm" : "ky-policy";
    case "rule":
      return "ky-rule";
    case "exception":
      return "ky-exception";
    case "namespace":
      return row.alarming ? "ky-alarm" : "ky-policy";
    case "resource":
      return "ky-rule";
    case "violation":
      return `ky-${row.result}`;
  }
}

function matches(row: KyRow, needle: string): boolean {
  const parts: string[] = [row.row];
  if ("name" in row) parts.push(row.name);
  if ("namespace" in row && row.namespace) parts.push(row.namespace);
  if ("kind" in row && row.kind) parts.push(row.kind);
  if ("message" in row && row.message) parts.push(row.message);
  if ("match_summary" in row) parts.push(row.match_summary);
  if ("policy" in row) parts.push(row.policy, row.rule, row.severity, row.category);
  if ("scope" in row) parts.push(row.scope, row.action_label);
  return parts.join(" ").toLowerCase().includes(needle);
}
