// La vue RBAC : qui peut faire quoi sur ce cluster, et par quel chemin.
//
// Ce que cette vue apporte n'est pas la liste des liaisons mais le **score** et le **graphe** : un
// Role seul n'accorde rien tant qu'il n'est pas lié, et le même ClusterRole est anodin en
// RoleBinding namespacée et critique en ClusterRoleBinding. La sévérité, les constats, les arêtes
// d'agrégation et l'attribution d'un objet à ce qui l'a posé viennent tous de `kdt::rbac`.
//
// Le navigateur ne juge rien et ne redessine aucune arête : il décide quels plis sont ouverts et
// quelle ligne on lit.

import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import type { Lang, Strings } from "./i18n";
import { InspectPanel, PanelToggle, Splitter, type PanelTab } from "./panel";
import { ObjectActions } from "./objects";
import { visibleRows } from "./tree";
import type {
  RbacBindingRow,
  RbacOrient,
  RbacPayload,
  RbacProvenance,
  RbacRoleRow,
  RbacRow,
  RbacRule,
  RbacSeverity,
  RbacSubjectRow,
} from "./types";

/** Les colonnes de la liste d'audit : `SEV SCOPE SUBJECT ROLE SOURCE RISK AGE`, celles du TUI. */
const FLAT_COLUMNS =
  "84px minmax(140px,22ch) minmax(200px,1.2fr) minmax(200px,32ch) minmax(180px,30ch)" +
  " minmax(120px,20ch) 56px";

/** Les colonnes des trois lectures en arbre : `NODE SEV SCOPE ORIGIN DETAIL AGE`. */
const TREE_COLUMNS =
  "minmax(300px,1.3fr) 84px minmax(120px,18ch) minmax(180px,28ch) minmax(200px,1.2fr) 56px";

const SEVERITIES: RbacSeverity[] = ["info", "low", "medium", "high", "critical"];

export default function RbacView({
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
  const [payload, setPayload] = useState<RbacPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [orient, setOrient] = useState<RbacOrient>("flat");
  const [minSev, setMinSev] = useState<RbacSeverity>("info");
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<PanelTab>("detail");
  const [toggled, setToggled] = useState<Record<string, boolean>>({});

  // Une seule portée : « la RBAC d'un namespace » est une question sur un namespace, pas sur trois.
  const namespace = namespaces[0] ?? "";

  const load = useCallback(async () => {
    try {
      setPayload(await api.rbac(namespace, orient, minSev));
      setError(null);
      setLoaded(true);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else if (e instanceof ApiError) setError(e.message);
      else setError(String(e));
      setLoaded(true);
    }
  }, [namespace, orient, minSev, onNeedsAuth]);

  useEffect(() => {
    void load();
    // La cadence du TUI : la RBAC d'un cluster bouge à la journée, pas à la seconde, et une passe
    // liste toutes les liaisons, tous les rôles et tous les ServiceAccounts.
    const timer = window.setInterval(() => void load(), 60000);
    return () => window.clearInterval(timer);
  }, [load]);

  const rows = payload?.rows ?? [];
  const needle = query.trim().toLowerCase();

  /**
   * Le pliage : le verdict vient du serveur — tout ce dont le pire nœud est sous HIGH se referme —
   * et un pli posé à la main gagne toujours.
   *
   * Il porte sur la **clé de nœud**, pas sur l'uid de la ligne : un ClusterRole atteint par deux
   * liaisons se replie d'un seul geste, partout où il apparaît. C'est la règle de kdt.
   */
  const collapsed = useMemo(() => {
    const out = new Set<string>();
    for (const row of rows) {
      if (!row.has_children) continue;
      const key = row.fold_key ?? row.uid;
      const manual = toggled[key];
      if (manual === undefined ? row.fold_default : manual) out.add(row.uid);
    }
    return out;
  }, [rows, toggled]);

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

  const toggleFold = useCallback((row: RbacRow, folded: boolean) => {
    const key = row.fold_key ?? row.uid;
    setToggled((prev) => ({ ...prev, [key]: !folded }));
  }, []);

  const counts = payload?.counts;
  const columns = orient === "flat" ? FLAT_COLUMNS : TREE_COLUMNS;

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
              label: st.rbacDetail,
              node: selectedRow ? (
                <RbacDetail st={st} rows={rows} row={selectedRow} degraded={payload?.sa_degraded} />
              ) : null,
            }}
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds" role="tablist">
        {(["flat", "subject", "binding", "role"] as const).map((o) => (
          <button
            key={o}
            role="tab"
            aria-selected={orient === o}
            title={st.rbacOrientHelp}
            onClick={() => setOrient(o)}
          >
            {o === "flat"
              ? st.rbacFlat
              : o === "subject"
                ? st.rbacBySubject
                : o === "binding"
                  ? st.rbacByBinding
                  : st.rbacByRole}
          </button>
        ))}

        {/* Le plancher de sévérité, que le TUI cycle sur `f`. Les cinq marches tiennent côte à
            côte : on voit où l'on est sans avoir à appuyer pour le découvrir. */}
        <div className="segmented" role="group" aria-label={st.rbacMinSevHelp}>
          {SEVERITIES.map((s) => (
            <button
              key={s}
              aria-pressed={minSev === s}
              title={st.rbacMinSevHelp}
              onClick={() => setMinSev(s)}
            >
              {sevShort(s)}
            </button>
          ))}
        </div>

        {counts && (
          <div className="tally">
            {counts.critical > 0 && (
              <span className="err" title="critical">
                ●{counts.critical}
              </span>
            )}
            {counts.high > 0 && (
              <span className="warn" title="high">
                ●{counts.high}
              </span>
            )}
            <span className="dim">
              {counts.bindings} {st.rbacBindings} · {counts.roles} {st.rbacRoles} ·{" "}
              {counts.service_accounts} {st.rbacAccounts}
            </span>
          </div>
        )}

        <div className="right">
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
              <h2>{needle || minSev !== "info" ? st.emptyTitle : st.rbacEmpty}</h2>
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
              <div className="tr" style={{ gridTemplateColumns: columns }}>
                {orient === "flat" ? (
                  <>
                    <div className="cell">SEV</div>
                    <div className="cell">SCOPE</div>
                    <div className="cell">SUBJECT</div>
                    <div className="cell">ROLE</div>
                    <div className="cell">SOURCE</div>
                    <div className="cell">RISK</div>
                    <div className="cell num">AGE</div>
                  </>
                ) : (
                  <>
                    <div className="cell">NODE</div>
                    <div className="cell">SEV</div>
                    <div className="cell">SCOPE</div>
                    <div className="cell">ORIGIN</div>
                    <div className="cell">DETAIL</div>
                    <div className="cell num">AGE</div>
                  </>
                )}
              </div>
            </div>
            <div className="tbody">
              {shown.map((row) => (
                <Line
                  key={row.uid}
                  row={row}
                  orient={orient}
                  columns={columns}
                  st={st}
                  collapsed={collapsed.has(row.uid)}
                  selected={selected === row.uid}
                  onSelect={() => setSelected(row.uid)}
                  onFold={() => toggleFold(row, collapsed.has(row.uid))}
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
        <span>{namespace || (lang === "fr" ? "tout le cluster" : "whole cluster")}</span>
        {/* Une lecture refusée change ce que la vue peut affirmer : elle le dit, plutôt que de
            montrer un graphe troué sans prévenir. */}
        {payload?.sa_degraded && <span className="warn">{st.rbacSaDegraded}</span>}
        {error && <span className="err">{error}</span>}
        <span style={{ marginLeft: "auto" }}>
          <span className="kbd">/</span> {st.hintFilter} <span className="kbd">Esc</span>{" "}
          {st.hintClose}
        </span>
      </div>
    </>
  );
}

function Line({
  row,
  orient,
  columns,
  st,
  collapsed,
  selected,
  onSelect,
  onFold,
}: {
  row: RbacRow;
  orient: RbacOrient;
  columns: string;
  st: Strings;
  collapsed: boolean;
  selected: boolean;
  onSelect: () => void;
  onFold: () => void;
}) {
  const common = {
    className: `tr ${rowClass(row)}`,
    style: { gridTemplateColumns: columns },
    "aria-selected": selected,
    tabIndex: 0,
    onClick: onSelect,
    onKeyDown: (e: React.KeyboardEvent) => {
      if (e.key === "Enter") onSelect();
      else if (e.key === " " && row.has_children) {
        e.preventDefault();
        onFold();
      }
    },
  };

  if (orient === "flat") {
    // La liste d'audit ne montre que des liaisons : c'est la lecture pour laquelle `:rbac` existe.
    if (row.row !== "binding") return null;
    return (
      <div {...common}>
        <div className={`cell sev-${row.severity}`}>
          {row.sev_icon} {row.sev_label}
        </div>
        <div className={`cell ${row.scope_alarming ? "warn" : "dim"}`} title={row.scope_label}>
          {row.scope_label}
        </div>
        <div className="cell id" title={row.subject_rows.map((s) => s.label).join(", ")}>
          {row.subject_label}
        </div>
        <div className="cell info" title={row.role_label}>
          {row.role_label}
        </div>
        <div className={`cell ${provClass(row.provenance)}`} title={row.provenance_label}>
          {row.provenance_label}
        </div>
        <div className={`cell sev-${row.severity}`} title={row.risk_tags}>
          {row.risk_top}
        </div>
        <div className="cell num dim">{row.age}</div>
      </div>
    );
  }

  return (
    <div {...common}>
      <div className="cell id" style={{ paddingLeft: `${row.depth * 1.15}rem` }}>
        {row.has_children ? (
          <button
            className="fold"
            title={st.rbacFold}
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
        <Label row={row} st={st} />
      </div>
      <TreeCells row={row} st={st} />
    </div>
  );
}

function Label({ row, st }: { row: RbacRow; st: Strings }) {
  switch (row.row) {
    case "subject":
      return (
        <>
          {row.short_label}
          {row.missing && <span className="badge err"> ✗</span>}
        </>
      );
    case "binding":
      return (
        <>
          <span className="kind">
            {row.binding_kind === "ClusterRoleBinding" ? "crb" : "rb"}
          </span>{" "}
          {row.binding_name}
        </>
      );
    case "role":
      return (
        <>
          <span className="kind">{row.kind_short}</span> {row.name}
        </>
      );
    case "contributor":
      // `⊞` se lit « replié dans le parent », le même marqueur que l'inventaire de l'arbre Flux.
      return (
        <>
          <span className="gl">⊞</span> {row.name}
        </>
      );
    case "nsgroup":
      return (
        <>
          <span className="kind">ns</span> {row.namespace}
        </>
      );
    case "rule":
      return (
        <>
          <span className="gl">·</span> {row.verbs}
        </>
      );
    case "subject-leaf":
      return (
        <>
          <span className="gl">·</span> {row.short_label}
          {row.missing && <span className="badge err"> {st.rbacSaMissing}</span>}
        </>
      );
  }
}

function TreeCells({ row, st }: { row: RbacRow; st: Strings }) {
  const blank = (
    <>
      <div className="cell" />
      <div className="cell" />
      <div className="cell" />
      <div className="cell" />
      <div className="cell" />
    </>
  );

  switch (row.row) {
    case "subject":
      return (
        <>
          <div className={`cell sev-${row.severity}`}>
            {row.sev_icon} {row.sev_label}
          </div>
          <div className="cell dim">{row.namespace ? `ns:${row.namespace}` : row.kind}</div>
          <div
            className={`cell ${row.sa ? provClass(row.sa.provenance) : "dim"}`}
            title={row.sa?.provenance_label}
          >
            {row.sa?.exists ? row.sa.provenance_label : ""}
          </div>
          <div className="cell dim">
            {row.missing ? (
              <span className="err">{st.rbacSaMissing}</span>
            ) : (
              <>
                {st.rbacNBindings.replace("{n}", String(row.grants.length))}
                {row.sa?.automount === false && ` · ${st.rbacAutomount} ${st.rbacAutomountOff}`}
              </>
            )}
          </div>
          <div className="cell num dim">{row.sa?.exists ? row.sa.age : ""}</div>
        </>
      );
    case "binding":
      return (
        <>
          <div className={`cell sev-${row.severity}`}>
            {row.sev_icon} {row.sev_label}
          </div>
          <div className={`cell ${row.scope_alarming ? "warn" : "dim"}`} title={row.scope_label}>
            {row.scope_label}
          </div>
          <div className={`cell ${provClass(row.provenance)}`} title={row.provenance_label}>
            {row.provenance_label}
          </div>
          <div className={`cell sev-${row.severity}`} title={row.risk_tags}>
            {row.risk_top}
          </div>
          <div className="cell num dim">{row.age}</div>
        </>
      );
    case "role":
    case "contributor":
      return (
        <>
          <div className={`cell sev-${row.severity}`}>
            {row.sev_icon} {row.sev_label}
          </div>
          <div className="cell dim">{row.namespace ? `ns:${row.namespace}` : "cluster"}</div>
          <div className={`cell ${provClass(row.provenance)}`} title={row.provenance_label}>
            {row.provenance_label}
          </div>
          <div className={`cell ${row.is_unbound ? "dim" : `sev-${row.severity}`}`}>
            {roleDetail(row, st)}
          </div>
          <div className="cell num dim">{row.age}</div>
        </>
      );
    case "nsgroup":
      return (
        <>
          <div className="cell" />
          <div className="cell dim">ns:{row.namespace}</div>
          <div className="cell" />
          <div className="cell dim">{st.rbacNBindings.replace("{n}", String(row.bindings))}</div>
          <div className="cell" />
        </>
      );
    case "rule":
      return (
        <>
          <div className="cell" />
          <div className="cell" />
          <div className="cell" />
          <div className="cell">
            <span className="dim">res </span>
            {row.resources} <span className="dim">grp </span>
            {row.api_groups}
            {row.resource_names.length > 0 && (
              <>
                <span className="dim"> names </span>
                {row.resource_names.join(",")}
              </>
            )}
          </div>
          <div className="cell" />
        </>
      );
    case "subject-leaf":
      return blank;
  }
}

/**
 * Ce qu'un nœud de rôle dit de lui-même : combien de règles il porte, et les deux états que seule
 * cette lecture montre — une définition re-accordée namespace par namespace, et une que personne
 * ne lie.
 */
function roleDetail(row: RbacRoleRow, st: Strings): string {
  const parts = [st.rbacNRules.replace("{n}", String(row.rule_rows.length))];
  if (row.aggregated) {
    parts.push(`⊞ ${row.aggregates_names.length}`);
  }
  if (row.is_template) {
    parts.push(st.rbacTemplate.replace("{n}", String(row.bound_namespaces.length)));
  } else if (row.is_unbound) {
    parts.push(st.rbacUnbound);
  }
  return parts.join(" · ");
}

/** Le panneau : ce que la ligne lue accorde, et par quel chemin. */
function RbacDetail({
  st,
  rows,
  row,
  degraded,
}: {
  st: Strings;
  rows: RbacRow[];
  row: RbacRow;
  degraded?: boolean;
}) {
  // Une règle et un groupe par namespace décrivent tous deux leur rôle : c'est l'objet dont le
  // panneau peut dire quelque chose d'utile. Un sujet en feuille décrit sa liaison.
  const owner = useMemo(() => {
    if (row.row === "rule" || row.row === "nsgroup" || row.row === "subject-leaf") {
      const start = rows.indexOf(row);
      for (let i = start - 1; i >= 0; i -= 1) {
        const up = rows[i];
        if (up.depth >= row.depth) continue;
        if (row.row === "subject-leaf" ? up.row === "binding" : up.row === "role" || up.row === "contributor") {
          return up;
        }
        if (up.depth === 0) break;
      }
      return null;
    }
    return row;
  }, [rows, row]);

  if (!owner) return null;
  if (owner.row === "binding") return <BindingDetail st={st} row={owner} degraded={degraded} />;
  if (owner.row === "role" || owner.row === "contributor")
    return <RoleDetail st={st} row={owner} />;
  if (owner.row === "subject") return <SubjectDetail st={st} row={owner} degraded={degraded} />;
  return null;
}

function BindingDetail({
  st,
  row,
  degraded,
}: {
  st: Strings;
  row: RbacBindingRow;
  degraded?: boolean;
}) {
  return (
    <div className="detail">
      <dl className="facts">
        <dt>severity</dt>
        <dd className={sevClass(row.severity)}>{row.sev_label}</dd>
        <dt>{st.rbacScopeLabel}</dt>
        <dd className={row.scope_alarming ? "warn" : undefined}>{row.scope_label}</dd>
        <dt>{st.rbacRoleLabel}</dt>
        <dd>{row.role_label}</dd>
        {row.via_clusterrole && (
          <>
            <dt>{st.rbacVia}</dt>
            <dd>{st.rbacViaClusterrole.replace("{scope}", row.scope_label)}</dd>
          </>
        )}
        {row.aggregated && (
          <>
            <dt>aggregation</dt>
            <dd>{st.rbacAggregatedLabel}</dd>
          </>
        )}
        <dt>{st.rbacOrigin}</dt>
        <dd className={provClass(row.provenance)}>{row.provenance_label}</dd>
        {row.source && (
          <>
            <dt>{st.rbacSource}</dt>
            <dd className="wrap">{row.source}</dd>
          </>
        )}
        <dt>{st.rbacSubjects}</dt>
        <dd>
          {row.subject_rows.map((s) => (
            <div key={s.label} className={s.missing ? "err" : undefined}>
              {s.label}
              {/* Un compte absent n'accorde rien aujourd'hui — et accordera tout dès que
                  quelqu'un le créera. Muet tant que la liste n'a pas pu être lue. */}
              {s.missing && !degraded && ` (${st.rbacSaMissing})`}
            </div>
          ))}
        </dd>
        <dt>age</dt>
        <dd>{row.age}</dd>
      </dl>

      <div className="sect">{st.rbacFindings}</div>
      {row.findings.length === 0 ? (
        <p className="dim">{st.rbacReadOnly}</p>
      ) : (
        <ul className="hints">
          {row.findings.map((f) => (
            <li key={f.tag} className={hintClass(f.sev)}>
              <span className="gl">{sevIcon(f.sev)}</span>
              <strong>{f.tag}</strong> — {f.detail}
            </li>
          ))}
        </ul>
      )}

      <div className="sect">{st.rbacRules}</div>
      <RuleList st={st} rules={row.rule_rows} />
    </div>
  );
}

function RoleDetail({ st, row }: { st: Strings; row: RbacRoleRow }) {
  return (
    <div className="detail">
      <dl className="facts">
        <dt>severity</dt>
        <dd className={sevClass(row.severity)}>{row.sev_label}</dd>
        <dt>{st.rbacScopeLabel}</dt>
        <dd>{row.namespace ? `ns:${row.namespace}` : "cluster"}</dd>
        <dt>{st.rbacOrigin}</dt>
        <dd className={provClass(row.provenance)}>{row.provenance_label}</dd>
        {row.source && (
          <>
            <dt>{st.rbacSource}</dt>
            <dd className="wrap">{row.source}</dd>
          </>
        )}
        <dt>{st.rbacBound}</dt>
        <dd className={row.is_unbound ? "dim" : undefined}>
          {row.is_unbound
            ? st.rbacUnbound
            : [
                row.bound_cluster > 0
                  ? st.rbacBoundCluster.replace("{n}", String(row.bound_cluster))
                  : null,
                row.bound_namespaces.length > 0
                  ? st.rbacBoundNs.replace("{n}", String(row.bound_namespaces.length))
                  : null,
              ]
                .filter(Boolean)
                .join(" · ")}
        </dd>
        {row.is_template && (
          <>
            <dt>{st.rbacGrantedIn}</dt>
            <dd className="wrap">{row.bound_namespaces.join(", ")}</dd>
          </>
        )}
        <dt>age</dt>
        <dd>{row.age}</dd>
      </dl>

      {row.aggregated && (
        <>
          <div className="sect">{st.rbacAggregation}</div>
          {/* Un sélecteur en matchExpressions n'est pas évalué : l'union est une borne basse, et le
              dire vaut mieux que de sous-déclarer en silence. */}
          {row.aggregation_partial && <p className="warn">{st.rbacAggregationPartial}</p>}
          {row.aggregates_names.length === 0 ? (
            <p className="dim">{st.rbacAggregatesNone}</p>
          ) : (
            <ul className="hints">
              {row.aggregates_names.map((c) => (
                <li key={c.name} className="info">
                  <span className="gl">⊞</span> {c.name}{" "}
                  <span className="dim">({st.rbacNRules.replace("{n}", String(c.rules))})</span>
                </li>
              ))}
            </ul>
          )}
        </>
      )}

      {/* L'arête inverse répond à « pourquoi `admin` accorde-t-il soudain ça ? » depuis le
          contributeur. */}
      {row.aggregates_into_names.length > 0 && (
        <>
          <div className="sect">{st.rbacFeeds}</div>
          <ul className="hints">
            {row.aggregates_into_names.map((n) => (
              <li key={n} className="info">
                <span className="gl">↑</span> {n}
              </li>
            ))}
          </ul>
        </>
      )}

      {row.findings.length > 0 && (
        <>
          <div className="sect">{st.rbacFindings}</div>
          <ul className="hints">
            {row.findings.map((f) => (
              <li key={f.tag} className={hintClass(f.sev)}>
                <span className="gl">{sevIcon(f.sev)}</span>
                <strong>{f.tag}</strong> — {f.detail}
              </li>
            ))}
          </ul>
        </>
      )}

      <div className="sect">{st.rbacRules}</div>
      <RuleList st={st} rules={row.rule_rows} />
    </div>
  );
}

function SubjectDetail({
  st,
  row,
  degraded,
}: {
  st: Strings;
  row: RbacSubjectRow;
  degraded?: boolean;
}) {
  return (
    <div className="detail">
      <dl className="facts">
        <dt>severity</dt>
        <dd className={sevClass(row.severity)}>{row.sev_label}</dd>
        <dt>kind</dt>
        <dd>{row.kind}</dd>
        {row.namespace && (
          <>
            <dt>namespace</dt>
            <dd>{row.namespace}</dd>
          </>
        )}
        {row.sa?.exists && (
          <>
            <dt>{st.rbacOrigin}</dt>
            <dd className={provClass(row.sa.provenance)}>{row.sa.provenance_label}</dd>
            {row.sa.source && (
              <>
                <dt>{st.rbacSource}</dt>
                <dd className="wrap">{row.sa.source}</dd>
              </>
            )}
            <dt>{st.rbacAutomount}</dt>
            <dd>
              {row.sa.automount === true
                ? st.rbacAutomountOn
                : row.sa.automount === false
                  ? st.rbacAutomountOff
                  : st.rbacAutomountDefault}
            </dd>
            <dt>{st.rbacSecrets}</dt>
            <dd>
              {row.sa.secrets} · imagePull {row.sa.image_pull_secrets}
            </dd>
            <dt>age</dt>
            <dd>{row.sa.age}</dd>
          </>
        )}
      </dl>

      {row.missing && !degraded && <p className="err">{st.rbacSaMissingDetail}</p>}
      {/* Un User ou un Group n'est pas un objet du cluster : c'est un nom que l'authentificateur
          rend, et rien d'honnête ne peut en être dit de plus. */}
      {!row.sa && row.kind !== "ServiceAccount" && <p className="dim">{st.rbacExternalSubject}</p>}

      <div className="sect">{st.rbacGrants}</div>
      {row.grants.length === 0 ? (
        <p className="dim">{st.rbacNoGrant}</p>
      ) : (
        <ul className="hints">
          {row.grants.map((g, i) => (
            <li key={i} className={hintClass(g.severity)}>
              <span className="gl">{g.sev_icon}</span>
              <strong>{g.sev_label}</strong> {g.role_label}{" "}
              <span className="dim">{g.scope_label}</span> — {g.risk_top}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function RuleList({ st, rules }: { st: Strings; rules: RbacRule[] }) {
  if (rules.length === 0) return <p className="dim">{st.rbacNoRule}</p>;
  return (
    <ul className="hints">
      {rules.map((r, i) => (
        <li key={i} className="info">
          <span className="dim">verbs </span>
          <span className="warn">{r.verbs}</span>
          <span className="dim"> res </span>
          {r.resources}
          <span className="dim"> grp </span>
          {r.api_groups}
          {r.resource_names.length > 0 && (
            <>
              <span className="dim"> names </span>
              <span className="ok">{r.resource_names.join(",")}</span>
            </>
          )}
        </li>
      ))}
    </ul>
  );
}

function sevShort(s: RbacSeverity): string {
  return { info: "INFO", low: "LOW", medium: "MED", high: "HIGH", critical: "CRIT" }[s];
}

function sevIcon(s: RbacSeverity): string {
  return s === "low" ? "○" : s === "info" ? "·" : "●";
}

function sevClass(s: RbacSeverity): string {
  return s === "critical" || s === "high" ? "err" : s === "medium" ? "warn" : "dim";
}

function hintClass(s: RbacSeverity): string {
  return s === "critical" || s === "high" ? "danger" : s === "medium" ? "warn" : "info";
}

/**
 * Le ton d'une origine.
 *
 * Un objet posé par un moteur GitOps est auditable ; un objet que personne ne réclame ne l'est pas.
 * Entre les deux, Kyverno, Rancher, les défauts du cluster et les gestionnaires d'add-ons **posent
 * des objets sans passer par kubectl** : ils sont attribués, et les peindre en rouge dirait faux.
 */
function provClass(p: RbacProvenance): string {
  switch (p.source) {
    case "flux-kustomization":
    case "flux-helm-release":
      return "ok";
    case "helm":
    case "argo":
      return "info";
    case "kyverno":
    case "rancher":
      return "prov-owned";
    case "bootstrap":
    case "addon":
    case "owner":
      return "dim";
    default:
      return "err";
  }
}

function rowClass(row: RbacRow): string {
  switch (row.row) {
    case "binding":
      // Une liaison critique garde son lit rouge où qu'elle ait défilé : c'est celle qui compte.
      return row.severity === "critical" ? "rbac-crit" : `rbac-sev-${row.severity}`;
    case "role":
    case "contributor":
      return "rbac-role";
    case "subject":
      return "rbac-subject";
    case "nsgroup":
      return "rbac-nsgroup";
    case "rule":
      return "rbac-rule";
    case "subject-leaf":
      return "rbac-leaf";
  }
}

function matches(row: RbacRow, needle: string): boolean {
  const parts: string[] = [row.row];
  if ("binding_name" in row) {
    parts.push(row.binding_name, row.role_label, row.subject_label, row.provenance_label, row.risk_tags, row.scope_label);
  }
  if ("name" in row) parts.push(row.name);
  if ("namespace" in row && row.namespace) parts.push(row.namespace);
  if ("label" in row) parts.push(row.label);
  if ("verbs" in row) parts.push(row.verbs, row.resources, row.api_groups);
  if ("provenance_label" in row) parts.push(row.provenance_label);
  return parts.join(" ").toLowerCase().includes(needle);
}
