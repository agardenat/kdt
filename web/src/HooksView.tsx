// La vue hooks : les trois surfaces que l'apiserver appelle.
//
// Les webhooks d'admission, les CRD qui confient leur conversion à un webhook, et les APIService
// agrégées. Trois mondes, un seul mode de panne — un service backing qui ne répond pas — et trois
// conséquences : des écritures refusées, des **lectures** cassées, une découverte incomplète.
//
// Un seul appel rend les trois : changer d'onglet ne coûte aucune requête.
//
// Deux règles qui décident de la mise en page :
//
// * une ligne d'admission est un webhook **nommé**, pas une configuration — c'est le nom que
//   l'apiserver met dans `failed calling webhook "..."`, donc celui qu'on cherche. Mais son
//   `record` désigne la configuration, seul objet que la suppression puisse atteindre, et le
//   panneau le dit en toutes lettres ;
// * `unchecked` n'est jamais peint en panne. Un backend que kdt n'a pas pu interroger dit qu'il n'a
//   pas pu être interrogé.

import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import type { Lang, Strings } from "./i18n";

/** Le pluriel, comme `Strings::plural` côté kdt : le français bascule à deux, l'anglais à un. */
function plural(lang: Lang, n: number, one: string, many: string): string {
  const isPlural = lang === "fr" ? n > 1 : n !== 1;
  return (isPlural ? many : one).replace("{n}", String(n));
}
import { BulkDeletePane, RowMenu, type ObjectTab } from "./objects";
import { RowCheckbox, SelectionBar, SelectionHead, useMultiSelect } from "./selection";
import { InspectPanel, PanelToggle, Splitter, ViewBody, type PanelTab } from "./panel";
import type {
  AdmissionConfigRow,
  AdmissionHookRow,
  ApiServiceHookRow,
  ConversionHookRow,
  EventRecord,
  HookCaBundle,
  HookHint,
  HookReach,
  HooksPayload,
} from "./types";

type World = "admission" | "conversion" | "apiservice";

/** `KIND CONFIGURATION WEBHOOK POLICY TMO BACKEND REACH SCOPE CA AGE VERDICT`, dans l'ordre du TUI. */
/* Le verdict est une phrase, et `.tbl` est en `width: max-content` : une piste `1fr` s'y résoudrait
 * sur le contenu et étirerait la table bien au-delà de l'écran. Elle a donc un plafond, comme les
 * autres colonnes de texte. La phrase entière reste dans le `title` et dans le panneau de détail,
 * qui est l'endroit fait pour la lire. */
const VERDICT = "minmax(220px,34ch)";

const ADMISSION_COLUMNS =
  "34px 52px minmax(140px,18ch) minmax(160px,22ch) 72px 56px minmax(150px,18ch) 76px" +
  ` minmax(90px,10ch) 64px 52px ${VERDICT} 34px`;

const CONVERSION_COLUMNS =
  "34px minmax(170px,24ch) minmax(120px,16ch) minmax(100px,12ch) minmax(120px,14ch)" +
  ` minmax(90px,9ch) minmax(150px,18ch) 76px 64px 52px ${VERDICT} 34px`;

const APISERVICE_COLUMNS =
  "34px minmax(180px,26ch) minmax(130px,18ch) 84px minmax(150px,18ch) 76px 72px" +
  ` minmax(120px,16ch) 64px 52px ${VERDICT} 34px`;

type Row = AdmissionHookRow | AdmissionConfigRow | ConversionHookRow | ApiServiceHookRow;

function isAdmission(row: Row): row is AdmissionHookRow {
  return "fail_closed" in row;
}

function isConfig(row: Row): row is AdmissionConfigRow {
  return "api_kind" in row;
}

/** Le pire constat de la ligne : celui qui décide de ce qu'il y a à faire. */
function worst(hints: HookHint[]): HookHint | null {
  const order = { info: 0, warn: 1, danger: 2 };
  return hints.reduce<HookHint | null>(
    (acc, h) => (acc === null || order[h.level] > order[acc.level] ? h : acc),
    null,
  );
}

function reachClass(reach: HookReach): string {
  if (reach === "ready") return "ok";
  if (reach === "not-ours" || reach === "unchecked") return "dim";
  return "err";
}

function reachText(reach: HookReach, st: Strings): string {
  switch (reach) {
    case "ready":
      return st.hooksReachReady;
    case "no-endpoints":
      return st.hooksReachNoEndpoints;
    case "service-gone":
      return st.hooksReachServiceGone;
    case "namespace-gone":
      return st.hooksReachNamespaceGone;
    case "not-ours":
      return st.hooksReachNotOurs;
    default:
      return st.hooksReachUnchecked;
  }
}

function caLabel(ca: HookCaBundle, st: Strings): { text: string; cls: string } {
  if (ca.state === "absent") {
    return ca.injector ? { text: "inject", cls: "dim" } : { text: "absent", cls: "warn" };
  }
  if (ca.state === "opaque") return { text: "opaque", cls: "dim" };
  const soonest = ca.certs.reduce<number | null>(
    (acc, c) => (acc === null || c.days_remaining < acc ? c.days_remaining : acc),
    null,
  );
  if (soonest === null) return { text: "opaque", cls: "dim" };
  if (soonest <= 0) return { text: st.hooksCaExpires.includes("expire") ? "expiré" : "expired", cls: "err" };
  return { text: `${soonest}${st.hooksCaExpires.includes("expire") ? "j" : "d"}`, cls: soonest <= 30 ? "warn" : "ok" };
}

export default function HooksView({
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
  const [payload, setPayload] = useState<HooksPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [world, setWorld] = useState<World>("admission");
  const [group, setGroup] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<PanelTab>("detail");
  const [notice, setNotice] = useState<string | null>(null);
  const { checked, toggle, clear, setAll } = useMultiSelect();
  const [bulkOpen, setBulkOpen] = useState(false);

  const load = useCallback(async () => {
    try {
      setPayload(await api.hooks(lang));
      setError(null);
      setLoaded(true);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else if (e instanceof ApiError) setError(e.message);
      else setError(String(e));
      setLoaded(true);
    }
  }, [lang, onNeedsAuth]);

  useEffect(() => {
    void load();
    // Une minute : cet appel liste toutes les CRD du cluster, et chacune porte son schéma OpenAPI
    // complet. Les configurations d'admission changent à un déploiement, pas à la seconde.
    const timer = window.setInterval(() => void load(), 60000);
    return () => window.clearInterval(timer);
  }, [load]);

  // Les lignes du monde courant, groupées ou non. Le groupement n'existe qu'en admission : rien à
  // emboîter ailleurs.
  const rows: Row[] = useMemo(() => {
    if (!payload) return [];
    if (world === "conversion") return payload.conversion;
    if (world === "apiservice") return payload.apiservices;
    if (!group) return payload.admission;
    const out: Row[] = [];
    for (const cfg of payload.configs) {
      out.push(cfg);
      for (const h of payload.admission) {
        if (h.kind === cfg.kind && h.config === cfg.name) out.push(h);
      }
    }
    return out;
  }, [payload, world, group]);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return rows;
    return rows.filter((row) => {
      const parts: string[] = [row.name, row.record.kind];
      if (isAdmission(row)) parts.push(row.config, row.backend_label, row.reach_label);
      else if (!isConfig(row)) parts.push(row.backend_label, row.reach_label, row.group);
      const hint = worst(row.hints);
      if (hint) parts.push(hint.text);
      return parts.join(" ").toLowerCase().includes(needle);
    });
  }, [rows, query]);

  const selectedRow = visible.find((r) => r.uid === selected) ?? null;
  const selectedRecord: EventRecord | null = selectedRow?.record ?? null;
  const counts = payload?.counts[world];
  const worldError =
    world === "admission"
      ? payload?.error
      : world === "conversion"
        ? payload?.conversion_error
        : payload?.apiservice_error;

  const flipPolicy = async (row: AdmissionHookRow) => {
    const to = row.fail_closed ? "Ignore" : "Fail";
    try {
      const { message } = await api.hookFailurePolicy(
        row.kind,
        row.config,
        row.index,
        row.name,
        to,
        lang,
      );
      setNotice(message);
      await load();
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else setNotice(e instanceof ApiError ? e.message : String(e));
    }
  };

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
            detail={
              selectedRow
                ? { label: st.tabDetail, node: <HookDetail row={selectedRow} st={st} /> }
                : undefined
            }
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds" role="tablist">
        {(
          [
            ["admission", st.hooksAdmission, payload?.counts.admission.rows],
            ["conversion", st.hooksConversion, payload?.counts.conversion.rows],
            ["apiservice", st.hooksApiServices, payload?.counts.apiservice.rows],
          ] as const
        ).map(([id, label, n]) => (
          <button
            key={id}
            role="tab"
            aria-selected={world === id}
            onClick={() => {
              setWorld(id);
              setSelected(null);
              clear();
            }}
          >
            {label}
            {n !== undefined && <span className="count">{n}</span>}
          </button>
        ))}

        {world === "admission" && (
          <label className="chk">
            <input type="checkbox" checked={group} onChange={() => setGroup(!group)} />
            {st.hooksGroup}
          </label>
        )}

        {counts && (
          <div className="tally">
            {counts.fail_closed > 0 && (
              <span className="warn">
                {counts.fail_closed}{" "}
                {plural(lang, counts.fail_closed, st.hooksFailClosedOne, st.hooksFailClosed)}
              </span>
            )}
            {counts.broken > 0 && (
              <span className="err">
                {counts.broken} {plural(lang, counts.broken, st.hooksBrokenOne, st.hooksBroken)}
              </span>
            )}
            {counts.catch_all > 0 && (
              <span className="warn">
                {counts.catch_all}{" "}
                {plural(lang, counts.catch_all, st.hooksCatchAllOne, st.hooksCatchAll)}
              </span>
            )}
          </div>
        )}

        <div className="right">
          <SelectionBar
            keys={visible.map((r) => r.uid)}
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
        record={selectedRecord}
        lang={lang}
        st={st}
        onTab={setTab}
        onNeedsAuth={onNeedsAuth}
        hasDetail={Boolean(selectedRow)}
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
                    records={visible.filter((r) => checked.has(r.uid)).map((r) => r.record)}
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
        ) : visible.length === 0 ? (
          <div className="center">
            <div className="box">
              <h2>{st.hooksEmpty}</h2>
              {error && <p className="err">{error}</p>}
              {worldError && <p className="err">{worldError}</p>}
            </div>
          </div>
        ) : (
          <HooksTable
            world={world}
            rows={visible}
            selected={selected}
            lang={lang}
            st={st}
            grouped={group}
            onSelect={(uid) => {
              setSelected(uid);
              setTab("detail");
            }}
            onOpenTab={(uid, t) => {
              setSelected(uid);
              setTab(t);
            }}
            onNeedsAuth={onNeedsAuth}
            checked={checked}
            onToggleCheck={toggle}
            onFlipPolicy={flipPolicy}
          />
        )}
      </ViewBody>

      <div className="statusbar">
        <span>
          {visible.length} {st.rows}
        </span>
        {world === "apiservice" && payload && payload.local_apiservices > 0 && (
          <span className="dim">
            {st.hooksLocalApi.replace("{n}", String(payload.local_apiservices))}
          </span>
        )}
        {notice && <span>{notice}</span>}
        {worldError && <span className="err">{worldError}</span>}
        {error && <span className="err">{error}</span>}
      </div>
    </>
  );
}

function HooksTable({
  world,
  rows,
  selected,
  lang,
  st,
  grouped,
  onSelect,
  onOpenTab,
  onNeedsAuth,
  checked,
  onToggleCheck,
  onFlipPolicy,
}: {
  world: World;
  rows: Row[];
  selected: string | null;
  lang: Lang;
  st: Strings;
  grouped: boolean;
  onSelect: (uid: string) => void;
  onOpenTab: (uid: string, tab: ObjectTab) => void;
  onNeedsAuth: (message: string) => void;
  checked: Set<string>;
  onToggleCheck: (key: string) => void;
  onFlipPolicy: (row: AdmissionHookRow) => void;
}) {
  const columns =
    world === "admission"
      ? ADMISSION_COLUMNS
      : world === "conversion"
        ? CONVERSION_COLUMNS
        : APISERVICE_COLUMNS;

  const headers =
    world === "admission"
      ? ["KIND", "CONFIGURATION", "WEBHOOK", "POLICY", "TMO", "BACKEND", "REACH", "SCOPE", "CA", "AGE", "VERDICT"]
      : world === "conversion"
        ? ["CRD", "GROUP", "KIND", "SERVED", "STORAGE", "BACKEND", "REACH", "CA", "AGE", "VERDICT"]
        : ["APISERVICE", "GROUP", "VERSION", "BACKEND", "REACH", "AVAIL", "REASON", "CA", "AGE", "VERDICT"];

  return (
    <div className="tbl">
      <div className="thead">
        <div className="tr" style={{ gridTemplateColumns: columns }}>
          <SelectionHead />
          {headers.map((h) => (
            <div key={h} className="cell">
              {h}
            </div>
          ))}
          <div className="cell act" />
        </div>
      </div>
      <div className="tbody">
        {rows.map((row) => (
          <div
            key={row.uid}
            className={`tr sev-${row.record.tone}`}
            style={{ gridTemplateColumns: columns }}
            aria-selected={selected === row.uid}
            tabIndex={0}
            onClick={() => onSelect(row.uid)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onSelect(row.uid);
            }}
          >
            <RowCheckbox
              checked={checked.has(row.uid)}
              onToggle={() => onToggleCheck(row.uid)}
              label={st.selectRow}
            />
            {world === "admission" ? (
              <AdmissionCells row={row} grouped={grouped} lang={lang} st={st} />
            ) : world === "conversion" ? (
              <ConversionCells row={row as ConversionHookRow} st={st} />
            ) : (
              <ApiServiceCells row={row as ApiServiceHookRow} st={st} />
            )}
            <div className="cell act">
              <RowMenu
                record={row.record}
                lang={lang}
                st={st}
                onOpen={(t) => onOpenTab(row.uid, t)}
                onNeedsAuth={onNeedsAuth}
              >
                {isAdmission(row)
                  ? ({ close }) => (
                      <button
                        className="menu-item"
                        onClick={() => {
                          close();
                          onFlipPolicy(row);
                        }}
                      >
                        {st.hooksPolicyAction.replace("{to}", row.fail_closed ? "Ignore" : "Fail")}
                      </button>
                    )
                  : undefined}
              </RowMenu>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function Verdict({ hints }: { hints: HookHint[] }) {
  const w = worst(hints);
  if (!w) return <div className="cell" />;
  const cls = w.level === "danger" ? "err" : w.level === "warn" ? "warn" : "dim";
  return (
    <div className={`cell ${cls}`} title={w.text}>
      {w.text}
    </div>
  );
}

function AdmissionCells({
  row,
  grouped,
  lang,
  st,
}: {
  row: Row;
  grouped: boolean;
  lang: Lang;
  st: Strings;
}) {
  if (isConfig(row)) {
    // La ligne parente : la configuration, son compte de webhooks et son pire verdict — jamais plus
    // saine que ses enfants.
    return (
      <>
        <div className={`cell mono wh-${row.kind}`}>{row.kind_label}</div>
        <div className="cell id">{row.name}</div>
        <div className="cell" />
        <div className="cell" />
        <div className="cell" />
        <div className="cell" />
        <div className="cell" />
        <div className="cell dim">{plural(lang, row.hooks, st.hooksWebhook, st.hooksWebhooks)}</div>
        <div className="cell" />
        <div className="cell num dim">{row.age}</div>
        <Verdict hints={row.hints} />
      </>
    );
  }
  const h = row as AdmissionHookRow;
  const ca = caLabel(h.ca, st);
  const policyCls = h.failure_policy_defaulted
    ? "dim"
    : h.fail_closed && h.broken
      ? "err"
      : h.fail_closed
        ? ""
        : "dim";
  return (
    <>
      <div className={`cell mono wh-${h.kind}`}>{h.kind_label}</div>
      {/* Groupé, la configuration est la ligne parente : inutile de répéter son nom partout. */}
      <div className="cell mono dim">{grouped ? "" : h.config}</div>
      <div className="cell id">{h.name}</div>
      <div className={`cell mono ${policyCls}`}>{h.fail_closed ? "Fail" : "Ignore"}</div>
      <div className={`cell num ${h.timeout_seconds === null ? "dim" : ""}`}>
        {h.timeout_seconds ?? 10}s
      </div>
      <div className="cell mono">{h.backend_label}</div>
      <div className={`cell mono ${reachClass(h.reach)}`} title={reachText(h.reach, st)}>
        {h.reach_label}
      </div>
      <div className={`cell mono ${h.catch_all ? "err" : "dim"}`}>
        {h.catch_all ? "*/*/*" : plural(lang, h.rules.length, st.hooksRule, st.hooksRules)}
      </div>
      <div className={`cell mono ${ca.cls}`}>{ca.text}</div>
      <div className="cell num dim">{h.age}</div>
      <Verdict hints={h.hints} />
    </>
  );
}

function ConversionCells({ row, st }: { row: ConversionHookRow; st: Strings }) {
  const ca = caLabel(row.ca, st);
  return (
    <>
      <div className="cell id">{row.name}</div>
      <div className="cell mono dim">{row.group}</div>
      <div className="cell">{row.kind}</div>
      <div className="cell mono dim">{row.served_label}</div>
      {/* La version de stockage décide si ce qui est déjà écrit peut être relu : elle a sa colonne. */}
      <div className={`cell mono ${row.storage_version_served ? "" : "err"}`}>
        {row.storage_version}
      </div>
      <div className="cell mono">{row.backend_label}</div>
      <div className={`cell mono ${reachClass(row.reach)}`} title={reachText(row.reach, st)}>
        {row.reach_label}
      </div>
      <div className={`cell mono ${ca.cls}`}>{ca.text}</div>
      <div className="cell num dim">{row.age}</div>
      <Verdict hints={row.hints} />
    </>
  );
}

function ApiServiceCells({ row, st }: { row: ApiServiceHookRow; st: Strings }) {
  const ca = caLabel(row.ca, st);
  const availCls =
    row.available === "True" ? "ok" : row.available === "False" ? "err" : "dim";
  return (
    <>
      <div className="cell id">{row.name}</div>
      <div className="cell mono dim">{row.group}</div>
      <div className="cell mono">{row.version}</div>
      <div className="cell mono">{row.backend_label}</div>
      <div className={`cell mono ${reachClass(row.reach)}`} title={reachText(row.reach, st)}>
        {row.reach_label}
      </div>
      <div className={`cell mono ${availCls}`}>{row.available_label}</div>
      <div className="cell dim" title={row.message}>
        {row.reason}
      </div>
      {/* `insecureSkipTLSVerify` remplace la colonne CA : il n'y a pas de certificat vérifié dont
          donner la date, et c'est la chose la plus utile à dire. */}
      {row.insecure ? (
        <div className="cell mono err">insec</div>
      ) : (
        <div className={`cell mono ${ca.cls}`}>{ca.text}</div>
      )}
      <div className="cell num dim">{row.age}</div>
      <Verdict hints={row.hints} />
    </>
  );
}

function HookDetail({ row, st }: { row: Row; st: Strings }) {
  if (isConfig(row)) {
    return (
      <div className="detail">
        <Section title={st.hooksSecIdentity} />
        <Line label="kind" value={row.api_kind} mono />
        <Line label="webhooks" value={String(row.hooks)} />
        <Line label="age" value={row.age} />
        <Findings hints={row.hints} st={st} />
      </div>
    );
  }
  if (isAdmission(row)) return <AdmissionDetail row={row} st={st} />;
  if ("storage_version" in row) return <ConversionDetail row={row} st={st} />;
  return <ApiServiceDetail row={row as ApiServiceHookRow} st={st} />;
}

function AdmissionDetail({ row, st }: { row: AdmissionHookRow; st: Strings }) {
  return (
    <div className="detail">
      <Section title={st.hooksSecIdentity} />
      <Line label="kind" value={row.record.kind} mono />
      <Line label="configuration" value={row.config} mono />
      <Line label="webhook" value={`${row.name} (#${row.index})`} mono />
      {/* Ce que la suppression emporterait : un webhook nommé n'est pas un objet d'API. */}
      <p className="hint-note warn">
        {st.hooksDeleteNote.replace("{config}", row.config).replace("{n}", String(row.siblings))}
      </p>

      <Reach backend={row.backend_label} reach={row.reach} st={st} />

      <Section title={st.hooksSecPolicy} />
      <Line
        label="failurePolicy"
        value={`${row.fail_closed ? "Fail" : "Ignore"}${row.failure_policy_defaulted ? " (default)" : ""}`}
        mono
      />
      <Line label="timeoutSeconds" value={String(row.timeout_seconds ?? 10)} mono />
      <Line label="sideEffects" value={row.side_effects} mono />
      <Line label="matchPolicy" value={row.match_policy} mono />
      {row.reinvocation_policy && (
        <Line label="reinvocationPolicy" value={row.reinvocation_policy} mono />
      )}
      <Line label="admissionReviewVersions" value={row.admission_review_versions.join(",")} mono />
      {row.match_conditions > 0 && (
        <p className="hint-note info">
          {st.hooksMatchConditions.replace("{n}", String(row.match_conditions))}
        </p>
      )}

      <Section title={st.hooksSecScope} />
      {row.rules.map((rule, i) => (
        <Line
          key={i}
          label={`rules[${i}]`}
          value={`${rule.api_groups.join(",") || "*"}/${rule.api_versions.join(",") || "*"} ${
            rule.resources.join(",") || "*"
          } [${rule.operations.join(",") || "*"}]`}
          mono
        />
      ))}
      <Line
        label="namespaceSelector"
        value={row.namespace_selector.matches_everything ? "*" : row.namespace_selector.summary}
        mono
      />
      <Line
        label="objectSelector"
        value={row.object_selector.matches_everything ? "*" : row.object_selector.summary}
        mono
      />

      <Ca ca={row.ca} st={st} />
      <Findings hints={row.hints} st={st} />
    </div>
  );
}

function ConversionDetail({ row, st }: { row: ConversionHookRow; st: Strings }) {
  return (
    <div className="detail">
      <Section title={st.hooksSecIdentity} />
      <Line label="kind" value="CustomResourceDefinition" mono />
      <Line label="group" value={row.group} mono />
      <Line label="scope" value={row.scope} mono />
      <Line label="conversionReviewVersions" value={row.conversion_review_versions.join(",")} mono />

      <Reach backend={row.backend_label} reach={row.reach} st={st} />
      {row.broken && (
        <p className="hint-note warn">{st.hooksConvCost.replace("{kind}", row.kind)}</p>
      )}

      <Section title={st.hooksSecVersions} />
      {row.versions.map((v) => (
        <Line
          key={v.name}
          label={v.name}
          value={[v.served && "served", v.storage && "storage", v.deprecated && "deprecated"]
            .filter(Boolean)
            .join(", ")}
          tone={v.storage && !v.served ? "err" : v.deprecated ? "warn" : undefined}
        />
      ))}

      <Ca ca={row.ca} st={st} />
      <Findings hints={row.hints} st={st} />
    </div>
  );
}

function ApiServiceDetail({ row, st }: { row: ApiServiceHookRow; st: Strings }) {
  return (
    <div className="detail">
      <Section title={st.hooksSecIdentity} />
      <Line label="kind" value="APIService" mono />
      <Line label="group" value={row.group} mono />
      <Line label="version" value={row.version} mono />
      <Line label="groupPriorityMinimum" value={String(row.group_priority_minimum)} mono />
      <Line label="versionPriority" value={String(row.version_priority)} mono />
      <Line label="insecureSkipTLSVerify" value={String(row.insecure)} mono />

      <Reach backend={row.backend_label} reach={row.reach} st={st} />

      <Section title="Available" />
      <Line label="status" value={row.available_label} mono />
      {/* La raison et le message de l'apiserver, verbatim : il sait pourquoi il a renoncé, et les
          reformuler perdrait la seule piste qu'il y a. */}
      {row.reason && <Line label="reason" value={row.reason} mono />}
      {row.message && <p className="hint-note info">{row.message}</p>}
      {(row.available !== "True" || row.broken) && (
        <p className="hint-note warn">{st.hooksApiCost}</p>
      )}

      <Ca ca={row.ca} st={st} />
      <Findings hints={row.hints} st={st} />
    </div>
  );
}

function Reach({ backend, reach, st }: { backend: string; reach: HookReach; st: Strings }) {
  return (
    <>
      <Section title={st.hooksSecReach} />
      <Line label="backend" value={backend} mono />
      <Line label="reach" value={reachText(reach, st)} tone={reachClass(reach)} />
    </>
  );
}

function Ca({ ca, st }: { ca: HookCaBundle; st: Strings }) {
  return (
    <>
      <Section title="caBundle" />
      {ca.state === "absent" && (
        <p className="hint-note info">
          {ca.injector ? st.hooksCaInjected.replace("{injector}", ca.injector) : st.hooksCaNone}
        </p>
      )}
      {ca.state === "opaque" && (
        <p className="hint-note warn">{st.hooksCaOpaque.replace("{n}", String(ca.bytes))}</p>
      )}
      {ca.state === "parsed" &&
        ca.certs.map((c, i) => (
          <Line
            key={i}
            label={c.subject_cn}
            value={`${c.self_signed ? st.hooksCaSelfSigned : c.issuer_cn} — ${st.hooksCaExpires
              .replace("{date}", c.not_after)
              .replace("{n}", String(c.days_remaining))}`}
            tone={c.days_remaining <= 0 ? "err" : c.days_remaining <= 30 ? "warn" : undefined}
          />
        ))}
    </>
  );
}

function Findings({ hints, st }: { hints: HookHint[]; st: Strings }) {
  if (hints.length === 0) return null;
  const order = { danger: 0, warn: 1, info: 2 };
  const sorted = [...hints].sort((a, b) => order[a.level] - order[b.level]);
  return (
    <>
      <Section title={st.hooksSecFindings} />
      {sorted.map((h, i) => (
        <p
          key={i}
          className={`hint-note ${h.level === "danger" ? "err" : h.level === "warn" ? "warn" : "info"}`}
        >
          {h.text}
        </p>
      ))}
    </>
  );
}

function Section({ title }: { title: string }) {
  return <h3 className="detail-section">{title}</h3>;
}

function Line({
  label,
  value,
  mono,
  tone,
}: {
  label: string;
  value: string;
  mono?: boolean;
  tone?: string;
}) {
  return (
    <div className="keys-row">
      <div className="k-col">
        <span className="k">{label}</span>
      </div>
      <span className={`v ${mono ? "mono" : ""} ${tone ?? ""}`}>{value}</span>
    </div>
  );
}
