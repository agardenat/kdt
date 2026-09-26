// La vue Argo CD : « le cluster est-il ce que git dit qu'il est », sans ouvrir l'UI d'Argo CD.
//
// Quatre mondes, comme dans le TUI : les Applications, les ApplicationSets, les AppProjects, et les
// dépôts/clusters enregistrés — des Secrets étiquetés, que la ligne désigne donc comme tels.
//
// Rien n'est jugé ici. Le couple sync/health, le health **périmé** d'une comparaison en échec (un
// `Unknown / Healthy` se lit éteint, jamais vert), `automated.enabled: false`, l'Application hors des
// namespaces honorés : tout arrive tout fait de `kdt::argocd`.
//
// Le panneau de détail d'une Application met le diagnostic **avant** l'inventaire : resources,
// historique et images repousseraient sinon le verdict hors du cadre.

import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import type { Lang, Strings } from "./i18n";
import { ToastLine, useToastTimeout, type Toast } from "./toast";
import { InspectPanel, PanelToggle, Splitter, ViewBody, type PanelTab } from "./panel";
import { BulkDeletePane, RowMenu, type ObjectTab } from "./objects";
import { RowCheckbox, SelectionBar, SelectionHead, useMultiSelect } from "./selection";
import type {
  ArgoAppRow,
  ArgoEndpointRow,
  ArgoPayload,
  ArgoProjectRow,
  ArgoServer,
  ArgoSetRow,
  EventRecord,
  Hint,
} from "./types";
import { cols } from "./table";

/** `NS NAME PROJECT SYNC HEALTH POLICY DESTINATION REV OOS OPERATION CMP AGE`. La première piste
 * porte la case de sélection multiple, la dernière le hamburger de la ligne. */
const APP_COLUMNS =
  "34px fit-content(20ch) fit-content(40ch) fit-content(20ch) fit-content(10ch) fit-content(12ch)" +
  " fit-content(14ch) minmax(18ch,1fr) fit-content(12ch) 40px fit-content(16ch) 52px 52px 34px";

/** `NS NAME GENERATORS APPS OOS BAD POLICY STATE AGE`. */
const SET_COLUMNS =
  "34px fit-content(20ch) fit-content(40ch) minmax(16ch,1fr) 48px 40px 40px fit-content(16ch)" +
  " fit-content(14ch) 52px 34px";

/** `NS NAME APPS OOS REPOS DESTINATIONS ROLES WIN DESCRIPTION AGE`. */
const PROJECT_COLUMNS =
  "34px fit-content(20ch) fit-content(30ch) 48px 40px 56px 104px 80px 40px minmax(18ch,1fr) 52px 34px";

/** `KIND NAME URL TYPE PROJECT AUTH SCOPE USED AGE`. */
const ENDPOINT_COLUMNS =
  "34px 64px fit-content(30ch) minmax(24ch,1fr) fit-content(8ch) fit-content(20ch) fit-content(22ch)" +
  " 64px 48px 52px 34px";

type World = "apps" | "sets" | "projects" | "repos";
type Filter = "all" | "problems";

export default function ArgocdView({
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
  const [payload, setPayload] = useState<ArgoPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [world, setWorld] = useState<World>("apps");
  const [filter, setFilter] = useState<Filter>("all");
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<PanelTab>("detail");
  const [toast, setToast] = useState<Toast>(null);
  const [busy, setBusy] = useState(false);
  const { checked, toggle, clear, setAll } = useMultiSelect();
  const [bulkOpen, setBulkOpen] = useState(false);

  const load = useCallback(async () => {
    try {
      setPayload(await api.argocdInventory(lang));
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
    // Vingt secondes, comme le TUI : une Application bouge au rythme de la comparaison (trois
    // minutes par défaut), mais un sync demandé d'ici se termine en secondes et la ligne doit le
    // montrer.
    const timer = window.setInterval(() => void load(), 20000);
    return () => window.clearInterval(timer);
  }, [load]);

  useToastTimeout(toast, setToast);

  const needle = query.trim().toLowerCase();
  const worse = (hints: Hint[]) => hints.some((h) => h.level !== "info");
  // Le tamis lit le message de l'enregistrement, comme la recherche du TUI : une Application se
  // retrouve depuis l'url d'un dépôt ou le namespace où elle déploie, c'est ainsi qu'on arrive ici
  // depuis un ticket.
  const keep = useCallback(
    (hints: Hint[], record: EventRecord) => {
      if (filter === "problems" && !worse(hints)) return false;
      if (!needle) return true;
      return [record.namespace, record.name, record.reason, record.message]
        .join(" ")
        .toLowerCase()
        .includes(needle);
    },
    [filter, needle],
  );

  const apps = useMemo(
    () => (payload?.apps ?? []).filter((a) => keep(a.hints, a.record)),
    [payload, keep],
  );
  const sets = useMemo(
    () => (payload?.sets ?? []).filter((x) => keep(x.hints, x.record)),
    [payload, keep],
  );
  const projects = useMemo(
    () => (payload?.projects ?? []).filter((p) => keep(p.hints, p.record)),
    [payload, keep],
  );
  const endpoints = useMemo(
    () => (payload?.endpoints ?? []).filter((e) => keep(e.hints, e.record)),
    [payload, keep],
  );

  const selectedApp = apps.find((a) => a.uid === selected) ?? null;
  const selectedSet = sets.find((x) => x.uid === selected) ?? null;
  const selectedProject = projects.find((p) => p.uid === selected) ?? null;
  const selectedEndpoint = endpoints.find((e) => e.uid === selected) ?? null;
  const selectedRecord: EventRecord | null =
    selectedApp?.record ??
    selectedSet?.record ??
    selectedProject?.record ??
    selectedEndpoint?.record ??
    null;

  const run = useCallback(
    async (request: Record<string, unknown>) => {
      setBusy(true);
      try {
        const { message } = await api.argocdWrite(request, lang);
        setToast({ tone: "ok", text: message });
        void load();
      } catch (e) {
        if (e instanceof NeedsAuth) onNeedsAuth(e.message);
        else setToast({ tone: "err", text: String((e as Error).message ?? e) });
      } finally {
        setBusy(false);
      }
    },
    [lang, load, onNeedsAuth],
  );

  const counts = payload?.counts;
  const rows: { uid: string; record: EventRecord }[] =
    world === "apps" ? apps : world === "sets" ? sets : world === "projects" ? projects : endpoints;

  // Sélectionner ne déplie pas le panneau : le pli est la décision de qui regarde.
  const select = (uid: string) => {
    setSelected(uid);
    setTab("detail");
  };
  const openTab = (uid: string, t: ObjectTab) => {
    setSelected(uid);
    setTab(t);
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
            detail={{
              label: st.argoDetail,
              node: selectedApp ? (
                <AppDetail app={selectedApp} st={st} />
              ) : selectedSet ? (
                <SetDetail set={selectedSet} st={st} />
              ) : selectedProject ? (
                <ProjectDetail project={selectedProject} st={st} />
              ) : selectedEndpoint ? (
                <EndpointDetail endpoint={selectedEndpoint} st={st} />
              ) : null,
            }}
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds" role="tablist">
        {(
          [
            ["apps", st.argoApps, counts?.apps],
            ["sets", st.argoSets, counts?.sets],
            ["projects", st.argoProjects, counts?.projects],
            ["repos", st.argoRepos, counts ? counts.repos + counts.creds + counts.clusters : undefined],
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

        <div className="segmented" role="group">
          {(["all", "problems"] as const).map((f) => (
            <button key={f} aria-pressed={filter === f} onClick={() => setFilter(f)}>
              {f === "all" ? st.filterAll : st.filterProblems}
            </button>
          ))}
        </div>

        {counts && (
          <div className="tally">
            {/* Les trois comptes du titre du TUI, chacun sous son ton : OutOfSync et « sans
                comparaison » veulent dire deux choses opposées, et ne se confondent pas. */}
            {world === "apps" && (
              <>
                {counts.out_of_sync > 0 && (
                  <span className="warn" title={st.argoOutOfSync}>
                    ≠{counts.out_of_sync}
                  </span>
                )}
                {counts.blind > 0 && (
                  <span className="err" title={st.argoBlind}>
                    ?{counts.blind}
                  </span>
                )}
                {counts.unhealthy > 0 && (
                  <span className="err" title={st.argoUnhealthy}>
                    ✗{counts.unhealthy}
                  </span>
                )}
              </>
            )}
            {world === "sets" && <span className="info">→{counts.set_apps} {st.argoApps}</span>}
            {world === "projects" && (
              <span className="info">
                {counts.project_apps} {st.argoApps}
              </span>
            )}
            {world === "repos" && (
              <span className="info">
                repo {counts.repos} · creds {counts.creds} · cluster {counts.clusters}
              </span>
            )}
          </div>
        )}

        <div className="right">
          {busy && <span>{st.objWorking}</span>}
          <ToastLine toast={toast} onDismiss={() => setToast(null)} lang={lang} />
          <SelectionBar
            keys={rows.map((r) => r.uid)}
            checked={checked}
            onSetAll={setAll}
            onClear={clear}
            onBulkDelete={() => setBulkOpen(true)}
            st={st}
          />
          <PanelToggle open={panelOpen} onOpen={onPanelOpen} lang={lang} />
        </div>
      </div>

      {/* L'installation elle-même, ce que le TUI montre quand aucune ligne n'est sélectionnée : elle
          vaut quelle que soit la ligne lue, d'où sa ligne à elle sous la barre. */}
      {payload?.server.present && <InstallBand server={payload.server} st={st} />}
      {payload?.server.hints.map((h, i) => (
        <div key={i} className={`vel-band ${h.level === "danger" ? "err" : h.level}`}>
          {h.text}
        </div>
      ))}

      <ViewBody
        tab={tab}
        record={selectedRecord}
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
                    records={rows.filter((r) => checked.has(r.uid)).map((r) => r.record)}
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
        ) : rows.length === 0 ? (
          <div className="center">
            <div className="box">
              <h2>{st.argoEmpty}</h2>
              {error && <p className="err">{error}</p>}
              {payload?.error && <p className="err">{payload.error}</p>}
              {/* Ce qui a été lu, et où : c'est la réponse à une liste vide — « rien n'est déclaré »
                  plutôt que « rien n'a été lu ». */}
              {payload?.server.present && <p>{payload.server.install_label}</p>}
            </div>
          </div>
        ) : world === "apps" ? (
          <AppTable
            rows={apps}
            selected={selected}
            lang={lang}
            st={st}
            onSelect={select}
            onOpenTab={openTab}
            onNeedsAuth={onNeedsAuth}
            onRun={run}
            checked={checked}
            onToggleCheck={toggle}
          />
        ) : world === "sets" ? (
          <SetTable
            rows={sets}
            selected={selected}
            lang={lang}
            st={st}
            onSelect={select}
            onOpenTab={openTab}
            onNeedsAuth={onNeedsAuth}
            checked={checked}
            onToggleCheck={toggle}
          />
        ) : world === "projects" ? (
          <ProjectTable
            rows={projects}
            selected={selected}
            lang={lang}
            st={st}
            onSelect={select}
            onOpenTab={openTab}
            onNeedsAuth={onNeedsAuth}
            checked={checked}
            onToggleCheck={toggle}
          />
        ) : (
          <EndpointTable
            rows={endpoints}
            selected={selected}
            lang={lang}
            st={st}
            onSelect={select}
            onOpenTab={openTab}
            onNeedsAuth={onNeedsAuth}
            checked={checked}
            onToggleCheck={toggle}
          />
        )}
      </ViewBody>

      <div className="statusbar">
        <span>
          {rows.length} {st.rows}
        </span>
        {payload?.server.present && <span>{payload.server.install_label}</span>}
        <span style={{ marginLeft: "auto" }}>{st.argoScopeless}</span>
      </div>
    </>
  );
}

/**
 * « Argo CD tourne-t-il seulement ? » — le namespace d'install découvert, l'UI, la période de
 * comparaison, les namespaces honorés, et chaque composant avec son compte de replicas.
 */
function InstallBand({ server, st }: { server: ArgoServer; st: Strings }) {
  return (
    <div className="ky-health">
      <span>{server.install_label}</span>
      {server.version && !server.version_in_label && (
        <span className="dim">
          {st.argoVersionLabel} {server.version}
        </span>
      )}
      {server.url && <span className="dim">{server.url}</span>}
      {server.reconcile && (
        <span className="dim">
          {st.argoPeriod} {server.reconcile}
        </span>
      )}
      {server.app_namespaces.length > 0 && (
        <span className="dim">namespaces {server.app_namespaces.join(", ")}</span>
      )}
      {server.components.map((c) => (
        <span key={c.name} className={c.tone}>
          {c.name} {c.ready}/{c.desired}
        </span>
      ))}
    </div>
  );
}

interface WorldTableProps {
  selected: string | null;
  lang: Lang;
  st: Strings;
  onSelect: (uid: string) => void;
  onOpenTab: (uid: string, tab: ObjectTab) => void;
  onNeedsAuth: (message: string) => void;
  checked: Set<string>;
  onToggleCheck: (key: string) => void;
}

function Head({ labels, num }: { labels: string[]; num: string[] }) {
  return (
    <div className="thead">
      <div className="tr">
        <SelectionHead />
        {labels.map((l) => (
          <div key={l} className={`cell${num.includes(l) ? " num" : ""}`}>
            {l}
          </div>
        ))}
        <div className="cell act" />
      </div>
    </div>
  );
}

/** Un compte nul se lit comme rien : ce qui compte, ce sont les lignes qui en ont. */
function Count({ n, tone }: { n: number; tone?: string }) {
  return n === 0 ? (
    <div className="cell num dim">·</div>
  ) : (
    <div className={`cell num ${tone ?? ""}`}>{n}</div>
  );
}

function AppTable({
  rows,
  onRun,
  ...p
}: { rows: ArgoAppRow[]; onRun: (request: Record<string, unknown>) => void } & WorldTableProps) {
  return (
    <div className="tbl" style={cols(APP_COLUMNS)}>
      <Head
        labels={["NS", "NAME", "PROJECT", "SYNC", "HEALTH", "POLICY", "DESTINATION", "REV", "OOS",
          "OPERATION", "CMP", "AGE"]}
        num={["OOS", "CMP", "AGE"]}
      />
      <div className="tbody">
        {rows.map((a) => (
          <Row
            key={a.uid}
            uid={a.uid}
            record={a.record}
            {...p}
            menu={({ close }) => (
              <AppMenu
                st={p.st}
                app={a}
                onRun={(request) => {
                  close();
                  onRun(request);
                }}
              />
            )}
          >
            <div className="cell dim">{a.namespace}</div>
            <div className="cell id">{a.name}</div>
            <div className="cell dim">{a.project}</div>
            <div className={`cell ${a.sync_tone}`}>{a.sync || "—"}</div>
            {/* Éteint quand la comparaison a échoué : un `Healthy` calculé avant l'erreur est un
                souvenir, et le peindre en vert est exactement l'erreur que cette vue existe pour
                empêcher. */}
            <div className={`cell ${a.health_tone}`}>{a.health || "—"}</div>
            <div className={`cell ${a.policy_tone}`}>{a.policy_label}</div>
            <div className="cell wrap">{a.destination_label}</div>
            <div className="cell mono dim">{a.revision}</div>
            <Count n={a.out_of_sync} tone="warn" />
            <div className={`cell ${a.phase_tone}`}>{a.operation_label}</div>
            <div className="cell num dim">{a.reconciled_age}</div>
            <div className="cell num dim">{a.age}</div>
          </Row>
        ))}
      </div>
    </div>
  );
}

function SetTable({ rows, ...p }: { rows: ArgoSetRow[] } & WorldTableProps) {
  return (
    <div className="tbl" style={cols(SET_COLUMNS)}>
      <Head
        labels={["NS", "NAME", "GENERATORS", "APPS", "OOS", "BAD", "POLICY", "STATE", "AGE"]}
        num={["APPS", "OOS", "BAD", "AGE"]}
      />
      <div className="tbody">
        {rows.map((x) => (
          <Row key={x.uid} uid={x.uid} record={x.record} {...p}>
            <div className="cell dim">{x.namespace}</div>
            <div className="cell id">{x.name}</div>
            <div className="cell wrap">{x.generators.join(",")}</div>
            <div className="cell num">{x.apps.length}</div>
            <Count n={x.apps_out_of_sync} />
            <Count n={x.apps_unhealthy} />
            <div className="cell dim">{x.policy_label}</div>
            <div className={`cell ${x.state_tone}`}>{x.state_label}</div>
            <div className="cell num dim">{x.age}</div>
          </Row>
        ))}
      </div>
    </div>
  );
}

function ProjectTable({ rows, ...p }: { rows: ArgoProjectRow[] } & WorldTableProps) {
  return (
    <div className="tbl" style={cols(PROJECT_COLUMNS)}>
      <Head
        labels={["NS", "NAME", "APPS", "OOS", "REPOS", "DESTINATIONS", "ROLES", "WIN", "DESCRIPTION",
          "AGE"]}
        num={["APPS", "OOS", "WIN", "AGE"]}
      />
      <div className="tbody">
        {rows.map((x) => (
          <Row key={x.uid} uid={x.uid} record={x.record} {...p}>
            <div className="cell dim">{x.namespace}</div>
            <div className="cell id">{x.name}</div>
            <Count n={x.apps} />
            <Count n={x.apps_out_of_sync} />
            <div className={`cell ${x.repos_tone}`}>{x.repos_label}</div>
            <div className={`cell ${x.destinations_tone}`}>{x.destinations_label}</div>
            <div className={`cell ${x.roles_tone}`}>{x.roles_label}</div>
            <Count n={x.windows.length} />
            <div className="cell wrap dim">{x.description}</div>
            <div className="cell num dim">{x.age}</div>
          </Row>
        ))}
      </div>
    </div>
  );
}

function EndpointTable({ rows, ...p }: { rows: ArgoEndpointRow[] } & WorldTableProps) {
  return (
    <div className="tbl" style={cols(ENDPOINT_COLUMNS)}>
      <Head
        labels={["KIND", "NAME", "URL", "TYPE", "PROJECT", "AUTH", "SCOPE", "USED", "AGE"]}
        num={["USED", "AGE"]}
      />
      <div className="tbody">
        {rows.map((e) => (
          <Row key={e.uid} uid={e.uid} record={e.record} {...p}>
            {/* La nature de la ligne, pas un verdict : un cluster se repère, un modèle de
                credentials s'efface derrière les dépôts qu'il sert. */}
            <div
              className={`cell ${e.kind === "cluster" ? "info" : e.kind === "creds" ? "dim" : ""}`}
            >
              {e.kind_label}
            </div>
            <div className="cell id">{e.label}</div>
            <div className="cell wrap mono">{e.url}</div>
            <div className="cell dim">{e.repo_type}</div>
            <div className="cell dim">{e.project}</div>
            <div className={`cell ${e.auth_tone}`}>{e.auth}</div>
            <div className={`cell ${e.scope_tone}`}>{e.scope_label}</div>
            <Count n={e.used_by} />
            <div className="cell num dim">{e.age}</div>
          </Row>
        ))}
      </div>
    </div>
  );
}

function Row({
  uid,
  record,
  selected,
  lang,
  st,
  onSelect,
  onOpenTab,
  onNeedsAuth,
  checked,
  onToggleCheck,
  menu,
  children,
}: {
  uid: string;
  record: EventRecord;
  /** Le menu propre à la vue, posé dans le hamburger de la ligne ; seule une Application en a un. */
  menu?: (args: { close: () => void }) => React.ReactNode;
  children: React.ReactNode;
} & WorldTableProps) {
  return (
    <div
      className={`tr sev-${record.tone}`}
      aria-selected={selected === uid}
      tabIndex={0}
      onClick={() => onSelect(uid)}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSelect(uid);
      }}
    >
      <RowCheckbox checked={checked.has(uid)} onToggle={() => onToggleCheck(uid)} label={st.selectRow} />
      {children}
      <div className="cell act">
        <RowMenu
          record={record}
          lang={lang}
          st={st}
          onOpen={(t) => onOpenTab(uid, t)}
          onNeedsAuth={onNeedsAuth}
        >
          {menu}
        </RowMenu>
      </div>
    </div>
  );
}

function AppDetail({ app, st }: { app: ArgoAppRow; st: Strings }) {
  return (
    <div className="detail">
      {/* Les deux mots qui décident de tout, sur une ligne et dans cet ordre. */}
      <div className="keys-row">
        <div className="k-col">
          <span className="k">sync</span>
        </div>
        <span className="v">
          <span className={app.sync_tone}>{app.sync || "—"}</span>
          <span className="dim"> · health </span>
          <span className={app.health_tone}>{app.health || "—"}</span>
        </span>
      </div>
      <Line label="project" value={app.project} />
      <Line label="destination" value={`${app.dest_label} · ${app.dest_namespace}`} />
      {app.dest_server && app.dest_server !== app.dest_label && (
        <Line label="" value={app.dest_server} mono />
      )}
      {app.source_labels.map((s, i) => (
        <Line key={i} label="source" value={s} mono />
      ))}
      {app.source_type && <Line label={st.argoRenderedBy} value={app.source_type} />}
      {app.revision_full && <Line label="revision" value={app.revision_full} mono />}
      <Line label="sync policy" value={app.policy_label} tone={app.policy_tone} />
      {app.sync_options.length > 0 && (
        <Line label="syncOptions" value={app.sync_options.join(", ")} />
      )}
      {app.reconciled_age && <Line label={st.argoReconciled} value={app.reconciled_age} />}
      {app.op_phase && (
        <Line
          label={st.argoOperation}
          value={[
            `${app.op_phase} (${app.op_age})`,
            app.op_by,
            app.op_retries > 0 ? `${app.op_retries}×` : "",
          ]
            .filter(Boolean)
            .join(" · ")}
          tone={app.phase_tone}
        />
      )}
      <Line label="age" value={app.age} />

      {/* Le diagnostic avant l'inventaire : resources, historique et images repousseraient sinon
          le verdict hors du cadre. */}
      <Hints hints={app.hints} st={st} />

      {app.resource_count > 0 && (
        <>
          <div className="sect">
            resources ({app.resource_count} · {app.out_of_sync} OutOfSync)
          </div>
          {app.resources_off.length === 0 ? (
            <p className="dim">{st.argoAllExpected}</p>
          ) : (
            app.resources_off.map((r) => (
              <div className="keys-row" key={r.label}>
                <div className="k-col">
                  <span className="k" />
                </div>
                <span className="v mono">
                  {r.label} <span className="warn">[{r.marks.join(" ")}]</span>
                </span>
              </div>
            ))
          )}
          {app.resources_off_count > app.resources_off.length && (
            <p className="dim">
              {st.argoMore.replace("{n}", String(app.resources_off_count - app.resources_off.length))}
            </p>
          )}
        </>
      )}

      {app.history.length > 0 && (
        <>
          <div className="sect">{st.argoHistory}</div>
          {app.history.map((h, i) => (
            <Line key={i} label={h.age || h.deployed_at} value={h.revision} mono />
          ))}
        </>
      )}

      {app.images.length > 0 && (
        <>
          <div className="sect">images</div>
          {app.images.slice(0, 12).map((i) => (
            <Line key={i} label="" value={i} mono />
          ))}
        </>
      )}
    </div>
  );
}

function SetDetail({ set, st }: { set: ArgoSetRow; st: Strings }) {
  return (
    <div className="detail">
      <Line label="generators" value={set.generators.length ? set.generators.join(", ") : "—"} />
      <Line label="sync policy" value={set.policy_label} />
      {set.rolling && <Line label={st.argoStrategy} value="rollingSync" />}
      {/* La syntaxe de template décide de la lecture des `{{ }}` : on la veut avant le reste. */}
      <Line label="goTemplate" value={set.go_template ? st.argoYes : st.argoNo} />
      <Line label="age" value={set.age} />
      {set.conditions.length > 0 && (
        <>
          <div className="sect">conditions</div>
          {set.conditions.map((c, i) => (
            <Line
              key={i}
              label={c.reason ? `${c.kind} = ${c.status} (${c.reason})` : `${c.kind} = ${c.status}`}
              value={c.message}
            />
          ))}
        </>
      )}
      <List title={st.argoApps} items={set.apps} />
      <Hints hints={set.hints} st={st} />
    </div>
  );
}

function ProjectDetail({ project, st }: { project: ArgoProjectRow; st: Strings }) {
  return (
    <div className="detail">
      {project.description && <Line label="description" value={project.description} />}
      <Line
        label="Applications"
        value={`${project.apps} (${project.apps_out_of_sync} OutOfSync)`}
      />
      <Line label="age" value={project.age} />
      <List title="sourceRepos" items={project.source_repos} />
      <List title="destinations" items={project.destinations} />
      <List title="clusterResourceWhitelist" items={project.cluster_allow} />
      <List title="clusterResourceBlacklist" items={project.cluster_deny} />
      <List title="namespaceResourceWhitelist" items={project.ns_allow} />
      <List title="namespaceResourceBlacklist" items={project.ns_deny} />
      <List title="sync windows" items={project.windows} />
      {project.roles.length > 0 && (
        <>
          <div className="sect">roles ({project.roles.length})</div>
          {/* Un role qui peut synchroniser ou supprimer n'est pas le même objet qu'un role en
              lecture, et le compte de policies ne dit pas lequel des deux il est. */}
          {project.roles.map((r) => (
            <div className="keys-row" key={r.name}>
              <div className="k-col">
                <span className="k">{r.name}</span>
              </div>
              <span className="v">
                <span className={r.writes ? "info" : "dim"}>{r.writes ? "write" : "read"}</span>
                <span className="dim">
                  {" "}
                  · {r.policies} policies · {r.groups.length ? r.groups.join(", ") : "—"}
                </span>
              </span>
            </div>
          ))}
        </>
      )}
      <Hints hints={project.hints} st={st} />
    </div>
  );
}

function EndpointDetail({ endpoint: e, st }: { endpoint: ArgoEndpointRow; st: Strings }) {
  return (
    <div className="detail">
      {/* Deux choses s'appellent « type » ici : ce qu'est la ligne (dépôt, modèle de credentials,
          cluster) et ce que sert un dépôt (git, helm). Les nommer pareil, c'est ne plus pouvoir se
          fier à aucune des deux. */}
      <Line label={st.argoNature} value={e.kind_label} />
      <Line label="url" value={e.url} mono />
      <Line label="secret" value={`${e.namespace}/${e.secret}`} mono />
      {e.repo_type && <Line label="type" value={e.repo_type} />}
      <Line label="auth" value={e.auth} tone={e.auth_tone} />
      {e.project && <Line label="project" value={e.project} />}
      {e.namespaces.length > 0 && <Line label="namespaces" value={e.namespaces.join(", ")} />}
      {e.cluster_resources !== null && (
        <Line label="clusterResources" value={e.cluster_resources ? st.argoYes : st.argoNo} />
      )}
      <Line label={st.argoUsedBy} value={String(e.used_by)} />
      <Line label="age" value={e.age} />
      <Hints hints={e.hints} st={st} />
    </div>
  );
}

function List({ title, items }: { title: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <>
      <div className="sect">
        {title} ({items.length})
      </div>
      {items.slice(0, 30).map((i) => (
        <Line key={i} label="" value={i} mono />
      ))}
    </>
  );
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

function Hints({ hints, st }: { hints: Hint[]; st: Strings }) {
  if (hints.length === 0) return null;
  return (
    <>
      <div className="sect">{st.sectionHints}</div>
      {hints.map((h) => (
        <p key={h.text} className={`guard ${h.level}`}>
          <span className="gl">{h.level === "danger" ? "✗" : h.level === "warn" ? "▲" : "·"}</span>{" "}
          {h.text}
        </p>
      ))}
    </>
  );
}

type Action =
  | { kind: "refresh"; hard: boolean }
  | { kind: "sync"; prune: boolean }
  | { kind: "terminate" };

/**
 * Les écritures du TUI sur une Application, chacune confirmée comme dans son menu.
 *
 * `terminate` n'est offert que pendant une opération ; le serveur relit la phase avant d'écrire,
 * parce qu'entre l'affichage et le clic l'opération a pu finir. Un sync en cours est le contexte
 * dans lequel toutes les autres entrées se lisent autrement : il est dit au-dessus d'elles.
 */
function AppMenu({
  st,
  app,
  onRun,
}: {
  st: Strings;
  app: ArgoAppRow;
  onRun: (request: Record<string, unknown>) => void;
}) {
  const [pending, setPending] = useState<Action | null>(null);
  const target = { namespace: app.namespace, name: app.name };
  const terminateHelp = st.argoTerminateHelp
    .replace("{phase}", app.op_phase)
    .replace("{age}", app.op_age);
  const syncHelp = st.argoSyncHelp.replace("{revision}", app.sync_target);

  // Posé comme `children` de `RowMenu` : pas de `.pop.menu`/`.pop-hd` à lui.
  if (pending === null) {
    return (
      <>
        {app.operation_running && (
          <p className="menu-note info">{st.argoOpRunning.replace("{age}", app.op_age)}</p>
        )}
        <MenuItem
          label={st.argoRefresh}
          desc={st.argoRefreshHelp}
          onClick={() => setPending({ kind: "refresh", hard: false })}
        />
        <MenuItem
          label={st.argoHardRefresh}
          desc={st.argoHardRefreshHelp}
          onClick={() => setPending({ kind: "refresh", hard: true })}
        />
        <MenuItem
          label={st.argoSync}
          desc={syncHelp}
          onClick={() => setPending({ kind: "sync", prune: false })}
        />
        <MenuItem
          label={st.argoSyncPrune}
          desc={st.argoSyncPruneHelp}
          onClick={() => setPending({ kind: "sync", prune: true })}
        />
        {app.operation_running && (
          <MenuItem
            label={st.argoTerminate}
            desc={terminateHelp}
            onClick={() => setPending({ kind: "terminate" })}
          />
        )}
      </>
    );
  }

  const [label, help, request] =
    pending.kind === "refresh"
      ? [
          pending.hard ? st.argoHardRefresh : st.argoRefresh,
          pending.hard ? st.argoHardRefreshHelp : st.argoRefreshHelp,
          { action: "refresh", ...target, hard: pending.hard },
        ]
      : pending.kind === "sync"
        ? [
            pending.prune ? st.argoSyncPrune : st.argoSync,
            pending.prune ? st.argoSyncPruneHelp : syncHelp,
            { action: "sync", ...target, prune: pending.prune },
          ]
        : [st.argoTerminate, terminateHelp, { action: "terminate", ...target }];
  // Ce qui supprime ou interrompt se distingue de ce qui relit : prune efface du cluster ce que git
  // ne contient plus, terminate coupe une opération à mi-course.
  const danger = (pending.kind === "sync" && pending.prune) || pending.kind === "terminate";

  return (
    <div className="menu-confirm">
      <p>
        <strong>{label}</strong> — {app.namespace}/{app.name}
      </p>
      <p className={danger ? "warn" : undefined}>{help}</p>
      {/* La sortie par défaut est celle qui n'écrit rien : c'est elle qui a le focus. */}
      <div className="menu-buttons">
        <button autoFocus onClick={() => setPending(null)}>
          {st.argoCancel}
        </button>
        <button className={danger ? "cta danger" : "cta"} onClick={() => onRun(request)}>
          {st.argoConfirm}
        </button>
      </div>
    </div>
  );
}

function MenuItem({ label, desc, onClick }: { label: string; desc: string; onClick: () => void }) {
  return (
    <button className="menu-item" onClick={onClick}>
      <span className="lbl">{label}</span>
      <span className="desc">{desc}</span>
    </button>
  );
}
