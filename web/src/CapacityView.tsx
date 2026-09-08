// La vue capacité : non pas « voilà la consommation », mais « voilà ce qui va casser ».
//
// Trois mondes, comme dans le TUI, et ils n'ont en commun que le cadre :
//
// - **Nodes** — ce qui est réservé face à ce qui existe, et surtout : *si ce node tombe, ses pods
//   ont-ils où atterrir ?* C'est la question à laquelle `kubectl top` ne répond pas.
// - **Workloads** — ceux que le scheduler ne voit pas, ceux qui réservent bien plus qu'ils
//   n'utilisent, et ceux qui touchent leur propre limite.
// - **Quotas** — le `ResourceQuota` qui refusera le prochain déploiement.
//
// Rien n'est jugé ici. La simulation de perte, les constats, les seuils de tension et les unités
// arrivent tout faits de `kdt::capacity` : le navigateur peint un verdict, il ne refait aucune
// division. Le cas qui décide de tout : sans metrics-server, la colonne « consommé » est `null` et
// la vue le dit — un zéro se lirait comme un cluster au repos.

import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import type { Lang, Strings } from "./i18n";
import { ObjectActions } from "./objects";
import { InspectPanel, PanelToggle, Splitter, type PanelTab } from "./panel";
import type {
  CapNodeRow,
  CapQuotaRow,
  CapRatio,
  CapWorkloadRow,
  CapacityPayload,
  EventRecord,
  Hint,
} from "./types";

/**
 * `NODE CPU RESERVED MEM RESERVED CPU USED MEM USED PODS IF LOST`, dans l'ordre du TUI.
 *
 * Les quatre colonnes de ratio portent le même gabarit — `3700m/4 (92%)` — donc la même largeur :
 * en donner moins à « used » qu'à « reserved » coupait la mémoire en plein milieu du total.
 */
const NODE_COLUMNS =
  "minmax(150px,1fr) minmax(150px,19ch) minmax(150px,19ch) minmax(150px,19ch)" +
  " minmax(150px,19ch) 84px minmax(130px,15ch)";

/** `NAMESPACE KIND NAME PODS CPU REQ→USED MEM REQ→USED QOS FINDING`. */
const WORKLOAD_COLUMNS =
  "minmax(110px,18ch) minmax(90px,12ch) minmax(150px,26ch) 56px minmax(140px,18ch)" +
  " minmax(140px,18ch) 104px minmax(180px,1.4fr)";

/**
 * `NAMESPACE QUOTA RESOURCE USED LIMIT %`.
 *
 * Les deux colonnes qui distinguent — le quota et la ressource — se partagent la place restante,
 * comme les deux `Min` du TUI : rien d'autre ici ne mérite de s'étirer.
 */
const QUOTA_COLUMNS =
  "minmax(110px,20ch) minmax(150px,1fr) minmax(160px,1.2fr) minmax(90px,14ch)" +
  " minmax(90px,14ch) 64px";

type World = "nodes" | "workloads" | "quotas";
type Filter = "all" | "problems";

const worse = (hints: Hint[]) => hints.some((h) => h.level !== "info");

export default function CapacityView({
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
  const [payload, setPayload] = useState<CapacityPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [world, setWorld] = useState<World>("nodes");
  const [filter, setFilter] = useState<Filter>("all");
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<PanelTab>("detail");

  const scope = namespaces[0] ?? "";

  const load = useCallback(async () => {
    try {
      setPayload(await api.capacity(scope, lang));
      setError(null);
      setLoaded(true);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else if (e instanceof ApiError) setError(e.message);
      else setError(String(e));
      setLoaded(true);
    }
  }, [scope, lang, onNeedsAuth]);

  useEffect(() => {
    void load();
    // Une minute : la lecture croise tous les nodes, tous les pods, les quotas et les ReplicaSets
    // du cluster, et la simulation de perte tourne sur l'ensemble. Ce n'est pas une vue qu'on
    // rafraîchit à la seconde.
    const timer = window.setInterval(() => void load(), 60000);
    return () => window.clearInterval(timer);
  }, [load]);

  const needle = query.trim().toLowerCase();
  const keep = useCallback(
    (hints: Hint[], haystack: string[]) => {
      if (filter === "problems" && !worse(hints)) return false;
      if (!needle) return true;
      return haystack.join(" ").toLowerCase().includes(needle);
    },
    [filter, needle],
  );

  const nodes = useMemo(
    () => (payload?.nodes ?? []).filter((n) => keep(n.hints, [n.name, n.loss.short, n.loss.word])),
    [payload, keep],
  );
  const workloads = useMemo(
    () =>
      (payload?.workloads ?? []).filter((w) =>
        keep(w.hints, [w.namespace, w.kind, w.name, w.qos_label, w.finding]),
      ),
    [payload, keep],
  );
  const quotas = useMemo(
    () =>
      (payload?.quotas ?? []).filter((q) =>
        keep(q.hints, [q.namespace, q.name, ...q.items.map((i) => i.resource)]),
      ),
    [payload, keep],
  );

  const selectedNode = nodes.find((n) => n.uid === selected) ?? null;
  const selectedWorkload = workloads.find((w) => w.uid === selected) ?? null;
  const selectedQuota = quotas.find((q) => q.uid === selected) ?? null;
  const selectedRecord: EventRecord | null =
    selectedNode?.record ?? selectedWorkload?.record ?? selectedQuota?.record ?? null;

  const shownCount =
    world === "nodes" ? nodes.length : world === "workloads" ? workloads.length : quotas.length;

  const select = (uid: string) => {
    setSelected(uid);
    setTab("detail");
  };

  const detailNode = selectedNode ? (
    <NodeDetail node={selectedNode} note={payload?.simulation_note ?? ""} st={st} />
  ) : selectedWorkload ? (
    <WorkloadDetail workload={selectedWorkload} st={st} />
  ) : selectedQuota ? (
    <QuotaDetail quota={selectedQuota} st={st} />
  ) : null;

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
            onDeleted={() => {
              setSelected(null);
              void load();
            }}
            detail={detailNode ? { label: st.tabDetail, node: detailNode } : undefined}
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds" role="tablist">
        {(
          [
            ["nodes", "Nodes", payload?.nodes.length],
            ["workloads", "Workloads", payload?.workloads.length],
            ["quotas", "Quotas", payload?.quotas.length],
          ] as const
        ).map(([id, label, n]) => (
          <button
            key={id}
            role="tab"
            aria-selected={world === id}
            onClick={() => {
              setWorld(id);
              setSelected(null);
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

        {/* Sans metrics-server la moitié des règles se tait : le dire une fois dans la barre vaut
            mieux que des tirets qu'on prend pour des zéros. */}
        {payload && !payload.metrics_available && (
          <div className="tally">
            <span className="warn" title={st.capNoMetrics}>
              ⌁ {st.capUsed} —
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

      {/* Les constats qui n'appartiennent à aucune ligne : ceux du cluster. */}
      {payload && payload.cluster_hints.length > 0 && (
        <div
          className={`sto-band ${
            payload.cluster_hints.some((h) => h.level === "danger")
              ? "danger"
              : payload.cluster_hints.some((h) => h.level === "warn")
                ? "warn"
                : "info"
          }`}
        >
          {payload.cluster_hints.map((h) => (
            <span key={h.text} className={h.level}>
              {h.level === "danger" ? "✗" : h.level === "warn" ? "▲" : "·"} {h.text}
            </span>
          ))}
        </div>
      )}

      <div className="body">
        {!loaded ? (
          <div className="center" />
        ) : shownCount === 0 ? (
          <div className="center">
            <div className="box">
              <h2>{st.capEmpty}</h2>
              {error && <p className="err">{error}</p>}
              <p>
                {st.emptyScope} <code>{scope || st.scopeAll}</code>
              </p>
            </div>
          </div>
        ) : world === "nodes" ? (
          <NodeTable rows={nodes} selected={selected} st={st} onSelect={select} />
        ) : world === "workloads" ? (
          <WorkloadTable rows={workloads} selected={selected} onSelect={select} />
        ) : (
          <QuotaTable rows={quotas} selected={selected} onSelect={select} />
        )}
      </div>

      <div className="statusbar">
        <span>
          {shownCount} {st.rows}
        </span>
        {/* Les nodes ignorent la portée : ils n'ont pas de namespace, et « si celui-ci tombe » se
            pose depuis n'importe où. La barre le dit pour que le compte ne surprenne pas. */}
        <span>
          {st.scopeLabel}: {world === "nodes" ? st.scopeAll : scope || st.scopeAll}
        </span>
        {payload && !payload.metrics_available && <span className="warn">{st.capNoMetrics}</span>}
        {error && <span className="err">{error}</span>}
      </div>
    </>
  );
}

/** Une ressource rapportée à ce qui existe : la quantité, le total, et à quel point c'est tendu. */
function Ratio({ ratio }: { ratio: CapRatio | null }) {
  if (!ratio) return <div className="cell num dim">—</div>;
  return (
    <div className={`cell num cap-${ratio.tension}`}>
      {ratio.text}/{ratio.total_text} <span className="pct">({ratio.pct}%)</span>
    </div>
  );
}

function NodeTable({
  rows,
  selected,
  st,
  onSelect,
}: {
  rows: CapNodeRow[];
  selected: string | null;
  st: Strings;
  onSelect: (uid: string) => void;
}) {
  return (
    <div className="tbl">
      <div className="thead">
        <div className="tr" style={{ gridTemplateColumns: NODE_COLUMNS }}>
          <div className="cell">NODE</div>
          <div className="cell num">CPU RESERVED</div>
          <div className="cell num">MEM RESERVED</div>
          <div className="cell num">CPU USED</div>
          <div className="cell num">MEM USED</div>
          <div className="cell num">PODS</div>
          <div className="cell">IF LOST</div>
        </div>
      </div>
      <div className="tbody">
        {rows.map((n) => (
          <div
            key={n.uid}
            className={`tr sev-${n.record.tone}`}
            style={{ gridTemplateColumns: NODE_COLUMNS }}
            aria-selected={selected === n.uid}
            tabIndex={0}
            onClick={() => onSelect(n.uid)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onSelect(n.uid);
            }}
          >
            <div className="cell id">
              {n.name}
              {!n.ready && <span className="badge-node err">{st.capNodeNotReady}</span>}
              {n.ready && !n.schedulable && (
                <span className="badge-node warn">{st.capNodeCordoned}</span>
              )}
            </div>
            <Ratio ratio={n.cpu_reserved} />
            <Ratio ratio={n.mem_reserved} />
            <Ratio ratio={n.cpu_used} />
            <Ratio ratio={n.mem_used} />
            <div
              className="cell num dim"
              title={n.pod_capacity > 0 ? st.capSlots : undefined}
            >
              {n.pod_capacity > 0 ? `${n.pods}/${n.pod_capacity}` : n.pods}
            </div>
            <div className={`cell ${n.loss.tone}`}>{n.loss.short}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function WorkloadTable({
  rows,
  selected,
  onSelect,
}: {
  rows: CapWorkloadRow[];
  selected: string | null;
  onSelect: (uid: string) => void;
}) {
  return (
    <div className="tbl">
      <div className="thead">
        <div className="tr" style={{ gridTemplateColumns: WORKLOAD_COLUMNS }}>
          <div className="cell">NAMESPACE</div>
          <div className="cell">KIND</div>
          <div className="cell">NAME</div>
          <div className="cell num">PODS</div>
          <div className="cell num">CPU REQ→USED</div>
          <div className="cell num">MEM REQ→USED</div>
          <div className="cell">QOS</div>
          <div className="cell">FINDING</div>
        </div>
      </div>
      <div className="tbody">
        {rows.map((w) => (
          <div
            key={w.uid}
            className={`tr sev-${w.record.tone}`}
            style={{ gridTemplateColumns: WORKLOAD_COLUMNS }}
            aria-selected={selected === w.uid}
            tabIndex={0}
            onClick={() => onSelect(w.uid)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onSelect(w.uid);
            }}
          >
            <div className="cell mono dim">{w.namespace}</div>
            <div className="cell mono dim">{w.kind}</div>
            <div className="cell id">{w.name}</div>
            <div className="cell num dim">{w.pods}</div>
            {/* Sans mesure, la réservation reste vraie et se dit seule : une flèche vers rien
                donnerait à croire à une consommation nulle. */}
            <div className={`cell num ${w.cpu_use_text ? "" : "dim"}`}>
              {w.cpu_use_text ? `${w.cpu_req_text} → ${w.cpu_use_text}` : w.cpu_req_text}
            </div>
            <div className={`cell num ${w.mem_use_text ? "" : "dim"}`}>
              {w.mem_use_text ? `${w.mem_req_text} → ${w.mem_use_text}` : w.mem_req_text}
            </div>
            <div className={`cell qos-${w.qos}`}>{w.qos_label}</div>
            <div className={`cell ${w.record.tone === "ok" ? "dim" : w.record.tone}`}>
              {w.finding}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function QuotaTable({
  rows,
  selected,
  onSelect,
}: {
  rows: CapQuotaRow[];
  selected: string | null;
  onSelect: (uid: string) => void;
}) {
  return (
    <div className="tbl">
      <div className="thead">
        <div className="tr" style={{ gridTemplateColumns: QUOTA_COLUMNS }}>
          <div className="cell">NAMESPACE</div>
          <div className="cell">QUOTA</div>
          <div className="cell">RESOURCE</div>
          <div className="cell num">USED</div>
          <div className="cell num">LIMIT</div>
          <div className="cell num">%</div>
        </div>
      </div>
      <div className="tbody">
        {rows.map((q) => {
          // Un quota est un objet avec plusieurs compteurs : la ligne montre le plus tendu — celui
          // qui refusera la prochaine création — et le panneau les liste tous.
          const worstItem = q.items[0];
          return (
            <div
              key={q.uid}
              className={`tr sev-${q.record.tone}`}
              style={{ gridTemplateColumns: QUOTA_COLUMNS }}
              aria-selected={selected === q.uid}
              tabIndex={0}
              onClick={() => onSelect(q.uid)}
              onKeyDown={(e) => {
                if (e.key === "Enter") onSelect(q.uid);
              }}
            >
              <div className="cell mono dim">{q.namespace}</div>
              <div className="cell id">{q.name}</div>
              <div className="cell mono">{worstItem?.resource ?? "—"}</div>
              <div className="cell num">{worstItem?.used_text ?? "—"}</div>
              <div className="cell num dim">{worstItem?.hard_text ?? "—"}</div>
              <div className={`cell num cap-${worstItem?.tension ?? "ok"}`}>
                {worstItem ? `${worstItem.pct}%` : "—"}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function NodeDetail({
  node,
  note,
  st,
}: {
  node: CapNodeRow;
  note: string;
  st: Strings;
}) {
  const homeless = node.loss.pods ?? [];
  return (
    <div className="detail">
      <Line
        label="CPU"
        value={`req ${node.cpu_reserved.text} · lim ${node.cpu_limits_text} / alloc ${node.cpu_reserved.total_text}`}
      />
      <Line
        label="memory"
        value={`req ${node.mem_reserved.text} · lim ${node.mem_limits_text} / alloc ${node.mem_reserved.total_text}`}
      />
      <Line
        label={st.capUsed}
        value={
          node.cpu_used && node.mem_used
            ? `cpu ${node.cpu_used.text} · mem ${node.mem_used.text}`
            : st.capNoMetrics
        }
        tone={node.cpu_used ? undefined : "dim"}
      />
      <Line
        label="pods"
        value={node.pod_capacity > 0 ? `${node.pods} / ${node.pod_capacity}` : String(node.pods)}
      />
      <Line
        label="state"
        value={`${node.ready ? "Ready" : st.capNodeNotReady} · ${
          node.schedulable ? "schedulable" : st.capNodeCordoned
        }`}
        tone={node.ready && node.schedulable ? undefined : "warn"}
      />

      <div className="sect">{st.capIfLost}</div>
      <p className={`hint-note ${node.loss.tone}`}>{node.loss.note}</p>
      {homeless.length > 0 && (
        <>
          <div className="sect">{st.capHomeless}</div>
          <ul className="hints">
            {homeless.map((p) => (
              <li key={`${p.namespace}/${p.name}`} className="danger">
                <span className="gl">✗</span> <span className="mono">
                  {p.namespace}/{p.name}
                </span>{" "}
                <span className="dim">
                  (cpu {p.cpu_text} · mem {p.mem_text})
                </span>{" "}
                {p.why_label}
              </li>
            ))}
          </ul>
          {/* Ce que la simulation vaut, dit par kdt : elle ne se fait pas passer pour le scheduler. */}
          {note && <p className="hint-note dim">{note}</p>}
        </>
      )}

      <Hints hints={node.hints} st={st} />
    </div>
  );
}

function WorkloadDetail({ workload, st }: { workload: CapWorkloadRow; st: Strings }) {
  return (
    <div className="detail">
      <Line label="pods" value={String(workload.pods)} />
      <Line label="QoS" value={workload.qos_label} />
      <Line
        label="CPU"
        value={
          workload.cpu_use_text
            ? `req ${workload.cpu_req_text} · lim ${workload.cpu_lim_text} · ${st.capUsed} ${workload.cpu_use_text}`
            : `req ${workload.cpu_req_text} · lim ${workload.cpu_lim_text}`
        }
      />
      <Line
        label="memory"
        value={
          workload.mem_use_text
            ? `req ${workload.mem_req_text} · lim ${workload.mem_lim_text} · ${st.capUsed} ${workload.mem_use_text}`
            : `req ${workload.mem_req_text} · lim ${workload.mem_lim_text}`
        }
      />
      <Hints hints={workload.hints} st={st} />
    </div>
  );
}

function QuotaDetail({ quota, st }: { quota: CapQuotaRow; st: Strings }) {
  return (
    <div className="detail">
      {/* Tous les compteurs, pas seulement le plus tendu : c'est ce que la table ne peut pas
          montrer, et la raison d'ouvrir le panneau sur un quota. */}
      {quota.items.map((i) => (
        <div className="keys-row" key={i.resource}>
          <div className="k-col">
            <span className="k">{i.resource}</span>
          </div>
          <span className={`v mono cap-${i.tension}`}>
            {i.used_text} / {i.hard_text} ({i.pct}%)
          </span>
        </div>
      ))}
      <Hints hints={quota.hints} st={st} />
    </div>
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
      <ul className="hints">
        {hints.map((h) => (
          <li key={h.text} className={h.level}>
            <span className="gl">{h.level === "danger" ? "✗" : h.level === "warn" ? "▲" : "·"}</span>{" "}
            {h.text}
          </li>
        ))}
      </ul>
    </>
  );
}
