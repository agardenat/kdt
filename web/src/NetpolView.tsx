// La vue network policies : deux mondes de politiques dans une même liste.
//
// Le `NetworkPolicy` natif, avec un vrai verdict de posture par direction, et les CRD du CNI —
// Cilium, Calico — rendues factuellement. Rien n'est jugé ici : le `DirEffect` de chaque direction
// et son ton arrivent tout faits de `kdt::netpol`, `unknown` compris. Le navigateur les peint, il ne
// les déduit pas d'un compte de règles.
//
// Le cas qui décide de la mise en page : `deny` est une **bonne** nouvelle — la direction est
// gouvernée et rien n'y est autorisé — donc le vert va là et pas sur `allow-all`.

import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import type { Lang, Strings } from "./i18n";
import { ObjectActions } from "./objects";
import { InspectPanel, PanelToggle, Splitter, type PanelTab } from "./panel";
import type { EventRecord, NetPolRow, NetpolPayload } from "./types";

/** `NAMESPACE NAME ENGINE TARGET TYPES INGRESS EGRESS AGE`, dans l'ordre du TUI. */
const COLUMNS =
  "minmax(110px,18ch) minmax(150px,24ch) 72px minmax(150px,1fr) minmax(96px,14ch)" +
  " minmax(180px,1.6fr) minmax(170px,1.2fr) 52px";

export default function NetpolView({
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
  const [payload, setPayload] = useState<NetpolPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<PanelTab>("detail");

  // Un seul namespace, comme les autres vues qui listent des objets namespacés : la portée est un
  // paramètre de l'URL côté serveur, et deux namespaces mélangés ne donneraient pas une liste plus
  // vraie, juste une liste plus longue.
  const scope = namespaces[0] ?? "";

  const load = useCallback(async () => {
    try {
      setPayload(await api.netpol(scope));
      setError(null);
      setLoaded(true);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else if (e instanceof ApiError) setError(e.message);
      else setError(String(e));
      setLoaded(true);
    }
  }, [scope, onNeedsAuth]);

  useEffect(() => {
    void load();
    // Les policies ne bougent pas à la seconde : une minute suffit, et une liste qui se relit sans
    // arrêt coûterait au cluster une lecture par CRD découverte.
    const timer = window.setInterval(() => void load(), 60000);
    return () => window.clearInterval(timer);
  }, [load]);

  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const all = payload?.rows ?? [];
    if (!needle) return all;
    return all.filter((p) =>
      [p.namespace, p.name, p.engine_label, p.kind, p.target, p.types, p.ingress, p.egress]
        .join(" ")
        .toLowerCase()
        .includes(needle),
    );
  }, [payload, query]);

  const selectedRow = rows.find((p) => p.uid === selected) ?? null;
  const selectedRecord: EventRecord | null = selectedRow?.record ?? null;
  const counts = payload?.counts;

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
            detail={
              selectedRow
                ? { label: st.tabDetail, node: <PolicyDetail policy={selectedRow} st={st} /> }
                : undefined
            }
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds" role="tablist">
        {/* Un seul monde : la barre garde sa place pour les compteurs et les actions, mais elle
            n'invente pas des onglets là où il n'y a qu'une liste. « Policies » et non
            « NetworkPolicy » : les CRD des CNI portent d'autres kinds et sont dans la même liste. */}
        <button role="tab" aria-selected>
          Policies
          <span className="count">{rows.length}</span>
        </button>

        {counts && (
          <div className="tally">
            <span className="info">k8s {counts.k8s}</span>
            {counts.cilium > 0 && <span className="info">cilium {counts.cilium}</span>}
            {counts.calico > 0 && <span className="info">calico {counts.calico}</span>}
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
        ) : rows.length === 0 ? (
          <div className="center">
            <div className="box">
              <h2>{st.netpolEmpty}</h2>
              {error && <p className="err">{error}</p>}
              {payload?.error && <p className="err">{payload.error}</p>}
              <p>
                {st.emptyScope} <code>{scope || st.scopeAll}</code>
              </p>
            </div>
          </div>
        ) : (
          <PolicyTable
            rows={rows}
            selected={selected}
            st={st}
            onSelect={(uid) => {
              setSelected(uid);
              setTab("detail");
            }}
          />
        )}
      </div>

      <div className="statusbar">
        <span>
          {rows.length} {st.rows}
        </span>
        <span>
          {st.scopeLabel}: {scope || st.scopeAll}
        </span>
        {/* Une erreur sur les natives voyage avec les lignes déjà lues : les CRD du CNI peuvent
            très bien avoir répondu. */}
        {payload?.error && <span className="err">{payload.error}</span>}
        {error && <span className="err">{error}</span>}
      </div>
    </>
  );
}

function PolicyTable({
  rows,
  selected,
  st,
  onSelect,
}: {
  rows: NetPolRow[];
  selected: string | null;
  st: Strings;
  onSelect: (uid: string) => void;
}) {
  return (
    <div className="tbl">
      <div className="thead">
        <div className="tr" style={{ gridTemplateColumns: COLUMNS }}>
          <div className="cell">NAMESPACE</div>
          <div className="cell">NAME</div>
          <div className="cell">ENGINE</div>
          <div className="cell">TARGET</div>
          <div className="cell">TYPES</div>
          <div className="cell">INGRESS</div>
          <div className="cell">EGRESS</div>
          <div className="cell num">AGE</div>
        </div>
      </div>
      <div className="tbody">
        {rows.map((p) => (
          <div
            key={p.uid}
            className={`tr sev-${p.record.tone}`}
            style={{ gridTemplateColumns: COLUMNS }}
            aria-selected={selected === p.uid}
            tabIndex={0}
            onClick={() => onSelect(p.uid)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onSelect(p.uid);
            }}
          >
            <div className="cell mono dim">{p.cluster_scoped ? st.netpolCluster : p.namespace}</div>
            <div className="cell id">{p.name}</div>
            <div className={`cell mono engine-${p.engine}`}>{p.engine_label}</div>
            <div className="cell mono">{p.target}</div>
            <div className="cell dim">{p.types || "—"}</div>
            <div
              className={`cell ${p.ingress_tone}`}
              title={p.ingress_effect === "unknown" ? st.netpolNoVerdict : undefined}
            >
              {p.ingress}
            </div>
            <div
              className={`cell ${p.egress_tone}`}
              title={p.egress_effect === "unknown" ? st.netpolNoVerdict : undefined}
            >
              {p.egress}
            </div>
            <div className="cell num dim">{p.age}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function PolicyDetail({ policy, st }: { policy: NetPolRow; st: Strings }) {
  return (
    <div className="detail">
      <Line label="kind" value={`${policy.kind} (${policy.api_version})`} mono />
      <Line label="engine" value={policy.engine_label} />
      <Line label={st.netpolTarget} value={policy.target} mono />
      <Line label="policyTypes" value={policy.types || "—"} />
      <Line label="ingress" value={policy.ingress} tone={policy.ingress_tone} />
      <Line label="egress" value={policy.egress} tone={policy.egress_tone} />
      <Line label="age" value={policy.age} />
      {/* Le refus de juger, écrit là où quelqu'un se demanderait pourquoi il n'y a pas de verdict. */}
      {policy.engine !== "k8s" && <p className="hint-note info">{st.netpolNoVerdict}</p>}
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
