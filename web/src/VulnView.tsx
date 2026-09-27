// La vue vulnérabilités : ce que Trivy Operator a trouvé dans les images, et le risque de la version
// Kubernetes elle-même.
//
// Les colonnes du TUI, dans son ordre : `SEV NAMESPACE COMPONENT VERSION CRIT HIGH MED LOW → TARGET
// AGE`. La ligne Kubernetes est toujours en tête et ne se cache pas avec la portée ; les images sont
// triées de la plus grave à la moins grave par kdt.
//
// Rien n'est jugé ici : le plancher, les comptes, la cible de patch et son ton, le liseré d'une
// ligne viennent de `kdt::vulnerabilities`. Et une ligne n'est pas un objet qu'on édite : le TUI
// n'y offre ni `y`, ni `e`, ni `h`, ni `Ctrl-D` — seulement l'analyse, que le hamburger garde seule.

import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import type { Lang, Strings } from "./i18n";
import { InspectPanel, PanelToggle, Splitter, ViewBody, type PanelTab } from "./panel";
import { RowMenu, type ObjectTab } from "./objects";
import type {
  EventRecord,
  VulnCve,
  VulnImageRow,
  VulnK8sRow,
  VulnPayload,
  VulnReport,
  VulnRow,
  VulnSev,
} from "./types";
import { cols } from "./table";

/** `SEV NAMESPACE COMPONENT VERSION CRIT HIGH MED LOW → TARGET AGE`, puis le hamburger. Pas de case :
 * un résultat de scan ne se supprime pas en masse. COMPONENT est la piste souple — un chemin d'image
 * est long, et c'est lui qui distingue les lignes. */
const COLUMNS =
  "fit-content(10ch) fit-content(24ch) minmax(28ch,1fr) fit-content(22ch)" +
  " fit-content(7ch) fit-content(7ch) fit-content(7ch) fit-content(7ch) fit-content(16ch) 6ch 34px";

const FLOORS: Array<[VulnSev, string | null]> = [
  ["unknown", null],
  ["high", "HIGH+"],
  ["critical", "CRIT"],
];

/** Les libellés de `Sev::label()` — ceux de la colonne SEV, que la liste des CVE reprend. */
const SEV_LABEL: Record<VulnSev, string> = {
  unknown: "UNKNOWN",
  low: "LOW",
  medium: "MED",
  high: "HIGH",
  critical: "CRIT",
};

/** `unknown` n'a pas de couleur à lui dans la table partagée : il se lit comme une information. */
function sevClass(sev: VulnSev): string {
  return `sev-${sev === "unknown" ? "info" : sev}`;
}

function matches(row: VulnRow, needle: string): boolean {
  const fields =
    row.row === "k8s"
      ? ["kubernetes", row.version]
      : [row.namespace, row.workload, row.image, row.version];
  return fields.join(" ").toLowerCase().includes(needle);
}

export default function VulnView({
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
  const namespace = namespaces[0] ?? "";
  const [payload, setPayload] = useState<VulnPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [min, setMin] = useState<VulnSev>("unknown");
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<PanelTab>("detail");
  // Le rapport de l'image sélectionnée, relu à la demande : ses CVE et l'enregistrement complet.
  const [report, setReport] = useState<{ uid: string; data: VulnReport } | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await api.vuln(namespace, min, lang);
      setPayload(data);
      setError(null);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else if (e instanceof ApiError) setError(e.message);
      else setError(String(e));
    } finally {
      setLoaded(true);
    }
  }, [namespace, min, lang, onNeedsAuth]);

  useEffect(() => {
    void load();
    // Soixante secondes, comme le TUI : l'opérateur rescanne sur un calendrier, les rapports
    // bougent lentement.
    const timer = window.setInterval(() => void load(), 60000);
    return () => window.clearInterval(timer);
  }, [load]);

  const rows = useMemo(() => payload?.rows ?? [], [payload]);
  const needle = query.trim().toLowerCase();
  const display = useMemo(
    () => (needle ? rows.filter((r) => matches(r, needle)) : rows),
    [rows, needle],
  );

  const selectedRow = useMemo(() => rows.find((r) => r.uid === selected) ?? null, [rows, selected]);
  const imageRow = selectedRow?.row === "image" ? selectedRow : null;
  const reportKey = imageRow ? `${imageRow.report_kind}|${imageRow.namespace}|${imageRow.report}` : null;

  // Une lecture par image sélectionnée et par langue, pas à chaque passe de la liste : le rapport ne
  // change qu'au prochain scan, et relire redessinerait la liste des CVE sous les yeux.
  useEffect(() => {
    if (!imageRow || !reportKey) return;
    let live = true;
    setReportError(null);
    api
      .vulnReport(imageRow, lang)
      .then((data) => live && setReport({ uid: imageRow.uid, data }))
      .catch((e) => {
        if (!live) return;
        if (e instanceof NeedsAuth) onNeedsAuth(e.message);
        else setReportError(String((e as Error).message ?? e));
      });
    return () => {
      live = false;
    };
    // `imageRow` est un objet neuf à chaque passe : c'est la clé du rapport qui décide de relire.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reportKey, lang, onNeedsAuth]);

  const imageReport = imageRow && report?.uid === imageRow.uid ? report.data : null;

  // L'analyse reçoit l'enregistrement complet : celui du rapport pour une image, CVE comprises.
  const analysisRecord: EventRecord | null = selectedRow
    ? selectedRow.row === "k8s"
      ? selectedRow.record
      : (imageReport?.record ?? null)
    : null;

  const counts = payload?.counts;

  return (
    <>
      {panelOpen && (
        <>
          <InspectPanel
            record={selectedRow?.record ?? null}
            tab={tab}
            onTab={setTab}
            onClose={() => onPanelOpen(false)}
            height={panelHeight}
            lang={lang}
            st={st}
            objectTabs={false}
            detail={{
              label: st.vulnDetail,
              node: selectedRow ? (
                selectedRow.row === "k8s" ? (
                  <K8sDetail row={selectedRow} st={st} />
                ) : (
                  <ImageDetail row={selectedRow} report={imageReport} error={reportError} st={st} />
                )
              ) : null,
            }}
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds">
        <div className="segmented" role="group" title={st.vulnFloorTitle}>
          {FLOORS.map(([sev, label]) => (
            <button key={sev} aria-pressed={min === sev} onClick={() => setMin(sev)}>
              {label ?? st.filterAll}
            </button>
          ))}
        </div>

        {counts && payload?.available && (
          <div className="tally">
            <span>
              {counts.scanned} {st.vulnScanned}
            </span>
            <span className={counts.critical ? "err" : "dim"}>CRIT {counts.critical}</span>
            <span className={counts.high ? "warn" : "dim"}>HIGH {counts.high}</span>
            <span className="dim">MED {counts.medium}</span>
            <span className="dim">LOW {counts.low}</span>
          </div>
        )}

        <div className="right">
          <PanelToggle open={panelOpen} onOpen={onPanelOpen} lang={lang} />
        </div>
      </div>

      {/* Sans Trivy, toute la table s'explique d'un coup : une ligne à soi sous la barre. */}
      {payload && !payload.available && <div className="vel-band info">{st.vulnNoTrivy}</div>}

      <ViewBody
        tab={tab}
        record={analysisRecord}
        lang={lang}
        st={st}
        onTab={setTab}
        onNeedsAuth={onNeedsAuth}
        hasDetail
      >
        {!loaded ? (
          <div className="center" />
        ) : display.length === 0 ? (
          <div className="center">
            <div className="box">
              <h2>{needle || min !== "unknown" ? st.emptyTitle : st.vulnEmpty}</h2>
              {error && <p className="err">{error}</p>}
              {payload?.error && <p className="err">{payload.error}</p>}
            </div>
          </div>
        ) : (
          <div className="tbl" style={cols(COLUMNS)}>
            <div className="thead">
              <div className="tr">
                <div className="cell">SEV</div>
                <div className="cell">NAMESPACE</div>
                <div className="cell">COMPONENT</div>
                <div className="cell">VERSION</div>
                <div className="cell num">CRIT</div>
                <div className="cell num">HIGH</div>
                <div className="cell num">MED</div>
                <div className="cell num">LOW</div>
                <div className="cell">→ TARGET</div>
                <div className="cell num">AGE</div>
                <div className="cell act" />
              </div>
            </div>
            <div className="tbody">
              {display.map((row) => (
                <Line
                  key={row.uid}
                  row={row}
                  lang={lang}
                  st={st}
                  selected={selected === row.uid}
                  onSelect={() => {
                    setSelected(row.uid);
                    setTab("detail");
                  }}
                  onOpenTab={(t) => {
                    setSelected(row.uid);
                    setTab(t);
                  }}
                  onNeedsAuth={onNeedsAuth}
                />
              ))}
            </div>
          </div>
        )}
      </ViewBody>

      <div className="statusbar">
        <span>
          {display.length} {st.rows}
        </span>
        {error && <span className="err">{error}</span>}
        {payload?.error && <span className="err">{payload.error}</span>}
        <span style={{ marginLeft: "auto" }}>{st.vulnScopeNote}</span>
      </div>
    </>
  );
}

function Count({ n, sev }: { n: number; sev: VulnSev }) {
  return n === 0 ? (
    <div className="cell num dim">·</div>
  ) : (
    <div className={`cell num ${sevClass(sev)}`}>{n}</div>
  );
}

function Line({
  row,
  lang,
  st,
  selected,
  onSelect,
  onOpenTab,
  onNeedsAuth,
}: {
  row: VulnRow;
  lang: Lang;
  st: Strings;
  selected: boolean;
  onSelect: () => void;
  onOpenTab: (tab: ObjectTab) => void;
  onNeedsAuth: (message: string) => void;
}) {
  const k8s = row.row === "k8s";
  return (
    <div
      className={`tr sev-${row.tone}`}
      aria-selected={selected}
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSelect();
      }}
    >
      {k8s ? (
        <div className="cell info">k8s</div>
      ) : (
        <div className={`cell ${sevClass(row.max_sev)}`}>{row.max_label}</div>
      )}
      <div className="cell dim">{k8s ? "control-plane" : row.namespace}</div>
      <div className={`cell id wrap ${k8s ? "info" : ""}`} title={k8s ? undefined : row.image}>
        {row.component}
      </div>
      <div className={`cell mono ${k8s ? "" : "dim"}`}>{row.version}</div>
      <Count n={row.critical} sev="critical" />
      <Count n={row.high} sev="high" />
      <Count n={row.medium} sev="medium" />
      <Count n={row.low} sev="low" />
      <div className={`cell tone-${row.target_tone}`}>{row.target}</div>
      <div className="cell num dim">{k8s ? "—" : row.age}</div>
      <div className="cell act">
        <RowMenu
          record={row.record}
          lang={lang}
          st={st}
          onOpen={onOpenTab}
          onNeedsAuth={onNeedsAuth}
          generic={false}
        />
      </div>
    </div>
  );
}

function ImageDetail({
  row,
  report,
  error,
  st,
}: {
  row: VulnImageRow;
  report: VulnReport | null;
  error: string | null;
  st: Strings;
}) {
  return (
    <div className="detail">
      <dl className="facts">
        <dt>workload</dt>
        <dd>{row.workload}</dd>
        <dt>image</dt>
        <dd className="wrap">
          {row.image}:{row.version}
        </dd>
        <dt>counts</dt>
        <dd>
          crit {row.critical} · high {row.high} · med {row.medium} · low {row.low} · total {row.total}
        </dd>
        <dt>fixables</dt>
        <dd className={row.fixable > 0 ? "ok" : undefined}>{row.fixable_text}</dd>
      </dl>
      <div className="sect">CVEs</div>
      {error ? (
        <p className="err">{error}</p>
      ) : !report ? (
        <p className="pane-wait">{st.vulnReading}</p>
      ) : report.cves.length === 0 ? (
        <p className="dim">{st.vulnNone}</p>
      ) : (
        <CveList cves={report.cves} image noFix={report.no_fix} />
      )}
    </div>
  );
}

function K8sDetail({ row, st }: { row: VulnK8sRow; st: Strings }) {
  return (
    <div className="detail">
      <dl className="facts">
        <dt>version</dt>
        <dd>{row.version}</dd>
        <dt>{st.vulnPatchTarget}</dt>
        <dd className={row.target_tone === "dim" ? undefined : row.target_tone}>{row.target_text}</dd>
        {row.eol && (
          <>
            <dt>EOL</dt>
            <dd className="err">{row.eol_text}</dd>
          </>
        )}
        {row.note && (
          <>
            <dt>note</dt>
            <dd>{row.note}</dd>
          </>
        )}
      </dl>
      <div className="sect">{st.vulnRecentCves}</div>
      {row.cves.length === 0 ? (
        <p className="dim">{st.vulnNoneUnavailable}</p>
      ) : (
        <CveList cves={row.cves} />
      )}
    </div>
  );
}

/** Une CVE par ligne, dans l'ordre du TUI : sévérité, score, identifiant, puis le paquet et son
 * correctif pour une image, ou le résumé du feed pour Kubernetes. */
function CveList({ cves, image, noFix }: { cves: VulnCve[]; image?: boolean; noFix?: string }) {
  return (
    <div className={`cve-list ${image ? "image" : "k8s"}`}>
      {cves.map((c, i) => (
        <div className="cve" key={`${c.id}|${c.package}|${i}`}>
          <span className={sevClass(c.severity)}>{SEV_LABEL[c.severity]}</span>
          <span className="num">{c.score.toFixed(1)}</span>
          <span className="mono">
            {c.url ? (
              <a href={c.url} target="_blank" rel="noopener noreferrer">
                {c.id}
              </a>
            ) : (
              c.id
            )}
          </span>
          {image ? (
            <>
              <span className="mono pkg">{c.package}</span>
              {c.fixed ? (
                <span className="mono ok">
                  {c.installed} → {c.fixed}
                </span>
              ) : (
                <span className="dim">{noFix}</span>
              )}
            </>
          ) : (
            <span className="t">{c.title}</span>
          )}
        </div>
      ))}
    </div>
  );
}
