// Le panneau d'inspection, partagé par toutes les vues.
//
// Il ne connaît qu'un `EventRecord`, et c'est ce qui le rend partageable : une ressource Flux en
// devient un côté serveur (`kdt::flux::synthetic_record`), exactement comme le TUI en fabrique un
// pour que sa vue Flux réutilise le même panneau. Les trois onglets — Logs, Status, Related — sont
// donc les mêmes objets sur la même donnée, quelle que soit la vue qui a ouvert la ligne.

import { useEffect, useState, type ReactNode } from "react";
import * as api from "./api";
import type { Lang, Strings } from "./i18n";
import { EditPane, YamlPane } from "./objects";
import {
  hasLogs,
  toneLabel,
  type EventRecord,
  type PodLogs,
  type RelatedSection,
  type StatusPayload,
} from "./types";

/**
 * Les onglets, dans l'ordre et sous les noms du TUI.
 *
 * `DetailTab { Logs, Status, Related }` côté Rust : mêmes trois, même ordre. Un onglet « Détail »
 * en plus n'existerait que sur le web, et les deux interfaces ne se ressembleraient plus.
 *
 * `yaml` et `edit` viennent après : dans kdt ce sont deux overlays qu'ouvrent `y` et `e`, et ils
 * marchent dans toutes les vues. Ici ce sont deux onglets du même panneau — les boutons qui les
 * ouvrent vivent dans la barre, le contenu vit là où va tout contenu.
 */
export type PanelTab = "detail" | "logs" | "status" | "related" | "yaml" | "edit";

/**
 * Un onglet propre à une vue, posé devant les trois onglets partagés.
 *
 * Certaines vues de kdt montrent l'objet lui-même dans le panneau du haut, et pas seulement son
 * état : un Secret y affiche son type, ses clés, son certificat, ses consommateurs, et c'est là
 * que ses valeurs se révèlent. Ce contenu-là est propre à la vue, donc c'est elle qui le rend ;
 * le panneau se contente de lui faire une place devant `Logs`.
 */
export interface DetailPane {
  label: string;
  node: ReactNode;
}

/** Hauteur du panneau au premier affichage, et celle que le double-clic sur la poignée rétablit. */
export const DEFAULT_PANEL_HEIGHT = 300;

/**
 * Bornes du panneau, calculées à chaque fois plutôt que figées.
 *
 * Le plancher garde les onglets et deux lignes lisibles ; le plafond garde toujours quelques
 * lignes de table sous les yeux, sans quoi le double panneau ne servirait plus à rien.
 */
export function clampPanelHeight(height: number): number {
  const ceiling = Math.max(160, window.innerHeight - 260);
  return Math.min(Math.max(height, 120), ceiling);
}

/**
 * Le panneau d'inspection, **au-dessus** de la table comme dans le TUI.
 *
 * Un panneau latéral paraissait plus moderne ; il est surtout trop étroit pour ce qu'on y met.
 * Des logs sur 390 px se lisent en accordéon, alors que la largeur entière de l'écran les rend
 * comme un terminal. C'est aussi la disposition que kdt a déjà, donc celle que quelqu'un qui
 * passe de l'un à l'autre n'a pas à réapprendre.
 */
export function InspectPanel({
  record,
  tab,
  onTab,
  onClose,
  height,
  lang,
  st,
  detail,
  onNeedsAuth,
}: {
  record: EventRecord;
  tab: PanelTab;
  onTab: (t: PanelTab) => void;
  onClose: () => void;
  height: number;
  lang: Lang;
  st: Strings;
  detail?: DetailPane;
  onNeedsAuth: (message: string) => void;
}) {
  // Un Pod rend ses propres logs, une ressource Flux ceux de son controller filtrés sur elle.
  // Ailleurs, l'onglet resterait vide : remonter d'un Deployment à ses pods demande de choisir
  // lesquels, et ce choix a des règles qu'on ne réinvente pas ici.
  const logs = hasLogs(record);
  // `y` et `e` visent l'objet Kubernetes derrière la ligne : sans kind ni nom, il n'y en a pas.
  const addressable = Boolean(record.kind && record.name);

  return (
    <section className="panel" style={{ height }}>
      <div className="phd">
        <div className="ptabs" role="tablist">
          {detail && (
            <button role="tab" aria-selected={tab === "detail"} onClick={() => onTab("detail")}>
              {detail.label}
            </button>
          )}
          <button
            role="tab"
            aria-selected={tab === "logs"}
            disabled={!logs}
            title={
              logs
                ? undefined
                : lang === "fr"
                  ? "Les logs sont lisibles sur un Pod ou une ressource Flux"
                  : "Logs are available on a Pod or a Flux resource"
            }
            onClick={() => onTab("logs")}
          >
            Logs
          </button>
          <button role="tab" aria-selected={tab === "status"} onClick={() => onTab("status")}>
            Status
          </button>
          <button role="tab" aria-selected={tab === "related"} onClick={() => onTab("related")}>
            Related
          </button>
          {/* Les deux gestes de kdt qui portent sur n'importe quel objet. Un enregistrement qui ne
              désigne rien — une ligne de regroupement — n'en a pas : l'onglet le dit. */}
          <button
            role="tab"
            aria-selected={tab === "yaml"}
            disabled={!addressable}
            title={addressable ? undefined : st.objSelectRow}
            onClick={() => onTab("yaml")}
          >
            {st.actionYaml}
          </button>
          <button
            role="tab"
            aria-selected={tab === "edit"}
            disabled={!addressable}
            title={addressable ? undefined : st.objSelectRow}
            onClick={() => onTab("edit")}
          >
            {st.actionEdit}
          </button>
        </div>

        <div className="pid">
          <span className={`st ${record.tone}`}>{toneLabel(record.tone)}</span>
          <span className="mono">
            {record.kind} {record.namespace ? `${record.namespace}/${record.name}` : record.name}
          </span>
          <span className="reason">{record.reason}</span>
        </div>

        <button
          className="pclose"
          title={lang === "fr" ? "Replier le panneau" : "Collapse the panel"}
          onClick={onClose}
        >
          ▾
        </button>
      </div>

      <div className="pbody">
        {/* L'onglet propre à la vue passe devant : quand il existe, c'est lui qu'on vient lire. */}
        {tab === "detail" && (detail?.node ?? null)}
        {tab === "logs" &&
          (logs ? (
            <LogsPane record={record} lang={lang} />
          ) : (
            <p className="pane-wait">
              {lang === "fr"
                ? "Cet objet ne porte pas de logs à suivre."
                : "This object carries no logs to follow."}
            </p>
          ))}
        {tab === "status" && <StatusPane record={record} lang={lang} />}
        {tab === "related" && <RelatedPane record={record} lang={lang} />}
        {tab === "yaml" && addressable && (
          <YamlPane key={record.uid} record={record} lang={lang} st={st} />
        )}
        {tab === "edit" && addressable && (
          <EditPane key={record.uid} record={record} lang={lang} st={st} onNeedsAuth={onNeedsAuth} />
        )}
      </div>
    </section>
  );
}

/**
 * La poignée entre le panneau et la table.
 *
 * `setPointerCapture` plutôt que des écouteurs sur `window` : le glissement continue de suivre le
 * curseur même s'il sort de la poignée ou passe au-dessus d'une iframe, et il s'arrête tout seul
 * quand le bouton est relâché n'importe où.
 *
 * Elle est aussi au clavier — c'est un `separator` focusable — parce qu'une poignée qui n'existe
 * qu'à la souris exclut ceux qui n'en utilisent pas.
 */
export function Splitter({
  height,
  onHeight,
  lang,
}: {
  height: number;
  onHeight: (h: number) => void;
  lang: Lang;
}) {
  const [dragging, setDragging] = useState(false);

  return (
    <div
      className={dragging ? "splitter dragging" : "splitter"}
      role="separator"
      aria-orientation="horizontal"
      aria-label={lang === "fr" ? "Hauteur du panneau" : "Panel height"}
      aria-valuenow={Math.round(height)}
      tabIndex={0}
      title={
        lang === "fr"
          ? "Glisser pour redimensionner, double-clic pour réinitialiser"
          : "Drag to resize, double-click to reset"
      }
      onPointerDown={(e) => {
        e.preventDefault();
        e.currentTarget.setPointerCapture(e.pointerId);
        setDragging(true);
      }}
      onPointerMove={(e) => {
        if (!dragging) return;
        // La hauteur se lit sur la position du curseur, pas sur un cumul de deltas : un cumul
        // dérive dès que la valeur est bornée, et la poignée finit décalée du curseur.
        const top = e.currentTarget.parentElement?.getBoundingClientRect().top ?? 0;
        onHeight(clampPanelHeight(e.clientY - top));
      }}
      onPointerUp={(e) => {
        e.currentTarget.releasePointerCapture(e.pointerId);
        setDragging(false);
      }}
      onDoubleClick={() => onHeight(DEFAULT_PANEL_HEIGHT)}
      onKeyDown={(e) => {
        const step = e.shiftKey ? 60 : 16;
        if (e.key === "ArrowUp") {
          e.preventDefault();
          onHeight(clampPanelHeight(height - step));
        } else if (e.key === "ArrowDown") {
          e.preventDefault();
          onHeight(clampPanelHeight(height + step));
        } else if (e.key === "Home") {
          e.preventDefault();
          onHeight(DEFAULT_PANEL_HEIGHT);
        }
      }}
    />
  );
}

/** L'état de l'objet, mis en forme par kdt et peint avec le ton de chaque ligne. */
function StatusPane({ record, lang }: { record: EventRecord; lang: Lang }) {
  const [payload, setPayload] = useState<StatusPayload | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setPayload(null);
    setError(null);
    api
      .status(record)
      .then((r) => live && setPayload(r))
      .catch((e) => live && setError(String(e.message ?? e)));
    return () => {
      live = false;
    };
  }, [record]);

  if (error) return <p className="pane-err">{error}</p>;
  if (!payload) return <p className="pane-wait">{lang === "fr" ? "Lecture…" : "Reading…"}</p>;
  if (payload.error) return <p className="pane-err">{payload.error}</p>;

  return (
    <pre className="statuslines">
      {payload.lines.map((line, i) => (
        <div key={i} className={`ln ${line.tone}`}>
          {line.text || " "}
        </div>
      ))}
    </pre>
  );
}

/**
 * Le contexte autour de l'objet, tel que `gather_extra_context` le rassemble côté serveur.
 *
 * Les sondes partent avec l'identité de la personne connectée : une section absente veut souvent
 * dire « pas le droit de la lire », pas « rien à voir ».
 */
function RelatedPane({ record, lang }: { record: EventRecord; lang: Lang }) {
  const [sections, setSections] = useState<RelatedSection[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setSections(null);
    setError(null);
    api
      .related(record)
      .then((r) => live && setSections(r.sections))
      .catch((e) => live && setError(String(e.message ?? e)));
    return () => {
      live = false;
    };
  }, [record]);

  if (error) return <p className="pane-err">{error}</p>;
  if (!sections) return <p className="pane-wait">{lang === "fr" ? "Recherche…" : "Gathering…"}</p>;
  if (sections.length === 0)
    return (
      <p className="pane-wait">
        {lang === "fr"
          ? "Aucun objet lié trouvé, ou aucun que vos droits laissent lire."
          : "No related object found, or none your rights allow reading."}
      </p>
    );

  return (
    <div className="relgrid">
      {sections.map((section) => (
        <details key={section.title} className="related">
          <summary>{section.title}</summary>
          <pre className="json">{prettyJson(section.body)}</pre>
        </details>
      ))}
    </div>
  );
}

/** Le JSON compact du serveur, ré-indenté pour la lecture. Illisible, il est rendu tel quel. */
function prettyJson(body: string): string {
  try {
    return JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    return body;
  }
}

function LogsPane({ record, lang }: { record: EventRecord; lang: Lang }) {
  const [logs, setLogs] = useState<PodLogs | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [container, setContainer] = useState<string>("");
  const [previous, setPrevious] = useState(false);

  // Un controller Flux n'a pas de containers à choisir, et « run précédent » ne veut rien dire
  // pour lui : ses lignes sont celles de son pod à lui, filtrées sur l'objet. La barre d'options
  // ne s'affiche donc que là où elle change quelque chose.
  const isPod = record.kind === "Pod";
  const key = `${record.namespace}/${record.name}/${record.kind}`;

  // L'objet change : le choix de container ne vaut plus, celui-ci n'existe pas forcément ailleurs.
  useEffect(() => {
    setContainer("");
    setPrevious(false);
  }, [key]);

  useEffect(() => {
    let live = true;
    setLogs(null);
    setError(null);
    api
      .logs(record, { container, previous })
      .then((r) => live && setLogs(r))
      .catch((e) => live && setError(String(e.message ?? e)));
    return () => {
      live = false;
    };
  }, [record, container, previous]);

  return (
    <>
      {isPod && (
        <div className="logbar">
          <select value={container} onChange={(e) => setContainer(e.target.value)}>
            <option value="">{lang === "fr" ? "tous les containers" : "all containers"}</option>
            {(logs?.containers ?? []).map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
          <label>
            <input
              type="checkbox"
              checked={previous}
              onChange={(e) => setPrevious(e.target.checked)}
            />
            {lang === "fr" ? "run précédent" : "previous run"}
          </label>
        </div>
      )}

      {error ? (
        <p className="pane-err">{error}</p>
      ) : !logs ? (
        <p className="pane-wait">{lang === "fr" ? "Lecture…" : "Reading…"}</p>
      ) : logs.lines.length === 0 ? (
        <p className="pane-wait">
          {isPod
            ? lang === "fr"
              ? "Ce pod n'a rien écrit."
              : "This pod wrote nothing."
            : lang === "fr"
              ? "Aucune ligne : le controller n'a rien dit de cet objet dans son historique récent."
              : "No line: the controller said nothing about this object in its recent history."}
        </p>
      ) : (
        <pre className="logs">{logs.lines.join("\n")}</pre>
      )}
    </>
  );
}
