// Le panneau d'inspection, partagé par toutes les vues.
//
// Il ne connaît qu'un `EventRecord`, et c'est ce qui le rend partageable : une ressource Flux en
// devient un côté serveur (`kdt::flux::synthetic_record`), exactement comme le TUI en fabrique un
// pour que sa vue Flux réutilise le même panneau. Les trois onglets — Logs, Status, Related — sont
// donc les mêmes objets sur la même donnée, quelle que soit la vue qui a ouvert la ligne.
//
// `yaml`, `edit`, `delete`, `ai` et `custom` n'y vivent plus : ce sont des overlays qui remplacent
// la table (le panneau du bas), pas un onglet de plus dans le panneau du haut — un YAML de 40
// lignes ou un éditeur se lisent mal dans une bande de 300 px, et le panneau du haut reste ainsi
// toujours ce qu'il montre d'habitude, ligne sélectionnée ou pas. `ViewBody` est le point d'entrée
// que chaque vue pose autour de sa table pour obtenir ce comportement.

import { useEffect, useState, type ReactNode, type RefObject } from "react";
import * as api from "./api";
import type { Lang, Strings } from "./i18n";
import { AiPane } from "./ai";
import { DeletePane, EditPane, YamlPane } from "./objects";
import { useRecordChanged } from "./record";
import {
  hasLogs,
  toneLabel,
  type EventRecord,
  type PodLogs,
  type RelatedSection,
  type StatusPayload,
} from "./types";

/**
 * Les onglets du panneau du haut, plus les cinq overlays qui remplacent la table.
 *
 * `detail`, `logs`, `status`, `related` sont les onglets du panneau du haut. `DetailTab { Logs,
 * Status, Related }` côté Rust : mêmes trois, même ordre. Un onglet « Détail » en plus n'existerait
 * que sur le web, et les deux interfaces ne se ressembleraient plus.
 *
 * `yaml`, `edit`, `delete` et `ai` viennent après : dans kdt ce sont quatre overlays qu'ouvrent `y`,
 * `e`, `Ctrl-D` et `i`, et ils marchent dans toutes les vues. Ici les boutons qui les ouvrent vivent
 * dans la barre, comme dans le TUI, mais leur contenu remplace la table — c'est `ViewBody` qui
 * décide, pas `InspectPanel`.
 *
 * Ces quatre-là sont des **overlays**, pas des onglets permanents : dans kdt on les ouvre et on les
 * ferme. Ils n'apparaissent donc que tant qu'on y est, et disparaissent dès qu'on va ailleurs.
 *
 * `custom` est le même contrat, ouvert aux vues : un overlay que kdt n'a que dans une vue — le
 * panneau de drain d'un node — s'ouvre depuis la barre de cette vue et se referme pareil. Il n'y
 * en a qu'un à la fois, parce qu'une vue qui en voudrait deux voudrait en fait deux onglets.
 */
export type PanelTab =
  | "detail"
  | "logs"
  | "status"
  | "related"
  | "yaml"
  | "edit"
  | "delete"
  | "ai"
  | "custom";

/** Les onglets qui ne vivent que le temps qu'on les regarde. */
const OVERLAY_TABS: PanelTab[] = ["yaml", "edit", "delete", "ai", "custom"];

/** L'onglet de repli quand un overlay se ferme, ou quand la ligne visée disparaît. */
function fallbackTab(hasDetail: boolean): PanelTab {
  return hasDetail ? "detail" : "status";
}

/** Un onglet qui remplace la table le temps qu'on l'y regarde — jamais le panneau du haut. */
export function isOverlayTab(tab: PanelTab): boolean {
  return OVERLAY_TABS.includes(tab);
}

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
 *
 * **Il reste à l'écran tant qu'il est déplié, sélection ou pas.** Le faire apparaître avec la
 * sélection décalait la table de 300 px à chaque clic, et on perdait la ligne qu'on venait de
 * viser. Sans sélection il montre son cadre et l'invite ; c'est le pli — que la personne commande
 * et que kdt retient — qui décide de sa présence, jamais l'état de la donnée.
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
}: {
  /** `null` quand rien n'est sélectionné : le panneau reste en place et le dit. */
  record: EventRecord | null;
  tab: PanelTab;
  onTab: (t: PanelTab) => void;
  onClose: () => void;
  height: number;
  lang: Lang;
  st: Strings;
  detail?: DetailPane;
}) {
  // Un Pod rend ses propres logs, une ressource Flux ceux de son controller filtrés sur elle.
  // Ailleurs, l'onglet resterait vide : remonter d'un Deployment à ses pods demande de choisir
  // lesquels, et ce choix a des règles qu'on ne réinvente pas ici.
  const logs = record ? hasLogs(record) : false;
  // L'onglet réellement affiché. Un `yaml`/`edit`/`delete`/`ai`/`custom` demandé vit dans le
  // panneau du bas (`ViewBody`) : ici il retombe sur ce qui reste lisible, exactement comme une
  // ligne désélectionnée ou un objet supprimé — le panneau du haut ne connaît que ses quatre
  // onglets propres.
  const shown: PanelTab =
    isOverlayTab(tab) || (tab === "detail" && !detail) ? fallbackTab(Boolean(detail)) : tab;

  return (
    <section className="panel" style={{ height }}>
      <div className="phd">
        <div className="ptabs" role="tablist">
          {detail && (
            <button role="tab" aria-selected={shown === "detail"} onClick={() => onTab("detail")}>
              {detail.label}
            </button>
          )}
          <button
            role="tab"
            aria-selected={shown === "logs"}
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
          <button role="tab" aria-selected={shown === "status"} onClick={() => onTab("status")}>
            Status
          </button>
          <button role="tab" aria-selected={shown === "related"} onClick={() => onTab("related")}>
            Related
          </button>
        </div>

        <div className="pid">
          {record ? (
            <>
              <span className={`st ${record.tone}`}>{toneLabel(record.tone)}</span>
              <span className="mono">
                {record.kind}{" "}
                {record.namespace ? `${record.namespace}/${record.name}` : record.name}
              </span>
              <span className="reason">{record.reason}</span>
            </>
          ) : (
            <span className="dim">{st.objSelectRow}</span>
          )}
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
        {/* Sans sélection le panneau garde sa place et le dit : le faire disparaître décalerait la
            table sous le curseur à chaque clic. */}
        {!record ? (
          <p className="pane-wait">{st.objSelectRow}</p>
        ) : (
          <>
            {/* L'onglet propre à la vue passe devant : quand il existe, c'est lui qu'on vient lire. */}
            {shown === "detail" && (detail?.node ?? null)}
            {shown === "logs" &&
              (logs ? (
                <LogsPane record={record} lang={lang} />
              ) : (
                <p className="pane-wait">
                  {lang === "fr"
                    ? "Cet objet ne porte pas de logs à suivre."
                    : "This object carries no logs to follow."}
                </p>
              ))}
            {shown === "status" && <StatusPane record={record} lang={lang} />}
            {shown === "related" && <RelatedPane record={record} lang={lang} />}
          </>
        )}
      </div>
    </section>
  );
}

/**
 * Ce que `y`, `e`, `Ctrl-D`, `i` et l'overlay propre d'une vue ouvrent, **à la place de la table**.
 *
 * Un YAML, un éditeur, une confirmation de suppression ou une analyse IA prennent une page entière
 * dans le TUI ; ici ils prennent le panneau du bas plutôt qu'une bande de 300 px sous des onglets.
 * La croix referme, comme dans le TUI, et rend la table.
 */
function ObjectOverlay({
  tab,
  record,
  lang,
  st,
  overlay,
  onClose,
  onDeleted,
  onNeedsAuth,
}: {
  tab: PanelTab;
  record: EventRecord;
  lang: Lang;
  st: Strings;
  /** Le contenu de l'overlay `custom`, propre à la vue (le drain d'un node, par exemple). */
  overlay?: DetailPane;
  onClose: () => void;
  onDeleted?: (message: string) => void;
  onNeedsAuth: (message: string) => void;
}) {
  // `Échap` referme l'overlay avant de replier le panneau — l'ordre du TUI, où la touche ferme ce
  // qui est ouvert par-dessus. La capture est nécessaire pour passer devant le handler global de
  // la coquille, qui replierait le panneau du haut.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      e.stopPropagation();
      onClose();
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [onClose]);

  const label =
    tab === "custom"
      ? (overlay?.label ?? "")
      : tab === "yaml"
        ? st.actionYaml
        : tab === "edit"
          ? st.actionEdit
          : tab === "ai"
            ? st.actionAi
            : st.actionDelete;

  return (
    <div className="body-overlay">
      <div className="phd">
        <div className="pid">
          <span className={`st ${record.tone}`}>{toneLabel(record.tone)}</span>
          <span className="mono">
            {record.kind}{" "}
            {record.namespace ? `${record.namespace}/${record.name}` : record.name}
          </span>
        </div>
        <span className="ov-label">{label}</span>
        <button
          className="pclose"
          title={lang === "fr" ? "Fermer" : "Close"}
          onClick={onClose}
        >
          ✕
        </button>
      </div>
      <div className="pbody">
        {tab === "custom" && (overlay?.node ?? null)}
        {tab === "yaml" && <YamlPane key={record.uid} record={record} lang={lang} st={st} />}
        {tab === "edit" && (
          <EditPane key={record.uid} record={record} lang={lang} st={st} onNeedsAuth={onNeedsAuth} />
        )}
        {/* L'analyse survit à la fermeture de l'overlay : elle vit dans un état de module, pas
            dans ce composant. Y revenir relit ce qui a été écrit, sans rappeler le modèle. */}
        {tab === "ai" && (
          <AiPane key={record.uid} record={record} lang={lang} st={st} onNeedsAuth={onNeedsAuth} />
        )}
        {tab === "delete" && (
          <DeletePane
            key={record.uid}
            record={record}
            lang={lang}
            st={st}
            // Annuler referme l'overlay et rend l'objet à sa vue : replier le panneau ferait
            // disparaître la ligne qu'on vient de décider de garder, et un demi-recul le
            // laisserait armé.
            onCancel={onClose}
            onDeleted={onDeleted}
            onNeedsAuth={onNeedsAuth}
          />
        )}
      </div>
    </div>
  );
}

/**
 * L'enveloppe que chaque vue pose autour de sa table, à la place d'un simple `<div className="body">`.
 *
 * Elle ne juge rien de la table elle-même — `children` reste ce que la vue rendait déjà — mais
 * substitue l'overlay demandé quand `tab` en vise un et que la ligne sélectionnée en a un : la
 * table disparaît, l'overlay prend sa place, et `Échap` ou sa croix la rendent.
 */
export function ViewBody({
  tab,
  record,
  lang,
  st,
  onTab,
  overlay,
  onDeleted,
  onNeedsAuth,
  hasDetail,
  bodyRef,
  children,
}: {
  tab: PanelTab;
  record: EventRecord | null;
  lang: Lang;
  st: Strings;
  onTab: (t: PanelTab) => void;
  overlay?: DetailPane;
  onDeleted?: (message: string) => void;
  onNeedsAuth: (message: string) => void;
  /** La vue pose un onglet `detail` : fermer l'overlay y retombe plutôt que sur `status`. */
  hasDetail?: boolean;
  bodyRef?: RefObject<HTMLDivElement | null>;
  children: ReactNode;
}) {
  // `y`, `e` et `Ctrl-D` visent l'objet Kubernetes derrière la ligne : sans kind ni nom, il n'y en
  // a pas. L'overlay `custom` vise ce que la vue lui a donné, pas l'objet — un drain garde son
  // node même si la sélection change entre-temps.
  const addressable = Boolean(record && record.kind && record.name);
  const active =
    tab === "custom" ? (overlay ? tab : null) : isOverlayTab(tab) && addressable ? tab : null;

  return (
    <div className="body" ref={bodyRef}>
      {active && record ? (
        <ObjectOverlay
          tab={active}
          record={record}
          lang={lang}
          st={st}
          overlay={overlay}
          onClose={() => onTab(fallbackTab(Boolean(hasDetail)))}
          onDeleted={onDeleted}
          onNeedsAuth={onNeedsAuth}
        />
      ) : (
        children
      )}
    </div>
  );
}

/**
 * Le pli du panneau, posé dans la barre d'actions de chaque vue.
 *
 * Toujours offert : le panneau ne dépend plus de la sélection, et ce bouton — avec `Échap` — est
 * ce qui décide de sa présence. Le libellé nomme **la direction que le clic prendrait**, jamais
 * l'état courant : « ▾ replier » sur un panneau ouvert, comme le pied de page du TUI.
 */
export function PanelToggle({
  open,
  onOpen,
  lang,
}: {
  open: boolean;
  onOpen: (open: boolean) => void;
  lang: Lang;
}) {
  return (
    <button
      className="panel-toggle"
      title={lang === "fr" ? "Panneau d'inspection" : "Inspection panel"}
      onClick={() => onOpen(!open)}
    >
      {open
        ? lang === "fr"
          ? "▾ replier"
          : "▾ collapse"
        : lang === "fr"
          ? "▸ panneau"
          : "▸ panel"}
    </button>
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

  if (useRecordChanged(record)) {
    setPayload(null);
    setError(null);
  }

  useEffect(() => {
    let live = true;
    api
      .status(record)
      // La lecture qui aboutit efface l'échec de la précédente : sans ça un refus passager resterait
      // à l'écran sur une donnée qui, elle, s'est remise à arriver.
      .then((r) => live && (setPayload(r), setError(null)))
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

  // Les sections dépliées sont dans le DOM : tant que la liste garde ses titres, `<details>` garde
  // ce qui est ouvert. Ce qui les refermait, c'était de repasser par « Recherche… » à chaque
  // rafraîchissement.
  if (useRecordChanged(record)) {
    setSections(null);
    setError(null);
  }

  useEffect(() => {
    let live = true;
    api
      .related(record)
      .then((r) => live && (setSections(r.sections), setError(null)))
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

  // L'objet change : le choix de container ne vaut plus, celui-ci n'existe pas forcément ailleurs,
  // et les lignes affichées sont celles d'un autre pod.
  if (useRecordChanged(record)) {
    setContainer("");
    setPrevious(false);
    setLogs(null);
    setError(null);
  }

  useEffect(() => {
    let live = true;
    api
      .logs(record, { container, previous })
      .then((r) => live && (setLogs(r), setError(null)))
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
