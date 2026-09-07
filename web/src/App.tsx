// La coquille : barre de portée persistante, rail des vues, et la vue choisie en dessous.
//
// Ce fichier ne connaît aucune vue de l'intérieur. Il tient ce qui est commun — qui est connecté,
// la langue, le thème, le filtre, la hauteur du panneau — et laisse chaque vue charger et juger
// sa propre donnée.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import * as api from "./api";
import CertsView from "./CertsView";
import EventsView from "./EventsView";
import FluxView from "./FluxView";
import IdentityView from "./IdentityView";
import RancherView from "./RancherView";
import WorkloadsView from "./WorkloadsView";
import DataView from "./DataView";
import { storedLang, storeLang, strings, type Lang } from "./i18n";
import { clampPanelHeight, DEFAULT_PANEL_HEIGHT } from "./panel";
import { apply as applyTheme, stored as storedTheme, toggled, type Theme } from "./theme";
import type { Capabilities, Identity } from "./types";

type ViewId = "events" | "flux" | "workloads" | "data" | "certs" | "identity" | "rancher";

/**
 * Les vues, dans l'ordre du rail.
 *
 * `needs` nomme l'add-on sans lequel la vue n'aurait pas de sujet : elle disparaît alors du rail
 * plutôt que d'y figurer grisée. Une vue absente pose moins de questions qu'une vue qu'on ne peut
 * pas ouvrir — et un cluster sans Argo CD n'a pas de vue Argo CD, ce n'est pas une privation.
 *
 * Sans `needs`, la vue repose sur les objets natifs de Kubernetes : elle répond partout.
 */
const VIEWS: Array<{
  id: string;
  label: string;
  key: string;
  ready?: boolean;
  needs?: keyof Capabilities;
}> = [
  { id: "events", label: "Events", key: "e", ready: true },
  { id: "workloads", label: "Workloads", key: "w", ready: true },
  { id: "flux", label: "Flux", key: "f", ready: true, needs: "flux" },
  { id: "argocd", label: "Argo CD", key: "a", needs: "argocd" },
  { id: "velero", label: "Velero", key: "v", needs: "velero" },
  { id: "capacity", label: "Capacity", key: "c" },
  { id: "storage", label: "Storage", key: "s" },
  { id: "data", label: "Secrets / CM", key: "b", ready: true },
  { id: "certs", label: "Certs", key: "t", ready: true, needs: "certs" },
  { id: "rbac", label: "RBAC", key: "r" },
  { id: "kyverno", label: "Kyverno", key: "k", needs: "kyverno" },
  { id: "identity", label: "Identity", key: "i", ready: true, needs: "identity" },
  // Deux vues d'identité, nommées par leur source, comme dans kdt : `identity` liste les comptes
  // que ce cluster écrit, `rancher` l'annuaire fédéré qu'il ne fait que lire.
  { id: "rancher", label: "Rancher", key: "u", ready: true, needs: "rancher" },
  { id: "netpol", label: "NetPol", key: "n" },
  { id: "diagnostic", label: "Diagnostic", key: "d" },
];

export default function App() {
  const [lang, setLang] = useState<Lang>(storedLang);
  const [theme, setTheme] = useState<Theme>(storedTheme);
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [capabilities, setCapabilities] = useState<Capabilities | null>(null);
  const [booting, setBooting] = useState(true);

  const [view, setView] = useState<ViewId>("events");
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [query, setQuery] = useState("");
  const [needsAuth, setNeedsAuth] = useState<string | null>(null);

  // Hauteur du panneau, en pixels et retenue d'une session à l'autre. Lire des logs et lire une
  // table ne demandent pas le même partage de l'écran, et ce partage est affaire de goût — donc
  // il se règle plutôt qu'il ne se décrète. Il vit ici parce qu'il vaut pour toutes les vues.
  const [panelHeight, setPanelHeight] = useState(() => {
    try {
      const stored = Number(localStorage.getItem("kdt-panel-h"));
      if (Number.isFinite(stored) && stored > 0) return stored;
    } catch {
      // Stockage bloqué : la hauteur par défaut fait l'affaire.
    }
    return DEFAULT_PANEL_HEIGHT;
  });
  // Replié, le panneau laisse toute la hauteur à la table. Le choix est retenu, comme le
  // `hide_top_panel` que kdt écrit dans sa configuration.
  const [panelOpen, setPanelOpen] = useState(() => {
    try {
      return localStorage.getItem("kdt-panel") !== "closed";
    } catch {
      return true;
    }
  });
  const [scopeOpen, setScopeOpen] = useState(false);
  // La cible d'un saut vers la vue Secrets — le `s` de la vue certs. Elle est consommée par
  // `DataView`, qui la sélectionne si elle est dans sa liste, puis la rend.
  const [focusSecret, setFocusSecret] = useState<{ namespace: string; name: string } | null>(null);
  // Et la cible du saut inverse — le `o` du TUI, d'un Secret vers la chaîne qui l'émet.
  const [focusCert, setFocusCert] = useState<{ namespace: string; name: string } | null>(null);
  const filterRef = useRef<HTMLInputElement>(null);
  const st = strings(lang);

  useEffect(() => applyTheme(theme), [theme]);

  useEffect(() => {
    try {
      localStorage.setItem("kdt-panel", panelOpen ? "open" : "closed");
    } catch {
      // Stockage bloqué : le choix vaut pour l'onglet ouvert, ce n'est pas une erreur.
    }
  }, [panelOpen]);

  useEffect(() => {
    try {
      localStorage.setItem("kdt-panel-h", String(panelHeight));
    } catch {
      // Idem : sans persistance, la hauteur vaut pour l'onglet ouvert.
    }
  }, [panelHeight]);

  // Une fenêtre rétrécie peut rendre la hauteur retenue plus grande que ce qui tient : la
  // ramener dans les bornes évite un panneau qui recouvre toute la table au redimensionnement.
  useEffect(() => {
    const onResize = () => setPanelHeight((h) => clampPanelHeight(h));
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  // Qui est connecté. Tant qu'on ne le sait pas, on n'affiche ni l'application ni l'invitation à
  // se connecter : montrer l'une puis l'autre ferait clignoter la page à chaque chargement.
  useEffect(() => {
    api
      .identity()
      .then(setIdentity)
      .catch(() => setIdentity(null))
      .finally(() => setBooting(false));
  }, []);

  // Ce que le cluster sait faire, une fois seulement : les CRD ne s'installent pas pendant qu'on
  // regarde une table, et resonder à chaque tick coûterait une requête pour une réponse qui ne
  // change pas. Un rechargement de page suffit à en tenir compte.
  useEffect(() => {
    if (!identity) return;
    api
      .capabilities()
      .then(setCapabilities)
      // Sonde en échec — apiserver injoignable, le plus souvent. On reste à `null`, et le rail
      // n'écarte alors **rien** : une vue qui disparaît est un message, et le message serait
      // faux. Chaque vue dira elle-même ce qu'elle n'a pas pu lire.
      .catch(() => setCapabilities(null));
  }, [identity]);

  const views = useMemo(
    // Tant que la sonde n'a pas répondu — ou qu'elle a échoué — tout reste affiché : filtrer sur
    // une réponse qu'on n'a pas revient à affirmer une absence qu'on n'a pas constatée.
    () => (capabilities ? VIEWS.filter((v) => !v.needs || capabilities[v.needs]) : VIEWS),
    [capabilities],
  );

  // La vue ouverte peut disparaître du rail — un add-on désinstallé, une sonde qui échoue au
  // rechargement. On retombe sur les évènements plutôt que de laisser une vue sans onglet.
  useEffect(() => {
    if (!views.some((v) => v.id === view)) setView("events");
  }, [views, view]);

  // `/` met le focus sur le filtre, `Échap` ferme ce qui est ouvert. Deux gestes du TUI qui
  // survivent au changement de média parce qu'ils ne coûtent rien à qui les ignore.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "/" && document.activeElement !== filterRef.current) {
        e.preventDefault();
        filterRef.current?.focus();
      } else if (e.key === "Escape") {
        if (scopeOpen) setScopeOpen(false);
        else if (document.activeElement === filterRef.current) filterRef.current?.blur();
        else if (panelOpen) setPanelOpen(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [scopeOpen, panelOpen]);

  const onNeedsAuth = useCallback((message: string) => setNeedsAuth(message), []);

  if (booting) return <div className="center" />;

  if (!identity) {
    return (
      <div className="center">
        <div className="box">
          <h2>kdt</h2>
          <p>
            Cette interface utilise <strong>votre</strong> identité sur le cluster : elle ne voit
            que ce que vos droits vous permettent de voir.
          </p>
          <button className="cta" onClick={() => api.login()}>
            Se connecter
          </button>
        </div>
      </div>
    );
  }

  // Les vues qui listent des objets indépendants sont dans la portée ; celles qui dessinent un
  // graphe n'y sont pas — filtrer l'arbre Flux par namespace lui ferait perdre ses arêtes, la
  // GitRepository de flux-system étant le parent de presque tout. C'est le partage de kdt.
  // Les vues qui listent des objets indépendants sont dans la portée ; celles qui dessinent un
  // graphe n'y sont pas, et les deux annuaires non plus — leurs objets sont cluster-scoped, ou
  // vivent dans le namespace de leur cluster Rancher, ce qui n'a rien à voir avec la question posée.
  const scoped =
    view === "events" || view === "workloads" || view === "data" || view === "certs";
  const scopelessReason =
    view === "identity" ? st.identScopeless : view === "rancher" ? st.ranchScopeless : st.fluxScopeless;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="name">kdt</span>
        </div>

        <div className="scope">
          <button
            className="scope-btn"
            aria-expanded={scopeOpen}
            disabled={!scoped}
            title={scoped ? undefined : scopelessReason}
            onClick={() => setScopeOpen((v) => !v)}
          >
            <span className="lbl">{st.scopeLabel}</span>
            <span className="val">
              {!scoped
                ? st.scopeAll
                : namespaces.length === 0
                  ? st.scopeAll
                  : namespaces.length === 1
                    ? namespaces[0]
                    : `${namespaces[0]} +${namespaces.length - 1}`}
            </span>
            <span className="chev">▾</span>
          </button>
          {scopeOpen && scoped && (
            <ScopePicker
              namespaces={namespaces}
              onChange={setNamespaces}
              onClose={() => setScopeOpen(false)}
              labels={{ title: st.scopeTitle, all: st.scopeAll }}
            />
          )}
        </div>

        <div className="filter">
          <span className="slash">/</span>
          <input
            ref={filterRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={st.filterPlaceholder}
            autoComplete="off"
            spellCheck={false}
          />
          {query && (
            <button className="clear" aria-label={st.filterClear} onClick={() => setQuery("")}>
              ✕
            </button>
          )}
        </div>

        <div className="spacer" />
        <div className="who">
          <span className="sub">{identity.subject}</span>
          {identity.groups.map((g) => (
            <span className="grp" key={g}>
              {g}
            </span>
          ))}
        </div>
        <button
          className="icon-btn"
          title={st.langToggle}
          onClick={() => {
            const next: Lang = lang === "fr" ? "en" : "fr";
            setLang(next);
            storeLang(next);
          }}
        >
          {lang.toUpperCase()}
        </button>
        <button
          className="icon-btn"
          title={st.themeToggle}
          onClick={() => setTheme(toggled(theme))}
        >
          ◐
        </button>
        <button className="icon-btn" title="Se déconnecter" onClick={() => void api.logout()}>
          ⏻
        </button>
      </header>

      <div className="chrome">
        <nav className="rail">
          <div className="rail-hd">{st.views}</div>
          {views.map((v) => (
            <button
              key={v.id}
              aria-current={v.id === view}
              disabled={!v.ready}
              title={v.ready ? undefined : st.notMockedTitle}
              onClick={() => v.ready && setView(v.id as ViewId)}
            >
              <span>{v.label}</span>
              <span className="k">{v.key}</span>
            </button>
          ))}
        </nav>

        <section className="pane">
          {needsAuth ? (
            <div className="body">
              <div className="center">
                <div className="box">
                  <h2>{lang === "fr" ? "Votre accès a expiré" : "Your access has expired"}</h2>
                  <p>{needsAuth}</p>
                  <button className="cta" onClick={() => api.login()}>
                    {lang === "fr" ? "Se reconnecter" : "Sign in again"}
                  </button>
                </div>
              </div>
            </div>
          ) : view === "data" ? (
            <DataView
              lang={lang}
              st={st}
              query={query}
              namespaces={namespaces}
              panelHeight={panelHeight}
              onPanelHeight={setPanelHeight}
              panelOpen={panelOpen}
              onPanelOpen={setPanelOpen}
              onNeedsAuth={onNeedsAuth}
              focusSecret={focusSecret}
              onFocusConsumed={() => setFocusSecret(null)}
              // Le saut vers la chaîne n'est offert que si le rail porte la vue certs : sans
              // cert-manager sur ce cluster, elle n'existe pas et le bouton mènerait nulle part.
              onOpenCert={
                views.some((v) => v.id === "certs")
                  ? (namespace, name) => {
                      setFocusCert({ namespace, name });
                      setView("certs");
                    }
                  : undefined
              }
            />
          ) : view === "certs" ? (
            <CertsView
              lang={lang}
              st={st}
              query={query}
              namespaces={namespaces}
              panelHeight={panelHeight}
              onPanelHeight={setPanelHeight}
              panelOpen={panelOpen}
              onPanelOpen={setPanelOpen}
              onNeedsAuth={onNeedsAuth}
              // Le `s` du TUI : la vue Secrets sait déjà décoder un certificat et révéler des
              // valeurs, et la vue certs lui passe la main plutôt que d'en refaire une moitié.
              onOpenSecret={(namespace, name) => {
                setFocusSecret({ namespace, name });
                setView("data");
              }}
              focusCert={focusCert}
              onFocusConsumed={() => setFocusCert(null)}
            />
          ) : view === "identity" ? (
            <IdentityView
              lang={lang}
              st={st}
              query={query}
              panelHeight={panelHeight}
              onPanelHeight={setPanelHeight}
              panelOpen={panelOpen}
              onPanelOpen={setPanelOpen}
              onNeedsAuth={onNeedsAuth}
            />
          ) : view === "rancher" ? (
            <RancherView
              lang={lang}
              st={st}
              query={query}
              panelHeight={panelHeight}
              onPanelHeight={setPanelHeight}
              panelOpen={panelOpen}
              onPanelOpen={setPanelOpen}
              onNeedsAuth={onNeedsAuth}
            />
          ) : view === "workloads" ? (
            <WorkloadsView
              lang={lang}
              st={st}
              query={query}
              namespaces={namespaces}
              panelHeight={panelHeight}
              onPanelHeight={setPanelHeight}
              panelOpen={panelOpen}
              onPanelOpen={setPanelOpen}
              onNeedsAuth={onNeedsAuth}
            />
          ) : view === "flux" ? (
            <FluxView
              lang={lang}
              st={st}
              query={query}
              panelHeight={panelHeight}
              onPanelHeight={setPanelHeight}
              panelOpen={panelOpen}
              onPanelOpen={setPanelOpen}
              onNeedsAuth={onNeedsAuth}
            />
          ) : (
            <EventsView
              lang={lang}
              st={st}
              query={query}
              namespaces={namespaces}
              panelHeight={panelHeight}
              onPanelHeight={setPanelHeight}
              panelOpen={panelOpen}
              onPanelOpen={setPanelOpen}
              onNeedsAuth={onNeedsAuth}
            />
          )}
        </section>
      </div>
    </div>
  );
}

/** Choix de la portée : plusieurs namespaces, ou tout le cluster. */
function ScopePicker({
  namespaces,
  onChange,
  onClose,
  labels,
}: {
  namespaces: string[];
  onChange: (next: string[]) => void;
  onClose: () => void;
  labels: { title: string; all: string };
}) {
  const [draft, setDraft] = useState("");

  return (
    <div className="pop" onClick={(e) => e.stopPropagation()}>
      <div className="pop-hd">
        <span>namespaces</span>
        <button
          onClick={() => {
            onChange([]);
            onClose();
          }}
        >
          {labels.title}
        </button>
      </div>

      {/* Saisi plutôt que choisi dans une liste : lister les namespaces demande un droit que
          tout le monde n'a pas, et le refus se verrait ici au lieu de se voir sur la donnée. */}
      <input
        className="ns-add"
        value={draft}
        placeholder="namespace + Entrée"
        autoFocus
        spellCheck={false}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key !== "Enter") return;
          const name = draft.trim();
          if (name && !namespaces.includes(name)) onChange([...namespaces, name]);
          setDraft("");
        }}
      />

      <div className="ns-list">
        {namespaces.length === 0 && (
          <div className="ns-item">
            <span style={{ opacity: 0.6 }}>{labels.all}</span>
          </div>
        )}
        {namespaces.map((ns) => (
          <div className="ns-item" key={ns}>
            <span>{ns}</span>
            <button
              aria-label={`retirer ${ns}`}
              onClick={() => onChange(namespaces.filter((n) => n !== ns))}
            >
              ✕
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
