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
import KyvernoView from "./KyvernoView";
import RbacView from "./RbacView";
import VeleroView from "./VeleroView";
import RancherView from "./RancherView";
import WorkloadsView from "./WorkloadsView";
import DataView from "./DataView";
import { useDismiss } from "./dismiss";
import { storedLang, storeLang, strings, type Lang, type Strings } from "./i18n";
import { clampPanelHeight, DEFAULT_PANEL_HEIGHT } from "./panel";
import { apply as applyTheme, stored as storedTheme, toggled, type Theme } from "./theme";
import type { Capabilities, ClusterBanner, ClusterResource, Identity } from "./types";

type ViewId =
  | "events"
  | "flux"
  | "workloads"
  | "data"
  | "certs"
  | "identity"
  | "rancher"
  | "kyverno"
  | "rbac"
  | "velero";

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
  { id: "velero", label: "Velero", key: "v", ready: true, needs: "velero" },
  { id: "capacity", label: "Capacity", key: "c" },
  { id: "storage", label: "Storage", key: "s" },
  { id: "data", label: "Secrets / CM", key: "b", ready: true },
  { id: "certs", label: "Certs", key: "t", ready: true, needs: "certs" },
  { id: "rbac", label: "RBAC", key: "r", ready: true },
  { id: "kyverno", label: "Kyverno", key: "k", ready: true, needs: "kyverno" },
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

  // Le bandeau : quel cluster, dans quel état. Il vit ici parce qu'il vaut pour toutes les vues,
  // et parce que la question qu'il tranche — « suis-je sur le bon cluster ? » — se pose avant
  // d'en ouvrir une.
  const [cluster, setCluster] = useState<ClusterBanner | null>(null);
  const [clusterError, setClusterError] = useState<string | null>(null);

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
  // Les namespaces proposés par le sélecteur de portée. `null` tant qu'on n'a pas lu, et
  // `nsError` non nul quand la lecture a été refusée — un refus n'est pas un cluster sans
  // namespace, et la saisie libre reste alors le seul chemin.
  const [nsList, setNsList] = useState<string[] | null>(null);
  const [nsError, setNsError] = useState<string | null>(null);
  const [nsLoading, setNsLoading] = useState(false);
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

  // Le bandeau se relit, à la différence des add-ons : des nodes se remplacent, une version
  // change, la pression monte. Un onglet caché ne relit rien — le compte se ferait payer par le
  // cluster pour une page que personne ne regarde — et rattrape son retard en redevenant visible.
  useEffect(() => {
    if (!identity) return;
    let alive = true;
    const load = () => {
      if (document.hidden) return;
      api
        .cluster()
        .then((banner) => {
          if (!alive) return;
          setCluster(banner);
          setClusterError(null);
        })
        .catch((e) => {
          if (!alive) return;
          // Une session expirée n'est pas une panne du bandeau : c'est l'application entière qui
          // doit repasser par le portail, et le bandeau est souvent le premier à s'en apercevoir.
          if (e instanceof api.NeedsAuth) setNeedsAuth(e.message);
          // Le dernier état lu est gardé : le remplacer par du vide effacerait le nom du cluster
          // sur un hoquet réseau, là où la question à laquelle il répond, elle, ne change pas.
          else setClusterError(e instanceof Error ? e.message : String(e));
        });
    };
    load();
    const timer = window.setInterval(load, 30_000);
    const onVisible = () => {
      if (!document.hidden) load();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      alive = false;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
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

  // La liste des namespaces se relit à chaque ouverture du sélecteur : ils se créent et se
  // suppriment, et une liste lue au chargement de la page vieillirait sans que rien ne le dise.
  // Ce qui a déjà été lu reste affiché pendant la lecture, pour que la liste ne clignote pas.
  useEffect(() => {
    if (!scopeOpen) return;
    let alive = true;
    setNsLoading(true);
    api
      .namespaces()
      .then((payload) => {
        if (!alive) return;
        setNsList(payload.namespaces);
        setNsError(payload.error);
      })
      .catch((e) => {
        if (!alive) return;
        if (e instanceof api.NeedsAuth) setNeedsAuth(e.message);
        else setNsError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (alive) setNsLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [scopeOpen]);

  // `/` met le focus sur le filtre, `Échap` ferme ce qui est ouvert. Deux gestes du TUI qui
  // survivent au changement de média parce qu'ils ne coûtent rien à qui les ignore.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "/" && document.activeElement !== filterRef.current) {
        e.preventDefault();
        filterRef.current?.focus();
      } else if (e.key === "Escape") {
        // Le sélecteur de portée n'est plus traité ici : `useDismiss` le ferme et coupe la
        // propagation, donc cet `Échap`-là n'arrive jamais jusqu'à ce point.
        if (document.activeElement === filterRef.current) filterRef.current?.blur();
        else if (panelOpen) setPanelOpen(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [panelOpen]);

  const onNeedsAuth = useCallback((message: string) => setNeedsAuth(message), []);

  // Le sélecteur de portée se referme au clic à côté, comme les menus des vues. La ref porte sur
  // le bloc entier — bouton et liste — pour que le bouton reste le geste qui bascule.
  const closeScope = useCallback(() => setScopeOpen(false), []);
  const scopeRef = useDismiss<HTMLDivElement>(scopeOpen, closeScope);

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
  // La vue RBAC est dans la portée, à la différence des autres vues en graphe : la question « la
  // RBAC de ce namespace » a un sens, et kdt y répond en filtrant les lignes sans jamais réduire ce
  // qui est lu — une arête d'agrégation calculée sur une liste partielle serait fausse.
  const scoped =
    view === "events" ||
    view === "workloads" ||
    view === "data" ||
    view === "certs" ||
    view === "rbac" ||
    view === "velero";
  const scopelessReason =
    view === "identity"
      ? st.identScopeless
      : view === "rancher"
        ? st.ranchScopeless
        : view === "kyverno"
          ? st.kyScopeless
          : st.fluxScopeless;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="name">kdt</span>
          {cluster ? (
            <>
              {/* L'adresse de l'apiserver sous le nom : le nom est un libellé qu'on a donné,
                  l'adresse est ce que le serveur a réellement joint. */}
              <span className="ctx" title={`apiserver ${cluster.apiserver}`}>
                {cluster.cluster}
              </span>
              <span
                className="k8s"
                title={cluster.server_version ? undefined : st.clusterVersionUnknown}
              >
                {cluster.server_version ?? "—"}
              </span>
            </>
          ) : (
            clusterError && (
              <span className="ctx dim" title={clusterError}>
                {st.clusterUnknown}
              </span>
            )
          )}
        </div>

        <div className="scope" ref={scopeRef}>
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
              available={nsList}
              error={nsError}
              loading={nsLoading}
              st={st}
              onChange={setNamespaces}
              onClose={() => setScopeOpen(false)}
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
        {cluster && <ClusterStats banner={cluster} st={st} />}
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
          ) : view === "velero" ? (
            <VeleroView
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
          ) : view === "rbac" ? (
            <RbacView
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
          ) : view === "kyverno" ? (
            <KyvernoView
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

/**
 * L'état du cluster, à droite de la barre : ses nodes, sa pression CPU et mémoire.
 *
 * Ce qui n'a pas été lu n'est pas peint en vert : sans le droit de lister les nodes il n'y a ni
 * compte ni allocation, et le bandeau le dit au lieu d'afficher des zéros.
 */
function ClusterStats({ banner, st }: { banner: ClusterBanner; st: Strings }) {
  if (!banner.nodes) {
    return (
      <div className="cstats">
        <span className="cstat" title={st.clusterNodesDenied}>
          <span className="lbl">nodes</span>
          <span className="val dim">—</span>
        </span>
      </div>
    );
  }

  return (
    <div className="cstats">
      <span className="cstat">
        <span className="lbl">nodes</span>
        <span className={`val tone-${banner.nodes.tone}`}>
          {banner.nodes.ready}/{banner.nodes.total}
        </span>
      </span>
      <Gauge label="CPU" resource={banner.cpu} noMetrics={st.clusterNoMetrics} />
      <Gauge label="MEM" resource={banner.mem} noMetrics={st.clusterNoMetrics} />
    </div>
  );
}

/** Une ressource et son occupation, ou son allocation seule quand l'usage n'est pas mesuré. */
function Gauge({
  label,
  resource,
  noMetrics,
}: {
  label: string;
  resource: ClusterResource | null;
  noMetrics: string;
}) {
  if (!resource) return null;

  // Sans metrics-server, l'allocation reste vraie et se dit seule : une jauge vide se lirait
  // comme un cluster au repos.
  if (resource.pct === null) {
    return (
      <span className="cstat" title={noMetrics}>
        <span className="lbl">{label}</span>
        <span className="val dim">{resource.alloc}</span>
      </span>
    );
  }

  return (
    <span className="cstat" title={`${resource.used} / ${resource.alloc}`}>
      <span className="lbl">{label}</span>
      <span className="track">
        <span
          className={`fill tone-${resource.tone}`}
          // Au-delà de 100 % la barre est pleine ; c'est le pourcentage à côté qui dit de combien
          // on dépasse, la barre ne saurait pas le montrer.
          style={{ width: `${Math.min(100, resource.pct)}%` }}
        />
      </span>
      <span className={`val tone-${resource.tone}`}>{resource.pct}%</span>
      {/* Les quantités, comme dans le bandeau du TUI : le pourcentage dit la tension, ces deux
          chiffres disent de quoi on parle — 9 % de quatre cœurs n'est pas 9 % de deux cents. */}
      <span className="sub">
        {resource.used}/{resource.alloc}
      </span>
    </span>
  );
}

/**
 * Choix de la portée : plusieurs namespaces, ou tout le cluster.
 *
 * La liste est proposée et se resserre à la frappe, plutôt que d'être devinée : un nom de
 * namespace se retient mal, et une faute de frappe rend une vue vide qu'on lit comme un cluster
 * vide. Ce que le TUI fait avec `n`, qui liste ce que le cluster sert.
 *
 * La saisie libre reste, et c'est la porte de sortie : lister les namespaces demande un droit
 * cluster-scoped que beaucoup n'ont pas tout en travaillant dans un namespace qu'ils nomment très
 * bien. Un refus laisse donc le champ utilisable, et dit pourquoi il ne propose rien.
 */
function ScopePicker({
  namespaces,
  available,
  error,
  loading,
  st,
  onChange,
  onClose,
}: {
  namespaces: string[];
  available: string[] | null;
  error: string | null;
  loading: boolean;
  st: Strings;
  onChange: (next: string[]) => void;
  onClose: () => void;
}) {
  const [draft, setDraft] = useState("");
  // La ligne que `Entrée` prendrait. Elle repart en tête à chaque frappe : après avoir tapé, ce
  // qu'on vise est la meilleure correspondance, pas la ligne où le curseur traînait.
  const [highlight, setHighlight] = useState(0);

  const query = draft.trim().toLowerCase();
  // Les namespaces choisis sont listés à part, en tête et hors filtre : c'est là qu'on les
  // retire, et une portée qu'on ne voit plus est une portée qu'on oublie.
  const matches = (available ?? [])
    .filter((ns) => !namespaces.includes(ns))
    .filter((ns) => !query || ns.toLowerCase().includes(query));
  const exact = matches.length > 0 ? matches[Math.min(highlight, matches.length - 1)] : null;
  // Ce que la saisie ajouterait telle quelle : un nom qui n'est pas proposé — parce que la liste
  // est refusée, ou parce qu'il vient d'être créé.
  const raw = draft.trim();
  const rawAddable = raw.length > 0 && !namespaces.includes(raw) && !matches.includes(raw);

  const toggle = (ns: string) => {
    onChange(namespaces.includes(ns) ? namespaces.filter((n) => n !== ns) : [...namespaces, ns]);
    setDraft("");
    setHighlight(0);
  };

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
          {st.scopeTitle}
        </button>
      </div>

      <input
        className="ns-add"
        value={draft}
        placeholder={st.nsSearch}
        autoFocus
        spellCheck={false}
        onChange={(e) => {
          setDraft(e.target.value);
          setHighlight(0);
        }}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") {
            e.preventDefault();
            setHighlight((h) => Math.min(h + 1, Math.max(matches.length - 1, 0)));
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setHighlight((h) => Math.max(h - 1, 0));
          } else if (e.key === "Enter") {
            // La ligne visée d'abord, la saisie brute ensuite : quand la liste répond, ce qu'on
            // ajoute est ce qui existe ; quand elle ne répond pas, ce qu'on a tapé.
            if (exact) toggle(exact);
            else if (rawAddable) toggle(raw);
          }
        }}
      />

      {error && <div className="ns-note warn">{st.nsDenied}</div>}
      {loading && available === null && <div className="ns-note">{st.nsLoading}</div>}

      <div className="ns-list">
        {namespaces.length === 0 && !rawAddable && matches.length === 0 && !loading && (
          <div className="ns-item flat">
            <span style={{ opacity: 0.6 }}>{st.scopeAll}</span>
          </div>
        )}

        {namespaces.map((ns) => (
          <button className="ns-item on" key={`on-${ns}`} onClick={() => toggle(ns)}>
            <span className="tick">✓</span>
            <span>{ns}</span>
            <span className="rm" aria-hidden="true">
              ✕
            </span>
          </button>
        ))}

        {matches.map((ns, i) => (
          <button
            className={`ns-item${ns === exact && i === Math.min(highlight, matches.length - 1) ? " hl" : ""}`}
            key={ns}
            onMouseEnter={() => setHighlight(i)}
            onClick={() => toggle(ns)}
          >
            <span className="tick" />
            <span>{ns}</span>
          </button>
        ))}

        {/* La sortie de secours, sous les propositions : `Entrée` vise la ligne en tête, donc
            l'ajout tel quel ne doit jamais s'y trouver quand le cluster propose mieux. Elle sert
            à un namespace qui vient d'être créé — ou à une liste qu'on n'a pas le droit de lire. */}
        {rawAddable && (
          <button className="ns-item raw" onClick={() => toggle(raw)}>
            <span className="tick">+</span>
            <span>{raw}</span>
            <span className="hint">{st.nsAdd}</span>
          </button>
        )}

        {!error && available !== null && matches.length === 0 && query !== "" && (
          <div className="ns-note">{st.nsNoMatch}</div>
        )}
      </div>
    </div>
  );
}
