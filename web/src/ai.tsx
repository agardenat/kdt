// Le `i` de kdt : envoyer ce qu'on regarde à un modèle, et lire son analyse.
//
// Dans le TUI c'est une touche et un overlay plein écran ; ici c'est la grammaire du web, celle
// des quatre autres gestes génériques (mémoire `gui-affordances-not-tui-keys`) : **le bouton vit
// dans la barre d'actions, la réponse dans le panneau du haut**, et l'onglet n'existe que tant
// qu'on le regarde.
//
// # Trois choses vivent ici
//
// * **Ce que le serveur offre** — ses fournisseurs, et s'il en accepte d'autres. Lu une fois, mis
//   en cache : le rail comme la barre d'actions ont besoin de savoir si le geste a un sens, et
//   trois vues ouvertes ne doivent pas poser trois fois la question.
// * **Les fournisseurs personnels**, gardés par le navigateur. C'est ce qui rend le réglage
//   possible depuis l'application sans que le serveur détienne la clé de qui que ce soit — comme
//   le fichier de configuration de kdt tient celle du TUI. Une clé dans le `localStorage` est
//   lisible par tout script qui s'exécuterait sur cette origine : le réglage le dit.
// * **L'analyse en cours**, dans un état de module et non dans la vue. Une analyse prend une
//   minute ; changer d'onglet ou de vue pendant qu'elle s'écrit ne doit pas la perdre, et c'est
//   exactement ce que kdt fait avec son `AiState` partagé.

import { useCallback, useEffect, useMemo, useState, useSyncExternalStore } from "react";
import * as api from "./api";
import { NeedsAuth } from "./api";
import { CopyButton } from "./copy";
import type { Lang, Strings } from "./i18n";
import type {
  AiConfigPayload,
  AiPersonalProvider,
  AiProviderChoice,
  EventRecord,
} from "./types";

// ---------------------------------------------------------------------------
// Ce que le serveur offre
// ---------------------------------------------------------------------------

let configPromise: Promise<AiConfigPayload | null> | null = null;

/** Lu une fois par session de navigateur : ce qu'un déploiement offre ne change pas sous les pieds. */
function loadConfig(): Promise<AiConfigPayload | null> {
  if (!configPromise) {
    configPromise = api.aiConfig().catch(() => null);
  }
  return configPromise;
}

export function useAiConfig(): AiConfigPayload | null {
  const [config, setConfig] = useState<AiConfigPayload | null>(null);
  useEffect(() => {
    let live = true;
    void loadConfig().then((c) => live && setConfig(c));
    return () => {
      live = false;
    };
  }, []);
  return config;
}

// ---------------------------------------------------------------------------
// Les fournisseurs personnels, et celui qui est actif
// ---------------------------------------------------------------------------

const PROVIDERS_KEY = "kdt-ai-providers";
const ACTIVE_KEY = "kdt-ai-active";

/** Le fournisseur retenu, nommé par son monde : le même nom peut exister des deux côtés. */
export type ActiveProvider = { kind: "server"; name: string } | { kind: "custom"; id: string };

// Le contenu lu, gardé jusqu'à la prochaine écriture. Sans ce cache, chaque rendu rendrait un
// tableau neuf : les `useMemo` qui en dépendent ne mémoïseraient plus rien, et l'effet qui lance
// l'analyse se redéclencherait à chaque rendu.
let personalCache: AiPersonalProvider[] | null = null;
let activeCache: { value: ActiveProvider | null } | null = null;

function readPersonal(): AiPersonalProvider[] {
  if (personalCache) return personalCache;
  personalCache = parsePersonal();
  return personalCache;
}

function parsePersonal(): AiPersonalProvider[] {
  try {
    const raw = localStorage.getItem(PROVIDERS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as AiPersonalProvider[]) : [];
  } catch {
    // Stockage bloqué ou contenu illisible : aucun fournisseur personnel, le réglage le montrera.
    return [];
  }
}

function readActive(): ActiveProvider | null {
  if (activeCache) return activeCache.value;
  try {
    const raw = localStorage.getItem(ACTIVE_KEY);
    activeCache = { value: raw ? (JSON.parse(raw) as ActiveProvider) : null };
  } catch {
    activeCache = { value: null };
  }
  return activeCache.value;
}

// Le réglage vit dans le navigateur mais s'affiche à plusieurs endroits — la barre d'actions, le
// panneau, la fenêtre de réglage. Un petit abonnement évite qu'ils divergent le temps d'un rendu.
const settingsListeners = new Set<() => void>();
let settingsVersion = 0;

function notifySettings() {
  personalCache = null;
  activeCache = null;
  settingsVersion += 1;
  settingsListeners.forEach((l) => l());
}

function subscribeSettings(listener: () => void) {
  settingsListeners.add(listener);
  return () => settingsListeners.delete(listener);
}

let settingsOpen = false;

/** Ouvre la fenêtre de réglage, d'où qu'on la demande. */
export function openAiSettings() {
  settingsOpen = true;
  notifySettings();
}

export function closeAiSettings() {
  settingsOpen = false;
  notifySettings();
}

/**
 * La fenêtre de réglage est unique et vit dans la coquille.
 *
 * Un état de module plutôt qu'une propriété : le bouton qui l'ouvre est dans la barre d'actions de
 * treize vues, et le faire descendre de `App` à travers chacune n'aurait rien appris à personne.
 */
export function useAiSettingsOpen(): boolean {
  useSyncExternalStore(
    subscribeSettings,
    () => settingsVersion,
    () => settingsVersion,
  );
  return settingsOpen;
}

export function useAiSettings() {
  useSyncExternalStore(
    subscribeSettings,
    () => settingsVersion,
    () => settingsVersion,
  );
  const personal = readPersonal();
  const active = readActive();

  const setPersonal = useCallback((next: AiPersonalProvider[]) => {
    try {
      localStorage.setItem(PROVIDERS_KEY, JSON.stringify(next));
    } catch {
      // Stockage refusé : le réglage ne survivra pas au rechargement, et c'est tout ce qu'on peut.
    }
    notifySettings();
  }, []);

  const setActive = useCallback((next: ActiveProvider) => {
    try {
      localStorage.setItem(ACTIVE_KEY, JSON.stringify(next));
    } catch {
      // idem : le choix vaut pour cette page.
    }
    notifySettings();
  }, []);

  return { personal, active, setPersonal, setActive };
}

/**
 * Le fournisseur que la prochaine analyse doit viser.
 *
 * Celui qui a été retenu s'il existe encore — un fournisseur supprimé côté serveur, ou effacé du
 * navigateur, ne doit pas faire échouer le geste — sinon le premier qui se présente.
 */
export function resolveActive(
  config: AiConfigPayload | null,
  personal: AiPersonalProvider[],
  active: ActiveProvider | null,
): ActiveProvider | null {
  if (active?.kind === "server" && config?.providers.some((p) => p.name === active.name)) {
    return active;
  }
  if (active?.kind === "custom" && personal.some((p) => p.id === active.id)) {
    return config?.allow_custom === false ? null : active;
  }
  if (config?.providers.length) return { kind: "server", name: config.providers[0].name };
  if (config?.allow_custom && personal.length) return { kind: "custom", id: personal[0].id };
  return null;
}

/**
 * Le fournisseur que la prochaine analyse doit viser, prêt à partir.
 *
 * Passe par [`resolveActive`] pour que le réglage montre coché **ce qui servirait vraiment** : une
 * retombée silencieuse sur le premier fournisseur ferait un formulaire où rien n'est choisi et une
 * analyse qui part quand même.
 */
export function resolveProvider(
  config: AiConfigPayload | null,
  personal: AiPersonalProvider[],
  active: ActiveProvider | null,
): AiProviderChoice | null {
  const effective = resolveActive(config, personal, active);
  if (!effective) return null;
  if (effective.kind === "server") return { source: "server", name: effective.name };
  const found = personal.find((p) => p.id === effective.id);
  return found ? asChoice(found) : null;
}

function asChoice(p: AiPersonalProvider): AiProviderChoice {
  return {
    source: "custom",
    base_url: p.base_url,
    model: p.model,
    api_key: p.api_key,
    context_window: p.context_window,
  };
}

/** Le geste a-t-il un sens sur ce déploiement : un fournisseur, ou de quoi en déclarer un. */
export function useAiAvailable(): boolean {
  const config = useAiConfig();
  const { personal } = useAiSettings();
  if (!config) return false;
  return config.providers.length > 0 || (config.allow_custom && personal.length > 0);
}

// ---------------------------------------------------------------------------
// L'analyse en cours
// ---------------------------------------------------------------------------

export interface AnalysisState {
  /** L'objet analysé, tel qu'on le renomme dans l'en-tête. `null` : aucune analyse. */
  key: string | null;
  target: string;
  status: "running" | "done" | "error";
  stage: string;
  content: string;
  error: string | null;
  provider: string;
  model: string;
  startedAt: number;
  endedAt: number | null;
  needsAuth: string | null;
}

const EMPTY: AnalysisState = {
  key: null,
  target: "",
  status: "done",
  stage: "",
  content: "",
  error: null,
  provider: "",
  model: "",
  startedAt: 0,
  endedAt: null,
  needsAuth: null,
};

let state: AnalysisState = EMPTY;
let controller: AbortController | null = null;
const listeners = new Set<() => void>();

function set(patch: Partial<AnalysisState>) {
  state = { ...state, ...patch };
  listeners.forEach((l) => l());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function useAnalysis(): AnalysisState {
  return useSyncExternalStore(
    subscribe,
    () => state,
    () => state,
  );
}

/** Ce qui identifie une analyse : l'objet **et** l'instant de l'évènement, comme la clé de kdt. */
export function analysisKey(record: EventRecord): string {
  return `${record.uid}/${record.time}`;
}

/**
 * Lance l'analyse et remplace celle qui courait.
 *
 * Une seule à la fois, comme dans kdt où une nouvelle demande écrase la précédente : deux analyses
 * en parallèle coûteraient deux fois et ne se liraient qu'une.
 */
export function startAnalysis(
  record: EventRecord,
  provider: AiProviderChoice,
  lang: Lang,
): void {
  controller?.abort();
  const key = analysisKey(record);
  const mine = new AbortController();
  controller = mine;

  set({
    key,
    target: record.namespace ? `${record.kind} ${record.namespace}/${record.name}` : `${record.kind} ${record.name}`,
    status: "running",
    stage: "",
    content: "",
    error: null,
    provider: provider.source === "server" ? provider.name : provider.model,
    model: provider.source === "server" ? "" : provider.model,
    startedAt: Date.now(),
    endedAt: null,
    needsAuth: null,
  });

  void api
    .aiAnalyze(
      { record, provider, lang },
      (event) => {
        // Une réponse arrivée après un abandon appartient à une analyse qu'on ne regarde plus.
        if (mine.signal.aborted || state.key !== key) return;
        switch (event.type) {
          case "meta":
            set({ provider: event.data.provider ?? state.provider, model: event.data.model ?? "" });
            break;
          case "stage":
            set({ stage: event.data.text ?? "" });
            break;
          case "delta":
            set({ stage: "", content: state.content + (event.data.text ?? "") });
            break;
          case "error":
            set({ status: "error", error: event.data.error ?? "", endedAt: Date.now() });
            break;
          case "done":
            set({ status: "done", stage: "", endedAt: Date.now() });
            break;
        }
      },
      mine.signal,
    )
    .then(() => {
      if (mine.signal.aborted || state.key !== key) return;
      // Le flux s'est refermé sans `done` ni `error` : la réponse est ce qui est arrivé.
      if (state.status === "running") set({ status: "done", stage: "", endedAt: Date.now() });
    })
    .catch((e: unknown) => {
      if (mine.signal.aborted || state.key !== key) return;
      if (e instanceof NeedsAuth) {
        set({ status: "error", needsAuth: e.message, error: e.message, endedAt: Date.now() });
      } else {
        set({ status: "error", error: String((e as Error).message ?? e), endedAt: Date.now() });
      }
    });
}

export function stopAnalysis(): void {
  controller?.abort();
  controller = null;
  if (state.status === "running") set({ status: "done", stage: "", endedAt: Date.now() });
}

// ---------------------------------------------------------------------------
// Le bouton, dans la barre d'actions de toutes les vues
// ---------------------------------------------------------------------------

/**
 * Le geste, posé à côté des quatre autres.
 *
 * Éteint tant qu'aucun fournisseur n'est configuré, et il dit alors où le configurer : un bouton
 * qui ne fait rien fait chercher la panne ailleurs.
 */
export function AiButton({
  usable,
  st,
  onOpen,
}: {
  usable: boolean;
  st: Strings;
  onOpen: () => void;
}) {
  const available = useAiAvailable();
  const config = useAiConfig();

  if (config && !available) {
    return (
      <button className="panel-toggle" title={st.aiNoProviderHelp} onClick={openAiSettings}>
        {st.actionAi}
      </button>
    );
  }
  return (
    <button
      className="panel-toggle ai"
      disabled={!usable || !available}
      title={usable ? st.aiHelp : st.objSelectRow}
      onClick={onOpen}
    >
      {st.actionAi}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Le panneau
// ---------------------------------------------------------------------------

/**
 * L'analyse de la ligne visée, dans le panneau du haut.
 *
 * Elle part toute seule à l'ouverture — c'est ce que fait `i` dans kdt — mais **jamais deux fois
 * pour la même ligne** : revenir sur l'onglet montre ce qui a déjà été écrit plutôt que de
 * rappeler le modèle, qui coûte et qui répondrait autre chose.
 */
export function AiPane({
  record,
  lang,
  st,
  onNeedsAuth,
}: {
  record: EventRecord;
  lang: Lang;
  st: Strings;
  onNeedsAuth: (message: string) => void;
}) {
  const analysis = useAnalysis();
  const config = useAiConfig();
  const { personal, active, setActive } = useAiSettings();
  const key = analysisKey(record);
  const mine = analysis.key === key;

  const choice = useMemo(
    () => resolveProvider(config, personal, active),
    [config, personal, active],
  );

  const launch = useCallback(() => {
    if (!choice) return;
    startAnalysis(record, choice, lang);
  }, [choice, record, lang]);

  // La première ouverture sur une ligne lance l'analyse ; les suivantes la relisent.
  useEffect(() => {
    if (mine || !choice) return;
    startAnalysis(record, choice, lang);
    // `lang` volontairement hors des dépendances : changer de langue ne relance pas une analyse
    // déjà payée, c'est le bouton qui le fait.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, choice]);

  useEffect(() => {
    if (mine && analysis.needsAuth) onNeedsAuth(analysis.needsAuth);
  }, [mine, analysis.needsAuth, onNeedsAuth]);

  const running = mine && analysis.status === "running";
  const options = useMemo(() => {
    const rows: Array<{ value: string; label: string }> = [];
    for (const p of config?.providers ?? []) {
      rows.push({ value: `server:${p.name}`, label: `${p.name} · ${p.model}` });
    }
    if (config?.allow_custom) {
      for (const p of personal) {
        rows.push({ value: `custom:${p.id}`, label: `${p.name} · ${p.model}` });
      }
    }
    return rows;
  }, [config, personal]);

  const effective = resolveActive(config, personal, active);
  const selected =
    effective?.kind === "server"
      ? `server:${effective.name}`
      : effective?.kind === "custom"
        ? `custom:${effective.id}`
        : (options[0]?.value ?? "");

  if (!choice) {
    return (
      <div className="pane-wait">
        <p>{st.aiNoProvider}</p>
        <button className="panel-toggle" onClick={openAiSettings}>
          {st.aiSettings}
        </button>
      </div>
    );
  }

  return (
    <div className="aipane">
      <div className="logbar">
        <select
          value={selected}
          onChange={(e) => {
            const [kind, ...rest] = e.target.value.split(":");
            const id = rest.join(":");
            setActive(kind === "server" ? { kind: "server", name: id } : { kind: "custom", id });
          }}
        >
          {options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        <button className="panel-toggle" onClick={running ? stopAnalysis : launch}>
          {running ? st.aiStop : st.aiRerun}
        </button>
        <button className="panel-toggle" onClick={openAiSettings}>
          {st.aiSettings}
        </button>
        {mine && analysis.model && <span className="dim">{analysis.model}</span>}
        {mine && analysis.endedAt && (
          <span className="dim">
            {st.aiElapsed.replace(
              "{s}",
              String(Math.max(1, Math.round((analysis.endedAt - analysis.startedAt) / 1000))),
            )}
          </span>
        )}
        {mine && analysis.content && (
          <CopyButton text={analysis.content} label={st.secCopy} done={st.secCopied} />
        )}
      </div>

      {/* Ce qui est à l'écran peut porter sur une autre ligne : l'analyse survit au changement de
          sélection, et le taire ferait lire un diagnostic pour le mauvais objet. */}
      {mine ? null : analysis.key ? (
        <p className="pane-warn">{st.aiOtherTarget.replace("{target}", analysis.target)}</p>
      ) : null}

      {mine && analysis.error && <p className="pane-err">{analysis.error}</p>}
      {mine && running && !analysis.content && (
        <p className="pane-wait">{analysis.stage || st.aiWorking}</p>
      )}
      {analysis.content && <Markdown text={analysis.content} st={st} />}
      {mine && !running && !analysis.content && !analysis.error && (
        <p className="pane-wait">{st.aiEmptyAnswer}</p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Le réglage
// ---------------------------------------------------------------------------

/**
 * La fenêtre de réglage, ouverte depuis la barre du haut.
 *
 * Deux mondes s'y lisent sans se confondre : ce que le serveur offre — nommé, sans clé, et qu'on
 * ne peut que choisir — et ce que ce navigateur garde, qu'on écrit et qu'on efface. Ce qui part
 * vers l'endpoint est dit là, en une phrase : c'est le moment où la question se pose.
 */
export function AiSettings({ st }: { st: Strings }) {
  const onClose = closeAiSettings;
  const config = useAiConfig();
  const { personal, active, setPersonal, setActive } = useAiSettings();
  // Ce qui est coché est ce qui servirait, pas seulement ce qui a été cliqué un jour : sans
  // sélection explicite, l'analyse part vers le premier fournisseur, et le réglage doit le dire.
  const effective = resolveActive(config, personal, active);
  const [draft, setDraft] = useState<AiPersonalProvider | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [onClose]);

  const save = () => {
    if (!draft) return;
    const clean: AiPersonalProvider = {
      ...draft,
      name: draft.name.trim() || draft.model.trim(),
      base_url: draft.base_url.trim().replace(/\/$/, ""),
      model: draft.model.trim(),
      api_key: draft.api_key.trim(),
    };
    if (!clean.base_url || !clean.model || !clean.api_key) return;
    const next = personal.some((p) => p.id === clean.id)
      ? personal.map((p) => (p.id === clean.id ? clean : p))
      : [...personal, clean];
    setPersonal(next);
    setActive({ kind: "custom", id: clean.id });
    setDraft(null);
  };

  return (
    <div
      className="modal"
      role="dialog"
      aria-modal="true"
      aria-label={st.aiSettings}
      // Le clic à côté referme, comme les menus des vues. Le test porte sur la cible : un clic
      // dans la fenêtre remonte jusqu'ici, et refermerait sur chaque champ saisi.
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="modal-box">
        <div className="modal-hd">
          <h2>{st.aiSettings}</h2>
          <button className="pclose" onClick={onClose} aria-label={st.aiClose}>
            ✕
          </button>
        </div>

        <p className="modal-note">{st.aiPrivacy}</p>

        <h3>{st.aiServerProviders}</h3>
        {!config ? (
          <p className="pane-wait">…</p>
        ) : config.providers.length === 0 ? (
          <p className="dim">{st.aiNoServerProvider}</p>
        ) : (
          <ul className="ai-list">
            {config.providers.map((p) => (
              <li key={p.name}>
                <label>
                  <input
                    type="radio"
                    name="ai-provider"
                    checked={effective?.kind === "server" && effective.name === p.name}
                    onChange={() => setActive({ kind: "server", name: p.name })}
                  />
                  <span className="mono">{p.name}</span>
                  <span className="dim">{p.model}</span>
                  <span className="dim">{p.host}</span>
                </label>
              </li>
            ))}
          </ul>
        )}

        <h3>{st.aiPersonalProviders}</h3>
        {config && !config.allow_custom ? (
          <p className="dim">{st.aiCustomRefused}</p>
        ) : (
          <>
            <p className="modal-note">{st.aiKeyStorage}</p>
            <ul className="ai-list">
              {personal.map((p) => (
                <li key={p.id}>
                  <label>
                    <input
                      type="radio"
                      name="ai-provider"
                      checked={effective?.kind === "custom" && effective.id === p.id}
                      onChange={() => setActive({ kind: "custom", id: p.id })}
                    />
                    <span className="mono">{p.name}</span>
                    <span className="dim">{p.model}</span>
                    <span className="dim">{hostOf(p.base_url)}</span>
                  </label>
                  <span className="ai-row-actions">
                    <button className="panel-toggle" onClick={() => setDraft({ ...p })}>
                      {st.aiEdit}
                    </button>
                    <button
                      className="panel-toggle action"
                      onClick={() => setPersonal(personal.filter((q) => q.id !== p.id))}
                    >
                      {st.aiForget}
                    </button>
                  </span>
                </li>
              ))}
            </ul>

            {draft ? (
              <div className="ai-form">
                <label>
                  {st.aiName}
                  <input
                    value={draft.name}
                    placeholder="openai"
                    onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                  />
                </label>
                <label>
                  {st.aiBaseUrl}
                  <input
                    value={draft.base_url}
                    placeholder="https://api.openai.com/v1"
                    onChange={(e) => setDraft({ ...draft, base_url: e.target.value })}
                  />
                </label>
                <label>
                  {st.aiModel}
                  <input
                    value={draft.model}
                    placeholder="gpt-4o-mini"
                    onChange={(e) => setDraft({ ...draft, model: e.target.value })}
                  />
                </label>
                <label>
                  {st.aiApiKey}
                  <input
                    type="password"
                    value={draft.api_key}
                    autoComplete="off"
                    onChange={(e) => setDraft({ ...draft, api_key: e.target.value })}
                  />
                </label>
                <label>
                  {st.aiContextWindow}
                  <input
                    inputMode="numeric"
                    value={draft.context_window ?? ""}
                    placeholder="128000"
                    onChange={(e) =>
                      setDraft({
                        ...draft,
                        context_window: e.target.value ? Number(e.target.value) : null,
                      })
                    }
                  />
                </label>
                <p className="modal-note">{st.aiContextHelp}</p>
                <div className="ai-form-actions">
                  <button className="panel-toggle" onClick={() => setDraft(null)}>
                    {st.aiCancel}
                  </button>
                  <button className="cta" onClick={save}>
                    {st.aiSave}
                  </button>
                </div>
              </div>
            ) : (
              <button
                className="panel-toggle"
                onClick={() =>
                  setDraft({
                    id: `p${Date.now().toString(36)}`,
                    name: "",
                    base_url: "https://api.openai.com/v1",
                    model: "",
                    api_key: "",
                    context_window: null,
                  })
                }
              >
                {st.aiAdd}
              </button>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

// ---------------------------------------------------------------------------
// Le rendu markdown
// ---------------------------------------------------------------------------

/**
 * Le markdown que les modèles écrivent, réduit à ce qu'ils écrivent vraiment.
 *
 * kdt en fait autant côté terminal : titres, listes, blocs de code et emphase, rien d'autre. Le
 * texte est posé dans des nœuds React, jamais dans du HTML : ce qui vient d'un modèle qui a lu des
 * logs du cluster n'est pas du balisage de confiance.
 *
 * Les commandes sont le cœur de la réponse — la règle du prompt de kdt est qu'aucune action ne va
 * sans sa commande — donc chaque bloc porte son bouton de copie.
 */
function Markdown({ text, st }: { text: string; st: Strings }) {
  const blocks = useMemo(() => parseMarkdown(text), [text]);
  return (
    <div className="ai-md">
      {blocks.map((block, i) => {
        if (block.kind === "code") {
          return (
            <div className="ai-code" key={i}>
              <div className="ai-code-hd">
                <span className="dim">{block.lang || "sh"}</span>
                <CopyButton text={block.text} label={st.secCopy} done={st.secCopied} />
              </div>
              <pre>{block.text}</pre>
            </div>
          );
        }
        if (block.kind === "heading") {
          const Tag = (block.level <= 2 ? "h3" : "h4") as "h3" | "h4";
          return <Tag key={i}>{inline(block.text)}</Tag>;
        }
        if (block.kind === "list") {
          return (
            <ul key={i}>
              {block.items.map((item, j) => (
                <li key={j}>{inline(item)}</li>
              ))}
            </ul>
          );
        }
        return <p key={i}>{inline(block.text)}</p>;
      })}
    </div>
  );
}

type Block =
  | { kind: "code"; lang: string; text: string }
  | { kind: "heading"; level: number; text: string }
  | { kind: "list"; items: string[] }
  | { kind: "para"; text: string };

function parseMarkdown(text: string): Block[] {
  const blocks: Block[] = [];
  const lines = text.split("\n");
  let para: string[] = [];
  let items: string[] = [];

  const flush = () => {
    if (para.length) {
      blocks.push({ kind: "para", text: para.join("\n") });
      para = [];
    }
    if (items.length) {
      blocks.push({ kind: "list", items });
      items = [];
    }
  };

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const fence = line.match(/^\s*```(\w*)/);
    if (fence) {
      flush();
      const body: string[] = [];
      i += 1;
      while (i < lines.length && !/^\s*```/.test(lines[i])) {
        body.push(lines[i]);
        i += 1;
      }
      blocks.push({ kind: "code", lang: fence[1], text: body.join("\n") });
      continue;
    }
    const heading = line.match(/^(#{1,6})\s+(.*)$/);
    if (heading) {
      flush();
      blocks.push({ kind: "heading", level: heading[1].length, text: heading[2] });
      continue;
    }
    const bullet = line.match(/^\s*(?:[-*]|\d+[.)])\s+(.*)$/);
    if (bullet) {
      if (para.length) flush();
      items.push(bullet[1]);
      continue;
    }
    if (!line.trim()) {
      flush();
      continue;
    }
    if (items.length) flush();
    para.push(line);
  }
  flush();
  return blocks;
}

/** Le code inline et le gras, les deux seules marques qui changent la lecture d'un diagnostic. */
function inline(text: string) {
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
  return parts.map((part, i) => {
    if (part.startsWith("`") && part.endsWith("`") && part.length > 1) {
      return (
        <code key={i} className="mono">
          {part.slice(1, -1)}
        </code>
      );
    }
    if (part.startsWith("**") && part.endsWith("**") && part.length > 3) {
      return <strong key={i}>{part.slice(2, -2)}</strong>;
    }
    return <span key={i}>{part}</span>;
  });
}
