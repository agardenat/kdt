// Les cinq gestes que kdt porte sur **n'importe quel** objet : lire son YAML, l'éditer, le
// toucher, le supprimer, et l'envoyer à l'IA.
//
// Dans le TUI ce sont cinq touches — `y`, `e`, `h`, `Ctrl-D`, `i` — disponibles dans toutes les vues
// parce qu'elles visent l'objet Kubernetes derrière la ligne, pas la ligne. Ici c'est la même chose,
// dans la grammaire du web (mémoire `gui-affordances-not-tui-keys`) : **les actions vivent dans la
// barre qui sépare les deux panneaux, et ce qu'elles ouvrent s'affiche dans le panneau du haut.**
//
// `Toucher` est le seul qui écrive sans rien ouvrir, et c'est déjà le cas dans kdt : deux
// annotations sous `kdt.io/` s'ajoutent, rien n'est retiré, et l'intérêt de la touche est d'être
// assez rapide pour parcourir une liste avec. L'accusé se lit à côté du bouton.
//
// `Supprimer` fait l'inverse et ouvre tout : les garde-fous d'abord, la confirmation ensuite. La
// sortie par défaut est celle qui ne supprime rien — dans le TUI `Entrée` annule et c'est `Ctrl-D`
// qui affirme ; ici c'est le bouton d'annulation qui prend le focus, et celui qui supprime est une
// cible distincte qu'il faut aller chercher.

import { useCallback, useEffect, useState } from "react";
import * as api from "./api";
import { NeedsAuth } from "./api";
import { AiButton } from "./ai";
import type { Lang, Strings } from "./i18n";
import { CopyButton } from "./copy";
import type {
  DeletePreflight,
  DeleteReason,
  EditDiff,
  EditPreflight,
  EditReason,
  EventRecord,
  ObjectYaml,
} from "./types";

/** L'onglet du panneau qu'un bouton de la barre ouvre. */
export type ObjectTab = "yaml" | "edit" | "delete" | "ai";

/**
 * Les boutons, posés dans la barre des onglets de la vue.
 *
 * Ils portent sur la ligne sélectionnée. Sans sélection ils sont éteints et le disent : proposer un
 * geste qui n'a pas de cible ferait chercher pourquoi il ne se passe rien.
 */
export function ObjectActions({
  record,
  lang,
  st,
  onOpen,
  onNeedsAuth,
}: {
  record: EventRecord | null;
  lang: Lang;
  st: Strings;
  onOpen: (tab: ObjectTab) => void;
  onNeedsAuth: (message: string) => void;
}) {
  const [ack, setAck] = useState<{ tone: "ok" | "err"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  // L'accusé s'efface tout seul : c'est un accusé de réception, pas un état de l'objet.
  useEffect(() => {
    if (!ack) return;
    const timer = window.setTimeout(() => setAck(null), 8000);
    return () => window.clearTimeout(timer);
  }, [ack]);

  // La cible change : l'accusé précédent ne parle plus de ce qui est sous les yeux.
  useEffect(() => setAck(null), [record?.uid]);

  // Un enregistrement sans kind ni nom ne désigne aucun objet — une ligne de regroupement, par
  // exemple. Les trois gestes n'ont alors rien à viser.
  const usable = Boolean(record && record.kind && record.name);

  const touch = useCallback(async () => {
    if (!record) return;
    setBusy(true);
    try {
      const { message } = await api.objectTouch(record, lang);
      setAck({ tone: "ok", text: message });
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else setAck({ tone: "err", text: String((e as Error).message ?? e) });
    } finally {
      setBusy(false);
    }
  }, [record, lang, onNeedsAuth]);

  return (
    <div className="obj-actions" role="group" aria-label={st.objActions}>
      <button
        className="panel-toggle"
        disabled={!usable}
        title={usable ? undefined : st.objSelectRow}
        onClick={() => onOpen("yaml")}
      >
        {st.actionYaml}
      </button>
      <button
        className="panel-toggle"
        disabled={!usable}
        title={usable ? undefined : st.objSelectRow}
        onClick={() => onOpen("edit")}
      >
        {st.actionEdit}
      </button>
      <button
        className="panel-toggle"
        disabled={!usable || busy}
        title={usable ? st.objTouchHelp : st.objSelectRow}
        onClick={() => void touch()}
      >
        {st.actionTouch}
      </button>
      {/* Il n'écrit rien tout seul : il ouvre les garde-fous dans le panneau du haut, et c'est là
          que la confirmation se donne. Le bouton porte quand même le ton d'une action sur le
          cluster — une commande éteinte se cherche. */}
      <button
        className="panel-toggle action"
        disabled={!usable}
        title={usable ? undefined : st.objSelectRow}
        onClick={() => onOpen("delete")}
      >
        {st.actionDelete}
      </button>
      {/* Le geste `i` de kdt. Dernier de la barre et non premier : c'est celui qui fait sortir de
          la donnée du cluster, et il se prend délibérément. */}
      <AiButton usable={usable} st={st} onOpen={() => onOpen("ai")} />
      {busy && <span className="dim">{st.objWorking}</span>}
      {ack && <span className={ack.tone === "err" ? "err" : "ok"}>{ack.text}</span>}
    </div>
  );
}

/**
 * Le YAML de l'objet, dans les deux rendus de l'overlay `y` du TUI.
 *
 * `brut` est ce que l'apiserver donne ; `net` est le même document débarrassé de ce que le runtime
 * y a ajouté — métadonnées de bookkeeping, `status`, valeurs par défaut d'un pod spec. C'est ce
 * second qui se recolle dans un dépôt, et c'est pour ça qu'il existe.
 */
export function YamlPane({
  record,
  lang,
  st,
}: {
  record: EventRecord;
  lang: Lang;
  st: Strings;
}) {
  const [doc, setDoc] = useState<ObjectYaml | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [neat, setNeat] = useState(true);

  useEffect(() => {
    let live = true;
    setDoc(null);
    setError(null);
    api
      .objectYaml(record)
      .then((r) => live && setDoc(r))
      .catch((e) => live && setError(String((e as Error).message ?? e)));
    return () => {
      live = false;
    };
  }, [record]);

  if (error) return <p className="pane-err">{error}</p>;
  if (!doc) return <p className="pane-wait">{lang === "fr" ? "Lecture…" : "Reading…"}</p>;

  const text = neat ? doc.neat : doc.raw;
  return (
    <>
      <div className="logbar">
        <div className="segmented" role="group">
          <button aria-pressed={neat} onClick={() => setNeat(true)}>
            {st.objYamlNeat}
          </button>
          <button aria-pressed={!neat} onClick={() => setNeat(false)}>
            {st.objYamlRaw}
          </button>
        </div>
        <CopyButton text={text} label={st.secCopy} done={st.secCopied} />
      </div>
      <pre className="logs">{text}</pre>
    </>
  );
}

/**
 * L'édition, avec les garde-fous de kdt et son tri des changements.
 *
 * Deux temps, comme dans le TUI : les raisons de réfléchir arrivent **avant** que le document
 * s'ouvre — un objet appliqué par Flux sera remis en place à la réconciliation suivante — et le tri
 * des changements arrive **avant** l'écriture. Aucun des deux ne bloque : ils disent ce qui va se
 * passer, et la sortie par défaut reste celle qui n'écrit rien.
 */
export function EditPane({
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
  const [preflight, setPreflight] = useState<EditPreflight | null>(null);
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [diff, setDiff] = useState<EditDiff | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<string | null>(null);

  const load = useCallback(async () => {
    setPreflight(null);
    setDiff(null);
    setDone(null);
    setError(null);
    try {
      const payload = await api.objectEdit(record, lang);
      setPreflight(payload);
      setText(payload.text);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else setError(String((e as Error).message ?? e));
    }
  }, [record, lang, onNeedsAuth]);

  useEffect(() => {
    void load();
  }, [load]);

  const ask = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      setDiff(await api.objectDiff(record, text, lang));
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else setError(String((e as Error).message ?? e));
    } finally {
      setBusy(false);
    }
  }, [record, text, lang, onNeedsAuth]);

  const write = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const { message } = await api.objectApply(record, text, lang);
      setDone(message);
      setDiff(null);
      // Relire : l'objet a un nouveau `resourceVersion`, et éditer à partir de l'ancien document se
      // ferait refuser par l'apiserver sans qu'on comprenne pourquoi.
      void load();
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else setError(String((e as Error).message ?? e));
    } finally {
      setBusy(false);
    }
  }, [record, text, lang, load, onNeedsAuth]);

  if (error && !preflight) return <p className="pane-err">{error}</p>;
  if (!preflight) return <p className="pane-wait">{lang === "fr" ? "Lecture…" : "Reading…"}</p>;

  return (
    <div className="editor">
      {preflight.reasons.length > 0 && (
        <div className="guards">
          <div className="sect">{st.objEditGuards}</div>
          {preflight.reasons.map((r) => (
            <Guard key={r.text} reason={r} />
          ))}
        </div>
      )}

      <div className="logbar">
        {/* Les deux commandes de la barre portent les classes de l'interface, et pas seulement un
            libellé : un bouton sans style hérite du fond clair du navigateur et de la couleur de
            texte du panneau — donc du gris clair sur du blanc, illisible en thème sombre.
            `Appliquer` mène à une écriture, donc l'accent ; `Recharger` ne fait que relire. */}
        <button
          className="panel-toggle action"
          disabled={busy}
          onClick={() => void ask()}
        >
          {st.objEditApply}
        </button>
        <button className="panel-toggle" disabled={busy} onClick={() => void load()}>
          {st.objEditReload}
        </button>
        {busy && <span className="dim">{st.objWorking}</span>}
        {done && <span className="ok">{done}</span>}
        {!diff && !done && <span className="dim">{st.objEditReadOnlyHint}</span>}
      </div>

      {error && <p className="pane-err">{error}</p>}

      {diff && (
        <div className="diff">
          <div className="sect">{st.objEditChanges}</div>
          {diff.empty ? (
            <p className="pane-wait">{st.objEditNoChange}</p>
          ) : (
            <>
              <ul className="paths">
                {diff.paths.map((p) => (
                  <li key={p} className={pathTone(p, diff)}>
                    <span className="mono">{p}</span>
                    {diff.identity.includes(p) && <span className="badge err">{st.objEditIdentity}</span>}
                    {diff.immutable.includes(p) && (
                      <span className="badge err">{st.objEditImmutable}</span>
                    )}
                    {diff.server_owned.includes(p) && (
                      <span className="badge">{st.objEditServerOwned}</span>
                    )}
                  </li>
                ))}
              </ul>
              {diff.noop && <p className="warn">{st.objEditNoop}</p>}
            </>
          )}
          <div className="menu-buttons">
            {/* La sortie par défaut est celle qui n'écrit rien. */}
            <button autoFocus onClick={() => setDiff(null)}>
              {st.objEditCancel}
            </button>
            <button className="cta" disabled={busy || diff.empty} onClick={() => void write()}>
              {st.objEditConfirm}
            </button>
          </div>
        </div>
      )}

      <textarea
        className="yaml-edit"
        spellCheck={false}
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          // Le tri affiché portait sur le texte d'avant : le garder à l'écran ferait confirmer un
          // changement qui n'est plus celui-là.
          setDiff(null);
        }}
      />
    </div>
  );
}

/** Un garde-fou, peint par son niveau. Aucun ne bloque : ils disent ce qui va se passer. */
function Guard({ reason }: { reason: EditReason }) {
  const glyph = reason.level === "danger" ? "✗" : reason.level === "warn" ? "▲" : "·";
  return (
    <p className={`guard ${reason.level}`}>
      <span className="gl">{glyph}</span> {reason.text}
    </p>
  );
}

/** Le ton d'un chemin modifié : refusé, ignoré, ou simplement changé. */
function pathTone(path: string, diff: EditDiff): string {
  if (diff.identity.includes(path) || diff.immutable.includes(path)) return "err";
  if (diff.server_owned.includes(path)) return "dim";
  return "";
}


/**
 * La suppression, avec les garde-fous de kdt et sa confirmation à deux vitesses.
 *
 * Rien n'est retiré avant que l'objet ait été lu et inspecté pour les raisons qui font d'une
 * suppression une erreur — au premier rang desquelles être déployé par un moteur GitOps, où le
 * controller remet en place ce qu'on a enlevé. Aucun constat ne bloque : ils décident **combien**
 * la confirmation coûte, exactement comme dans le TUI.
 *
 * Deux règles reprises telles quelles de kdt, et une transposée :
 *
 * - **la sortie par défaut ne supprime rien** — c'est le bouton d'annulation qui a le focus, et le
 *   bouton destructeur est une cible séparée qu'il faut viser ;
 * - **un constat grave, ou une vérification qui n'a pas conclu, exige de retaper le nom** — et le
 *   serveur le revérifie, parce qu'un garde-fou qui ne vit que dans la page se contourne ;
 * - la transposition : le TUI distingue « armer » et « confirmer » avec deux touches faute de
 *   mieux. Ici les deux issues sont deux boutons visibles côte à côte, ce qui rend le geste
 *   volontaire par construction sans rien à apprendre.
 */
export function DeletePane({
  record,
  lang,
  st,
  onCancel,
  onDeleted,
  onNeedsAuth,
}: {
  record: EventRecord;
  lang: Lang;
  st: Strings;
  onCancel: () => void;
  onDeleted?: (message: string) => void;
  onNeedsAuth: (message: string) => void;
}) {
  const [preflight, setPreflight] = useState<DeletePreflight | null>(null);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  const load = useCallback(async () => {
    setPreflight(null);
    setError(null);
    setDone(null);
    setTyped("");
    try {
      setPreflight(await api.objectDeletePreflight(record, lang));
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else setError(String((e as Error).message ?? e));
    }
  }, [record, lang, onNeedsAuth]);

  useEffect(() => {
    void load();
  }, [load]);

  const remove = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const { message } = await api.objectDelete(record, typed, lang);
      setDone(message);
      onDeleted?.(message);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else setError(String((e as Error).message ?? e));
    } finally {
      setBusy(false);
    }
  }, [record, typed, lang, onDeleted, onNeedsAuth]);

  if (error && !preflight) return <p className="pane-err">{error}</p>;
  if (!preflight) return <p className="pane-wait">{st.delChecking}</p>;

  const strict = preflight.strict;
  const matches = typed.trim() === record.name;

  return (
    <div className="editor">
      <div className="guards">
        <div className="sect">{st.delTarget}</div>
        <p className="mono">
          {record.kind} {record.namespace ? `${record.namespace}/${record.name}` : record.name}
        </p>
      </div>

      <div className="guards">
        <div className="sect">{st.delTitle}</div>
        {/* Une vérification qui n'a pas pu conclure n'est pas un feu vert : elle se dit, et elle
            fait passer la confirmation en mode strict. */}
        {preflight.error && <p className="guard danger">{preflight.error}</p>}
        {preflight.clear && <p className="guard info">{preflight.clear}</p>}
        {preflight.reasons.map((r) => (
          <Finding key={r.text} reason={r} />
        ))}
        {preflight.reasons.length > 0 && <p className="dim">{st.delHelp}</p>}
      </div>

      {error && <p className="pane-err">{error}</p>}
      {done ? (
        <p className="ok">{done}</p>
      ) : (
        <div className="delete-confirm">
          {strict && (
            <>
              <p className="warn">{st.delStrictHelp}</p>
              <input
                className="ns-add"
                value={typed}
                spellCheck={false}
                autoComplete="off"
                placeholder={st.delStrictPlaceholder}
                onChange={(e) => setTyped(e.target.value)}
              />
              {typed.trim() !== "" && !matches && (
                <p className="err">{st.delStrictMismatch.replace("{name}", record.name)}</p>
              )}
            </>
          )}
          <div className="menu-buttons">
            {/* La sortie par défaut est celle qui ne supprime rien : c'est elle qui a le focus. */}
            <button autoFocus onClick={onCancel}>
              {st.delCancel}
            </button>
            <button className="panel-toggle" disabled={busy} onClick={() => void load()}>
              {st.delReload}
            </button>
            <button
              className="cta danger"
              disabled={busy || (strict && !matches)}
              onClick={() => void remove()}
            >
              {st.delConfirm}
            </button>
          </div>
          {busy && <span className="dim">{lang === "fr" ? "suppression…" : "deleting…"}</span>}
        </div>
      )}
    </div>
  );
}

/** Un constat, peint par son niveau. Aucun ne bloque : ils disent ce qui va se passer. */
function Finding({ reason }: { reason: DeleteReason }) {
  const glyph = reason.level === "danger" ? "✗" : reason.level === "warn" ? "▲" : "·";
  return (
    <p className={`guard ${reason.level}`}>
      <span className="gl">{glyph}</span> {reason.text}
    </p>
  );
}
