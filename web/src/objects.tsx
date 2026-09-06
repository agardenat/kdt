// Les trois gestes que kdt porte sur **n'importe quel** objet : lire son YAML, l'éditer, le toucher.
//
// Dans le TUI ce sont trois touches — `y`, `e`, `h` — disponibles dans toutes les vues parce
// qu'elles visent l'objet Kubernetes derrière la ligne, pas la ligne. Ici c'est la même chose, dans
// la grammaire du web (mémoire `gui-affordances-not-tui-keys`) : **les actions vivent dans la barre
// qui sépare les deux panneaux, et ce qu'elles ouvrent s'affiche dans le panneau du haut.**
//
// `Toucher` est le seul qui écrive sans rien ouvrir, et c'est déjà le cas dans kdt : deux
// annotations sous `kdt.io/` s'ajoutent, rien n'est retiré, et l'intérêt de la touche est d'être
// assez rapide pour parcourir une liste avec. L'accusé se lit à côté du bouton.

import { useCallback, useEffect, useState } from "react";
import * as api from "./api";
import { NeedsAuth } from "./api";
import type { Lang, Strings } from "./i18n";
import { CopyButton } from "./copy";
import type { EditDiff, EditPreflight, EditReason, EventRecord, ObjectYaml } from "./types";

/** L'onglet du panneau qu'un bouton de la barre ouvre. */
export type ObjectTab = "yaml" | "edit";

/**
 * Les trois boutons, posés dans la barre des onglets de la vue.
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
