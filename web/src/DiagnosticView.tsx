// Le diagnostic du cluster — le `D` de kdt.
//
// Une séquence fixe d'étapes en lecture seule, qui arrivent au fil de l'eau : chaque étape naît en
// « … » et se referme sur son verdict, comme la liste du TUI se remplit. Rien n'est jugé ici — le
// statut de l'étape et le ton de chaque ligne sont posés par `kdt::diagnostic` et peints tels
// quels, sinon les deux interfaces finiraient par colorer différemment le même constat.
//
// Ce n'est pas une table : il n'y a pas d'objet par ligne, donc ni case de sélection, ni hamburger,
// ni suppression groupée. Le seul geste est `i` — et il vise le diagnostic entier, pas une étape.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import { AiButton, type AiExtra } from "./ai";
import type { Lang, Strings } from "./i18n";
import { ViewBody, type PanelTab } from "./panel";
import type { DiagCounts, DiagDone, DiagStep, EventRecord } from "./types";

/** Ce que le `done` du flux a laissé : les compteurs finaux, et de quoi lancer une analyse. */
interface Outcome {
  elapsed_ms: number | null;
  counts: DiagCounts;
  record: EventRecord;
  ai_text: string;
}

export default function DiagnosticView({
  lang,
  st,
  query,
  onNeedsAuth,
}: {
  lang: Lang;
  st: Strings;
  query: string;
  onNeedsAuth: (message: string) => void;
}) {
  const [steps, setSteps] = useState<DiagStep[]>([]);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [onlyProblems, setOnlyProblems] = useState(false);
  const [tab, setTab] = useState<PanelTab>("detail");

  // Le flux en cours. Relancer abandonne le précédent : deux séquences en parallèle liraient le
  // cluster deux fois et n'écriraient qu'une liste.
  const stream = useRef<AbortController | null>(null);

  const launch = useCallback(() => {
    stream.current?.abort();
    const mine = new AbortController();
    stream.current = mine;

    setSteps([]);
    setOutcome(null);
    setError(null);
    setRunning(true);

    void api
      .diagnostic(
        lang,
        (event) => {
          if (mine.signal.aborted) return;
          if (event.type === "step") {
            const step = event.data as DiagStep;
            // Une étape est poussée à sa naissance puis de nouveau à son verdict : elle se
            // remplace à son index plutôt que de s'ajouter, sinon la liste doublerait.
            setSteps((previous) => {
              const next = previous.slice();
              next[step.index] = step;
              return next;
            });
          } else if (event.type === "done") {
            const done = event.data as DiagDone;
            setOutcome({
              elapsed_ms: done.elapsed_ms,
              counts: done.counts,
              record: done.record,
              ai_text: done.ai_text,
            });
            setRunning(false);
          }
        },
        mine.signal,
      )
      .catch((e: unknown) => {
        if (mine.signal.aborted) return;
        setRunning(false);
        if (e instanceof NeedsAuth) onNeedsAuth(e.message);
        else if (e instanceof ApiError) setError(e.message);
        else setError(String(e));
      })
      .finally(() => {
        if (!mine.signal.aborted) setRunning(false);
      });
  }, [lang, onNeedsAuth]);

  // Lancé à l'ouverture, comme `D` lance la séquence en entrant dans la vue du TUI. Pas de
  // rafraîchissement périodique : un diagnostic est une photo qu'on demande, et le relire toutes
  // les minutes ferait lire le cluster entier en boucle.
  useEffect(() => {
    launch();
    return () => stream.current?.abort();
    // `launch` change avec la langue ; relancer sur ce seul changement referait tourner
    // vingt-cinq étapes pour retraduire des phrases. Le bouton est là pour ça.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Les compteurs pendant que ça tourne : ceux du serveur n'arrivent qu'au `done`, et l'en-tête
  // doit dire ce qui est déjà su. Une étape en cours n'en alimente aucun, comme côté serveur.
  const counts = useMemo<DiagCounts>(() => {
    if (outcome) return outcome.counts;
    const tally = { steps: steps.length, ok: 0, info: 0, warn: 0, err: 0 };
    for (const step of steps) {
      if (step?.status === "ok") tally.ok += 1;
      else if (step?.status === "info") tally.info += 1;
      else if (step?.status === "warn") tally.warn += 1;
      else if (step?.status === "err") tally.err += 1;
    }
    return tally;
  }, [steps, outcome]);

  const shown = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return steps.filter((step) => {
      if (!step) return false;
      // Le filtre garde l'étape en cours : la masquer ferait disparaître la seule ligne qui bouge.
      if (onlyProblems && step.status !== "warn" && step.status !== "err" && step.status !== "running") {
        return false;
      }
      if (!needle) return true;
      return [step.title, step.command, ...step.lines.map((l) => l.text)]
        .join(" ")
        .toLowerCase()
        .includes(needle);
    });
  }, [steps, query, onlyProblems]);

  // Ce que `i` envoie au modèle : le diagnostic entier, mis à plat par le serveur. Tant qu'il
  // tourne il n'y a rien de complet à envoyer, et le bouton reste éteint.
  const aiExtra = useMemo<AiExtra | undefined>(
    () => (outcome ? [{ title: "Cluster diagnostic", text: outcome.ai_text }] : undefined),
    [outcome],
  );

  const state = running ? st.diagRunning : outcome ? st.diagFinished : st.diagIdle;
  const stateTone = running ? "info" : counts.err > 0 ? "err" : counts.warn > 0 ? "warn" : "ok";

  return (
    <>
      <div className="worlds" role="tablist">
        <button role="tab" aria-selected>
          {st.diagTitle}
          <span className="count">{counts.steps}</span>
        </button>

        <div className="tally">
          <span className={`chip ${stateTone}`}>{state}</span>
          <span className="ok">ok {counts.ok}</span>
          <span className="info">info {counts.info}</span>
          <span className="warn">warn {counts.warn}</span>
          <span className="err">err {counts.err}</span>
          {outcome?.elapsed_ms != null && (
            <span className="info">
              {st.diagDuration} {outcome.elapsed_ms} ms
            </span>
          )}
        </div>

        <div className="right">
          <button
            className={`panel-toggle ${onlyProblems ? "on" : ""}`}
            aria-pressed={onlyProblems}
            onClick={() => setOnlyProblems(!onlyProblems)}
          >
            {st.diagOnlyProblems}
          </button>
          <AiButton
            usable={Boolean(outcome)}
            st={st}
            onOpen={() => setTab("ai")}
          />
          <button className="panel-toggle" onClick={launch} disabled={running}>
            {steps.length === 0 && !running ? st.diagRun : st.diagRerun}
          </button>
        </div>
      </div>

      <ViewBody
        tab={tab}
        record={outcome?.record ?? null}
        lang={lang}
        st={st}
        onTab={setTab}
        onNeedsAuth={onNeedsAuth}
        aiExtra={aiExtra}
      >
        {steps.length === 0 ? (
          <div className="center">
            <div className="box">
              <h2>{running ? st.diagRunning : st.diagEmpty}</h2>
              <p>{st.diagIntro}</p>
              {error && <p className="err">{error}</p>}
            </div>
          </div>
        ) : shown.length === 0 ? (
          <div className="center">
            <div className="box">
              <h2>{st.diagNoMatch}</h2>
            </div>
          </div>
        ) : (
          <div className="diag">
            {shown.map((step) => (
              <Step key={step.index} step={step} />
            ))}
          </div>
        )}
      </ViewBody>

      <div className="statusbar">
        <span>
          {counts.steps} {st.diagSteps}
        </span>
        <span>{st.diagScopeless}</span>
        {error && <span className="err">{error}</span>}
      </div>
    </>
  );
}

/**
 * Une étape : sa pastille, son titre, la commande `kubectl` équivalente, et ses constats.
 *
 * La commande est là pour la même raison que dans le TUI : elle dit ce qui a été lu, donc ce qu'un
 * refus RBAC porterait sur, et elle se recopie telle quelle dans un terminal.
 */
function Step({ step }: { step: DiagStep }) {
  return (
    <section className={`diag-step ${step.status}`}>
      <header className="diag-hd">
        <span className={`diag-badge ${step.status}`}>{step.label}</span>
        <span className="diag-title">{step.title}</span>
        <code className="diag-cmd">$ {step.command}</code>
      </header>
      {step.lines.length > 0 && (
        <div className="diag-lines">
          {step.lines.map((line, i) => (
            <div key={i} className={`diag-line ${line.tone}`}>
              {line.text}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
