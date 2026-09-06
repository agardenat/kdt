// Le bouton de copie, seul dans son fichier parce que trois contenus s'en servent — les valeurs
// d'un Secret, celles d'une ConfigMap, et le YAML d'un objet — et que le poser dans l'un d'eux
// ferait dépendre les autres de lui.

import { useEffect, useState } from "react";

/**
 * Copie une valeur dans le presse-papier, avec un accusé qui s'efface.
 *
 * `navigator.clipboard` exige un contexte sécurisé : `https`, ou `localhost`, qui en est un. Servi
 * en clair depuis une autre machine, l'API est absente — le bouton le dit alors plutôt que
 * d'échouer en silence.
 *
 * La copie ne porte que sur ce qui est déjà à l'écran : copier une valeur masquée reviendrait à
 * la sortir sans l'avoir demandée.
 */
export function CopyButton({ text, label, done }: { text: string; label: string; done: string }) {
  const [state, setState] = useState<"idle" | "ok" | "unavailable">("idle");

  useEffect(() => {
    if (state === "idle") return;
    const timer = window.setTimeout(() => setState("idle"), 2000);
    return () => window.clearTimeout(timer);
  }, [state]);

  return (
    <button
      className={`inv-pill copy${state === "ok" ? " done" : ""}`}
      title={label}
      onClick={(e) => {
        e.stopPropagation();
        const write = navigator.clipboard?.writeText(text);
        if (write) write.then(() => setState("ok")).catch(() => setState("unavailable"));
        else setState("unavailable");
      }}
    >
      {state === "ok" ? `✓ ${done}` : state === "unavailable" ? "✗" : "⧉"}
    </button>
  );
}
