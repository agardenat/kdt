// Le message d'action de la barre de statut, seul dans son fichier parce que les huit vues qui
// écrivent sur le cluster s'en servent à l'identique.

import { useEffect, type Dispatch, type SetStateAction } from "react";
import type { Lang } from "./i18n";

/** Le résultat du dernier geste : ce qui a marché, ou ce qui a échoué et pourquoi. */
export type Toast = { tone: "ok" | "err"; text: string } | null;

/**
 * Efface le message au bout de quelques secondes — **sauf quand il rapporte un échec**.
 *
 * Un succès n'a rien à relire : la table dit déjà que l'objet a bougé. Un échec, lui, porte souvent
 * la seule trace de ce qui s'est passé, et il est long — une URL signée, un refus de l'API. Le
 * voir disparaître pendant qu'on le lit revenait à perdre la réponse à la question qu'on venait de
 * poser. Il reste donc jusqu'au geste suivant, ou jusqu'à ce qu'on le referme.
 */
export function useToastTimeout(toast: Toast, setToast: Dispatch<SetStateAction<Toast>>) {
  useEffect(() => {
    if (!toast || toast.tone === "err") return;
    const timer = window.setTimeout(() => setToast(null), 8000);
    return () => window.clearTimeout(timer);
  }, [toast, setToast]);
}

/**
 * Le message dans la barre de statut.
 *
 * Il tient sur une ligne et s'élide : la barre a d'autres choses à dire, et le texte entier est
 * dans l'infobulle. Un échec qui ne s'efface pas tout seul doit pouvoir se refermer, d'où le clic —
 * annoncé par l'infobulle plutôt que par une croix, qui prendrait la place du texte.
 */
export function ToastLine({
  toast,
  onDismiss,
  lang,
}: {
  toast: Toast;
  onDismiss: () => void;
  lang: Lang;
}) {
  if (!toast) return null;
  return (
    <button
      className={`toast ${toast.tone}`}
      title={`${toast.text}\n\n${lang === "fr" ? "Cliquer pour effacer" : "Click to dismiss"}`}
      onClick={onDismiss}
    >
      {toast.text}
    </button>
  );
}
