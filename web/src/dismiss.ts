// La fermeture d'un menu déroulant : cliquer ailleurs le referme.
//
// Sur une page, un menu ouvert est modal de fait — il recouvre ce qu'on veut atteindre — et le
// geste qui le referme est le clic à côté. Le lui faire rouvrir par un second clic sur son propre
// bouton est un piège : on clique sur ce qu'on visait, rien ne se passe, et il faut deviner que
// le menu attendait un clic ailleurs.
//
// L'ancre est le conteneur qui porte **le bouton et le menu**, pas le menu seul : sans le bouton
// dedans, un clic sur lui fermerait ici puis rouvrirait au `onClick`, et le menu ne se fermerait
// jamais par son propre bouton.

import { useEffect, useRef } from "react";

/**
 * Ferme au clic hors de l'ancre et à `Échap`, tant que `open` est vrai.
 *
 * Rend la ref à poser sur l'ancre. `onClose` est appelé une fois par geste ; le stabiliser avec
 * `useCallback` évite de réabonner l'écouteur à chaque rendu.
 */
export function useDismiss<T extends HTMLElement>(open: boolean, onClose: () => void) {
  const ref = useRef<T | null>(null);

  useEffect(() => {
    if (!open) return;

    // `pointerdown` et non `click` : le geste se juge où il commence. Un `click` se déclenche à
    // la fin, et un glissement qui part du menu pour finir dehors le refermerait.
    const onPointerDown = (e: PointerEvent) => {
      const el = ref.current;
      if (el && e.target instanceof Node && el.contains(e.target)) return;
      onClose();
    };

    // En capture, et la propagation coupée : `Échap` referme le menu et **rien d'autre**, sans
    // quoi le raccourci global de la page replierait aussi le panneau derrière.
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      e.stopPropagation();
      onClose();
    };

    document.addEventListener("pointerdown", onPointerDown, true);
    document.addEventListener("keydown", onKeyDown, true);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown, true);
      document.removeEventListener("keydown", onKeyDown, true);
    };
  }, [open, onClose]);

  return ref;
}
