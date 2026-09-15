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
//
// Quand le menu est rendu ailleurs dans le document (`MenuAnchor`, `menu.tsx`, le sort dans
// `document.body` pour échapper au découpage des cellules), il n'est plus dans l'ancre : il se
// déclare alors en second, sans quoi un clic dans le menu passerait pour un clic à côté.

import { useEffect, useRef, type RefObject } from "react";

/**
 * Ferme au clic hors de l'ancre et à `Échap`, tant que `open` est vrai.
 *
 * Rend la ref à poser sur l'ancre. `onClose` est appelé une fois par geste ; le stabiliser avec
 * `useCallback` évite de réabonner l'écouteur à chaque rendu.
 */
export function useDismiss<T extends HTMLElement>(
  open: boolean,
  onClose: () => void,
  detached?: RefObject<HTMLElement | null>,
) {
  const ref = useRef<T | null>(null);

  useEffect(() => {
    if (!open) return;

    // `pointerdown` et non `click` : le geste se juge où il commence. Un `click` se déclenche à
    // la fin, et un glissement qui part du menu pour finir dehors le refermerait.
    const onPointerDown = (e: PointerEvent) => {
      if (!(e.target instanceof Node)) return onClose();
      if (ref.current?.contains(e.target)) return;
      if (detached?.current?.contains(e.target)) return;
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
  }, [open, onClose, detached]);

  return ref;
}
