// Un menu déroulant ancré à son bouton, mais **rendu hors de la table**.
//
// Une cellule de table coupe ce qui dépasse (`.cell { overflow: hidden }`, `styles.css`) : c'est ce
// qui fait tenir un nom trop long en une ligne élidée. Un menu posé en `position: absolute` dans
// cette cellule est donc découpé à la hauteur de la ligne — on voit le bouton, jamais le menu. Le
// corps de la vue défile en plus (`.body { overflow: auto }`), ce qui recouperait le menu des
// dernières lignes même si la cellule laissait passer.
//
// D'où le portail : le menu est rendu dans `document.body`, en `position: fixed`, et sa place est
// calculée depuis le rectangle du bouton — sous lui, retourné au-dessus quand le bas manque,
// ramené dans la fenêtre quand la droite manque. Il suit le défilement tant qu'il est ouvert.

import { useCallback, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { useDismiss } from "./dismiss";

/** L'écart gardé entre le menu et le bord de la fenêtre, et entre le menu et son bouton. */
const GAP = 4;
const MARGIN = 8;

/**
 * Le bouton `☰` et ce qu'il ouvre.
 *
 * `children` est une fonction et non un nœud tout fait : ce qu'un menu contient a souvent besoin
 * de le refermer une fois son geste lancé.
 */
export function MenuAnchor({
  label,
  className = "",
  onOpenChange,
  children,
}: {
  label: string;
  /** Classes ajoutées au menu lui-même — `wide` pour un formulaire, par exemple. */
  className?: string;
  onOpenChange?: (open: boolean) => void;
  children: (ctl: { close: () => void }) => ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const popRef = useRef<HTMLDivElement | null>(null);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);

  const setOpenState = useCallback(
    (next: boolean) => {
      setOpen(next);
      if (!next) setPos(null);
      onOpenChange?.(next);
    },
    [onOpenChange],
  );

  const close = useCallback(() => setOpenState(false), [setOpenState]);

  // L'ancre du clic-à-côté, c'est le bouton **et** le menu : hors de la table, le menu n'est plus
  // un descendant du bouton, et un clic dedans passerait pour un clic ailleurs.
  const btnRef = useDismiss<HTMLButtonElement>(open, close, popRef);

  // Placé avant la peinture : le menu ne doit pas apparaître une frame en (0, 0).
  useLayoutEffect(() => {
    if (!open) return;

    const place = () => {
      const btn = btnRef.current;
      const pop = popRef.current;
      if (!btn || !pop) return;
      const r = btn.getBoundingClientRect();
      const { offsetWidth: w, offsetHeight: h } = pop;

      let top = r.bottom + GAP;
      // Pas la place dessous : au-dessus, sauf si le haut est encore plus étroit.
      if (top + h > window.innerHeight - MARGIN && r.top - GAP - h > MARGIN) top = r.top - GAP - h;
      top = Math.max(MARGIN, Math.min(top, window.innerHeight - MARGIN - h));

      let left = r.left;
      if (left + w > window.innerWidth - MARGIN) left = window.innerWidth - MARGIN - w;
      left = Math.max(MARGIN, left);

      setPos({ top, left });
    };

    place();
    // En capture : le défilement qui compte est celui du corps de la vue, pas celui de la fenêtre.
    window.addEventListener("scroll", place, true);
    window.addEventListener("resize", place);
    // Le contenu d'un menu change de taille sans que le menu se referme — une confirmation qui
    // remplace la liste, un accusé qui s'ajoute. Ouvert près du bas, il sortirait de la fenêtre.
    const observer = new ResizeObserver(place);
    if (popRef.current) observer.observe(popRef.current);
    return () => {
      window.removeEventListener("scroll", place, true);
      window.removeEventListener("resize", place);
      observer.disconnect();
    };
  }, [open, btnRef]);

  return (
    <>
      <button
        ref={btnRef}
        className="row-menu-btn"
        aria-label={label}
        title={label}
        aria-expanded={open}
        onClick={(e) => {
          // Ne pas laisser le clic remonter jusqu'à la ligne : ouvrir le menu ne doit pas aussi la
          // sélectionner, sans quoi cliquer le bouton ferait deux choses à la fois.
          e.stopPropagation();
          setOpenState(!open);
        }}
      >
        ☰
      </button>
      {open &&
        createPortal(
          <div
            ref={popRef}
            className={`pop menu floating ${className}`}
            style={{
              top: pos?.top ?? 0,
              left: pos?.left ?? 0,
              visibility: pos ? undefined : "hidden",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {children({ close })}
          </div>,
          document.body,
        )}
    </>
  );
}
