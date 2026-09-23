// Le gabarit de colonnes d'une table.
//
// Les pistes vivent sur la table (`.tbl`), plus sur chaque ligne : les lignes s'y raccrochent en
// `grid-template-columns: subgrid`. C'est ce qui permet à une colonne de se tailler sur son
// contenu — `fit-content(<plafond>)` se mesure alors sur *toutes* les lignes à la fois, pas sur
// celle qu'on rend — sans que deux lignes voisines tombent à des places différentes.
//
// Le gabarit passe donc par une propriété personnalisée, que React ne connaît pas dans son type de
// style : le cast est là pour ça, et nulle part ailleurs.

import type { CSSProperties } from "react";

/** Ce qu'une colonne de texte garde au minimum quand la fenêtre force tout le monde à se serrer. */
const FLOOR_CH = 8;

/** L'écart entre deux colonnes et le rembourrage de la ligne, en rem — les valeurs de `.tr`. */
const GAP_REM = 0.9;
const PAD_REM = 0.85;

/**
 * L'écart entre colonnes est **pris dans la piste**, pas ajouté entre elles.
 *
 * C'est la règle des grilles imbriquées : une ligne en `subgrid` garde ses propres gouttières, et
 * elles se prélèvent sur les pistes du parent. Une colonne déclarée à 62 px n'offrirait donc que
 * 48 px à son contenu, et les libellés courts d'une colonne étroite — `CPU req`, `DISK` — se
 * mettraient à s'élider sans qu'on ait rien demandé.
 *
 * Les gabarits restent donc écrits en largeur **utile**, celle qu'on veut voir, et c'est ici que
 * chaque piste se voit ajouter sa gouttière.
 */
function widen(template: string): string {
  const gap = `${GAP_REM}rem`;
  return template
    .replace(/fit-content\((\d+(?:\.\d+)?(?:ch|px))\)/g, `fit-content(calc($1 + ${gap}))`)
    .replace(/minmax\((\d+(?:\.\d+)?(?:ch|px)),/g, `minmax(calc($1 + ${gap}),`)
    .replace(/(^|\s)(\d+(?:\.\d+)?px)(?=\s|$)/g, `$1calc($2 + ${gap})`);
}

/**
 * La largeur en deçà de laquelle la table cesse de se serrer et se met à défiler.
 *
 * Sans elle, une fenêtre trop étroite comprime toutes les pistes souples jusqu'à ne plus laisser
 * qu'une ellipse dans chaque colonne : la table tient, mais ne dit plus rien. Passé ce plancher il
 * vaut mieux déborder — les deux colonnes de gestes sont épinglées justement pour ce cas.
 *
 * Le plancher se lit dans le gabarit lui-même : une piste fixe vaut sa valeur, une piste taillée
 * sur son contenu vaut son plafond borné à {@link FLOOR_CH}, une piste souple vaut son minimum
 * déclaré.
 */
function floor(template: string): string {
  const tracks = template.split(/\s+(?![^(]*\))/).filter(Boolean);
  let px = 0;
  let ch = 0;
  for (const t of tracks) {
    let m = /^(\d+(?:\.\d+)?)px$/.exec(t);
    if (m) {
      px += Number(m[1]);
      continue;
    }
    m = /^fit-content\((\d+(?:\.\d+)?)ch\)$/.exec(t);
    if (m) {
      ch += Math.min(Number(m[1]), FLOOR_CH);
      continue;
    }
    m = /^minmax\((\d+(?:\.\d+)?)ch,/.exec(t);
    if (m) {
      ch += Number(m[1]);
      continue;
    }
    m = /^minmax\((\d+(?:\.\d+)?)px,/.exec(t);
    if (m) px += Number(m[1]);
  }
  const rem = GAP_REM * tracks.length + PAD_REM * 2;
  return `calc(${px}px + ${ch}ch + ${rem}rem)`;
}

/** Le gabarit à poser sur `.tbl` — `<div className="tbl" style={cols(COLUMNS)}>`. */
export function cols(template: string): CSSProperties {
  return { "--cols": widen(template), minWidth: floor(template) } as CSSProperties;
}
