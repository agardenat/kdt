// Le pliage de l'arbre Flux, et rien d'autre.
//
// Le serveur envoie l'arbre entièrement déplié, en parcours préfixe, chaque ligne portant sa
// profondeur. Toutes les arêtes sont donc déjà résolues — `dependsOn`, `status.helmChart`,
// `spec.sourceRef` — et ce fichier n'en redessine aucune : il ne fait que décider ce qui est
// visible, ce qu'un pli cache, et quelle branche doit rester ouverte.
//
// C'est bien de l'affichage, et c'est pour ça que ça vit ici et pas côté serveur : un pli est un
// état de la personne qui regarde, pas du cluster.
//
// La seule règle à retenir : **en parcours préfixe, les descendants d'une ligne sont les lignes
// suivantes dont la profondeur est strictement plus grande, jusqu'à la première qui ne l'est
// plus.** Les trois fonctions ci-dessous en découlent.

import type { FluxRow } from "./types";

/** Les descendants de `i` : l'intervalle `]i, fin[` des lignes plus profondes. */
function subtreeEnd(rows: FluxRow[], i: number): number {
  const depth = rows[i].depth;
  let end = i + 1;
  while (end < rows.length && rows[end].depth > depth) end += 1;
  return end;
}

/** Ce qu'un pli cache et qui vaut d'être annoncé : les échecs, et les réconciliations en cours. */
export interface Hidden {
  failed: number;
  reconciling: number;
}

/**
 * Ce que le pli de la ligne `i` dissimule.
 *
 * Une branche repliée qui ne dit rien de son contenu est exactement ce qui transforme « où est
 * l'erreur » en promenade dans tout l'arbre. Seuls les deux états sur lesquels on agit sont
 * comptés : une branche pleine de ressources saines n'a rien à annoncer.
 *
 * Suspendu ne compte pas — c'est un état voulu, pas un problème à chasser.
 */
export function hiddenUnder(rows: FluxRow[], i: number): Hidden {
  const end = subtreeEnd(rows, i);
  let failed = 0;
  let reconciling = 0;
  for (let k = i + 1; k < end; k += 1) {
    const r = rows[k];
    if (r.suspended) continue;
    if (r.ready === "failed") failed += 1;
    else if (r.ready === "reconciling") reconciling += 1;
  }
  return { failed, reconciling };
}

/**
 * Les uid des ancêtres de la ligne `i`, en remontant les profondeurs décroissantes.
 *
 * La ligne n'est pas son propre ancêtre : repliée à la main, elle le reste.
 */
export function ancestorsOf(rows: FluxRow[], i: number): string[] {
  const out: string[] = [];
  let want = rows[i].depth - 1;
  for (let k = i - 1; k >= 0 && want >= 0; k -= 1) {
    if (rows[k].depth === want) {
      out.push(rows[k].uid);
      want -= 1;
    }
  }
  return out;
}

/**
 * Les branches à garder ouvertes : celles qui mènent à un problème, et celle qu'on est en train
 * de lire.
 *
 * Le second cas est aussi important que le premier : une branche qui se referme sur elle-même ne
 * doit jamais emporter la ligne sélectionnée, sinon la réconciliation qu'on regardait finit avec
 * le curseur renvoyé en haut de l'arbre.
 */
export function revealed(rows: FluxRow[], selectedUid: string | null): Set<string> {
  const out = new Set<string>();
  rows.forEach((r, i) => {
    const isProblem = !r.suspended && (r.ready === "failed" || r.ready === "reconciling");
    if (!isProblem && r.uid !== selectedUid) return;
    for (const uid of ancestorsOf(rows, i)) out.add(uid);
  });
  return out;
}

/**
 * Les lignes effectivement affichées, une fois les plis appliqués.
 *
 * Une ligne repliée reste visible : c'est sa descendance qui disparaît. Et un pli révélé —
 * ancêtre d'un problème, ou de la ligne lue — ne s'applique pas : il est enjambé sans être
 * oublié, pour que le pli reprenne dès que la branche redevient calme.
 */
export function visibleRows(
  rows: FluxRow[],
  collapsed: Set<string>,
  reveal: Set<string>,
): FluxRow[] {
  const out: FluxRow[] = [];
  // Tant que ce seuil est posé, toute ligne plus profonde est sous un pli et n'est pas émise.
  let hideDeeperThan: number | null = null;
  for (const row of rows) {
    if (hideDeeperThan !== null) {
      if (row.depth > hideDeeperThan) continue;
      hideDeeperThan = null;
    }
    out.push(row);
    if (row.has_children && collapsed.has(row.uid) && !reveal.has(row.uid)) {
      hideDeeperThan = row.depth;
    }
  }
  return out;
}

/**
 * Les lignes qui passent le filtre, **plus leurs ancêtres**.
 *
 * Filtrer un arbre ligne à ligne le casse : les enfants d'une ligne écartée se retrouvent
 * rattachés à n'importe quoi, et la profondeur ne veut plus rien dire. Les ancêtres sont donc
 * gardés comme chemin — ils disent d'où vient ce qui reste, ce qui est justement ce qu'on
 * demande à un arbre.
 */
export function filterTree(rows: FluxRow[], needle: string): FluxRow[] {
  if (!needle) return rows;
  const keep = new Set<string>();
  rows.forEach((r, i) => {
    if (!matches(r, needle)) return;
    keep.add(r.uid);
    for (const uid of ancestorsOf(rows, i)) keep.add(uid);
  });
  return rows.filter((r) => keep.has(r.uid));
}

function matches(r: FluxRow, needle: string): boolean {
  return [r.kind, r.namespace, r.name, r.message, r.revision, r.ready_label]
    .join(" ")
    .toLowerCase()
    .includes(needle);
}
