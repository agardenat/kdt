// L'identité de l'objet que regarde un pane, séparée de l'enregistrement qui la porte.
//
// Les vues relisent leur inventaire toutes les quelques secondes, et chaque passe **reconstruit**
// ses `EventRecord` : le record d'une même ligne est un objet neuf à chaque fois, alors que
// l'objet Kubernetes derrière lui n'a pas bougé. Un effet qui dépend du record part donc toutes
// les vingt secondes — ce qui refermait les sections dépliées de `Related`, effaçait les logs
// sous les yeux, et rechargeait par-dessus le texte qu'on était en train d'écrire dans `e` ou le
// nom qu'on retapait pour confirmer une suppression.

import { useEffect, useState } from "react";
import type { EventRecord } from "./types";

/** L'objet visé, réduit à ce qui le distingue d'un autre. */
export function recordIdentity(record: EventRecord): string {
  return `${record.uid}|${record.kind}|${record.namespace}|${record.name}`;
}

/**
 * `true` la première fois qu'on rend un autre objet que le précédent.
 *
 * Le calcul se fait pendant le rendu, et non dans un effet : un effet s'exécute après la peinture,
 * et on verrait une frame du contenu de l'objet précédent sous le nom du nouveau.
 */
export function useRecordChanged(record: EventRecord): boolean {
  const [seen, setSeen] = useState(() => recordIdentity(record));
  const now = recordIdentity(record);
  if (seen !== now) {
    setSeen(now);
    return true;
  }
  return false;
}

/**
 * Une boîte qui tient toujours l'enregistrement le plus frais, et qui ne change d'identité que
 * quand l'objet visé change vraiment.
 *
 * C'est ce qu'on met dans les dépendances d'un effet ou d'un `useCallback` qui vise un objet : la
 * lecture se refait quand la cible change, jamais parce que la vue vient de relire sa liste. Le
 * contenu, lui, reste à jour — ce qui compte pour une action déclenchée plus tard.
 */
export function useTarget(record: EventRecord): { current: EventRecord } {
  const [box, setBox] = useState(() => ({ current: record }));
  const fresh = recordIdentity(box.current) === recordIdentity(record) ? box : { current: record };
  if (fresh !== box) setBox(fresh);
  // Posé dans un effet, et déclaré avant ceux de l'appelant : au moment où ils s'exécutent, la
  // boîte porte déjà l'enregistrement de ce rendu.
  useEffect(() => {
    fresh.current = record;
  });
  return fresh;
}
