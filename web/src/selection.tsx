// La sélection multiple d'une vue : un ensemble de clés, la case qui la pose sur chaque ligne
// adressable, et — dans la barre horizontale de la vue, pas dans l'en-tête de la table — le « tout
// sélectionner » et le hamburger de masse. La barre est le seul endroit qui ne bouge ni au
// défilement vertical ni à l'horizontal : un sélecteur qui commande toute la table n'a rien à faire
// dans une ligne qui peut sortir de l'écran.
//
// La clé est `uid` dans la plupart des vues, mais pas partout : `EventsView` n'a pas toujours un
// `uid` et se sélectionne par `recordIdentity` (mémoire `kdt-web-record-identity`). `useMultiSelect`
// ne le sait pas et ne le doit pas — c'est à la vue de choisir sa clé.
//
// Une ligne de regroupement (en-tête de StorageClass, total) n'a pas de case : elle n'a déjà pas de
// `RowMenu`, même garde. Et une ligne qui n'est pas un objet de l'API n'en a pas non plus : un
// container porte le `record` de son pod, le cocher supprimerait le pod sous un autre nom.
//
// Dans une table plate, la case a sa colonne, `34px`, la première du gabarit (`RowCheckbox`). Dans
// un arbre, elle n'en a pas : elle se pose dans la cellule du nom, entre le pli et le libellé
// (`TreeCheckbox`), et suit l'indentation. Une colonne fixe laissait la case à gauche de tout, loin
// de l'objet qu'elle coche dès la deuxième profondeur — l'œil devait refaire la ligne pour savoir
// quelle case allait avec quel nom.
//
// La cascade ne vaut que pour une **possession** : un parent dont la suppression emporte ses
// enfants (`ownerReferences`, suppression en `Background`). Cocher le parent coche alors ses
// enfants — grisés, puisqu'ils partent avec lui — et seul le parent part à la suppression : le
// garbage collector fait le reste, et retaper le nom de trente pods n'apprend rien à personne. Un
// arbre de références (Flux `dependsOn`/`sourceRef`, une liaison RBAC vers son rôle, un Issuer vers
// ses Certificates) n'a pas de cascade : y cocher une branche cocherait des objets qu'on ne veut
// pas supprimer. Et la cascade ne remonte jamais : cocher tous les pods d'un Deployment n'est pas
// cocher le Deployment, le parent passe seulement en indéterminé.

import { useCallback, useMemo, useState } from "react";
import { MenuAnchor } from "./menu";
import type { Strings } from "./i18n";

/** Le parent possédant d'une clé : sa clé à lui, et le nom qui le désigne dans une infobulle. */
export interface Owner {
  key: string;
  label: string;
}

/** Faute de possession, aucune clé n'a de parent : la sélection est plate. */
const NO_OWNERS = new Map<string, Owner>();

/** Les parents possédants d'une clé, du plus proche au plus lointain. */
export function ownersOf(owners: Map<string, Owner>, key: string): Owner[] {
  const out: Owner[] = [];
  for (let o = owners.get(key); o !== undefined && out.length < 32; o = owners.get(o.key)) {
    out.push(o);
  }
  return out;
}

/** Ce que la sélection brute devient une fois les possessions appliquées — cf. `useMultiSelect`. */
export function resolveSelection(raw: Set<string>, owners: Map<string, Owner>) {
  const checked = new Set<string>();
  for (const k of raw) if (!ownersOf(owners, k).some((a) => raw.has(a.key))) checked.add(k);
  const shown = new Set(checked);
  for (const k of owners.keys()) {
    if (ownersOf(owners, k).some((a) => checked.has(a.key))) shown.add(k);
  }
  const partial = new Set<string>();
  for (const k of checked) for (const a of ownersOf(owners, k)) partial.add(a.key);
  return { checked, shown, partial };
}

/**
 * La sélection multiple d'une vue.
 *
 * `owners` décrit les possessions de la vue, enfant → parent, sur **tous** les objets qu'elle a lus
 * et pas seulement ceux affichés : un pod filtré hors de l'écran part quand même avec son
 * Deployment. Sans `owners`, la sélection est un simple ensemble de clés.
 *
 * - `checked` : ce qui part à la suppression — les clés cochées dont aucun parent ne l'est ;
 * - `shown` : ce qui s'affiche coché, enfants couverts compris ;
 * - `partial` : les parents non cochés dont un descendant l'est ;
 * - `coveredBy` : le parent coché qui emporte une clé, s'il y en a un.
 */
export function useMultiSelect(owners: Map<string, Owner> = NO_OWNERS) {
  const [raw, setRaw] = useState<Set<string>>(() => new Set());

  const ancestors = useCallback((key: string) => ownersOf(owners, key), [owners]);

  const { checked, shown, partial } = useMemo(() => resolveSelection(raw, owners), [raw, owners]);

  const coveredBy = useCallback(
    (key: string): Owner | undefined => ancestors(key).find((a) => checked.has(a.key)),
    [ancestors, checked],
  );

  // Cocher un parent oublie ce qui était coché dessous : le décocher ensuite ne doit pas faire
  // réapparaître une sélection d'enfants qu'on a recouverte.
  const dropDescendants = useCallback(
    (set: Set<string>, parent: string) => {
      for (const k of [...set]) if (ancestors(k).some((a) => a.key === parent)) set.delete(k);
    },
    [ancestors],
  );

  const toggle = useCallback(
    (key: string) => {
      setRaw((prev) => {
        const next = new Set(prev);
        if (next.has(key)) next.delete(key);
        else {
          next.add(key);
          dropDescendants(next, key);
        }
        return next;
      });
    },
    [dropDescendants],
  );

  const clear = useCallback(() => setRaw(new Set()), []);

  // Décocher une clé couverte, c'est décocher ce qui la couvre : sans ça, « tout désélectionner »
  // laisserait cochés les pods d'un Deployment coché depuis l'autre monde.
  const setAll = useCallback(
    (keys: string[], on: boolean) => {
      setRaw((prev) => {
        const next = new Set(prev);
        for (const k of keys) {
          if (on) next.add(k);
          else {
            next.delete(k);
            for (const a of ancestors(k)) next.delete(a.key);
          }
        }
        if (on) for (const k of keys) if (next.has(k)) dropDescendants(next, k);
        return next;
      });
    },
    [ancestors, dropDescendants],
  );

  return { checked, shown, partial, coveredBy, toggle, clear, setAll };
}

/** La case d'une ligne adressable. Cocher ne sélectionne pas la ligne pour le panneau du haut : les
 * deux gestes restent indépendants, comme le hamburger qui ne sélectionne rien non plus. */
export function RowCheckbox({
  checked,
  onToggle,
  label,
  covered,
  st,
}: {
  checked: boolean;
  onToggle: () => void;
  label: string;
  /** Le parent coché qui emporte la ligne — cf. `TreeCheckbox`, quand une table plate montre des
   * objets possédés (les pods à plat de Workloads). */
  covered?: Owner;
  st?: Strings;
}) {
  return (
    <div
      className="cell sel"
      title={covered && st ? st.selectCovered.replace("{owner}", covered.label) : undefined}
    >
      <input
        type="checkbox"
        checked={checked || covered !== undefined}
        disabled={covered !== undefined}
        aria-label={label}
        onClick={(e) => e.stopPropagation()}
        onChange={onToggle}
      />
    </div>
  );
}

/**
 * La case d'une ligne d'arbre, posée dans la cellule du nom juste après le pli.
 *
 * `covered` nomme le parent coché qui emporte la ligne : la case est alors cochée et grisée — on ne
 * retire pas un pod d'un Deployment qu'on supprime, on décoche le Deployment. `partial` est l'état
 * indéterminé d'un parent dont un descendant seulement est coché.
 *
 * Sans `onToggle`, la ligne n'est pas adressable : un espace de la même largeur tient la place,
 * pour que les noms d'une même profondeur restent alignés — la même raison que `.fold-gap`.
 */
export function TreeCheckbox({
  checked,
  onToggle,
  label,
  covered,
  partial = false,
  st,
}: {
  checked: boolean;
  onToggle?: () => void;
  label: string;
  covered?: Owner;
  partial?: boolean;
  st: Strings;
}) {
  if (!onToggle) return <span className="tree-sel" />;
  return (
    <span
      className="tree-sel"
      title={covered ? st.selectCovered.replace("{owner}", covered.label) : undefined}
    >
      <input
        type="checkbox"
        checked={checked || covered !== undefined}
        disabled={covered !== undefined}
        ref={(el) => {
          if (el) el.indeterminate = partial && !checked && covered === undefined;
        }}
        aria-label={label}
        onClick={(e) => e.stopPropagation()}
        onChange={onToggle}
      />
    </span>
  );
}

/** La cellule d'en-tête de la colonne de sélection : vide, elle ne tient la piste que pour que
 * l'en-tête et les lignes restent alignés. Ce qu'elle portait est passé dans `SelectionBar`. */
export function SelectionHead() {
  return <div className="cell sel" />;
}

/** Le gabarit d'un arbre, privé de la piste de la case : elle est passée dans la cellule du nom. */
export function withoutSelTrack(template: string): string {
  return template.replace(/^34px\s+/, "");
}

/**
 * Le « tout sélectionner » de la vue et, dès qu'une ligne est cochée, le hamburger de masse.
 *
 * Posé dans la barre horizontale de la vue (`.worlds .right`), au-dessus de la table : c'est le
 * seul endroit d'où il ne peut pas disparaître, ni en défilant vers le bas ni en défilant vers la
 * droite. `keys` est la liste des lignes adressables **de la table affichée** — une vue à plusieurs
 * mondes ne coche que celui qu'on regarde.
 *
 * `checked` est ce qui s'affiche coché (`shown` quand la vue a une cascade), `count` ce qui partira
 * vraiment : un Deployment coché avec ses trois pods fait une suppression, pas quatre.
 *
 * Une seule action groupée pour l'instant — supprimer — on n'en invente pas d'autre avant qu'elle
 * ne serve.
 */
export function SelectionBar({
  keys,
  checked,
  count = checked.size,
  onSetAll,
  onClear,
  onBulkDelete,
  st,
}: {
  keys: string[];
  checked: Set<string>;
  count?: number;
  onSetAll: (keys: string[], on: boolean) => void;
  onClear: () => void;
  onBulkDelete: () => void;
  st: Strings;
}) {
  const selectedHere = useMemo(() => keys.filter((k) => checked.has(k)), [keys, checked]);
  const all = keys.length > 0 && selectedHere.length === keys.length;
  const some = selectedHere.length > 0 && !all;

  return (
    <div className="sel-bar">
      <label className="opt" title={st.selectAll}>
        <input
          type="checkbox"
          checked={all}
          ref={(el) => {
            if (el) el.indeterminate = some;
          }}
          disabled={keys.length === 0}
          aria-label={st.selectAll}
          onChange={() => onSetAll(keys, !all)}
        />
        {st.selectAll}
      </label>
      {count > 0 && (
        <>
          <span className="sel-count mono">{st.bulkCount.replace("{n}", String(count))}</span>
          <MenuAnchor label={st.bulkActions}>
            {({ close }) => (
              <>
                <div className="pop-hd">
                  <span>{st.bulkActions}</span>
                </div>
                <div className="menu-target mono">
                  {st.bulkCount.replace("{n}", String(count))}
                </div>
                <div className="menu-list">
                  <button
                    className="menu-item danger"
                    onClick={() => {
                      close();
                      onBulkDelete();
                    }}
                  >
                    <span className="lbl">{st.actionDelete}</span>
                  </button>
                  <button
                    className="menu-item"
                    onClick={() => {
                      close();
                      onClear();
                    }}
                  >
                    <span className="lbl">{st.bulkClear}</span>
                  </button>
                </div>
              </>
            )}
          </MenuAnchor>
        </>
      )}
    </div>
  );
}
