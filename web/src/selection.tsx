// La sélection multiple d'une vue : un ensemble de clés, la case qui la pose en tête de chaque
// ligne adressable, et — dans la barre horizontale de la vue, pas dans l'en-tête de la table — le
// « tout sélectionner » et le hamburger de masse. La barre est le seul endroit qui ne bouge ni au
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
// La colonne fait `34px` dans tous les gabarits : une case, rien d'autre — les deux contrôles qui
// demandaient les `44px` d'avant sont montés dans la barre.

import { useCallback, useMemo, useState } from "react";
import { MenuAnchor } from "./menu";
import type { Strings } from "./i18n";

export function useMultiSelect() {
  const [checked, setChecked] = useState<Set<string>>(() => new Set());

  const toggle = useCallback((key: string) => {
    setChecked((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  const clear = useCallback(() => setChecked(new Set()), []);

  const setAll = useCallback((keys: string[], on: boolean) => {
    setChecked((prev) => {
      const next = new Set(prev);
      for (const k of keys) {
        if (on) next.add(k);
        else next.delete(k);
      }
      return next;
    });
  }, []);

  return { checked, toggle, clear, setAll };
}

/** La case d'une ligne adressable. Cocher ne sélectionne pas la ligne pour le panneau du haut : les
 * deux gestes restent indépendants, comme le hamburger qui ne sélectionne rien non plus. */
export function RowCheckbox({
  checked,
  onToggle,
  label,
}: {
  checked: boolean;
  onToggle: () => void;
  label: string;
}) {
  return (
    <div className="cell sel">
      <input
        type="checkbox"
        checked={checked}
        aria-label={label}
        onClick={(e) => e.stopPropagation()}
        onChange={onToggle}
      />
    </div>
  );
}

/** La cellule d'en-tête de la colonne de sélection : vide, elle ne tient la piste que pour que
 * l'en-tête et les lignes restent alignés. Ce qu'elle portait est passé dans `SelectionBar`. */
export function SelectionHead() {
  return <div className="cell sel" />;
}

/**
 * Le « tout sélectionner » de la vue et, dès qu'une ligne est cochée, le hamburger de masse.
 *
 * Posé dans la barre horizontale de la vue (`.worlds .right`), au-dessus de la table : c'est le
 * seul endroit d'où il ne peut pas disparaître, ni en défilant vers le bas ni en défilant vers la
 * droite. `keys` est la liste des lignes adressables **de la table affichée** — une vue à plusieurs
 * mondes ne coche que celui qu'on regarde.
 *
 * Une seule action groupée pour l'instant — supprimer — on n'en invente pas d'autre avant qu'elle
 * ne serve.
 */
export function SelectionBar({
  keys,
  checked,
  onSetAll,
  onClear,
  onBulkDelete,
  st,
}: {
  keys: string[];
  checked: Set<string>;
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
      {checked.size > 0 && (
        <>
          <span className="sel-count mono">{st.bulkCount.replace("{n}", String(checked.size))}</span>
          <MenuAnchor label={st.bulkActions}>
            {({ close }) => (
              <>
                <div className="pop-hd">
                  <span>{st.bulkActions}</span>
                </div>
                <div className="menu-target mono">
                  {st.bulkCount.replace("{n}", String(checked.size))}
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
