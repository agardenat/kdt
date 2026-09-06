// Le thème a trois états, pas deux : clair choisi, sombre choisi, et le défaut où c'est le
// système qui tranche. Le troisième ne stampe rien sur la racine — c'est ce que voit la plupart
// des gens, et c'est celui qu'on oublie de tester.

export type Theme = "light" | "dark" | "system";

const KEY = "kdt-theme";

export function stored(): Theme {
  try {
    const v = localStorage.getItem(KEY);
    if (v === "light" || v === "dark") return v;
  } catch {
    // Navigation privée, stockage bloqué : le thème du système fait l'affaire.
  }
  return "system";
}

export function apply(theme: Theme): void {
  const root = document.documentElement;
  if (theme === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", theme);

  try {
    if (theme === "system") localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, theme);
  } catch {
    // Sans persistance, le choix vaut pour l'onglet ouvert. Ce n'est pas une erreur.
  }
}

/** Ce que donnerait un basculement : l'inverse de ce qui est affiché en ce moment. */
export function toggled(current: Theme): Theme {
  const dark =
    current === "dark" ||
    (current === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  return dark ? "light" : "dark";
}
