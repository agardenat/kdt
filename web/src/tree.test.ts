// Le pendant des tests de `flux.rs`, sur la moitié du pliage qui vit dans le navigateur.
//
// Ces cas sont ceux de `flux::tests` côté Rust, rejoués ici : c'est le même arbre, plié par un
// autre code, et deux implémentations d'une même règle ne restent d'accord que si on le vérifie.
// La subtilité qui justifie ces tests : « ancêtre d'un problème » n'est pas « en problème », et
// une branche peut être ouverte à cause d'un descendant qu'on ne voit pas.

import { describe, expect, it } from "vitest";
import { ancestorsOf, filterTree, hiddenUnder, revealed, visibleRows } from "./tree";
import type { FluxReady, FluxRow } from "./types";

function row(
  uid: string,
  depth: number,
  has_children: boolean,
  ready: FluxReady = "ready",
  suspended = false,
): FluxRow {
  return {
    uid,
    depth,
    has_children,
    ready,
    suspended,
    kind: "Kustomization",
    api_version: "kustomize.toolkit.fluxcd.io/v1",
    namespace: "default",
    name: uid,
    message: "",
    revision: "",
    age: "1d",
    prune: null,
    ready_label: ready,
    ready_tone: "ok",
    row_tone: "plain",
    no_prune: false,
    record: {} as FluxRow["record"],
  };
}

const names = (rows: FluxRow[]) => rows.map((r) => r.name).join(",");
const NONE = new Set<string>();

describe("ancestorsOf", () => {
  it("remonte la chaîne des profondeurs décroissantes", () => {
    const rows = [row("repo", 0, true), row("infra", 1, true), row("app", 2, false)];
    expect(ancestorsOf(rows, 2)).toEqual(["infra", "repo"]);
  });

  it("ne rend rien pour une racine", () => {
    expect(ancestorsOf([row("repo", 0, false)], 0)).toEqual([]);
  });
});

describe("visibleRows", () => {
  it("replie la descendance d'un nœud, mais pas le nœud lui-même", () => {
    const rows = [row("base", 0, true), row("app", 1, false), row("autre", 0, false)];
    expect(names(visibleRows(rows, new Set(["base"]), NONE))).toBe("base,autre");
  });

  it("laisse passer le frère d'une branche repliée", () => {
    // Le seuil de pli se lève dès qu'une ligne redescend à sa profondeur : sans ça, replier une
    // branche emporterait tout ce qui la suit au même niveau.
    const rows = [row("a", 0, true), row("b", 1, true), row("c", 2, false), row("d", 1, false)];
    expect(names(visibleRows(rows, new Set(["b"]), NONE))).toBe("a,b,d");
  });

  it("enjambe un pli révélé sans l'oublier", () => {
    // Le pli manuel n'est pas touché : c'est un override, et la branche se referme d'elle-même
    // dès que la révélation cesse.
    const rows = [row("base", 0, true), row("app", 1, false)];
    const folded = new Set(["base"]);
    expect(names(visibleRows(rows, folded, new Set(["base"])))).toBe("base,app");
    expect(names(visibleRows(rows, folded, NONE))).toBe("base");
  });
});

describe("hiddenUnder", () => {
  it("compte les problèmes de tout le sous-arbre, pas seulement des enfants directs", () => {
    const rows = [
      row("infra", 0, true),
      row("app", 1, true, "failed"),
      row("leaf", 2, false, "reconciling"),
    ];
    expect(hiddenUnder(rows, 0)).toEqual({ failed: 1, reconciling: 1 });
  });

  it("ne compte pas un échec suspendu", () => {
    // Suspendu est un état voulu, pas un problème à chasser : l'annoncer sous un pli enverrait
    // chercher une panne là où quelqu'un a délibérément appuyé sur pause.
    const rows = [row("infra", 0, true), row("leaf", 1, false, "failed", true)];
    expect(hiddenUnder(rows, 0)).toEqual({ failed: 0, reconciling: 0 });
  });

  it("n'annonce rien pour une branche saine", () => {
    const rows = [row("infra", 0, true), row("leaf", 1, false)];
    expect(hiddenUnder(rows, 0)).toEqual({ failed: 0, reconciling: 0 });
  });
});

describe("revealed", () => {
  it("ouvre les ancêtres d'un problème, et eux seuls", () => {
    const rows = [row("infra", 0, true), row("app", 1, true), row("leaf", 2, false, "failed")];
    const reveal = revealed(rows, null);
    expect([...reveal].sort()).toEqual(["app", "infra"]);
    // Le nœud en échec n'est pas son propre ancêtre : replié à la main, il le reste.
    expect(reveal.has("leaf")).toBe(false);
  });

  it("ouvre aussi la branche de la ligne qu'on lit, même si tout va bien", () => {
    // Sans ça, la branche qu'on est en train de lire se referme sous le curseur dès que la
    // réconciliation qu'elle montrait se termine.
    const rows = [row("infra", 0, true), row("app", 1, false)];
    expect([...revealed(rows, "app")]).toEqual(["infra"]);
  });

  it("ne révèle rien pour un uid que personne ne porte", () => {
    expect(revealed([row("infra", 0, false)], "nowhere").size).toBe(0);
  });

  it("ne révèle rien pour un échec suspendu", () => {
    const rows = [row("infra", 0, true), row("leaf", 1, false, "failed", true)];
    expect(revealed(rows, null).size).toBe(0);
  });
});

describe("filterTree", () => {
  it("garde le chemin jusqu'à ce qui correspond", () => {
    // Filtrer ligne à ligne casserait l'arbre : les enfants d'une ligne écartée se retrouveraient
    // rattachés à n'importe quoi et la profondeur ne voudrait plus rien dire.
    const rows = [row("repo", 0, true), row("infra", 1, true), row("app", 2, false)];
    expect(names(filterTree(rows, "app"))).toBe("repo,infra,app");
  });

  it("rend tout quand le filtre est vide", () => {
    const rows = [row("repo", 0, false)];
    expect(filterTree(rows, "")).toBe(rows);
  });

  it("ne rend rien quand rien ne correspond", () => {
    expect(filterTree([row("repo", 0, false)], "zzz")).toEqual([]);
  });
});
