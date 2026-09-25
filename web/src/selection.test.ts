import { describe, expect, it } from "vitest";
import { resolveSelection, type Owner } from "./selection";

const deploy: Owner = { key: "d", label: "Deployment web" };
const owners = new Map<string, Owner>([
  ["p1", deploy],
  ["p2", deploy],
  ["p3", deploy],
]);

describe("resolveSelection", () => {
  it("un parent coché couvre ses enfants sans les envoyer à la suppression", () => {
    const { checked, shown } = resolveSelection(new Set(["d"]), owners);
    expect([...checked]).toEqual(["d"]);
    expect([...shown].sort()).toEqual(["d", "p1", "p2", "p3"]);
  });

  it("un enfant coché sous un parent coché ne part pas deux fois", () => {
    const { checked } = resolveSelection(new Set(["p1", "d"]), owners);
    expect([...checked]).toEqual(["d"]);
  });

  it("tous les enfants cochés ne cochent pas le parent : il passe seulement en indéterminé", () => {
    const { checked, shown, partial } = resolveSelection(new Set(["p1", "p2", "p3"]), owners);
    expect(checked.has("d")).toBe(false);
    expect(shown.has("d")).toBe(false);
    expect(partial.has("d")).toBe(true);
  });

  it("la cascade traverse les étages d'une chaîne possédée", () => {
    const chain = new Map<string, Owner>([
      ["cr", { key: "cert", label: "Certificate tls" }],
      ["order", { key: "cr", label: "CertRequest tls-1" }],
      ["chal", { key: "order", label: "Order tls-1-1" }],
    ]);
    const { checked, shown } = resolveSelection(new Set(["cert", "chal"]), chain);
    expect([...checked]).toEqual(["cert"]);
    expect([...shown].sort()).toEqual(["cert", "chal", "cr", "order"]);
  });

  it("sans possession, la sélection reste plate", () => {
    const { checked, shown, partial } = resolveSelection(new Set(["a", "b"]), new Map());
    expect([...checked].sort()).toEqual(["a", "b"]);
    expect([...shown].sort()).toEqual(["a", "b"]);
    expect(partial.size).toBe(0);
  });

  it("un enfant disparu du cluster ne laisse pas son parent en indéterminé", () => {
    const { partial } = resolveSelection(new Set(["gone"]), owners);
    expect(partial.size).toBe(0);
  });
});
