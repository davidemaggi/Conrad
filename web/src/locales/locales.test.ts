import { describe, expect, it } from "vitest";
import en from "./en.json";
import itL from "./it.json";

type Tree = { [k: string]: string | Tree };

function keys(t: Tree, p = ""): string[] {
  return Object.entries(t).flatMap(([k, v]) => (typeof v === "string" ? [p + k] : keys(v, p + k + ".")));
}

function vars(s: string): string[] {
  return [...s.matchAll(/\{\{(\w+)\}\}|<(\w+)>/g)].map((m) => m[1] ?? m[2]).sort();
}

describe("locales", () => {
  it("en and it have the same keys", () => {
    expect(keys(itL as Tree).sort()).toEqual(keys(en as Tree).sort());
  });

  it("translations keep the same placeholders", () => {
    const get = (t: Tree, k: string) => k.split(".").reduce<string | Tree>((o, p) => (o as Tree)[p], t) as string;
    for (const k of keys(en as Tree)) {
      expect([k, vars(get(itL as Tree, k))]).toEqual([k, vars(get(en as Tree, k))]);
    }
  });
});
