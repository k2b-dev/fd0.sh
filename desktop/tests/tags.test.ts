import { expect, test } from "bun:test";
import fixtures from "../../internal/passitem/testdata/tags.json";
import { addTag, matchesItemTags, normalizeTags, readTags, suggestTags, tagCatalog, tagKey } from "../src/renderer/src/lib/tags";
import type { ItemSummary } from "../src/shared/contracts";

test("Go and Desktop share tag normalization and case matching", () => {
  for (const fixture of fixtures) {
    expect(normalizeTags(fixture.input)).toEqual(fixture.tags);
    expect(fixture.tags.map(tagKey)).toEqual(fixture.keys);
  }
  for (const value of [null, "Work", [1], [""], ["a\nb"], ["x".repeat(65)], ["\ud800"]]) {
    expect(() => normalizeTags(value)).toThrow();
    expect(readTags({ tags: value })).toEqual([]);
  }
  expect(() => normalizeTags(Array.from({ length: 33 }, (_, i) => `tag ${i}`))).toThrow();
  expect(normalizeTags(["🔑".repeat(64)])).toHaveLength(1);
});

test("suggestions stay inside the chosen vault and never replace fuzzy free text", () => {
  const item = (scopeId: string, tags: string[]): ItemSummary => ({ id: "id", scopeId, recordName: "Login", title: "Login", kind: "password", vault: scopeId, badge: "PASSWORD", tags });
  const items = [item("work", ["Work", "Team A"]), item("work", ["work"]), item("private", ["Private"]), { ...item("work", ["Infrastructure"]), kind: "ssh" as const }];
  const options = tagCatalog(items, "work");
  expect(options).toEqual([{ tag: "Infrastructure", count: 1 }, { tag: "Team A", count: 1 }, { tag: "Work", count: 2 }]);
  expect(suggestTags(options, [], "wo").map((option) => option.tag)).toEqual(["Work"]);
  expect(addTag([], "wo", options)).toEqual(["wo"]);
  expect(addTag([], "work", options)).toEqual(["Work"]);
  expect(suggestTags(options, ["Work"], "wo")).toEqual([]);
  expect(matchesItemTags(items[0]!, ["work", "Team A"], false)).toBe(true);
  expect(matchesItemTags(items[1]!, ["Work", "Team A"], false)).toBe(false);
  expect(matchesItemTags(items[0]!, [], true)).toBe(false);
  expect(matchesItemTags(item("work", []), [], true)).toBe(true);
});


test("native infrastructure casing stays selectable beside folded password tags", () => {
 const base: ItemSummary = {id:"host",scopeId:"work",recordName:"host:web",title:"web",kind:"ssh",vault:"work",badge:"SSH HOST",tags:["prod","Prod"]};
 const password: ItemSummary = {...base,id:"pass",recordName:"pass:login",kind:"password",badge:"PASSWORD",tags:["PROD"]};
 const catalog = tagCatalog([base,password]);
 expect(catalog.map(option => option.tag).sort()).toEqual(["Prod","prod"]);
 expect(catalog.every(option => option.count === 2)).toBe(true);
 expect(matchesItemTags(base,["PROD"],false)).toBe(false);
 expect(matchesItemTags(password,["prod"],false)).toBe(true);
});
