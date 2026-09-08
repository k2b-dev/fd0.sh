import type { ItemSummary } from "../../../shared/contracts";

export const MAX_TAGS = 32;
export const MAX_TAG_CHARACTERS = 64;

// Match Go's single-code-point upper/lower mappings (no locale or expansions).
export function tagKey(tag: string): string {
  return [...tag.normalize("NFC")].map((char) => {
    const upper = [...char.toUpperCase()];
    return [...(upper.length === 1 ? upper[0]! : char).toLowerCase()][0]!;
  }).join("");
}

export function trimTag(tag: string): string {
  return tag.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "").normalize("NFC");
}

export function normalizeTags(value: unknown): string[] {
  if (!Array.isArray(value)) throw new Error("Tags must be a list of text values.");
  const result: string[] = [];
  const seen = new Set<string>();
  for (const raw of value) {
    if (typeof raw !== "string") throw new Error("Tags must be a list of text values.");
    const tag = trimTag(raw);
    if (!tag || [...tag].length > MAX_TAG_CHARACTERS) throw new Error(`Each tag needs 1–${MAX_TAG_CHARACTERS} characters.`);
    if (/[\p{Cc}\p{Cs}]/u.test(tag)) throw new Error("Tags cannot contain control characters or invalid text.");
    const key = tagKey(tag);
    if (!seen.has(key)) { result.push(tag); seen.add(key); }
    if (result.length > MAX_TAGS) throw new Error(`An item can have at most ${MAX_TAGS} tags.`);
  }
  return result;
}

export function readTags(meta: unknown): string[] {
  if (!meta || typeof meta !== "object" || !("tags" in meta)) return [];
  try { return normalizeTags(meta.tags); } catch { return []; }
}

export type TagOption = { tag: string; count: number };

export function tagCatalog(items: ItemSummary[], scopeID = ""): TagOption[] {
  const options = new Map<string, TagOption>();
  for (const item of items) {
    if (item.kind !== "password" || (scopeID && item.scopeId !== scopeID)) continue;
    for (const tag of readTags({ tags: item.tags })) {
      const key = tagKey(tag);
      const current = options.get(key);
      options.set(key, { tag: current && current.tag < tag ? current.tag : tag, count: (current?.count ?? 0) + 1 });
    }
  }
  return [...options.values()].sort((a, b) => tagKey(a.tag).localeCompare(tagKey(b.tag)));
}

export function suggestTags(options: TagOption[], selected: string[], query: string): TagOption[] {
  const key = tagKey(trimTag(query));
  const used = new Set(selected.map(tagKey));
  return options.filter((option) => !used.has(tagKey(option.tag)) && tagKey(option.tag).includes(key))
    .sort((a, b) => Number(tagKey(b.tag).startsWith(key)) - Number(tagKey(a.tag).startsWith(key)))
    .slice(0, 8);
}

export function addTag(selected: string[], text: string, options: TagOption[]): string[] {
  const tag = trimTag(text);
  if (!tag) return selected;
  const existing = options.find((option) => tagKey(option.tag) === tagKey(tag));
  return normalizeTags([...selected, existing?.tag ?? tag]);
}

export function matchesItemTags(item: ItemSummary, tags: string[], untagged: boolean): boolean {
  if (!untagged && tags.length === 0) return true;
  if (item.kind !== "password") return false;
  const current = new Set((item.tags ?? []).map(tagKey));
  return untagged ? current.size === 0 : tags.every((tag) => current.has(tagKey(tag)));
}
