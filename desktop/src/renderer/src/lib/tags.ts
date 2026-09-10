import type { ItemSummary } from "../../../shared/contracts";

export function caseSensitiveTags(item: ItemSummary): boolean { return ["SSH HOST", "KUBE", "TALOS"].includes(item.badge); }

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
  const folded = new Map<string, TagOption>();
  const exact = new Map<string, TagOption>();
  for (const item of items) {
    if (scopeID && item.scopeId !== scopeID) continue;
    const sensitive = caseSensitiveTags(item);
    const tags = sensitive ? [...new Set((item.tags ?? []).flatMap(tag => readTags({ tags: [tag] })))] : readTags({ tags: item.tags });
    for (const tag of tags) {
      const options = sensitive ? exact : folded;
      const key = sensitive ? tag : tagKey(tag);
      const current = options.get(key);
      options.set(key, { tag: current && current.tag < tag ? current.tag : tag, count: (current?.count ?? 0) + 1 });
    }
  }
  // Each infrastructure spelling is a distinct selectable filter. Ordinary
  // items match every spelling, so include them in each matching count.
  const options = [...exact.values()].map(option => ({ ...option, count: option.count + (folded.get(tagKey(option.tag))?.count ?? 0) }));
  for (const option of folded.values()) {
    if (!options.some(candidate => tagKey(candidate.tag) === tagKey(option.tag))) options.push(option);
  }
  return options.sort((a, b) => tagKey(a.tag).localeCompare(tagKey(b.tag)) || a.tag.localeCompare(b.tag));
}

export function suggestTags(options: TagOption[], selected: string[], query: string, caseSensitive = false): TagOption[] {
  const key = tagKey(trimTag(query));
  const matchKey = caseSensitive ? (tag: string) => tag : tagKey;
  const used = new Set(selected.map(matchKey));
  return options.filter((option) => !used.has(matchKey(option.tag)) && tagKey(option.tag).includes(key))
    .sort((a, b) => Number(tagKey(b.tag).startsWith(key)) - Number(tagKey(a.tag).startsWith(key)))
    .slice(0, 8);
}

export function addTag(selected: string[], text: string, options: TagOption[], caseSensitive = false, rejectCommas = caseSensitive): string[] {
  const tag = trimTag(text);
  if (!tag) return selected;
  if (caseSensitive) {
    if (rejectCommas && tag.includes(",")) throw new Error("Host tags cannot contain commas.");
    normalizeTags([tag]);
    const result = selected.includes(tag) ? [...selected] : [...selected, tag];
    if (result.length > MAX_TAGS) throw new Error(`An item can have at most ${MAX_TAGS} tags.`);
    return result;
  }
  const existing = options.find((option) => tagKey(option.tag) === tagKey(tag));
  return normalizeTags([...selected, existing?.tag ?? tag]);
}

export function matchesItemTags(item: ItemSummary, tags: string[], untagged: boolean): boolean {
  if (!untagged && tags.length === 0) return true;
  const key = caseSensitiveTags(item) ? (tag: string) => tag : tagKey;
  const current = new Set((item.tags ?? []).map(key));
  return untagged ? current.size === 0 : tags.every((tag) => current.has(key(tag)));
}
