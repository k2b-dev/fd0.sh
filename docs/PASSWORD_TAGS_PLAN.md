# Password tags plan

Status: implemented and verified locally on 2026-09-08. No installation, commit, or release performed.

## Outcome and scope

Organize password items with free-text tags in Desktop and the CLI. Desktop suggests tags already used by accessible password items in the selected vault. Tags are encrypted item metadata and travel with the item through sync, history, export, restore, duplication, and moves. They do not change sharing or permissions.

Use optional `meta.tags: string[]` in the existing `fd0.pass.item` payload. No server changes, protocol version bump, or migration are required. Older items without tags remain valid. This first version covers password items only; SSH host tags retain their existing meaning.

Do not add folders, tag IDs, a separate tag registry, global rename/delete, colors, nested tags, bulk editing, or a browser-extension tag editor. Existing alphabetical item ordering remains; tags provide filtering rather than manual ordering.

## Tag contract

- Missing `meta.tags` and an empty array both mean no tags. Store an empty array when explicitly clearing tags through an update.
- Normalize surrounding whitespace and Unicode NFC. Keep internal spaces and the entered spelling. Compare tags without case sensitivity; `Work` and `work` are one tag for deduplication, suggestions, and filtering. Use equivalent Go/TypeScript comparison behavior with shared edge-case fixtures.
- Preserve the first spelling within an item. Suggestions prefer an existing spelling in the selected vault; do not rewrite other items when a user enters a different spelling.
- Limits: 32 tags per item, 64 Unicode characters per tag. Reject control characters and invalid writes with a field-level error. Do not silently truncate user input.
- The reader treats missing or malformed optional tag metadata as unavailable without making an otherwise valid password unreadable. Ordinary edits must preserve unknown metadata. Explicit tag writes require a valid array of valid strings.
- Adding an existing tag and removing an absent tag are idempotent and do not create a new revision when nothing changes. Updating tags uses the existing authorized item write, revision, history, and sync paths.

## Storage and compatibility

`internal/passitem/passitem.go` already carries arbitrary metadata. `Touch` changes only timestamps/revision. CLI and browser updates generally mutate decoded items, preserving their metadata.

Before this feature, `ItemEditor` sent title, URLs and fields without metadata. The bridge copied old metadata only when the incoming metadata map was nil. Sending only `{tags: [...]}` would have lost existing favorites and other metadata; `preparePassSave` now merges explicit tag changes into stored metadata.

The bridge must load the current stored item, retain its metadata, and apply only the explicitly supplied tag change. Preserve existing tags when omitted; clear them when explicitly supplied as `[]`. Desktop sends tags on creation or when the user changes them, so an ordinary edit cannot overwrite newer tag metadata or erase malformed metadata it did not understand. Keep the existing request shape by using `item.meta.tags`, not a new top-level bridge parameter. Creation must still initialize timestamps/revision when tags are supplied. Do not copy revision/timestamp/favorite metadata when duplicating: start a new item and copy its content and tags deliberately.

Add optional `tags` to safe Desktop inventory summaries and CLI summary JSON; keep all existing output fields. Derive suggestion lists/counts from authorized password inventory, grouped by scope ID. No separate persistent index or per-keystroke vault reads. Never derive suggestions from secret field values. If the inventory is truncated, suggestions are only from loaded items and the existing incomplete-inventory notice remains visible.

Compatibility acceptance must include the released Desktop 0.3.1 and CLI 0.14.0 write paths using synthetic fixtures. Test tags surviving an ordinary edit, password/browser update, rename, move, and serialization round trip. Do not promise compatibility with every historical binary without checking it. Existing older-client support for decoding metadata is not sufficient proof of preservation on writes.

## Desktop experience

### Editing

- Add an optional Tags field to the password editor, adjacent to its basic details, separate from secret fields.
- Display selected tags as removable chips followed by a free-text input. Tags may contain spaces; Enter commits one complete tag. Do not split normal text on spaces or commas.
- Show matching suggestions from the editor's currently selected vault, excluding selected tags. Prefer prefix matches, followed by substring matches, sorted consistently. Show a small bounded set rather than an unbounded popup.
- Show `Add "<text>"` for a new tag. With no explicitly selected suggestion, Enter commits the literal input. Arrow keys choose suggestions; Enter/click accepts the chosen suggestion. An exact case-insensitive match uses the existing spelling; fuzzy matches are never silently accepted.
- Tab commits nonempty literal input and continues normal focus navigation. Blur or Save must not discard pending text. Empty input does nothing. Escape closes suggestions before it can close the editor; it never commits an arbitrary suggestion.
- Keep the popup inside the existing `Popover`/`overlayStack` model. Provide combobox/listbox semantics, visible focus, accessible remove labels and validation feedback. Removing a chip must not unexpectedly delete input text.
- Changing the target vault refreshes suggestions but preserves already selected tags. Cancel changes nothing. Save failures retain the draft. Dirty-state detection includes committed tags and pending text.
- Initialize tags when editing and duplicating. Moving an existing item preserves its tags; it then contributes suggestions in the destination vault.

### Finding items

- Show clickable tag chips in the password detail header. Clicking a tag opens the password list with that exact tag filter.
- Add a compact Tags filter to the password list header. Reuse removable active-filter chips and Reset filters. Include `Without tags`.
- Multiple selected tags mean ALL selected tags, both in Desktop and CLI. Label this clearly. `Without tags` is mutually exclusive with specific tags.
- Combine tag filtering with vault, favorites, and text search. With one vault selected, filter suggestions are scoped to it; in All vaults, derive the union of accessible password tags. Changing vault removes unavailable tag filters so they cannot invisibly empty the list.
- Add tags to the ordinary password search, command palette search and CLI interactive browser search. Preserve exact URL/origin matching rules used for credential selection/autofill.
- Show at most two small tags plus a remaining count in normal list rows; compact rows stay compact, with full tags available in details. Wrap chips in editors/details on narrow windows. Cover light/dark, empty, disabled, focus and error states.

## CLI interface

Follow the existing noun/subcommand and `--scope` conventions:

```sh
fd0 pass add GitHub --scope work --tag Development --tag "Team A"
fd0 pass tags add GitHub Development "Team A" --scope work
fd0 pass tags rm GitHub "Team A" --scope work
fd0 pass tags clear GitHub --scope work
fd0 pass tags list --scope work --json
fd0 pass list --scope work --tag Development
fd0 pass find github --scope work --tag Development
fd0 pass browse --scope work --tag Development
fd0 pass list --scope work --untagged
```

- `tags list` lists existing tags and item counts, grouped by scope when no scope is selected. JSON uses stable explicit scope/tag/count fields and returns an empty array when there are none.
- `tags add`/`rm` accept multiple positional tags; `clear` removes all tags from the selected item. Resolve ambiguous item names with existing scope rules; never mutate multiple matching items implicitly.
- `--tag` is repeatable on add/list/find/browse; filter repetitions use AND. Reject combining `--untagged` with `--tag`. Preserve existing behavior when new flags are absent.
- `pass show` includes tags alongside other safe metadata; list/find JSON gains an optional tags array. Keep default list/find columns unchanged to avoid breaking existing output consumers. Users can inspect tags with show/JSON/catalog commands.
- `pass edit` continues to preserve tags. Use the dedicated tags commands for tag mutation rather than adding a second overlapping replacement interface.
- Keep stdout machine-readable for JSON; diagnostics remain on stderr. Catalog, search and tag operations never reveal password values.
- Use explicit commands for CLI discoverability in this version. Do not add shell completion that unexpectedly unlocks a vault or starts an agent on Tab.

## Implementation sequence and acceptance

1. **Domain and bridge:** normalization/access/update helpers, metadata merge, creation initialization, optional inventory projection and compatibility fixtures. Prove omitted-versus-empty behavior and preservation of favorites/unknown metadata.
2. **CLI:** commands, help, filtering, safe JSON/catalog output and interactive search. Parser and isolated command tests prove idempotency, exact scope targeting and AND/untagged behavior.
3. **Desktop:** editor tags, vault-local suggestions, draft initialization/duplication, details/list display and filters. Synthetic component tests cover keyboard input, exact/fuzzy suggestions, scope changes, clearing, unsaved text and safe errors.
4. **Documentation and verification:** update the existing CLI/Desktop/password user documentation and bundled fd0 skill references. Verify cross-client round trips, empty/invalid metadata, history/move/export preservation, typecheck and focused UI rendering.

Do not run elaborate local click-through tests. Any local behavioral tests must use fake bridge APIs or explicitly isolated temporary fd0 homes, sockets and SSH config paths; no production app, agent, vault, CLI wrappers or installation may be touched. Prefer pure domain and synthetic component tests locally and existing isolated CI for broader checks. Any historical-binary checks run on isolated CI or fixtures, never against the installed production instance.

Implementation was authorized after planning. Commit and release remain separate actions. A later additive feature release would normally use the next Desktop/CLI minor versions; determine exact tags at release time.

## Verification evidence

- Shared Go/TypeScript normalization fixtures, optional/malformed metadata, metadata merging, fresh creation, JSON round trips, CLI parser/filter/catalog behavior, and idempotent tag updates pass.
- An in-process agent with a temporary vault, socket and SSH configuration verifies CLI edits, browser password updates, rename, move, clear and history restore. Historical CLI 0.14.0 and Desktop 0.3.1 bridge binaries built from repository release sources preserve tags when editing this test vault. The historical bridge source is identical in both release tags.
- Thirteen focused Desktop tests pass, including the existing reveal regression tests. Tag coverage includes free text, explicit/exact suggestions, Tab/Escape, vault changes, empty and invalid input, failed saves, AND/untagged filters, and narrow layouts. Synthetic screenshots were inspected in light and dark themes.
- Desktop typecheck, Go vet for affected packages, and the website build pass. User documentation and the bundled fd0 skill describe the new commands and UI.
- No production fd0 app, installed wrapper, agent or vault was used. No Electron click-through or release/package installation was performed. Live remote sync was not exercised; tags use the existing encrypted item serialization and history paths.
