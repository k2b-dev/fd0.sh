# Scope roles plan

Status: implemented 2026-10-02 after design and code peer reviews (protocol, server, CLI, Desktop). Phase B of docs/MACHINE_IDENTITIES_PLAN.md.

## Outcome and scope

Today every scope member can write values and change membership. Add three member roles so people can give a machine, an agent or a colleague less than full control:

| Role | Read values | `secret.set` | `member.change` (add, remove, role) |
| --- | --- | --- | --- |
| `admin` | yes | yes | yes |
| `writer` | yes | yes | no |
| `reader` | yes | no | no |

Every member still receives the scope's OEK, so roles limit what a member can sign into the chain, not what it can read or disclose. Removing a member stops future key delivery; values it already saw must be rotated.

Not in scope: per-item permissions, hiding values from readers, time-limited roles, roles on the user chain.

## Protocol

- `member.change` payload gains an optional `role` (`"admin" / "writer" / "reader"`). Events without it keep their exact bytes; a missing role means `admin`. Every existing member stays an admin until an admin assigns a narrower role.
- `add` may carry a role (missing = admin). `remove` must not carry one.
- New op `role` changes an existing member's role: target must be a member, the role must change, `oek_version` stays the prior maximum, and there are no key deliveries and no projection. Read access is unchanged, so no rotation is needed.
- Genesis: the author is an admin; a genesis role other than `admin` is invalid.
- Authorization, implemented once as a pure function used by both the server validator and client replay, evaluated against the **prior** roles:
  - `secret.set`: author is `writer` or `admin`.
  - `member.change` (any op): author is `admin`.
- **Last admin**, evaluated against the **post** state: an event that leaves a non-empty scope without an admin is invalid. Removing the last member altogether still tombstones the scope.
- **Leaving** as reader or writer is local: `fd0 scope leave` drops the scope from the device and asks the user to have an admin remove them. Unilateral cryptographic self-removal by non-admins is not allowed, because the leaving member would author the replacement OEK deliveries and projection for everyone else.
- Server: `ScopeMeta` gains `roles` (member pub → role; missing = admin). The `scope_members` discovery index stays role-free; roles are authoritative only from the chain and its metadata.
- Client: `ScopeState` tracks roles; replay rejects any event the rules forbid, including events before our own admission, so a misbehaving or older server cannot make a client accept them. Writes are checked before the local append, so a reader never signs an event it is not allowed to make.
- Pending membership intents in sync reconciliation keep the requested role and are re-authorized after rebasing.

## Compatibility

- A client or server that does not know `role` drops it when re-encoding the signed prefix, the signature fails, and it rejects the event. Older software therefore cannot process scopes that use roles, which is the intended fail-closed behaviour for honest events.
- **No downgrade after roles are used:** an older server started on a database whose metadata carries roles would drop them and accept forbidden writes, which upgraded clients would then reject, blocking the scope. Release notes state this; the server refuses to start if its stored schema marker is newer than it knows.
- The server advertises support at an unsigned `GET /v1/capabilities` (`{"scopeRoles": true}`). The existing signed server info stays byte-identical. The capability is a usability guard: clients refuse to author role events against servers without it. Enforcement is the validator and replay, not the capability.
- Scopes that never use roles keep working with every client and server version.

## CLI and Desktop

```sh
fd0 scope add-member CARD --scope S [--role admin|writer|reader]   # default admin, as today
fd0 scope role CARD ROLE --scope S
fd0 scope members [S]                                               # shows each member's role
```

Desktop shows each member's role and lets admins change it in member management. Readers and writers see membership read-only and can leave locally.

## Threat model changes

- A compromised `reader` can read and disclose every value in its scopes; it cannot sign value or membership changes.
- A compromised `writer` can also alter or delete values and the scope's name and organization tags (stored as an ordinary record). Like any member today it can submit events other clients cannot decrypt, which blocks replay of that scope (THREATS.md T28); recovery is a new scope.
- A compromised `admin` is unchanged from today.
- THREATS.md gains entries for role enforcement, the leave model and the no-downgrade rule.

## Implementation order

1. `proto`: `role` payload field, `role` op, role constants, the shared authorization and last-admin function with table tests.
2. Server validator and metadata.
3. Client replay and builders; local author-time checks for every write path (plain and typed writes, moves, restore, metadata).
4. CLI: `--role`, `scope role`, role display, local-only leave for non-admins, reconciliation intents.
5. `GET /v1/capabilities` and the client guard; schema marker for no-downgrade.
6. Desktop member roles, docs, THREATS.md, guarded integration test (machine as reader: reads, cannot write, cannot add members).
