# fd0 HTTP API (v1)

Companion to `PROTOCOL.md`. Requests and responses use `application/cbor` with deterministic CBOR (RFC 8949 §4.2.1) unless noted. Authentication is per-request via signed headers; no sessions, no cookies.

## Contents

1. [Authentication header](#1-authentication-header)
2. [Endpoints](#2-endpoints) — `/v1/users`, `/v1/sync`, `/health`,
   `/version`.
3. [Status codes](#3-status-codes)

Translog endpoints (`/v1/server-info`, `/v1/chains`, `/v1/sth/...`,
`/v1/proof/inclusion`, `/v1/proof/consistency`) are documented in
`TRANSLOG.md` §5. Witness endpoints (`/v1/...`) are in
`TRANSLOG.md` §8.3.

---

## 1. Authentication header

```
Authorization: fd0-sig v1
    pk=<base64(super_pub)>,
    nonce=<base64(16 random bytes)>,
    ts=<unix_seconds>,
    sig=<base64(signature)>

signed_input = "fd0-http-request-v1" || cbor({
    method     : <uppercase HTTP method>,
    path       : <URL path, no query>,
    query      : { * tstr => tstr },        ; canonical: keys sorted lexicographically;
                                             ; multi-value keys forbidden in v1
    ts         : ts,
    nonce      : nonce,
    body_sha   : SHA-256(request body, or SHA-256("") if empty),
    server_pub : <recipient server's translog pubkey>,
})
signature = Ed25519(super_priv, signed_input)
```

`server_pub` binds the signature to a specific server (T21) — clients use the pinned translog pubkey from `/v1/server-info`.

Server checks (in `verifyHTTPSig`, in order):

```
1. per-IP pre-auth rate limit                → else 429
2. header well-formed (scheme, pk, nonce, ts, sig sizes) → else 401 bad scheme/pk/nonce/ts/sig
3. |now - ts| ≤ 300 s                        → else 401 stale_ts
4. read body; reject multi-value query keys  → else 400
5. build signed_input; signature verifies    → else 401 bad_sig
6. pk is a registered user                   → else 401 unregistered_pk
7. (pk, nonce) inserted into nonce table (ts stored) → else 401 replay
8. per-pubkey post-auth rate limit           → else 429
```

Per-endpoint authorization runs after `verifyHTTPSig`. Examples: `GET /v1/users/<shortId>/events` requires `pk == user_super_pub` (else 403); `/v1/sync` push items return `bad_author` per item when `author ≠ pk`; `/v1/sync` pull of a non-member scope returns `200` with `denied: true` (not 403).

`POST /v1/users` is unauthenticated; the embedded event signature provides binding to the new identity. All other authenticated user-chain endpoints additionally require the signing pubkey to equal the chain's `user_super_pub`.

---

## 2. Endpoints

### 2.1 `POST /v1/users` — register identity

```
Request:
{ event : UserEvent }                       ; kind = "auth.set", seq = 0

201 Created:
{
    shortId  : tstr,                        ; server-assigned, 8 chars
    event_id : tstr,
}

Errors:
  400 bad_event        schema, kind, or signature invariant (incl. signature does not verify)
  409 super_pub_taken  user_super_pub already registered
```

### 2.2 `GET /v1/users/<shortId>/events` — fetch identity chain

Authenticated. `pk` MUST equal the chain's `user_super_pub`.

Query modes:

- `?since=<seq>`: events with seq ≥ since, ascending.
- `?latest=true`: only the latest `auth.set` event.

```
200 OK (since mode):
{
    user_super_pub : bstr .size 32,
    events         : [* UserEvent],
    chain_tip_seq  : uint,
    chain_tip_hash : bstr .size 32,
}

200 OK (latest mode):
{
    user_super_pub : bstr .size 32,
    event          : UserEvent,
    chain_tip_seq  : uint,
    chain_tip_hash : bstr .size 32,
}

404 not_found
```

### 2.3 `POST /v1/users/<shortId>/events` — append to identity chain

Authenticated. `pk` MUST equal the chain's `user_super_pub`.

```
Request:
{ event : UserEvent }                       ; kind = "auth.set", seq > 0

200 OK:
{ event_id : tstr, seq : uint }

Errors:
  400 bad_event        schema, kind, or signature invariant (e.g., empty active set,
                       signature does not verify)
  409 divergence       prev_hash does not match chain tip
                       (response includes current_tip_seq, current_tip_hash)
  409 dup              event_id already exists
```

### 2.4 `POST /v1/sync` — pull, push, discover

Authenticated.

```
Request:
{
    pull : {
        scopes               : { * tstr => { cursor: { seq: uint, hash: bstr .size 32 / nil } } },
        limit_per_scope      : uint,             ; default 100, max 1000
        discover_memberships : bool,             ; optional, default false
        membership_after     : tstr,             ; optional pagination cursor
        membership_limit     : uint,             ; optional, default/max 256
    },
    push : [* { scope: tstr, event: ScopeEvent }],
}

200 OK:
{
    pull : { * tstr => {
        tip             : { seq: uint, hash: bstr .size 32 },
        oek_version_max : uint,
        events          : [* ScopeEvent],   ; contiguous, ascending from cursor.seq + 1
    } },
    memberships : [* {                       ; present iff request.pull.discover_memberships
        scope_id     : tstr,
        admit_event  : tstr,                 ; event_id of the member.change op="add" of self
        oek_version  : uint,
    }],
    memberships_next_after : tstr,           ; present when another page exists
    push : [* PushResult],
}

PushResult =
    { accepted: true,  event_id: tstr, seq: uint, scope_id: tstr } /
    { accepted: false, reason: tstr, ... }
```

`pull` returns events contiguous from `cursor.seq + 1`. Clients verify the chain link to their stored `cursor.hash` before advancing the cursor.

A sync request accepts at most 256 pull scopes and 64 push items. Pull
responses return at most 1024 events and 48 MiB of encoded event bytes in
aggregate; when several scopes are requested, the server lowers the effective
per-scope page size and serves lower cursors first. Clients repeat membership
discovery with `memberships_next_after`, bound pages per invocation, and persist
the continuation cursor per server so later syncs retain complete coverage.
Push rate accounting charges every submitted item, not only the enclosing
request.

Pagination-capable clients send a non-zero `membership_limit` (fd0 uses 32).
For compatibility, a request that omits the field still receives a complete
single page when the user has at most 256 memberships. If more rows exist, the
server returns `426 membership_pagination_required` instead of silently hiding
later scopes; upgrading the client resumes discovery without changing stored
scope data.

**Push cardinality invariant.** For every `/v1/sync` request, `len(response.push)` MUST equal `len(request.push)` — exactly one `PushResult` per submitted push item, in order, on a `200` response (including push-only requests with an empty `pull`). If the server cannot process a push item it MUST return a `PushResult` with `accepted: false` and a `reason`, never omit it. Clients rely on this 1:1 mapping to disposition each pushed event; a count mismatch on a `200` is a protocol violation and clients reject it. Non-`2xx` responses (e.g. `429` rate-limit) carry no `push` array at all — clients MUST check the HTTP status before decoding rather than treating a missing array as zero results.

Push reasons (always with `accepted: false`):

| reason                    | meaning                                                          |
| ------------------------- | ---------------------------------------------------------------- |
| `bad_sig`                 | event signature does not verify                                  |
| `bad_author`              | event author ≠ HTTP auth pk                                      |
| `bad_kind`                | unrecognised kind or generic schema invariant                    |
| `divergence`              | `prev_hash` or seq mismatch                                      |
| `stale_oek_version`       | event's `oek_version` < server's current                         |
| `future_oek_version`      | event's `oek_version` > server's current                         |
| `invalid_key_deliveries`  | recipient set doesn't match post-mutation member set             |
| `scope_mismatch`          | `signed_prefix.scope` ≠ outer push frame `scope`                 |
| `not_found`               | scope unknown                                                    |
| `out_of_range`            | translog index/size invalid for this chain                       |
| `internal`                | server-side error                                                |
| `dup`                     | `event_id` already stored; idempotent — reply still carries `event_id`, `seq`, `scope_id`, STH, inclusion proof, and (if requested) consistency proof |

Scope creation has no dedicated endpoint: a scope is created by pushing a `member.change` with `prev_hash=nil`, `op="add"`, `member == author`, and one `KeyDelivery` to the author. The server derives `scope_id = "s_" + base32(truncate_128(SHA-256(event_id)))` and assigns it in the `PushResult`.

### 2.5 `GET /health`

Liveness probe. Unauthenticated, version-neutral.

```
200 OK
Content-Type: application/json
{
    "status"  : "ok",
    "service" : "fd0-server",
    "version" : "x.y.z"
}
```

### 2.6 `GET /version`

```
200 OK
Content-Type: application/json
{
    "service"        : "fd0-server",
    "server_version" : "x.y.z",
    "api_version"    : "v1"
}
```

### 2.6a `GET /v1/capabilities`

```
200 OK
Content-Type: application/json
{ "scopeRoles": true }
```

Unsigned feature list. Clients check it before authoring scope role events so
they do not create events an older server would reject; it is not an
authorization signal. The signed `/v1/server-info` record is unchanged.

### 2.7 `GET /metrics`

Prometheus exposition. RED metrics (requests, errors, duration, in-flight, response bytes) plus the standard process + Go runtime collectors. Guarded by a bearer token when `FD0_METRICS_TOKEN` is set; otherwise serves openly.

```
200 OK
Content-Type: text/plain; version=0.0.4
# HELP fd0_http_requests_total HTTP requests processed, partitioned by service, operation and status class.
# TYPE fd0_http_requests_total counter
fd0_http_requests_total{service="fd0-server",op="POST /v1/sync",status_class="2xx"} 1247
...
```

Set `Authorization: Bearer <token>` when the env is configured. Unauthorised requests return `404 Not Found` — the endpoint never confirms its own existence to anonymous scrapers.

### 2.8 `GET /v1/chains`

Unauthenticated, bounded witness discovery.

```
GET /v1/chains?after=<chain_id>&limit=256

200 OK:
{
    "chains":     [* tstr],
    "next_after": tstr        ; absent on the final page
}
```

`limit` defaults to 1024 and is capped at 1024. Results are ordered by
`chain_id`. Witnesses continue with `next_after`; explicit configured chains
remain active independently of discovery pagination.

---

## 3. Status codes

| Code | Meaning                                                |
| ---- | ------------------------------------------------------ |
| 200  | OK                                                     |
| 201  | Created                                                |
| 400  | Malformed body, invariant violation                    |
| 401  | Auth header invalid, missing, or replayed              |
| 403  | Authenticated but not authorized (e.g. user-chain owner mismatch) |
| 404  | User or scope not found                                |
| 409  | Divergence, duplicate, or version conflict             |
| 413  | Payload exceeds limit (`STORAGE.md` §9)                |
| 426  | Client upgrade required for paginated membership discovery |
| 429  | Rate limit exceeded (`STORAGE.md` §9)                  |
| 500  | Server error                                           |
