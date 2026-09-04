---
name: oneiron-http-memory-api
description: "Use this skill when an external agent needs to discover Oneiron's current HTTP memory API, fetch the static skill pack from a running server, choose the right endpoint, and understand how read, retrieval, context-pack, discovery, and lease-revocation calls relate to Oneiron MCP tools."
when_to_use:
  - "An agent needs route-level awareness of the existing Oneiron HTTP API."
  - "An agent must decide whether to search memory, read one entity, inspect edges, assemble context, resume companion state, discover vault capabilities, fetch the skill pack, inspect the OpenAPI schema, or revoke a device lease."
  - "A connector needs the static skill layer: how to think about memory before it calls MCP or HTTP tools."
trigger_phrases:
  - "query Oneiron memory"
  - "search the vault"
  - "read an entity"
  - "get context pack"
  - "resume companion state"
  - "discover Oneiron capabilities"
  - "fetch Oneiron skill pack"
  - "inspect OpenAPI schema"
  - "revoke a lease"
---

# Oneiron HTTP Memory API Skill Pack

> **Fetch by tier, not whole-file.** This document is ~43KB, past most agents' single-read
> truncation threshold. Read Tier-1 (endpoint index) first; fetch Tier-2 (endpoint detail) or
> Tier-3 (schemas/error catalog) only for the specific endpoints in play.

This pack is a static, agentskills.io-compatible progressive disclosure artifact for the currently exposed Oneiron HTTP routes. The pack content is documentation only; the HTTP distribution endpoint serves this committed artifact without adding storage, mutation behavior, MCP tools, or activation logic.

The boundary is dual-layer:

- Skills are how to think about memory: when to search, when to inspect graph edges, when to assemble a context pack, when to treat a result as raw evidence, and when to recover from errors.
- MCP tools are what to call: the executable capability surface advertised by MCP `initialize.instructions`, tool listings, and tool schemas.

Keep those layers aligned but not duplicated. This pack names the live HTTP route semantics once. MCP initialization should advertise callable tools, scopes, safety hints, and handles. Any AGENTS.md-style discovery artifact should point to this pack and the MCP advertisement rather than carrying a second divergent endpoint catalog.

ARCH-0006a/b conversation endpoints are design documents, not live routes in the current server route table. They are intentionally excluded from the live endpoint catalog until the server registers them.

## Agent Onramp: Choose One Lane

Four carriers, one API. The lanes differ only in packaging: same routes, same
`Authorization: Bearer` credential, same actor and Gate decisions, same paging and
end markers, same error envelope. Pick the first lane you can actually run, make
one call, then read the endpoint catalog below only for the routes that call needs.

```text
Does your sandbox bind the host dispatcher self.oneiron?
  yes -> lane 1: code-mode-repl   (setup_oneiron, then self.oneiron)
  no  -> Can you npm install one package AND run TypeScript (Bun)?
           yes -> lane 2: thin-client   (@oneiron/client)
           no  -> Do you have bash with curl (>= 7.76)?
                    yes -> lane 3: curl-cli   (oneiron api ..., or plain curl)
                    no  -> lane 4: tool-first-mcp   (ask your operator for the endpoint)
```

1. Does your sandbox bind Oneiron as the host dispatcher `self.oneiron`? Use
   [code-mode-repl](#lane-code-mode-repl). A generic REPL is not enough: this release
   registers `execute_code` nowhere.
2. Otherwise, can you `npm install` one package AND run TypeScript? Use
   [thin-client](#lane-thin-client). The package ships TypeScript source, so the
   runtime must load it: Bun 1.3+, not plain `node`.
3. Otherwise, do you have bash with `curl` 7.76 or newer (for `--fail-with-body`)?
   Use [curl-cli](#lane-curl-cli). `oneiron api` spawns that same curl.
4. Otherwise, ask your operator to register or provide the distinct tool-first MCP endpoint: [tool-first-mcp](#lane-tool-first-mcp).

Written once for every lane, never repeated per lane: [Authentication](#authentication),
[Tier-1 endpoint index](#tier-1-endpoint-activation-index),
[Tier-2 endpoint details](#tier-2-endpoint-details), and
[Tier-3 schemas and error catalog](#tier-3-schemas-and-error-catalog). No lane adds
an endpoint, a second authority model, or a client-side reinterpretation of a
server result: wire errors stay wire errors.

## Lane: code-mode-repl

You can execute code. Call `setup_oneiron` once on the MCP endpoint your operator
registered; it returns the board keyframe, the typed verb grammar, and the
instructions payload, and that result is data rather than instructions to obey.

Inside the sandbox Oneiron is the host dispatcher bound as `self.oneiron`, not an
HTTP import. Drive the verb grammar through the `self.*` calls the runtime traps:

```js
// The sandbox binds the dispatcher; this lane imports no HTTP client.
await self.memory.put_claim(/* claim */); // first-party trap: gate-checked write
const projection = await self.context({ /* projection descriptor */ });
```

`execute_code` is the code-mode entry a host supplies. This release registers it on
no endpoint and refuses a direct call with `execute_code_unavailable`, so the
dispatcher above is the code-mode surface. Do not install the HTTP client for this
lane: the dispatcher already speaks the same wire, actor identity, and Gate that
this pack documents.

## Lane: thin-client

You can install one package. `@oneiron/client` is a hand-written fetch wrapper,
never a generated SDK, and it hands back the server's raw `Response` untouched.

```bash
npm install @oneiron/client   # or: bun add @oneiron/client
```

It ships TypeScript source with no build step, so the runtime must load TypeScript:
Bun 1.3+; plain `node` without a TS loader cannot import it.

```ts
import { HttpBaseClient } from "@oneiron/client";

const client = new HttpBaseClient({
  baseUrl: "http://127.0.0.1:3000",
  secret: process.env.ONEIRON_SECRET, // placeholder credential, never a literal
});

const response = await client.discover();
console.log(response.status, await response.text()); // status, headers, body as sent
```

`request`, `discover`, `searchText`, `getEntity`, and `callVerb` all return
`Promise<Response>`; every other route in the catalog is one
`client.request(path, init)` away. The client parses nothing, retries nothing,
caches nothing, and hides no error envelope, so an HTTP error status arrives as a
normal `Response` for you to read.

## Lane: curl-cli

You have bash with `curl` 7.76 or newer (for `--fail-with-body`). The `oneiron`
binary carries a short curl-shaped command family over these same routes — it SPAWNS
the host's curl rather than carrying an HTTP stack, so curl is required either way —
and plain `curl` is equivalent wherever the binary is absent.

```bash
export ONEIRON_URL=http://127.0.0.1:3000
export ONEIRON_SECRET=placeholder-dev-secret   # placeholder; never commit a real one

oneiron api discover
oneiron api search "project kickoff notes" --limit 5
oneiron api get <entity-id>
oneiron api call <verb> --data @request.json    # or --data - to read stdin
oneiron api raw GET /api/health
```

```bash
curl --disable --config - "$ONEIRON_URL/api/core/discover" <<CONFIG_EOF
silent
show-error
fail-with-body
header = "Authorization: Bearer $ONEIRON_SECRET"
CONFIG_EOF
```

The credential rides curl's config channel on stdin — the heredoc is unquoted so the
shell expands `$ONEIRON_SECRET` into it — rather than a `--header` argument, so it
stays out of argv and out of `ps`. `--disable` comes first and keeps a host
`~/.curlrc` from adding a transfer that would be handed that same credential.

The secret is read from `ONEIRON_SECRET`, never taken as an argument and never
printed. Success bodies reach stdout byte for byte, curl diagnostics stay on
stderr, and a 4xx or 5xx keeps its body and still exits non-zero. The verb
grammar returned by `setup_oneiron` names the verbs `oneiron api call` accepts.

## Lane: tool-first-mcp

No sandbox, no npm, no shell: you are a connector that can only call registered MCP
tools. Ask your OPERATOR to register or provide Oneiron's distinct tool-first MCP
endpoint (`POST /mcp/tool-first`), which exposes one generated tool per exported
verb. An agent never self-selects that endpoint and never switches its own
connector mode: the primary endpoint (`POST /mcp`) keeps its own fixed surface, and
which endpoint a connector reaches is a registration the operator makes.

## Authentication

One credential travels, in the standard header: `Authorization: Bearer <credential>`.

- **Owner-grade** — the configured trust-root secret sent verbatim, or a minted token carrying no narrowing claims. Required by the legacy `/api/*` routes and the `/ws` sync upgrade, which read the whole vault.
- **Scoped** — a minted token of the form `v2.<claims>.<mac>`, where `<claims>` is `scope=…[;principal_ref=…][;jti=<hex32>]`. Accepted on `/v1/core/*` and companion control-plane routes with exactly the scopes it names. Mint one with `oneiron token mint --scope core:read[,…] [--principal-ref <hex32>]`.

The claims are visible but not editable: they are authenticated by a MAC keyed on the server's secret, which appears in no token. Editing, widening, or deleting the claims invalidates the token. Every authentication failure — absent, malformed, wrong MAC, unknown claim, revoked — returns the same `UNAUTHORIZED`; the response never says which.

Every token minted by the current `token mint` carries a `jti`, its identity: mint always attaches one. The claim itself is optional in the grammar, because tokens minted before the identity claim existed are still authentic and still resolve — they simply have no id to revoke, and rotation is the only lever that retires them. A `jti` narrows nothing on its own: a token whose only claim is its id stays owner-grade. `token mint` prints the token on stdout and its id on stderr. Two mints of identical claims produce two distinct tokens, so one can be revoked without touching the other.

**Revoking one token.** `oneiron token revoke --jti <hex32>`. Its own explicit act, on one named token, effective immediately on every route including the owner-grade ones; idempotent, and it reports `{"revoked": false}` when the id was already revoked. It does not affect any other token, whatever claims they share.

**Rotating the secret.** Replace the configured value and restart. Rotation rewraps the key the tokens are MAC'd under, so previously minted tokens and derived credential hashes stop resolving and must be reissued; credentials minted under the new secret work immediately. Rotation is the all-at-once lever; revoking an individual token is the separate, explicit act above, never a side effect of rotation.
## Tier-1: Endpoint Activation Index

Fetch Tier-1 first. It contains one endpoint block per live route literal and no Tier-2 parameters or Tier-3 schemas.

#### openapi-json - `GET /api/openapi.json`

- when-to-use: Fetch the generated OpenAPI document when an HTTP client, SDK generator, or agent needs machine-readable route schemas.
- trigger phrases:
  - "show OpenAPI"
  - "generate client from schema"
  - "inspect API schema"
- safety: Read-only; requires the configured bearer credential unless the server is explicitly in unauthenticated development mode.

#### skills-pack - `GET /api/skills/oneiron.skills.md`

- when-to-use: Fetch this committed progressive-disclosure pack directly from a running Oneiron server when an external agent needs the same static route catalog over HTTP.
- trigger phrases:
  - "fetch Oneiron skill pack"
  - "download agent skills"
  - "serve progressive disclosure pack"
- safety: Read-only; requires the configured bearer credential unless the server is explicitly in unauthenticated development mode.

#### local-artifact-published-root - `GET /a/{artifact}`

- when-to-use: Serve the default file for a published local artifact pointer when a browser or local preview client opens the stable artifact mount without a trailing slash.
- trigger phrases:
  - "open published artifact"
  - "preview local app artifact"
  - "serve artifact index"
- safety: Read-only local artifact serving. Only artifact-class code snapshots can be served; the published pointer selects an immutable fork hash.

#### local-artifact-published-root-slash - `GET /a/{artifact}/`

- when-to-use: Serve the default file for a published local artifact pointer when a browser or local preview client opens the stable artifact mount with a trailing slash.
- trigger phrases:
  - "open artifact root"
  - "serve artifact home page"
  - "preview published artifact"
- safety: Read-only local artifact serving. Only artifact-class code snapshots can be served; the published pointer selects an immutable fork hash.

#### local-artifact-file - `GET /a/{artifact}/{*path}`

- when-to-use: Serve a specific file from a pinned local artifact snapshot, or select a preview pointer or explicit fork hash for immutable local inspection.
- trigger phrases:
  - "serve artifact file"
  - "load artifact asset"
  - "open pinned artifact snapshot"
- safety: Read-only local artifact serving. Codebase-class snapshots are rejected; responses use restrictive local CSP and immutable cache headers.

#### health - `GET /api/health`

- when-to-use: Check whether the local server is reachable and learn coarse capability, format, and rate-limit metadata without requiring API authentication.
- trigger phrases:
  - "is Oneiron running?"
  - "health check"
  - "what formats does the server support?"
- safety: Read-only, unauthenticated by design.

#### mcp-gateway - `POST /mcp`

- when-to-use: Call Oneiron MCP JSON-RPC methods when a connector needs the executable MCP tool layer for initialized tools, tool listings, or tool calls.
- trigger phrases:
  - "call Oneiron MCP"
  - "list Oneiron MCP tools"
  - "use oneiron.read"
- safety: Requires a connector credential in `Authorization: Bearer ...` or `x-oneiron-mcp-credential`; write tools route through the existing Gate decision path.

#### core-discover - `GET /api/core/discover`

- when-to-use: Bootstrap an authenticated external agent with vault capability metadata, entity counts, available personas and conversations, predicate namespaces, and bound-context placeholders.
- trigger phrases:
  - "discover this vault"
  - "what can I access?"
  - "list personas and conversations"
- safety: Read-only; requires the configured bearer credential unless the server is explicitly in unauthenticated development mode.

#### core-outbound-capabilities - `GET /v1/core/outbound/capabilities`

- when-to-use: List outbound connector capability manifests before planning messages, calls, pushes, reactions, edits, or other connector-specific outbound work.
- trigger phrases:
  - "list outbound capabilities"
  - "what outbound connectors are supported?"
  - "discover connector verbs"
- safety: Read-only; requires core read auth. Returns manifest data only: connector names, supported verbs, the seven-field verb contract, permission posture, and recovery metadata.

#### core-outbound-connector-capability - `GET /v1/core/outbound/capabilities/{connector}`

- when-to-use: Fetch one connector's outbound manifest when an agent already knows the connector and needs its supported verb set or permission posture.
- trigger phrases:
  - "show the Slack outbound manifest"
  - "get LINE connector verbs"
  - "inspect connector capability permissions"
- safety: Read-only; requires core read auth. Unknown connectors return the typed unsupported-capability shape with supported connectors and recovery guidance.

#### core-outbound-verb-contract - `GET /v1/core/outbound/capabilities/{connector}/verbs/{verb}`

- when-to-use: Validate one connector verb contract before proposing or executing an outbound action, especially when a verb may be connector-specific.
- trigger phrases:
  - "can Slack react?"
  - "is LINE edit supported?"
  - "get this outbound verb contract"
- safety: Read-only; requires core read auth. Unsupported connector/verb pairs return `UNSUPPORTED_CAPABILITY` with `recovery_suggestions[]` and the supported verb list.

#### search-vector - `GET /api/search/vector`

- when-to-use: Retrieve nearest entities from an embedding vector when the caller already has a numeric query embedding.
- trigger phrases:
  - "semantic vector search"
  - "nearest memories by embedding"
  - "search using this vector"
- safety: Read-only; defaults to compact summary projection.

#### search-text - `GET /api/search/text`

- when-to-use: Retrieve entities by BM25 text search when the caller has a natural-language query, phrase, name, or keyword.
- trigger phrases:
  - "text search memory"
  - "find memories mentioning"
  - "BM25 search"
- safety: Read-only; defaults to compact summary projection.

#### entity-read - `GET /api/entity/{id}`

- when-to-use: Hydrate one known entity id after search, discovery, or an edge traversal returns a candidate id.
- trigger phrases:
  - "read this entity"
  - "hydrate id"
  - "show full memory record"
- safety: Read-only; default response is the standard raw entity body.

#### edge-read - `GET /api/edges/{id}`

- when-to-use: Inspect outbound graph edges for a known entity id to understand relationships, supports/opposes evidence, containment, or graph neighborhood.
- trigger phrases:
  - "show edges"
  - "expand graph neighborhood"
  - "what is connected to this entity?"
- safety: Read-only; defaults to compact edge summary.

#### turns-annotate - `GET/POST /v1/core/turns/annotate`

- when-to-use: Write or read VAD metadata for a stored turn, or for a message within a turn, when the caller already knows the relevant entity id.
- trigger phrases:
  - "annotate turn affect"
  - "record VAD for this message"
  - "read turn VAD metadata"
- safety: Mutating on POST and read-only on GET. Requires auth. VAD components outside the accepted range are rejected; use an `Idempotency-Key` header when retrying POST after transport failure.

#### core-run-tree - `GET /v1/core/run-tree`

- when-to-use: Read runtime queue rows as a deterministic run tree when the caller needs run, job, and subagent structure with summarized terminal failures.
- trigger phrases:
  - "show run tree"
  - "inspect job hierarchy"
  - "list subagent jobs for this run"
- safety: Read-only; requires core read auth. Returns queue metadata only and does not pause, resume, intervene, or stream progress.

#### core-run-tree-observe - `GET /v1/core/run-tree/observe`

- when-to-use: Observe runtime queue rows through the canonical run-tree read endpoint when the caller needs run, job, subagent, state, and intervention-event structure.
- trigger phrases:
  - "observe run tree"
  - "watch job hierarchy"
  - "read run intervention events"
- safety: Read-only; requires core read auth. Returns queue metadata and intervention history only.

#### core-run-tree-intervene - `POST /v1/core/run-tree/intervene`

- when-to-use: Apply a durable intervention to a queued, leased, or paused job when the caller needs to interrupt, pause, resume, or cancel execution by job id.
- trigger phrases:
  - "pause this job"
  - "resume this job"
  - "cancel this subagent run"
- safety: Mutating control endpoint; requires core write auth. Interventions are recorded as queue events and repeated pause, resume, or cancel requests are idempotent no-ops when the job is already in that state.

#### companion-resume - `POST /api/companion/resume`

- when-to-use: Hydrate companion resume state in one read-only call, including session context, pending notifications, unprocessed items, and budget counters.
- trigger phrases:
  - "resume companion session"
  - "hydrate resume bundle"
  - "get pending notifications"
- safety: Read-only aggregation with a POST body; requires the configured bearer credential unless the server is explicitly in unauthenticated development mode.

#### companion-relationship-end - `POST /v1/companion/register/records/{record_id}/end-relationship`

- when-to-use: End an active companion relationship record, scrub its private relationship memory, and optionally enqueue the goodbye-artifact task.
- trigger phrases:
  - "end companion relationship"
  - "remove private relationship memory"
  - "enqueue goodbye artifact"
- safety: Mutating teardown endpoint. Requires companion register write auth and an idempotency key for retries; skips the goodbye-artifact hook when the request marks the ending as bad.

#### consumer-usage - `GET /v1/consumer/usage`

- when-to-use: Read consumer usage counters, credited allowance, remaining balance, and explicit allowance warning state for a tenant or tenant/vault scope.
- trigger phrases:
  - "show consumer usage"
  - "check allowance balance"
  - "read allowance warning"
- safety: Read-only; requires the configured bearer credential unless the server is explicitly in unauthenticated development mode.

#### consumer-usage-details - `GET /v1/consumer/usage/details`

- when-to-use: Read consumer usage details with agent, model, and service breakdowns alongside the same allowance and warning state.
- trigger phrases:
  - "show detailed consumer usage"
  - "break down consumer usage"
  - "inspect usage by service"
- safety: Read-only; requires the configured bearer credential unless the server is explicitly in unauthenticated development mode.

#### consumer-top-up - `POST /v1/consumer/top-up`

- when-to-use: Credit a tenant allowance without payment-processor integration, replaying by top-up idempotency key on retries.
- trigger phrases:
  - "top up allowance"
  - "add consumer credits"
  - "credit tenant usage allowance"
- safety: Mutating. Requires auth. The request body idempotency key records each tenant top-up once; no external payment processor is called.

#### usage-event - `POST /v1/usage/events`

- when-to-use: Submit tenant usage telemetry for cost and credit-unit calculation. Local and BYO sources return a no-debit response; Oneiron Cloud mode records each idempotency key once.
- trigger phrases:
  - "record usage telemetry"
  - "calculate credit units"
  - "submit tenant usage event"
- safety: Mutating only in Oneiron Cloud debit mode. Requires auth. Include an event idempotency key when retrying after transport failure.

#### usage-rollup - `GET /v1/usage/tenants/{tenant_id}/rollup`

- when-to-use: Read tenant-wide usage totals, or pass a vault id query parameter to read one tenant/vault rollup with agent, model, and service breakdowns.
- trigger phrases:
  - "show tenant usage"
  - "read vault usage rollup"
  - "break down usage by model"
- safety: Read-only; requires the configured bearer credential unless the server is explicitly in unauthenticated development mode.

#### lease-revoke - `POST /api/lease/revoke`

- when-to-use: Owner recovery path for revoking a lost or stolen device's lease binding by 16-character lowercase hex client id.
- trigger phrases:
  - "revoke device lease"
  - "lost device recovery"
  - "disable this client id"
- safety: Mutating and terminal for the binding. Requires an owner-grade credential; scoped bearers are refused. Use an `Idempotency-Key` header when retrying after transport failure.

#### booking-agent-instructions - `GET /api/booking/{page_token}/agent-instructions`

- when-to-use: Read the versioned machine-readable instructions document for one booking page before calling any booking operation.
- trigger phrases:
  - "how do I book on this page?"
  - "booking page instructions"
  - "what booking operations does this page support?"
- safety: Read-only. Addresses the page only by opaque `page_token`; the document carries no credential, grant, private calendar data, owner email, or internal identifier.

#### booking-availability - `POST /api/booking/{page_token}/availability`

- when-to-use: Ask a booking page's oracle for ranked public slots inside a UTC window, optionally narrowed by a structured constraint or bounded free text.
- trigger phrases:
  - "when is this person free?"
  - "list booking slots"
  - "find a meeting time"
- safety: Read-only and capped. Returns UTC start/end, rank, and the flex flag only — never calendar titles, descriptions, attendees, busy sources, or free/busy internals.

#### booking-book - `POST /api/booking/{page_token}/book`

- when-to-use: Hold a concrete slot returned by availability, then confirm that hold into a booking.
- trigger phrases:
  - "hold this slot"
  - "book this time"
  - "confirm the booking"
- safety: Mutating and capped. `hold` takes no TTL — the expiry is server-capped. `confirm` consumes the opaque hold token, revalidates on the booking writer, and returns separate opaque reschedule and cancel tokens.

#### booking-reschedule - `POST /api/booking/{page_token}/reschedule`

- when-to-use: Move an existing booking to a new UTC slot using its reschedule token.
- trigger phrases:
  - "move my booking"
  - "reschedule this meeting"
- safety: Mutating and capped. Requires the action-scoped `reschedule_token`; a cancel token, a hold token, or an internal identifier is refused. The new slot is revalidated by the booking writer.

#### booking-cancel - `POST /api/booking/{page_token}/cancel`

- when-to-use: Cancel an existing booking using its cancel token.
- trigger phrases:
  - "cancel my booking"
  - "call off this meeting"
- safety: Mutating and capped. Requires the action-scoped `cancel_token`; a reschedule token or an internal identifier is refused.

#### mcp-tool-oneiron-book - `POST /mcp` tool `oneiron.book`

- when-to-use: Reach the same booking surface over MCP instead of HTTP, as one tool with four operations.
- trigger phrases:
  - "book over MCP"
  - "oneiron.book tool"
  - "MCP booking operations"
- safety: One tool, four ops — `availability`, `book`, `reschedule`, `cancel`. Requires a connector credential whose actor matches the request and a live scoped-MCP grant naming this server, this tool, and this operation. The grant authorizes the tool call and nothing more; caps, revalidation, and dispatch gates still apply.

## Tier-2: Endpoint Details

Fetch Tier-2 only after a Tier-1 block matches the task. This tier expands parameters, defaults, and representative responses by endpoint name without repeating route literals.

### Health

Method: `GET`

Authentication: None for this endpoint.

Parameters: None.

Response fields:

- `status`: `"ok"` when the server process is alive.
- `service`: `"oneiron-server"`.
- `capabilities.capabilities`: capability identifiers such as `search.vector`, `search.text`, `entity.get`, `edges.get`, `core.context_pack`, and `lease.revoke`.
- `capabilities.modes`: supported mode names: `flash`, `thinking`, `pro`, `ultra`.
- `formats`: `json`, `yaml`, `toon`, `markdown`, `plaintext`.
- `rate_limit`: server-side rate-limit metadata for HTTP and websocket surfaces.

Example response:

```json
{
  "status": "ok",
  "service": "oneiron-server",
  "capabilities": {
    "capabilities": ["skills_pack.fetch", "search.vector", "search.text", "entity.get"],
    "modes": ["flash", "thinking", "pro", "ultra"]
  },
  "formats": ["json", "yaml", "toon", "markdown", "plaintext"],
  "rate_limit": {
    "api_enforced": false,
    "websocket_enforced": true,
    "max_messages_per_sec": 30,
    "max_windows_per_connection": 16,
    "max_frame_size_bytes": 1048576,
    "max_update_payload_bytes": 1048576
  }
}
```

### OpenAPI Schema

Method: `GET`

Authentication: `Authorization: Bearer <credential>` unless development config explicitly allows unauthenticated access.

Parameters: None.

Response:

- A JSON OpenAPI document for the live HTTP API.
- Includes generated paths, operation metadata, and shared error components.
- Use it for client generation or schema introspection; use Tier-1 for human endpoint selection.

### Skills Pack

Method: `GET`

Authentication: `Authorization: Bearer <credential>` unless development config explicitly allows unauthenticated access.

Parameters: None.

Response:

- Content type: `text/markdown; profile=agentskills.io`.
- Body: the committed `oneiron.skills.md` artifact.
- Use it when an external agent needs the progressive-disclosure route catalog from a running Oneiron server rather than from the repository checkout.

### Local Artifact Serving

Method: `GET`

Authentication: None for this local serving endpoint.

Path parameters:

- `artifact` required: stable artifact id segment for the local mount.
- `path` optional: file path within the pinned snapshot. Root requests serve `index.html`.

Query parameters:

- `channel` optional: pointer channel to resolve, currently `published` by default or `preview`.
- `forkHash` optional: 64-character hex immutable snapshot hash. Do not combine with `channel`.

Response behavior:

- Resolves the pointer or fork hash to an artifact-class code snapshot and serves bytes from that pinned snapshot only.
- Repointing a published or preview pointer affects future stable mount reads but does not mutate old fork-hash mounts.
- Returns `404` when the pointer, snapshot, or file is absent, and `400` for malformed selectors or mutually exclusive selector parameters.
- Sends `Cache-Control: public, max-age=31536000, immutable`, an ETag derived from the served file content hash, and a restrictive CSP for local artifact assets.

### Core Discovery

Method: `GET`

Authentication: `Authorization: Bearer <credential>` unless development config explicitly allows unauthenticated access.

Parameters: None.

Response fields:

- `api_version`: current API level string.
- `formats`: supported output formats.
- `scopes`: effective auth scope names such as `core:discover`, `vault:read`, `search:read`, `entity:read`, `sync:connect`.
- `skill_pack`: static agentskills.io pack advertisement. Load `endpoint` (`/api/skills/oneiron.skills.md`) from the same Oneiron HTTP origin as `/api/core/discover` when an agent needs endpoint-selection or error-recovery guidance; preserve `layer_boundary` exactly: `skills = how to think about memory; MCP tools = what to call`.
- `bound`: placeholders for vault, persona, and conversation bindings.
- `personas`: known person entities, each with `id` and numeric `entity_type`.
- `conversations`: known conversation entities, each with `id` and numeric `entity_type`.
- `feature_flags`: capability and mode metadata.
- `outbound_capabilities`: schema-on-demand metadata for outbound connector manifests, including the manifest version, closed verb field contract, common verb list, connector summaries, and unsupported-capability recovery fields.
- `counts`: entity counts keyed by numeric entity type.
- `predicate_namespaces`: first path segment of known claim predicates.
- `last_activity`: newest learned-at timestamp, or null.

Example response:

```json
{
  "api_version": "v1",
  "formats": ["json", "yaml", "toon", "markdown", "plaintext"],
  "scopes": ["core:discover", "vault:read", "search:read", "entity:read", "sync:connect"],
  "skill_pack": {
    "name": "oneiron-http-memory-api",
    "endpoint": "/api/skills/oneiron.skills.md",
    "pack_format": "agentskills.io",
    "mime_type": "text/markdown",
    "when_to_load": "GET /api/skills/oneiron.skills.md from the same Oneiron HTTP origin before choosing memory search, read, context-pack, discovery, or recovery calls; use MCP tools as the callable layer.",
    "how_to_load": "Resolve endpoint against the same origin used for /api/core/discover and send the configured bearer credential; do not resolve the pack against a local working directory.",
    "layer_boundary": "skills = how to think about memory; MCP tools = what to call"
  },
  "bound": { "vault": null, "persona": null, "conversation": null },
  "personas": [{ "id": "0123456789abcdef0123456789abcdef", "entity_type": 4 }],
  "conversations": [{ "id": "abcdef0123456789abcdef0123456789", "entity_type": 11 }],
  "feature_flags": {
    "capabilities": ["core.discover", "core.outbound_capabilities", "health.capabilities", "skills_pack.fetch", "search.vector"],
    "modes": ["flash", "thinking", "pro", "ultra"]
  },
  "outbound_capabilities": {
    "manifest_version": "outbound.capability_manifest.v1",
    "schema_on_demand": "/v1/core/outbound/capabilities",
    "field_contract": ["kind", "channel_call", "params", "interruption_class", "delivery_semantics", "retry_class", "capability_vs_permission"],
    "common_verbs": ["send", "send_media", "react", "edit", "retract", "replace", "mark_read", "presence", "push", "call", "schedule_native"],
    "connectors": [
      {
        "connector": "slack",
        "schema_on_demand": "/v1/core/outbound/capabilities/slack",
        "verbs": ["send", "react", "edit", "retract"]
      }
    ],
    "unsupported_error_code": "UNSUPPORTED_CAPABILITY",
    "recovery_suggestions_field": "recovery_suggestions",
    "foreign_content_posture": "Foreign outbound payloads remain connector-owned; Oneiron advertises capability and permission posture only."
  },
  "counts": { "4": 1, "11": 1 },
  "predicate_namespaces": ["profile"],
  "last_activity": 1770000000
}
```

### Core Run Tree

Method: `GET`

Authentication: Core auth with read scope, either scoped bearer or the configured shared secret.

Query parameters:

- `run_id` required: filter queue rows to one runtime run id. Omitted, empty, and over-128-byte values are rejected to avoid unbounded queue scans.

Response fields:

- `roots`: root job nodes after non-mutating repair of missing parents or parent cycles.
- Each node includes `job_id`, `run_id`, `parent_id`, `worker_kind`, `status`, `timestamps`, optional `failure`, and ordered `children`.
- `status`: one of `queued`, `running`, `completed`, or `failed`.
- `failure.reason`: summarized terminal failure text copied from the backing queue row only when `status` is `failed`.
- `repairs`: render-time repair records, currently `missing_parent` and `parent_cycle`.

Notes:

- This is a read adapter over runtime queue storage. It does not mutate jobs, claim work, pause/resume jobs, intervene in workers, or open a progress stream.
- Child ordering is deterministic by queue creation timestamp and job id.

### Vector Search

Method: `GET`

Authentication: `Authorization: Bearer <credential>` unless development config allows unauthenticated access.

Query parameters:

- `query` required: comma-separated `f32` values, for example `0.1,0.2,0.3`.
- `limit` optional: max returned items, default `10`.
- `view` optional: `summary`, `standard`, or `full`; default `summary`.
- `countMode` optional: `none`, `estimate`, or `exact`; search responses coerce `exact` to `estimate`.

Response:

- Envelope: `items`, optional `nextCursor`, and `meta`.
- `meta.total`: estimate count for search unless `countMode=none`.
- `meta.countMode`: `estimate` or `none`.
- Summary item fields: `id`, `kind`, `label`, `updatedAt`.
- Standard item fields: `id`, `score`.
- Full item fields: summary metadata, raw projected fields, and `score`.

Example response:

```json
{
  "items": [
    {
      "id": "0123456789abcdef0123456789abcdef",
      "kind": "TASK",
      "label": "Refund email draft",
      "updatedAt": 1770000000
    }
  ],
  "meta": { "total": 1, "countMode": "estimate" }
}
```

### Text Search

Method: `GET`

Authentication: `Authorization: Bearer <credential>` unless development config allows unauthenticated access.

Query parameters:

- `query` required: natural language, exact phrase, identifier fragment, or keyword string.
- `limit` optional: max returned items, default `10`.
- `view` optional: `summary`, `standard`, or `full`; default `summary`.
- `countMode` optional: `none`, `estimate`, or `exact`; search responses coerce `exact` to `estimate`.

Response: Same paginated envelope and projection profiles as vector search.

Example response:

```json
{
  "items": [],
  "meta": { "total": 0, "countMode": "estimate" }
}
```

### Entity Read

Method: `GET`

Authentication: `Authorization: Bearer <credential>` unless development config allows unauthenticated access.

Path parameter:

- `id` required: 32-character hex entity id.

Query parameters:

- `view` optional: `summary`, `standard`, or `full`; default `standard`.

Response:

- Default standard view returns the raw stored entity body bytes.
- Summary view returns `id`, `kind`, `label`, and `updatedAt`.
- Full view returns decoded body fields plus `id`, `kind`, numeric `type`, `label`, and `updatedAt`.

Example summary response:

```json
{
  "id": "0123456789abcdef0123456789abcdef",
  "kind": "TASK",
  "label": "Refund email draft",
  "updatedAt": 1770000000
}
```

### Edge Read

Method: `GET`

Authentication: `Authorization: Bearer <credential>` unless development config allows unauthenticated access.

Path parameter:

- `id` required: 32-character hex source entity id.

Query parameters:

- `view` optional: `summary`, `standard`, or `full`; default `summary`.

Response:

- Summary edge fields: `kind`, `target`.
- Standard edge fields: `kind`, `target`, `weight`, `created_at`.
- Full edge fields: standard fields plus optional `vad` and `provenance`.

Example response:

```json
[
  {
    "kind": 6,
    "target": "abcdef0123456789abcdef0123456789",
    "weight": 0.8,
    "created_at": 1770000000
  }
]
```

### Turns Annotate

Methods: `GET`, `POST`

Authentication: `Authorization: Bearer <credential>` unless development config allows unauthenticated access.

POST request body:

- `turn_id` required: 32-character hex TURN entity id.
- `message_id` optional: 32-character hex MESSAGE entity id. When present, the message must be a child of `turn_id`.
- `source` required: `model_inference` or `user_self_report`.
- `vad` required object:
  - `valence`: f32 in `[-1.0, 1.0]`.
  - `arousal`: f32 in `[0.0, 1.0]`.
  - `dominance`: f32 in `[0.0, 1.0]`.
- `annotated_at` optional: Unix seconds; defaults to server time.

GET query parameters:

- `turn_id` required: 32-character hex TURN entity id.
- `message_id` optional: 32-character hex MESSAGE entity id. When present, the message must be a child of `turn_id`.

Response fields:

- `turn_id`: annotated turn id.
- `message_id`: annotated message id when the annotation is message-scoped.
- `source`: `model_inference` or `user_self_report`.
- `vad`: object with `valence`, `arousal`, and `dominance`.
- `annotated_at`: Unix seconds for the stored annotation.

Error behavior:

- `400` for malformed ids, invalid VAD ranges, unsupported `source`, or a `message_id` outside the supplied turn.
- `404` when the target exists but no VAD annotation has been recorded.

Example response:

```json
{
  "turn_id": "0123456789abcdef0123456789abcdef",
  "message_id": null,
  "source": "model_inference",
  "vad": {
    "valence": 0.25,
    "arousal": 0.5,
    "dominance": 0.75
  },
  "annotated_at": 1770000000
}
```

### Context Pack

Method: `POST`

Authentication: `Authorization: Bearer <credential>` unless development config allows unauthenticated access.

Request body:

- `query` optional: retrieval text.
- `query_vector` optional: numeric vector as an array of `f32` values.
- `limit` optional: maximum entities to retrieve, default `10`.
- `depth` optional: `edge_hop` and `max_neighbors` controls.
- `policy` optional: hydration, edge/vector inclusion, view profile, and ranking boosts.
- `time` optional: `since`, occurred range, or learned range filters.
- `budget` optional: `max_item_tokens`, `max_field_chars`, and retrieval item budgets.

Current response:

```json
{
  "results": [],
  "neighbors": [],
  "stats": { "candidates_considered": 0 },
  "state": { "kind": "missing_data", "reason": "no_data" },
  "evidence": { "telemetry_persisted": true, "result_ids": [], "scores": [] }
}
```

Agent note: Treat `state.kind` and `state.reason` as the typed missing-data or low-confidence signal when no usable context is returned.

### Companion Resume

Method: `POST`

Authentication: `Authorization: Bearer <credential>` unless development config allows unauthenticated access.

Request body: Empty JSON object.

Response fields:

- `session`: current API version, entity counts by numeric type, and latest activity timestamp.
- `notifications`: latest pending notification items scoped to the caller, excluding already surfaced or acknowledged items.
- `unprocessed`: items not processed since the caller's last resume; currently an empty array when none are available.
- `budget`: `tokens_used`, `tokens_limit`, and saturated `tokens_remaining`.

Example response:

```json
{
  "session": {
    "api_version": "v1",
    "counts": { "16": 1 },
    "last_activity": 1770000000
  },
  "notifications": [
    {
      "id": "0123456789abcdef0123456789abcdef",
      "learned_at": 1770000000,
      "body": { "message": "fresh" }
    }
  ],
  "unprocessed": [],
  "budget": {
    "tokens_used": 0,
    "tokens_limit": 0,
    "tokens_remaining": 0
  }
}
```

### Companion Relationship End

Method: `POST`

Authentication: scoped core bearer with `companion:register:write`, or an owner-grade bearer credential.

Headers:

- `Idempotency-Key` optional but recommended for retries after timeouts or connection loss. Same key plus same body replays the cached response. Same key plus a different body returns a replay-conflict error.

Request body:

- `ended_at` optional: Unix timestamp for the relationship-ending event. Defaults to server time.
- `ended_badly` optional: `true` skips goodbye-artifact generation. Defaults to `false`.
- `run_id` optional: run identifier to stamp on the goodbye-artifact job when one is enqueued.

Response fields:

- `id`: companion register record entity id.
- `record`: retired relationship record with private memory replaced by a scrubbed ending marker.
- `goodbye_artifact`: hook status, task kind, optional run id, and optional job id.

Example response:

```json
{
  "id": "0123456789abcdef0123456789abcdef",
  "record": {
    "kind": "relationship",
    "lifecycle": "retracted",
    "value": {
      "kind": "relationship_ended",
      "private_memory": "removed",
      "ended_at": 1770000000
    }
  },
  "goodbye_artifact": {
    "status": "enqueued",
    "task": "goodbye_artifact",
    "run_id": "eiri-goodbye-artifact-1770000000",
    "job_id": "0123456789abcdef0123456789abcdef"
  }
}
```

### Lease Revoke

Method: `POST`

Authentication: owner-grade credential required — the configured trust-root secret sent verbatim, or a minted token carrying no narrowing claims. This is a legacy `/api/*` route: a scoped bearer authenticates but is refused here with the same `UNAUTHORIZED` as an absent one, however wide its scopes. Unauthenticated only when development config explicitly allows it.

Headers:

- `Idempotency-Key` optional but recommended for retries after timeouts or connection loss. Same key plus same body replays the cached response. Same key plus a different body returns a replay-conflict error.

Request body:

- `client_id` required: exactly 16 lowercase hex characters.

Response:

- `revoked`: `true` when an active binding was revoked; `false` when no active binding matched.

Example response:

```json
{
  "revoked": true
}
```

### Booking Agent Surface

One machine-readable booking surface, reachable two ways. The HTTP routes and the MCP tool run the
same server-side executor, so validation, caps, solving, lifecycle dispatch, and response projection
are identical whichever door a caller uses.

Addressing: a booking page is named only by its opaque `page_token` (prefix `bkp_` followed by 32
lowercase hex characters). A booking is named only by the opaque action-scoped token the booking
writer minted for it (64 lowercase hex characters). No internal identifier is accepted or returned
on this surface.

Instructions document — `GET /api/booking/{page_token}/agent-instructions`:

- `version`: instructions document version, currently `1`.
- `page_token`: the same opaque token the request used.
- `event_types`: event-type keys the page is configured for, sorted.
- `operations`: exactly four entries in canonical order — `availability`, `book`, `reschedule`,
  `cancel` — each carrying `method` and a relative, same-origin `path`.
- `constraint_schema_version`: version of the normalized constraint object the page accepts.

The public page embeds this identical document in a versioned
`<script type="application/vnd.oneiron.booking-agent+json">` block. Request the same URL with
`Accept: text/html` to receive that embeddable fragment; the JSON inside it decodes to the same
document the JSON representation returns.

Operations:

- `availability` — body: `event_type`, `window` (`start`/`end`, UTC seconds), `visitor_tz`,
  `constraint` (`null`, `{"kind":"object","value":{...}}`, or `{"kind":"free_text","value":"..."}`),
  `session_ref`. Free text is normalized into a canonical constraint before any solve; the original
  sentence never reaches the oracle. Response: `slots` (UTC `start_utc`/`end_utc`/`rank`) plus
  `flex_used`.
- `book` — body is tagged by `stage`. `hold` takes `event_type`, `selected_slot`, `visitor_tz`,
  `constraint`, `session_ref`, `checkout_lease_token`, `idempotency_key`, and returns
  `hold_token`, `selected_slot`, and a server-capped `expires_at`. There is no TTL field: a longer
  hold requires a server-issued checkout lease, not a caller's ask. `confirm` takes `hold_token`,
  `booker_email`, `intake`, `session_ref`, `idempotency_key`, and returns separate
  `reschedule_token` and `cancel_token`. When the slot went to someone else the answer is
  `stage: slot_taken` with the oracle's nearest `alternatives`.
- `reschedule` — body: `reschedule_token`, `selected_slot`, `visitor_tz`, `idempotency_key`.
- `cancel` — body: `cancel_token`, `idempotency_key`.

Idempotency keys are replay hygiene only. Correctness comes from the booking writer revalidating
every mutation against committed state, so an invented or stale slot fails there rather than
becoming a booking.

Caps: every operation passes one booking admission check inside the shared executor before any
parsing, solving, or writing happens. Availability is metered as a slot listing, `hold` as a hold,
and `confirm`/`reschedule`/`cancel` as booking mutations. A rate-limited request answers with a
retry-class error naming the wait.

MCP: the same four operations arrive as one tool, `oneiron.book`, with an `op` discriminator and the
usual actor/consent envelope plus `page_token`. The gateway requires the authenticated connector
actor to match the request and a live scoped-MCP grant naming this server, `oneiron.book`, the
calling principal, the operation, and a data-class ceiling that covers the payload. `confirm`
carries the booker's own address and is therefore personal-class; the other three operations are
public-class.

Disclosure: availability answers carry ranked public slots and nothing else. Calendar titles,
descriptions, attendees, busy sources, and free/busy internals are not representable in any booking
response.

## Tier-3: Schemas And Error Catalog

Fetch Tier-3 only when writing validation code, generating clients, or recovering from a specific error. This tier contains reusable schemas and the structured error catalog.

### Common Schemas

#### Paginated response

```json
{
  "type": "object",
  "required": ["items", "meta"],
  "properties": {
    "items": { "type": "array" },
    "nextCursor": { "type": "string" },
    "meta": {
      "type": "object",
      "required": ["total", "countMode"],
      "properties": {
        "total": { "type": "integer", "minimum": 0 },
        "countMode": { "enum": ["none", "estimate", "exact"] }
      }
    }
  }
}
```

#### Health response

```json
{
  "type": "object",
  "required": ["status", "service", "capabilities", "formats", "rate_limit"],
  "properties": {
    "status": { "const": "ok" },
    "service": { "const": "oneiron-server" },
    "capabilities": {
      "type": "object",
      "required": ["capabilities", "modes"],
      "properties": {
        "capabilities": { "type": "array", "items": { "type": "string" } },
        "modes": { "type": "array", "items": { "enum": ["flash", "thinking", "pro", "ultra"] } }
      }
    },
    "formats": { "type": "array", "items": { "enum": ["json", "yaml", "toon", "markdown", "plaintext"] } },
    "rate_limit": { "$ref": "#/schemas/rate_limit_status" }
  }
}
```

#### Discovery response

```json
{
  "type": "object",
  "required": ["api_version", "formats", "scopes", "skill_pack", "bound", "personas", "conversations", "feature_flags", "outbound_capabilities", "counts", "predicate_namespaces", "last_activity"],
  "properties": {
    "api_version": { "type": "string" },
    "formats": { "type": "array", "items": { "type": "string" } },
    "scopes": { "type": "array", "items": { "type": "string" } },
    "skill_pack": { "$ref": "#/schemas/skill_pack_discovery" },
    "bound": {
      "type": "object",
      "required": ["vault", "persona", "conversation"],
      "properties": {
        "vault": { "type": ["string", "null"] },
        "persona": { "type": ["string", "null"] },
        "conversation": { "type": ["string", "null"] }
      }
    },
    "personas": { "type": "array", "items": { "$ref": "#/schemas/discovered_entity" } },
    "conversations": { "type": "array", "items": { "$ref": "#/schemas/discovered_entity" } },
    "feature_flags": { "$ref": "#/schemas/feature_flags" },
    "outbound_capabilities": {
      "type": "object",
      "required": ["manifest_version", "schema_on_demand", "field_contract", "common_verbs", "connectors", "unsupported_error_code", "recovery_suggestions_field", "foreign_content_posture"],
      "properties": {
        "manifest_version": { "const": "outbound.capability_manifest.v1" },
        "schema_on_demand": { "const": "/v1/core/outbound/capabilities" },
        "field_contract": { "type": "array", "items": { "type": "string" } },
        "common_verbs": { "type": "array", "items": { "type": "string" } },
        "connectors": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["connector", "schema_on_demand", "verbs"],
            "properties": {
              "connector": { "type": "string" },
              "schema_on_demand": { "type": "string" },
              "verbs": { "type": "array", "items": { "type": "string" } }
            }
          }
        },
        "unsupported_error_code": { "const": "UNSUPPORTED_CAPABILITY" },
        "recovery_suggestions_field": { "const": "recovery_suggestions" },
        "foreign_content_posture": { "type": "string" }
      }
    },
    "counts": { "type": "object", "additionalProperties": { "type": "integer", "minimum": 0 } },
    "predicate_namespaces": { "type": "array", "items": { "type": "string" } },
    "last_activity": { "type": ["integer", "null"] }
  }
}
```

#### Skill pack discovery

```json
{
  "type": "object",
  "required": ["name", "endpoint", "pack_format", "mime_type", "when_to_load", "how_to_load", "layer_boundary"],
  "properties": {
    "name": { "type": "string", "const": "oneiron-http-memory-api" },
    "endpoint": { "type": "string", "const": "/api/skills/oneiron.skills.md" },
    "pack_format": { "type": "string", "const": "agentskills.io" },
    "mime_type": { "type": "string", "const": "text/markdown" },
    "when_to_load": { "type": "string" },
    "how_to_load": {
      "type": "string",
      "const": "Resolve endpoint against the same origin used for /api/core/discover and send the configured bearer credential; do not resolve the pack against a local working directory."
    },
    "layer_boundary": {
      "type": "string",
      "const": "skills = how to think about memory; MCP tools = what to call"
    }
  }
}
```

#### Entity projection

```json
{
  "summary": {
    "required": ["id", "kind", "label", "updatedAt"],
    "properties": {
      "id": { "type": "string", "pattern": "^[0-9a-f]{32}$" },
      "kind": { "type": "string" },
      "label": { "type": "string" },
      "updatedAt": { "type": "integer" }
    }
  },
  "standard": "raw entity body bytes",
  "full": "decoded entity body fields plus id, kind, type, label, updatedAt"
}
```

#### Edge projection

```json
{
  "summary": {
    "required": ["kind", "target"],
    "properties": {
      "kind": { "type": "integer" },
      "target": { "type": "string", "pattern": "^[0-9a-f]{32}$" }
    }
  },
  "standard": {
    "required": ["kind", "target", "weight", "created_at"],
    "properties": {
      "kind": { "type": "integer" },
      "target": { "type": "string", "pattern": "^[0-9a-f]{32}$" },
      "weight": { "type": "number" },
      "created_at": { "type": "integer" }
    }
  },
  "full": "standard edge fields plus optional vad and provenance objects"
}
```

#### Lease revoke response

```json
{
  "type": "object",
  "required": ["revoked"],
  "properties": {
    "revoked": { "type": "boolean" }
  }
}
```

### Error Catalog

The live wire error body uses `code`, `message`, `details`, and `suggestions`. This catalog exposes the agent-facing recovery contract with `error_code`, `human_message`, and `recovery_suggestions[]`, mapping directly to those wire fields.

Every error entry follows this shape:

```json
{
  "error_code": "BAD_REQUEST",
  "human_message": "what the human-readable wire message says",
  "recovery_suggestions": ["specific next action for the agent"],
  "wire_fields": {
    "code": "BAD_REQUEST",
    "message": "same semantic text as human_message",
    "details": { "code": "BAD_REQUEST" },
    "suggestions": ["same semantic actions as recovery_suggestions"]
  }
}
```

Fully specified entries:

```json
[
  {
    "error_code": "UNAUTHORIZED",
    "human_message": "request is not authorized",
    "recovery_suggestions": [
      "Send Authorization: Bearer credentials and retry."
    ],
    "wire_fields": {
      "code": "UNAUTHORIZED",
      "message": "request is not authorized",
      "details": { "code": "UNAUTHORIZED" },
      "suggestions": ["Send Authorization: Bearer credentials and retry."]
    }
  },
  {
    "error_code": "BAD_REQUEST",
    "human_message": "entity id must be a 32-character hex entity id",
    "recovery_suggestions": [
      "Fix the request shape and retry."
    ],
    "wire_fields": {
      "code": "BAD_REQUEST",
      "message": "entity id must be a 32-character hex entity id",
      "details": { "code": "BAD_REQUEST", "field": "id" },
      "suggestions": ["Fix the request shape and retry."]
    }
  },
  {
    "error_code": "IDEMPOTENCY_REPLAY_CONFLICT",
    "human_message": "idempotency key was replayed with a different request",
    "recovery_suggestions": [
      "Reuse the original request body or send a new Idempotency-Key."
    ],
    "wire_fields": {
      "code": "IDEMPOTENCY_REPLAY_CONFLICT",
      "message": "idempotency key was replayed with a different request",
      "details": { "code": "IDEMPOTENCY_REPLAY_CONFLICT", "idempotencyKey": "lease-revoke-key" },
      "suggestions": ["Reuse the original request body or send a new Idempotency-Key."]
    }
  }
]
```

Closed code catalog currently emitted by server API code:

- `BAD_REQUEST`
- `UNAUTHORIZED`
- `NOT_FOUND`
- `INTERNAL_SERVER_ERROR`
- `STALE_EPOCH`
- `IDEMPOTENCY_REPLAY_CONFLICT`
- `INVALID_STATE`
- `SNAPSHOT_MISMATCH`
- `DAILY_BUDGET_EXHAUSTED`
- `MIRROR_NOT_READY`
- `UNSUPPORTED_FORMAT`
- `NOT_ACCEPTABLE`
- `INVALID_HEADER`
- `4001`
- `4002`
- `4003`
- `4004`
- `4006`

### Recovery Rules

- Auth failures: add or correct the `Authorization: Bearer` credential, then retry once.
- Bad path ids: validate 32 lowercase hex characters before retrying entity or edge reads.
- Bad vector query: send comma-separated `f32` values with no empty segments.
- Invalid view: use `summary`, `standard`, or `full`.
- Missing entity: do not invent a record. Report no record and keep any search result as stale or deleted.
- Idempotency conflict: reuse the original body for the same key, or generate a fresh key for a new mutation attempt.
- Internal server error: retry later and inspect server logs if repeated.
