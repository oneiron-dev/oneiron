---
name: oneiron-http-memory-api
description: "Use this skill when an external agent needs to discover Oneiron's current HTTP memory API, choose the right endpoint, and understand how read, retrieval, context-pack, discovery, and lease-revocation calls relate to Oneiron MCP tools."
when_to_use:
  - "An agent needs route-level awareness of the existing Oneiron HTTP API."
  - "An agent must decide whether to search memory, read one entity, inspect edges, assemble context, discover vault capabilities, or revoke a device lease."
  - "A connector needs the static skill layer: how to think about memory before it calls MCP or HTTP tools."
trigger_phrases:
  - "query Oneiron memory"
  - "search the vault"
  - "read an entity"
  - "get context pack"
  - "discover Oneiron capabilities"
  - "revoke a lease"
---

# Oneiron HTTP Memory API Skill Pack

This pack is a static, agentskills.io-compatible progressive disclosure artifact for the currently exposed Oneiron HTTP routes. It is documentation only: it does not add routes, MCP tools, handlers, activation logic, or runtime distribution.

The boundary is dual-layer:

- Skills are how to think about memory: when to search, when to inspect graph edges, when to assemble a context pack, when to treat a result as raw evidence, and when to recover from errors.
- MCP tools are what to call: the executable capability surface advertised by MCP `initialize.instructions`, tool listings, and tool schemas.

Keep those layers aligned but not duplicated. This pack names the live HTTP route semantics once. MCP initialization should advertise callable tools, scopes, safety hints, and handles. Any AGENTS.md-style discovery artifact should point to this pack and the MCP advertisement rather than carrying a second divergent endpoint catalog.

ARCH-0006a/b conversation endpoints are design documents, not live routes in the current server route table. They are intentionally excluded from the live endpoint catalog until the server registers them.

## Tier-1: Endpoint Activation Index

Fetch Tier-1 first. It contains one endpoint block per live route literal and no Tier-2 parameters or Tier-3 schemas.

#### health - `GET /api/health`

- when-to-use: Check whether the local server is reachable and learn coarse capability, format, and rate-limit metadata without requiring API authentication.
- trigger phrases:
  - "is Oneiron running?"
  - "health check"
  - "what formats does the server support?"
- safety: Read-only, unauthenticated by design.

#### core-discover - `GET /api/core/discover`

- when-to-use: Bootstrap an authenticated external agent with vault capability metadata, entity counts, available personas and conversations, predicate namespaces, and bound-context placeholders.
- trigger phrases:
  - "discover this vault"
  - "what can I access?"
  - "list personas and conversations"
- safety: Read-only; requires the configured `x-oneiron-secret` header unless the server is explicitly in unauthenticated development mode.

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

#### context-pack - `POST /api/context-pack`

- when-to-use: Ask the server to assemble retrieval context for an agent turn from a query, query vector, and limit. The current route acknowledges the request while the full ContextPackBuilder integration is pending.
- trigger phrases:
  - "build context for this turn"
  - "assemble memory context"
  - "get a context pack"
- safety: Read-only retrieval intent with a POST body; no persisted mutation in the current implementation.

#### lease-revoke - `POST /api/lease/revoke`

- when-to-use: Owner recovery path for revoking a lost or stolen device's lease binding by 16-character lowercase hex client id.
- trigger phrases:
  - "revoke device lease"
  - "lost device recovery"
  - "disable this client id"
- safety: Mutating and terminal for the binding. Requires auth. Use an `Idempotency-Key` header when retrying after transport failure.

## Tier-2: Endpoint Details

Fetch Tier-2 only after a Tier-1 block matches the task. This tier expands parameters, defaults, and representative responses by endpoint name without repeating route literals.

### Health

Method: `GET`

Authentication: None for this endpoint.

Parameters: None.

Response fields:

- `status`: `"ok"` when the server process is alive.
- `service`: `"oneiron-server"`.
- `capabilities.capabilities`: capability identifiers such as `search.vector`, `search.text`, `entity.get`, `edges.get`, `context_pack`, and `lease.revoke`.
- `capabilities.modes`: supported mode names: `flash`, `thinking`, `pro`, `ultra`.
- `formats`: `json`, `yaml`, `toon`, `markdown`, `plaintext`.
- `rate_limit`: server-side rate-limit metadata for HTTP and websocket surfaces.

Example response:

```json
{
  "status": "ok",
  "service": "oneiron-server",
  "capabilities": {
    "capabilities": ["search.vector", "search.text", "entity.get"],
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

### Core Discovery

Method: `GET`

Authentication: `x-oneiron-secret` unless development config explicitly allows unauthenticated access.

Parameters: None.

Response fields:

- `api_version`: current API level string.
- `formats`: supported output formats.
- `scopes`: effective auth scope names such as `core:discover`, `vault:read`, `search:read`, `entity:read`, `sync:connect`.
- `bound`: placeholders for vault, persona, and conversation bindings.
- `personas`: known person entities, each with `id` and numeric `entity_type`.
- `conversations`: known conversation entities, each with `id` and numeric `entity_type`.
- `feature_flags`: capability and mode metadata.
- `counts`: entity counts keyed by numeric entity type.
- `predicate_namespaces`: first path segment of known claim predicates.
- `last_activity`: newest learned-at timestamp, or null.

Example response:

```json
{
  "api_version": "v1",
  "formats": ["json", "yaml", "toon", "markdown", "plaintext"],
  "scopes": ["core:discover", "vault:read", "search:read", "entity:read", "sync:connect"],
  "bound": { "vault": null, "persona": null, "conversation": null },
  "personas": [{ "id": "0123456789abcdef0123456789abcdef", "entity_type": 4 }],
  "conversations": [{ "id": "abcdef0123456789abcdef0123456789", "entity_type": 11 }],
  "feature_flags": {
    "capabilities": ["core.discover", "health.capabilities", "search.vector"],
    "modes": ["flash", "thinking", "pro", "ultra"]
  },
  "counts": { "4": 1, "11": 1 },
  "predicate_namespaces": ["profile"],
  "last_activity": 1770000000
}
```

### Vector Search

Method: `GET`

Authentication: `x-oneiron-secret` unless development config allows unauthenticated access.

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

Authentication: `x-oneiron-secret` unless development config allows unauthenticated access.

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

Authentication: `x-oneiron-secret` unless development config allows unauthenticated access.

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

Authentication: `x-oneiron-secret` unless development config allows unauthenticated access.

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

### Context Pack

Method: `POST`

Authentication: `x-oneiron-secret` unless development config allows unauthenticated access.

Request body:

- `query` optional: retrieval text.
- `query_vector` optional: numeric vector as an array of `f32` values.
- `limit` optional: maximum entities to retrieve, default `10`.

Current response:

```json
{
  "status": "ok",
  "message": "context-pack endpoint ready - full implementation pending ContextPackBuilder integration"
}
```

Agent note: Treat this as a future context-assembly route that already has a stable call shape, not as a complete context-pack implementation.

### Lease Revoke

Method: `POST`

Authentication: `x-oneiron-secret` required unless development config allows unauthenticated access.

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
  "required": ["api_version", "formats", "scopes", "bound", "personas", "conversations", "feature_flags", "counts", "predicate_namespaces", "last_activity"],
  "properties": {
    "api_version": { "type": "string" },
    "formats": { "type": "array", "items": { "type": "string" } },
    "scopes": { "type": "array", "items": { "type": "string" } },
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
    "counts": { "type": "object", "additionalProperties": { "type": "integer", "minimum": 0 } },
    "predicate_namespaces": { "type": "array", "items": { "type": "string" } },
    "last_activity": { "type": ["integer", "null"] }
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
      "Send the configured x-oneiron-secret header and retry."
    ],
    "wire_fields": {
      "code": "UNAUTHORIZED",
      "message": "request is not authorized",
      "details": { "code": "UNAUTHORIZED" },
      "suggestions": ["Send the configured x-oneiron-secret header and retry."]
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
- `4005`
- `4006`

### Recovery Rules

- Auth failures: add or correct `x-oneiron-secret`, then retry once.
- Bad path ids: validate 32 lowercase hex characters before retrying entity or edge reads.
- Bad vector query: send comma-separated `f32` values with no empty segments.
- Invalid view: use `summary`, `standard`, or `full`.
- Missing entity: do not invent a record. Report no record and keep any search result as stale or deleted.
- Idempotency conflict: reuse the original body for the same key, or generate a fresh key for a new mutation attempt.
- Internal server error: retry later and inspect server logs if repeated.
