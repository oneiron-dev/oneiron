# HTTP API connectors from an OpenAPI document

A plain HTTP API can be a connector without an MCP server in front of it
(L8-31). Its OpenAPI 3.0 or 3.1 document lists its tools; from there the
built admission takes over unchanged: screening, the resolved manifest, the
slate the owner stamps, consent, the scoped grant check, the gate and the
intent ledger.

## Install

```toml
[connectors.notes]
transport = "http_api"
endpoint = "https://api.example.com/v1"
document = "/etc/oneiron/notes-openapi.json"
```

- `endpoint` is where every call goes: https, or http on loopback.
- `document` is an absolute file path on the host, or a URL (https, or http on
  loopback). The host reads it at register, refresh and attest, with no
  credential: the connector's secret goes to its endpoint only, at a call. A
  document over 16 MiB is refused.
- `document` is required for `http_api` and refused for `mcp_http`.

## What becomes a tool

- Each operation is one tool, named by its `operationId`. An operation
  without one is refused at register, naming its method and path.
- The input is one object: a property per path, query and header parameter,
  plus `body` for an `application/json` request body. `$ref`s resolve inside
  the document only; an external or cyclic reference is refused, naming the
  operation.
- The output is the first 2xx `application/json` response, when its schema is
  an object; `connector.schema` serves it as the tool's TypeScript reply type.
- GET and HEAD are read-only. PUT and DELETE are idempotent. Every writer
  destroys unless the operation says `x-oneiron-destructive: false`.
- A header parameter named `Idempotency-Key` is no argument. The host fills
  it with the call's intent key, and the operation counts as idempotent, so a
  recovery that sends again sends the same key.
- Any other header parameter carries `x-mcp-header`, so the header data class
  and its consent question apply as they do to an MCP tool's.
- OPTIONS and TRACE operations become no tool; the register reply lists them
  under `skipped`.
- Security: `http` bearer or basic, `oauth2` and `openIdConnect` present the
  key's custody secret as `Authorization`, as an MCP connector's is presented.
  `apiKey` and other schemes are refused at register (FIX
  OPENAPI-APIKEY-SECURITY).
- A `servers` entry (document, path or operation) must have the installed
  endpoint's origin; another origin is refused at register, naming it.

The tool's method and path ride its slate row (`http`), inside the manifest
hash and the owner's stamp. A refresh that changes them is an expansion: the
owner is asked again. The key pins the document's version (`openapi-3.0` or
`openapi-3.1`) in place of an MCP protocol revision.

## Activation

Activate the key with `POST /v1/owner/connectors/attest`. The probe suite
grades MCP probe evidence, which an HTTP API never answers with, so
`POST /v1/owner/connectors/qualify` refuses an `http_api` connector and names
`/attest`. Attest translates the document again and refuses when the tools
differ from the stamped slate; `/refresh` is the change door.

Connector packs install MCP connectors only; their doors refuse an `http_api`
section.

## The call

`connector.call` sends one request to the installed endpoint plus the stamped
path, read from the governing key's slate at the send:

- Each path argument is one percent-encoded segment; `.`, `..` and an empty
  value are refused before anything is sent. The URL must keep the endpoint's
  origin and path.
- Query arguments go in the document's order; a list repeats its name.
- The body is the `body` argument's bytes as the frozen call encodes them.
- The credential goes in `Authorization` inside the credential door, after the
  issuer hold is read again; no redirect is followed.
- A 2xx JSON object is the reply's `structured_content`, and the body text its
  `content`. Any other status outside 5xx is an error reply whose first block
  is `HTTP <status>`, with the body after it. A 5xx is ambiguous (the API may
  have acted); a 429 keeps the provider's `Retry-After` wait. A body over
  16 MiB is unreadable, and the call ambiguous.
- Every reply field and the raw body are cleared of the presented secret
  before they leave the door.
