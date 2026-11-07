# Built-in web connector input schemas

`connector.schema` accepts `{"name":"web","tool":"search"}` or
`{"name":"web","tool":"fetch"}`. It follows the same first-party name and
supported-tool selection as the served `connector.call` path.

For a provider-backed route, the answer describes the actual built-in input:
- `search`: a query string, or `WebSearchInput` (`query`, optional `max_results`).
- `fetch`: a URL string, or `WebFetchInput` (`url`).

The object schemas come from those Rust input types. The string alternative is
also accepted by the existing argument parsers. This read does not load a
provider key, call a provider, charge a budget, or write usage. Its
`destructive` hint is false for the built-in provider search/read operations;
it is not an authorization or a promise that credentials, budget or a remote
provider are available. Existing input validation, count/text limits and
execution behavior are unchanged.

When the current web setting selects a Hub connector, schema discovery follows
that configured connector through the existing caller-bound route, grant,
governing key, approved manifest and slate. The actual schema and destructive
hint come from that connector. All native rows read for that decision remain
listed through `Memory::produced_from`, including unavailable outcomes. There
is no invented built-in grant or false read-only hint for a Hub tool.

Unknown web tools are unavailable, just as at the served call door. Non-web
schema discovery is unchanged. The existing SDK, facade and MCP operation reaches
this native reader; no new transport shape or verb is required.

## Connector discovery

`connector.list` includes the first-party `web` interface alongside every
matching live catalogued connector. Each entry has a `source` discriminator:

- `catalog`: the existing catalog fields, including its actual `call_class`
  and `registered_at`.
- `builtin`: `name`, `connector`, `summary` and the supported `search`/`fetch`
  interface names. There is no fabricated registration time, call class,
  catalog key, credential or MCP manifest.

Both names and summaries use the catalog's existing query matching. Catalog
entries keep their original order. The built-in entry is inserted before the
first catalog name at or after `web`; it does not replace or hide a catalogued
connector with the same name. A blank query includes both kinds. Tool names
are descriptive, not a promise that a provider key, grant, budget or service
is available. Calls and schema reads still run their existing native checks.
`connector.status` remains the history lens for catalogued keys, whose nested
entry now carries `source: "catalog"`.

The schema and discovery slices of physical FIX11606 (row text FIX11598) are
implemented here. A catalogued MCP connector named `web` remains stored and
listed, but the existing served call/schema name intercept still selects the
first-party route. Unshadowed selection of that catalogued connector remains
open; registration is not newly refused and no existing key is renamed.
There is no new default, policy, cap, migration or compatibility reader.
Deploy matching engine/server and regenerated SDK clients for the tagged
response shape. This document describes source behavior, not runtime or
whole-connector completion proof.
