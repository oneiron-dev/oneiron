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

This is the schema-discovery slice of physical FIX11606 (row text FIX11598).
Built-in `web` discovery in `connector.list` and catalog-name reservation remain
open. No fake catalog key, creation date, credential or MCP manifest is created.
There is no new registration refusal, default, policy, cap, migration or
compatibility reader. This document describes source behavior, not runtime or
whole-connector completion proof.
