# Connector source selection

`connector.call` and `connector.schema` accept an optional `source`:
`"catalog"` or `"builtin"`. When it is absent, the served door keeps its
implicit selection: an exact `web` name selects the built-in interface;
other names select their catalog entries.

To call a catalogued MCP connector whose actual name is `web`, pass:

```json
{"name":"web","source":"catalog","tool":"search","arguments":{"query":"example"}}
```

Read that same tool's approved schema with:

```json
{"name":"web","source":"catalog","tool":"search"}
```

The explicit catalog choice does not supply authority. The native catalog
route, caller's standing grant, active governing key, approved manifest,
slate, gate, credential and invocation checks still apply. A missing or
unavailable catalog route never falls back to a provider. Catalog names are
not reserved or renamed.

`source: "builtin"` selects only the built-in `web` interface. Another
builtin name is invalid; it does not fall back to a catalog connector.
The built-in's existing provider switch, supported tools, key custody,
charging and usage records are unchanged. If its setting selects a Hub,
that configured name is forwarded explicitly to the catalog, including
when the actual catalog name is `web`; schema discovery follows that same
Hub's governing manifest.

Held calls and their retries remain native catalog calls. Their existing
frozen request, caller, grant, invocation and receipt bindings are unchanged;
a retry by call ref cannot switch to the built-in provider. The foreign
reply's `source` string remains its existing attribution label, not a grant.

Native `Vault::call_connector*` methods and the connector-call arguments
nested inside `self.use` are catalog-only. They accept no explicit source
or `"catalog"`; an explicit `"builtin"` choice is invalid there. Built-in
calls use the served door and its own key selection instead.

Code-mode shorthand `connector.<name>.<tool>(args)` keeps implicit selection.
Use the typed `connector.call` or `connector.schema` operation with an explicit
source when the two interfaces share a name. Regenerate and ship the matching
SDKs with the engine to expose the new input field in typed clients.

This describes the source contract. It makes no provider-availability,
compile or runtime claim. No migration or old-format reader is added.
