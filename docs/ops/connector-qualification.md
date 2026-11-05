# Connector qualification discovery capture

The host's `HttpQualificationConnection` returns both the declarations and the
requests used to list them. Each HTTP `tools/list` page contributes one captured
request body and its headers, in send order. The capture comes from the built
request passed to `Client::execute`, not from the connector's reply. The existing
capture routine excludes `Authorization`.

The qualification runner keeps comparing the two connections' declarations.
It also checks each captured page's `Mcp-Method` against the `tools/list` body.
It does not compare session headers or page counts across connections. Discovery
requests do not change the qualification report hash. Existing call probes and
their header, grounding, scope, and replay checks are unchanged.

The built-in channel probe lists its static tool in process. Its discovery
capture is empty because it sends no HTTP discovery request. Ordinary admission
catalog discovery does not request captures; its listing behavior is unchanged.

## Remaining header contract

FIX 711 remains partial. ARCH-0028 requires method/name header conformance, but
an MCP `tools/list` request has no tool name in its body. This slice does not
invent a `Mcp-Name` value or require that the header be absent. It adds no rule
for request-id spelling, session equality, or response cursor-chain evidence.
The existing pagination and repeated-cursor handling remain in force.
