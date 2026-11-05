# Marketplace dependency-advisory asks

The owner can call `vault.skills.advisory_ask.set` with `{"enabled": false}` or
`{"enabled": true}` through the native SDK, HTTP facade or MCP. The HTTP facade is
`POST /v1/core/facade/vault.skills.advisory_ask.set`; pass the input object under `spec`
when using the MCP tool. The call returns the existing owner consent receipt.

The setting defaults to on. An advisory hit then changes an otherwise ready
marketplace fit into one owner ask. Turning it off leaves the advisory identifiers
in the fit analysis but does not turn that ready fit into an ask. Existing Ask and
NoFit decisions stay as they are. This setting does not change code auto-install,
permission admission, blocked hashes, held-out checks or publisher grants.

The setting uses the existing vault-local marketplace switch. The native writer
revalidates the owner and records and spends its one consent in the same write
transaction. No deployment configuration or data migration is needed.
