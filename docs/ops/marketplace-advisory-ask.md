# Marketplace dependency-advisory asks

The setting is the catalogue key `skills.advisory_ask` (a boolean). The owner sets it
with `vault.settings.set`, for example
`{"key": "skills.advisory_ask", "scope": {"kind": "vault"}, "value": false}`, through
the native SDK, HTTP facade or MCP. The HTTP facade is
`POST /v1/core/facade/vault.settings.set`; pass the input object under `spec` when
using the MCP tool. `vault.settings.get` with `{"key": "skills.advisory_ask"}` reads
the value in force and which row decided it. Every change is one row of the settings
change stream.

The setting defaults to on. An advisory hit then changes an otherwise ready
marketplace fit into one owner ask. Turning it off leaves the advisory identifiers
in the fit analysis but does not turn that ready fit into an ask. Existing Ask and
NoFit decisions stay as they are. This setting does not change code auto-install
(`skills.code_auto_install`), permission admission, blocked hashes, held-out checks
or publisher grants.

No deployment configuration is needed. A row stored by the earlier
`vault.skills.advisory_ask.set` verb is not read: that storage ended with the
storage ABI bump that moved this switch to the settings catalogue.
