# Federation pact status

`Vault::federation_status()` is the embedded status read. It returns all pact ids,
their existing `FederationPactStatus`, current pact consent epoch, and an optional
local inactivity reason. Rows are ordered by pact id. `Active`, `Suspended` and
the terminal statuses keep their native meanings; an absent reason does not mean
that a pact is active.

The read obtains the pacts and mismatch set from one read-only authority view.
For a pact that view already holds inactive because its scope commitment does
not match its live opening, the reason is `scope_commitment_mismatch`. It does
not recompute the commitment in a second checker, erase more scope, heal a pact,
advance the authority clock, mint a grant or change existing admission.

The owner reads the same status through `vault.federation.status`, available in
the SDK, HTTP Facade and MCP surfaces. The input is `{}`. The served door uses
the ordinary verified owner binding; the embedded SDK uses its existing
constructor-owned owner handle. `Vault::federation_status_as_owner()` revalidates
that proof in the same read transaction as the status projection. No host
signer or federation transport is required for this read.

The selector's distinct refusal reason is separate integration work; this status
projection changes no selector.

There is no new configuration, operating default, cap, migration or old-format
reader. Deploy only with the corresponding native commitment-checking authority
view. No deployment or runtime verification is included here.
