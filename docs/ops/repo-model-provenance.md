# Model provenance for an attached repo run

`vault.repo.model.generate` serves request content on the caller's own attached
live run. Send the same `live_run` handle used by the other `vault.repo.*` doors.
The `spec` contains `messages`, optional `tools`, `params` and `provider_options`,
and a required `response_format`. It returns the native `LlmResponse`.

The host supplies the run's registered model seat, frozen agent model list,
actor, lease and spend line. The caller supplies no model id, envelope, payer,
lease proof or provenance hashes. This invokes the configured native code-mode
provider; a host without that provider or a registered model seat cannot serve
it. An injected provider that cannot observe its finalized physical request does
not manufacture a witness from the input.

Each native model attempt passes the existing provider admission, inherited model
list, budget, route and source checks. Immediately before send, the host
rechecks the current run, credential attachment and lease. The request witness
is captured after the ladder binds its actual model, locality and prompt. The
scope's existing live-lease ledger is used per rung and its remaining spend is
booked at the end, including errors and cancellation. A scoped line that fails
to open never falls back to the host's line.

After a successful answer and final credential/lease check, the host keeps only
the canonical request digest, model id and hash of sampling params plus provider
options. The prompt is not retained by this attachment cache. The last
successful witnessed request on that exact attachment supplies
`vault.repo.proposal_submit` through the native gated provenance mint. The
proposal still checks its own work, declaration, grant, review policy and final
writer admission. Model output is not a grant or an approval.

A fresh attachment, credential rebind, new lease or server restart inherits no
cached request. A rebind clears the old cache. A run with no witnessed request
keeps the existing `repo_provenance_required` hold and its work. A later failed
model call does not replace the last successfully served request. The cache is
not durable model history, a replay capsule, or a caller-asserted witness.

No deployment, guest artifact, vault migration or configuration change is
required. Existing model configuration and funding are used.
