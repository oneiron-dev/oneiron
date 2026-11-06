# Pack script streamed output

`PackScriptRun` takes the host's actual shared `ProposalSpoolFloor` as `output_floor`. A server caller uses the existing shared `server.transfers.disk` floor; it must not create a per-run floor or an unmetered fallback. This library port does not add a server pack-script caller.

The foreign adapter lends a `MicroVmOutputSpool` to the required output callback on the same caller thread. Frames are admitted on that floor before append. Console and file frames append; a new finish or store value replaces its previous value.

`PackScriptOutcome.output_streams` retains the actual console, finish, store and first-seen ordered file bodies, including their disk claims. No observation is selected and no completion value is guessed. `step_result` preserves the guest's optional result exactly as returned. The script contract's successful typed overlay does not acquire a new required `done` field or step-result shape check.

These bodies are not materialized into whole strings or byte vectors. The caller owns them and may read their native ranges. A retained store body does not bind a store verb or make a vault write. The existing foreign-code consumer still selects its observation from its own required `done` contract; that behavior is unchanged.

The original single typed overlay output, grant and connector checks, session receipts, and grouped inbound/event/wake writer remain in place. Stream output is not typed inbound authority. A Candidate is not made Active or executed by this change. SCRIPT Candidate qualification, its real credential operation transport, and an actual owner-route caller remain separate unimplemented work.

The complete authored caller-port unit can be applied to the whole W363 supplier/current-main bank without activating unrelated pending Notes changes: its entire original script caller blob is identical on W363 and the pre-port parent. The separate whole Notes/4531 source banks remain intact for their future real integration.

SDK generation and static parsing are not a production compile, a successful sandbox run, or full resource/privacy proof. No tests, new runtime configuration, operational constants or default limits are introduced.
