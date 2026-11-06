# Pack script streamed output

`PackScriptRun` takes the host's actual shared `ProposalSpoolFloor` as `output_floor`. A server caller uses the existing shared `server.transfers.disk` floor; it must not create a per-run floor or an unmetered fallback. This library port does not add a server pack-script caller.

The foreign adapter lends a `MicroVmOutputSpool` to the required output callback on the same caller thread. Frames are admitted on that floor before append. Console and file frames append; a new finish or store value replaces its previous value. The native step result's required `done` boolean selects finish or console. No guessed done value is supplied.

`PackScriptOutcome.observation` and `output_files` retain the selected body and first-seen ordered file bodies, including their disk claims. They are not materialized into whole strings or byte vectors. The caller owns those bodies and may read their native ranges. Untaken store frames have the native spool's existing lifetime and do not make a vault write.

The original single typed overlay output, grant and connector checks, session receipts, and grouped inbound/event/wake writer remain in place. Stream output is not typed inbound authority. A Candidate is not made Active or executed by this change. SCRIPT Candidate qualification, its real credential operation transport, and an actual owner-route caller remain separate unimplemented work.

This source port preserves the whole published W363 supplier bank. SDK generation and static parsing are not a production compile, a successful sandbox run, or full resource/privacy proof. No tests, new runtime configuration, operational constants or default limits are introduced.
