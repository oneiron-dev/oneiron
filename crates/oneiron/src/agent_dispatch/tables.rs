//! The side tables `agent_dispatch` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Per-agent, per-unit launch spend calibration folded from settled launches. Key: string.
    AGENT_DISPATCH_SPEND_CALIBRATION: VaultMeta b"agent.dispatch.calibration.v1\0" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// One wait over the AGENT children an attempt spawned (slice 6.5b), and its first done
    /// reduction (JSON): the waiting attempt, the children's attempt ids, the policy and the
    /// step key. Key: id16(wait).
    AGENT_DISPATCH_CHILD_WAIT: VaultMeta b"agent.dispatch.child_wait.v1\0" Raw Authored [accepts: crate::agent_dispatch::agent_dispatch_child_wait_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// The index rows of the waits over AGENT children, by a one-byte tag: `w` id16(child
    /// attempt) + id16(wait) (a child's unsettled waits; a presence marker).
    AGENT_DISPATCH_CHILD_WAIT_INDEX: VaultMeta b"agent.dispatch.child_wait_index.v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// FIX 1380: one running child's comm widening, its per-reach asks to its parent and the
    /// reach the parent approved. Key: id16.
    AGENT_DISPATCH_COMM_WIDEN: VaultMeta b"agent.dispatch.comm.v1\0" Named Engine
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::agent_dispatch::erase_comm_widen_actor_in_txn;
    /// Resumable partial-result hold for one gracefully stopped spawn (OF-541). Key: id16.
    AGENT_DISPATCH_PLAN_HOLD: VaultMeta b"agent.dispatch.hold.v1\0" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::agent_dispatch::erase_plan_hold_actor_in_txn;
    /// FIX 3694: the owner's applied prompt continuation of one failed agent attempt: the card,
    /// ask and diagnostic it answered, the approving owner and when, the approval's fingerprint
    /// and id, and the successor attempt it enqueued. Key: id16(failed attempt).
    AGENT_DISPATCH_PROMPT_INJECT: VaultMeta b"agent.dispatch.prompt_inject.v1\0" Named Engine
        [restore: live] [family: unclassified] [tier: canonical];
    /// OF-544: the confession objectives one claimed agent run was asked, chosen at its first
    /// claim and read back at every later one (a continued run inherits its predecessor's). Key:
    /// id16(attempt).
    AGENT_DISPATCH_RUN_OBJECTIVES: VaultMeta b"agent.dispatch.run_objectives.v1\0" Named Engine
        [restore: live] [family: unclassified] [tier: canonical];
    /// Approved board-widened context slice override recorded for one parent attempt. Key: id16.
    AGENT_DISPATCH_WIDEN_SLICE: VaultMeta b"agent.dispatch.slice.v1\0" LegacyJson Authored [accepts: crate::agent_dispatch::agent_dispatch_widen_slice_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// One node of a launch's spend lease tree (root launch or child attempt). Key: string.
    AGENT_DISPATCH_SPEND_SCOPE: VaultMeta b"agent.dispatch.spend.v1\0" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::agent_dispatch::spend_handoff::erase_spend_scope_actor_in_txn;
    /// Index from a widen proposal's public content-hash id to its intent row key. Key: hex64.
    AGENT_DISPATCH_WIDEN_PROPOSAL_INDEX: VaultMeta b"agent.dispatch.widen_id.v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Dedupe index from a caller-supplied dedupe key to the workflow root attempt id. Key: hash32.
    AGENT_WORKFLOW_DEDUPE: VaultMeta b"agent.workflow.dedupe.v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A planned spawn under one asker's intent key (DOOR-111): the asker, the original ask and
    /// its digest, the custody phase and fence, the placed stamp and plan receipt or the kept
    /// refusal, and a launched team's frozen start and pack and its leader runs' exposures. An
    /// actor's scrub forgets the asker and keeps the row; behind the hard-delete marker, an erase
    /// of the asker or of the AGENT_DEF its plan seats leaves the row's erased form: its ids,
    /// times and state, and no text. Key: blake3 (32) of the framed asker, parent and intent key.
    SPAWN_PLANNED_INTENT: VaultMeta b"spawn:planned_intent:v2:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::agent_dispatch::AgentDispatcher::erase_planned_intent_actor_in_txn;
    /// The erase selector of each asker a hard erase reached: value-free and permanent, one
    /// marker per erased asker, so the intent fence still reaches a stale copy whose asker a
    /// plain scrub already forgot. Never a name or count. Key: blake3 (32) asker erase key.
    SPAWN_PLANNED_INTENT_ASKER_ERASED: VaultMeta b"spawn:planned_intent_asker_erased:v1:" Raw Engine
        // Payload family: The planned-intent fence's erased-asker selectors: value-free hashes
        // (FIX 11094).
        [restore: live] [family: structure] [tier: canonical];
    /// Content-free saved-tool fence, retained even when its payload cannot open. Key: id16 (attempt).
    WORKFLOW_TOOL_CHECKPOINT_FENCE: VaultMeta b"workflow:tool_checkpoint_fence:v1:" Named
        [restore: content] [family: structure] [tier: canonical];
}
