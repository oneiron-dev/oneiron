//! The side tables `task_verb` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Tracker issue id to task id. Key: string.
    LINEAR_ISSUE_REVERSE: VaultMeta b"linear.issue.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Tracker pull-page cursor. Key: ().
    LINEAR_PULL_CURSOR: VaultMeta b"linear.pull_cursor.v1" Raw Authored [accepts: crate::store::linear_pull_cursor::linear_pull_cursor_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// Repo-conflict claim to reconciliation task. Key: id16.
    REPO_CONFLICT_RECONCILIATION_INDEX: VaultMeta b"repo_conflict:reconciliation:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The review decision an owner accepted of a TASK no write had settled yet (FIX 11757),
    /// which the TASK's settlement names as its anchor: the first one, kept after the settlement
    /// as history and gone with the TASK's erase. Key: id16 (TASK).
    TASK_ACCEPTED_REVIEW: VaultMeta b"tasks.accepted_review.v1/" Named Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// Owner/question-class ask band and consumed receipt markers. Key: id16 + u16be + class [+ ':' id16].
    TASK_ASK_BAND: VaultMeta b"tasks.ask.band.v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Local ed25519 seed (32 bytes) that signs one ask group's option-link words. Key: id16 (group).
    TASK_ASK_LINK_SIGNER: VaultMeta b"tasks.ask.link_signer.v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// One option-link bearer row (group, person, revision, state). Key: blake3 hash32 of the token.
    TASK_ASK_OPTION_LINK: VaultMeta b"tasks.ask.option_link.v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// A person's current option-link bearer: the full token row key. Key: id16 (group) + id16
    /// (person).
    TASK_ASK_OPTION_SEAT: VaultMeta b"tasks.ask.option_seat.v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// `b"1"` marker that a person voided their option link. Key: id16 (group) + id16 (person).
    TASK_ASK_OPTION_VOID: VaultMeta b"tasks.ask.option_void.v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Highest acknowledged option-link void generation (u64be). Key: id16 (group).
    TASK_ASK_OPTION_VOID_ACK: VaultMeta b"tasks.ask.option_void_ack.v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Option-link void generation (u64be). Key: id16 (group).
    TASK_ASK_OPTION_VOID_GENERATION: VaultMeta b"tasks.ask.option_void_generation.v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Node-local ask origin entity id. Key: ().
    TASK_ASK_ORIGIN: VaultMeta b"tasks.ask.origin.v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Soft-confirm notice delivery state of one guest. Key: id16 (group) + id16 (person).
    TASK_ASK_SOFT_CONFIRM_DELIVERY: VaultMeta b"tasks.ask.soft_confirm.delivery.v1/" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Round-robin cursor of the soft-confirm retry sweep: the last visited delivery key suffix
    /// (id16 group + id16 person). Key: ().
    TASK_ASK_SOFT_CONFIRM_DELIVERY_CURSOR: VaultMeta b"tasks.ask.soft_confirm.delivery_cursor.v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One bound try's library program (CUA E4): the record its first lease resolved its TASK's
    /// handle to, with the TASK's arguments, or why there is none; the brief stamp and done-means
    /// it was leased under; and what its strict run came to. Copied from the admitted brief, and
    /// gone with its TASK's hard erase. Key: id16 (attempt).
    TASK_BROWSER_WORKFLOW_ATTEMPT: VaultMeta b"tasks.browser_workflow.attempt.v1/" Named Admitted
        [restore: content] [family: unclassified] [tier: canonical];
    /// By-owner index backfill marker. Key: ().
    TASK_BY_OWNER_BACKFILLED: VaultMeta b"tasks.by_owner.backfilled.v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Owner's tasks forward index. Key: id16 + id16 + id16.
    TASK_BY_OWNER_FORWARD: VaultMeta b"tasks.by_owner.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Per-actor task-create rate window. Key: id16 + u64be.
    TASK_CREATE_RATE_WINDOW: VaultMeta b"tasks.create.rate.v1\0" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// The creator attempt a create's agent TASK lands under (OF-532): parent attempt, its project
    /// and run tag, witnessed beside a gated create's proposal or a wave planning attempt. Key: id16
    /// (the proposal claim, or the id a wave planning attempt derives).
    TASK_CREATE_ORIGIN: VaultMeta b"tasks.create_origin.v1/" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Follow-up stage idempotency marker. Key: id16 + \x00 + string.
    TASK_FOLLOW_UP_MARKER: VaultMeta b"tasks.followup.v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The lifecycle receipts naming one TASK, by time (FIX 3270), written with each receipt in
    /// its own transaction. Value: one role byte, 1 on the receipt of the write that settled the
    /// TASK (FIX 3272), else 0. Key: id16 (TASK) + u64be (occurred_at) + string (receipt id).
    TASK_LIFECYCLE_RECEIPT_BY_TASK: VaultMeta b"tasks.lifecycle_receipt.by_task.v1/" Raw
        // Restore class: The receipt rows' own indexes: they come back with the rows they index.
        [restore: content] [family: unclassified] [tier: canonical];
    /// Every lifecycle receipt by time (FIX 3271), written with each receipt in its own
    /// transaction, so a query reads the newest first. Empty marker. Key: u64be (occurred_at) +
    /// string (receipt id).
    TASK_LIFECYCLE_RECEIPT_BY_TIME: VaultMeta b"tasks.lifecycle_receipt.by_time.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One mutating task-highway call's `TaskLifecycle` receipt (OF-220), projected as the receipt
    /// family reads it, written in the call's own transaction. Key: string (the receipt id,
    /// `task_lifecycle:` + 32 hex).
    TASK_LIFECYCLE_RECEIPT: VaultMeta b"tasks.lifecycle_receipt.v1/" Named
        // Restore class: Narrative of what each highway call did, like the report journal: not
        // authority.
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::task_verb::erase_lifecycle_actor_in_txn;
    /// Owner-authority fact to forward index key. Key: id16.
    TASK_OWNER_FACT_REVERSE: VaultMeta b"tasks.owner_fact.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Display handle for a peer actor. Key: id16.
    TASK_PEER_HANDLE: VaultMeta b"tasks.peer.handle.v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The skill tradeoff a project ask carries: proposal, question digest, project, task, question
    /// turn and whether the gate settled it or it went void. Key: id16 (ask group).
    TASK_PROJECT_TRADEOFF_ASK: VaultMeta b"tasks.project_tradeoff.ask.v1/" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The home-room TURN one skill tradeoff question was witnessed as, ids reserved before the
    /// speak. Key: id16 (proposal) + id16 (project) + question digest (64 hex).
    TASK_PROJECT_TRADEOFF_TURN: VaultMeta b"tasks.project_tradeoff.turn.v1/" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// One try's journaled report: the request and the receipt it was first answered with.
    /// Key: id16 (attempt) + u64 (attempt count) + bytes32 (reporter, TASK and report key).
    TASK_REPORT_JOURNAL: VaultMeta b"tasks.report.journal.v1/" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::task_verb::erase_report_actor_in_txn;
    /// Task symbol-overlap declaration. Key: id16.
    TASK_SYMBOL_LEASE: VaultMeta b"tasks.symbol_lease.v1/" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// One pending training offer asked of one owner (OF-577): the question TURN and MESSAGE ids
    /// and time reserved before the witness, the owner's conversation, and the ask group once
    /// admitted. Key: id16 (offer) + id16 (owner) + offer digest (64 hex).
    TASK_TRAINING_OFFER_ASK: VaultMeta b"tasks.training_offer_ask.v1/" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The training offer ask one ask group carries, by its reservation key. Key: id16 (ask group).
    TASK_TRAINING_OFFER_ASK_GROUP: VaultMeta b"tasks.training_offer_ask_group.v1/" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// One Scored training run's result asked of one owner (OF-577): the question ids reserved
    /// before the witness, the frozen swap expectation, the ask group once admitted and its state.
    /// Key: id16 (run) + id16 (owner) + result digest (64 hex).
    TASK_TRAINING_SWAP_ASK: VaultMeta b"tasks.training_swap_ask.v1/" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The training swap ask one ask group carries, by its reservation key. Key: id16 (ask group).
    TASK_TRAINING_SWAP_ASK_GROUP: VaultMeta b"tasks.training_swap_ask_group.v1/" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Registered external ask wait. Key: id16 + bytes32.
    TASK_ASK_WAIT: VaultMeta b"tasks.wait/" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::task_verb::erase_wait_actor_in_txn;
    /// Fan-out launch held for, or launched past, the approval mode: its frozen payload, plan,
    /// statement, pause or width-check row and ruling (OF-393). Key: hex32 (launch ref).
    TASK_FANOUT_LAUNCH: VaultMeta b"tasks/fanout/launch.v1/" Named
        // Restore class: An approved, denied or launched hold never rewinds to waiting.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::task_verb::erase_launch_actor_in_txn;
    /// Consult fan-out plan. Key: hex32.
    TASK_FANOUT_RUN: VaultMeta b"tasks/fanout/v1/" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::task_verb::erase_fanout_run_actor_in_txn;
    /// Wave-plan cut index. Key: bytes32.
    TASK_WAVE_PLAN_INDEX: VaultMeta b"wave.task.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
