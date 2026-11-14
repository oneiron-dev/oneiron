//! The side tables `code_run` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// FIX 4570: the SUMMARY one actor's compaction home wears as its self-model, by ref only;
    /// set by the owner or the actor's own door, read through the actor's own scoped SUMMARY
    /// read. Key: id16(actor).
    ACTOR_SELF_MODEL_SUMMARY: VaultMeta b"actor:self_model_summary:v1:" Named Engine
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::code_run::erase_self_model_binding_actor_in_txn;
    /// Node-local executor coverage bound to a minted epoch SUMMARY (fixed 73-byte frame). Key:
    /// id16(run) + id16(summary).
    CODE_RUN_COMPACTION: VaultMeta b"code_run:compaction:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One code consent wait (DOOR-079): the binding minted beside its held effect (run and
    /// write site, request and frozen digests, original caller and instrument, the pending
    /// connector call), its ask, the parked step's seal, the owner's first answer, the effect
    /// gate's admission and the settlement. Only `code_run::consent_wait` writes it. Key:
    /// id16(wait).
    CODE_RUN_CONSENT_WAIT: VaultMeta b"code_run:consent_wait:v1:" Named Engine
        // Restore class: A code consent wait (DOOR-079) entangles a one-shot answer, an external
        // effect's admission and settlement, and (1b) the replay that consumed it: a rollback could
        // unspend it, and keeping it live alone would point into a rolled-back replay. Its family
        // refuses a restore instead (CALLS: restore Refuse).
        [restore: refuse "code consent waits"] [family: unclassified] [tier: canonical];
    /// A successor attempt's approved continuation of a failed run (FIX 3694): the Failed
    /// predecessor, its run, the step the child starts at, the owner's approval, the approved
    /// prompt and its digest, the start body's digest and its capsule's lease generation. Key:
    /// id16(successor attempt).
    CODE_RUN_CONTINUATION: VaultMeta b"code_run:continuation:v1:" Named Authored [accepts: crate::code_run::code_run_continuation_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// One contribution check's matched-fork rows (FIX 3028, FIX 2870): each fork's receipt (the
    /// capsule it regenerated, its request hash, model, seed, response body ref, anchor hash, the
    /// outcome, goal revision and axis it was scored for, and its score), why the pair is
    /// unavailable for good, or an owner verdict's pending owner pair (FIX 3609). Key: hash32(attempt
    /// receipt, outcome, goal revision, axis, target) + string(row: `with_skill`, `without_skill`,
    /// `owner_pair` or `unavailable`).
    CODE_RUN_CONTRIBUTION_FORK: VaultMeta b"code_run:contribution_fork:v1:" Named Engine
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::code_run::erase_contribution_forks_in_txn;
    /// One model response a live code-mode REPL normalized at one step (FIX 4411, 4412): the
    /// configured model id, the four packaging repairs, the outcome (clean, normalized, or
    /// rejected with the executor's stable reason), the repair policy and, for a committed step,
    /// its checkpoint. Ids, counts, flags and engine text only, never response text. Key:
    /// id16(run) + be64(step) + be64(attempt).
    CODE_RUN_CORRECTION: VaultMeta b"code_run:correction:v1:" Named Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// Node-local per-model wire-heal tally, keyed by validated model id. Key: string.
    CODE_RUN_HEAL_COUNT: VaultMeta b"code_run:heal_count:v1:" Raw Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// One model call's evidence and replay record (FIX 12516), keyed by
    /// id16(attempt) + be64(lease generation) + be64(call index). Side-table
    /// evidence only: never an entity, BM25/vector/Dreamer input.
    CODE_RUN_MODEL_CALL: VaultMeta b"code_run:model_call:v1:" Named Authored
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::code_run::erase_model_call_actor_in_txn;
    /// DOOR-141 PR3b: a turn program's resume checkpoint, joined to its code run's checkpoint
    /// commit: the head (the pinned program it replays, the record position and state hash its
    /// last entry committed, the applied and injected positions, its page count and the wait it
    /// parked on) and keyed pages listing each settled call by its record row, request digest
    /// and the delivered wait reply answering it. Refs and digests only, never an effect's body.
    /// Key: id16(code run) + be64(kind: 0 head, 1 page) + be64(page).
    CODE_RUN_PROGRAM_RESUME: VaultMeta b"code_run:program_resume:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The worlds of the rows one code run was served (FIX 6130): its header (tag 0: the capture
    /// epochs still open and why the ledger misses rows) and one row per world a served row sat
    /// in (tag 1 + id16(world): the bridge positions it was served at). Ids and positions only.
    /// Key: id16(run) + u8 tag [+ id16(world)].
    CODE_RUN_READ_WORLD: VaultMeta b"code_run:read_world:v1:" Named Engine
        // Payload family: CALLS CODE_RUN_READ_WORLD: ids, positions and enums only, but no ruling
        // makes it structure yet.
        [restore: content] [family: unclassified] [tier: canonical];
    /// The last actual parent entry's full destination, route, actor and loaded install
    /// machine (JSON), qualified again on recovery. Key: id16(parent run).
    CODE_RUN_READER_CALLER: VaultMeta b"code_run:reader_caller:v1:" Raw Engine
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::code_run::erase_reader_caller_actor_in_txn;
    /// A code run's fold receipt (ARCH-0079 #reader-forks): the source and range a fold read,
    /// the jobs it named, the ranges read, unread and read short, its cutoff, recipe, summary
    /// tree and taint dependencies (JSON). Key: id16(owner run) + id16(folded occurrence).
    CODE_RUN_READER_FOLD: VaultMeta b"code_run:reader_fold:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The index rows of a code run's reader children, by a one-byte tag: `c` id16(parent) +
    /// be64(ordinal) + id16(task) (children in spawn order), `f` id16(parent) + handle -> id16(task)
    /// (findings), `q` be64(enqueued ms) + id16(task) (the queue), `w` id16(task) + id16(set)
    /// (a child's waits), `d` be64(due ms) + id16(set or task) -> `s` or `j` (the due sweep).
    CODE_RUN_READER_INDEX: VaultMeta b"code_run:reader_index:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One reader child of a code run: its binding, state, generation and latest finding (JSON).
    /// Key: id16(task).
    CODE_RUN_READER_JOB: VaultMeta b"code_run:reader_job:v1:" Raw Authored [accepts: crate::code_run::code_run_reader_job_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// A code run's reader row: its children's clock, fixed at its first spawn, their spend scope
    /// and its counts (JSON). Key: id16(run).
    CODE_RUN_READER_PARENT: VaultMeta b"code_run:reader_parent:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One wait over a code run's reader children, and its first done reduction (JSON). Key:
    /// id16(set).
    CODE_RUN_READER_WAIT: VaultMeta b"code_run:reader_wait:v1:" Raw Authored [accepts: crate::code_run::code_run_reader_wait_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// A canonical attempt's step replay capsule (FIX 3028): the request the step sent by its body
    /// ref and hash, each skill exposure in it, its seed and the rung that answered it. Key:
    /// id16(attempt) + be64(lease generation) + be64(step).
    CODE_RUN_REPLAY_CAPSULE: VaultMeta b"code_run:replay_capsule:v1:" Named Authored [accepts: crate::code_run::code_run_replay_capsule_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::code_run::erase_capsule_actor_in_txn;
    /// Whose reply content one code-run replay record holds (FIX 5718): the run it is (its own,
    /// or a write receipt's run) and one of three states. Kept: the replies are there, for the
    /// actor its host stamped. Deleted: a soft delete of that actor took them (FIX 15532). The
    /// row keeps the actor and the reply bodies it released, for that actor's hard erase (FIX
    /// 6591). Erased: an erase took them, or a late write found the actor's hard-delete marker,
    /// so its hard erasure is complete. The row names no actor. Deleted and Erased read as
    /// erased, for good. Key: id16(record).
    CODE_RUN_RESPONSE_OWNER: VaultMeta b"code_run:response_owner:v1:" Named Engine
        // Payload family: A code run's response owner and wait holder hold ids, status and an
        // actor's id or its erasure, never the reply (FIX 6589).
        [restore: content] [family: structure] [tier: canonical];
    /// One run's resume-divergence ask (L8-23): the held step, the walk's report, the report's
    /// effect digest, when asked and the owner's answer. Only `engine_executor::resume_divergence`
    /// writes it. Key: id16(run).
    CODE_RUN_RESUME_DIVERGENCE: VaultMeta b"code_run:resume_divergence:v1:" Named Engine
        // Restore class: A resume-divergence ask entangles a one-shot owner release of an effect
        // with the replay it releases: a rollback could unspend it, and keeping it live alone
        // would point into a rolled-back replay. Its family refuses a restore instead.
        [restore: refuse "resume divergence answers"] [family: unclassified] [tier: canonical];
    /// The owner's value-free dismissal of one code-run secret lift proposal. The
    /// occurrence's secret/taint marks stay unchanged. Key: string(handle/occurrence).
    CODE_RUN_SECRET_LIFT_DISMISSED: VaultMeta b"code_run:secret_lift:dismissed:v1:" Named Engine
        [restore: content] [family: structure] [tier: canonical];
    /// A summary a code run's `summarize` made: its task and its text's occurrence (JSON). Key:
    /// bytes32(memo: BLAKE3 of the members' occurrences and ranges, and the recipe).
    CODE_RUN_SUMMARY_MEMO: VaultMeta b"code_run:summary_memo:v1:" Raw Authored [accepts: crate::code_run::code_run_summary_memo_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// One program step's type feedback (FIX 8277): its check's state, measures and diagnostics
    /// or the run's body holding them, the preparation note, the actor the run ran as and the
    /// checker incarnation a pending check belongs to. Key: id16(run) + be64(step) +
    /// be64(invocation).
    CODE_RUN_TYPE_DIAGNOSTICS: VaultMeta b"code_run:type_diagnostics:v1:" Named Authored [accepts: crate::code_run::code_run_type_diagnostics_accepts_masked]
        // Payload family: CALLS CODE_RUN_TYPE_DIAGNOSTICS (FIX 8277): a step's check state and
        // measures, its diagnostics inline or in the run's own body; no ruling classes it yet.
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::code_run::erase_type_diagnostics_actor_in_txn;
    /// The code runs parked on a wait (`p` + id16(wait) + id16(run), value be64(generation)) and
    /// the reply the wait settled with (`s` + id16(wait), value JSON). Key: u8 tag + id16 [+ id16].
    CODE_RUN_WAIT_INDEX: VaultMeta b"code_run:wait_index:v1:" Raw Authored [accepts: crate::store::executor_wait_delivery::code_run_wait_index_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// Node-local C9 trap a host bound to one parked code-run wait, woken in the commit that
    /// delivers it (fixed layout). Key: id16(run) + id16(wait) + be64(generation).
    CODE_RUN_WAIT_TRAP: VaultMeta b"code_run:wait_trap:v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
}
