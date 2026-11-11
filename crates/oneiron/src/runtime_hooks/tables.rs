//! The side tables `runtime_hooks` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// A hook block: the rows one AddBlock pins for a recipient's board deliveries, its lifetime
    /// and its consumption. Key: id16 (block).
    HOOKS_BLOCK: VaultMeta b"hooks:block:v1:" Named Authored [accepts: crate::runtime_hooks::hooks_block_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// An owner check a hook's causal chain raised (a cycle or a deep chain). Key: hash32 (run key).
    HOOKS_CHECK: VaultMeta b"hooks:check:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A fact hook's cursor in one source. Key: id16 (binding) + u8 (source).
    HOOKS_CURSOR: VaultMeta b"hooks:cursor:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The vault's `hooks.enabled` switch; absent is on. Key: ().
    HOOKS_ENABLED: VaultMeta b"hooks:enabled:v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The owner's grant on one hook binding. Key: id16 (binding).
    HOOKS_GRANT: VaultMeta b"hooks:grant:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Queued work a hook run saved before its cursor moved, and whether it landed. Key: hash32
    /// (run key).
    HOOKS_INTENT: VaultMeta b"hooks:intent:v1:" Named Authored [accepts: crate::runtime_hooks::hooks_intent_accepts_masked]
        [restore: live] [family: unclassified] [tier: canonical];
    /// The hook chain behind a row a hook landed. Key: id16 (row).
    HOOKS_LINEAGE: VaultMeta b"hooks:lineage:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A hook run's saved result and pinned input. Key: hash32 (run key).
    HOOKS_MEMO: VaultMeta b"hooks:memo:v1:" Named Authored [accepts: crate::runtime_hooks::hooks_memo_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// A verb call a count-bound budget window paced, held in its caller's fair line until its
    /// turn (FIX 8753, ARCH-0044 C5): the call, its args with its ids fixed, the credential
    /// reference it resumes under, its arrival, its fixed deadline and when it may run, and what
    /// it came to. Key: id16 (invocation).
    HOOKS_PACED_VERB: VaultMeta b"hooks:paced_verb:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The paced line's bookkeeping: the last arrival handed out and the principal whose turn ran
    /// last. Key: ().
    HOOKS_PACED_VERB_LINE: VaultMeta b"hooks:paced_verb_line:v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The instrument a paced credential call's request was admitted on, pinned beside it for the
    /// drain to verify again: a slip, its holder's challenge and signature, or a managed vault's
    /// attested owner's person, never a secret. Dropped when the call ends. Key: id16
    /// (invocation).
    HOOKS_PACED_VERB_WITNESS: VaultMeta b"hooks:paced_verb_witness:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// A hook run's Hook receipt. Key: hash32 (run key).
    HOOKS_RECEIPT: VaultMeta b"hooks:receipt:v1:" Named Authored [accepts: crate::runtime_hooks::hooks_receipt_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// A hook's regen record: the contract its last good body passed under, its intent, and a
    /// regen decision waiting to be enacted. Key: id16 (binding).
    HOOKS_REGEN: VaultMeta b"hooks:regen:v1:" Named Authored [accepts: crate::runtime_hooks::hooks_regen_accepts_masked]
        [restore: live] [family: unclassified] [tier: canonical];
    /// One step in a hook's regen history (FIX 4691): a regen decision with its golden manifest,
    /// or an adoption, cancel or revert of one; body hashes only, never a body. Key: hash32
    /// (blake3 of the hook's pack, a zero byte and its name) + u64be (sequence within the hook).
    HOOKS_REGEN_RECEIPT: VaultMeta b"hooks:regen_receipt:v1:" Named Authored [accepts: crate::runtime_hooks::hooks_regen_receipt_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// Each hook binding's runs in commit order, each naming its saved row: a fact run's memo or
    /// a verb run's saved copy. Key: id16 (binding) + u64be (commit time, Unix ms) + hash32 (run
    /// key).
    HOOKS_RUN_INDEX: VaultMeta b"hooks:run_index:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A permanently erased id whose hook carriers an erase's scrub cleaned, and when (Unix
    /// seconds): the hard-erase sweep scrubs only the ids not here, as every hook carrier's writer
    /// keeps a fenced id out from that write on (FIX 22191). Key: id16 (the erased id).
    HOOKS_SCRUBBED_SOURCE: VaultMeta b"hooks:scrubbed_source:v1:" Named
        // Restore class: FIX 22191: the scrub marks restore with the carriers they vouch for, so an
        // image from before a scrub brings none back and its sweep runs.
        [restore: content] [family: unclassified] [tier: canonical];
    /// The settlement feed fact hooks follow: one row per settled proposal while a fact binding
    /// reads the feed; an erase leaves a row naming the erased proposal or settler as an empty
    /// erased row, and the runner prunes the rows every binding passed, every row while no fact
    /// binding is enabled. Key: u64be (sequence).
    HOOKS_SETTLED: VaultMeta b"hooks:settled:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The last settlement sequence handed out. Key: ().
    HOOKS_SETTLED_NEXT: VaultMeta b"hooks:settled_next:v1" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The inbound surface-event feed fact hooks follow (FIX 4749): one row per admitted
    /// connector SurfaceEvent while a fact binding reads the feed, its ids and tokens only; an
    /// erase leaves a row naming the erased entity as an empty erased row, and the runner prunes
    /// the rows every binding passed. Key: u64be (sequence).
    HOOKS_SURFACE_INBOUND: VaultMeta b"hooks:surface_inbound:v1:" Named
        // Restore class: FIX 4749: the watcher feeds, the due index and the tick feed restore with
        // the TASKs and cursors they stand beside.
        [restore: content] [family: unclassified] [tier: canonical];
    /// The last inbound surface-event sequence handed out. Key: ().
    HOOKS_SURFACE_INBOUND_NEXT: VaultMeta b"hooks:surface_inbound_next:v1" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Each TASK with a due time not yet ticked (FIX 4749). Key: u64be (due time, Unix seconds)
    /// + id16 (TASK).
    HOOKS_TASK_DUE: VaultMeta b"hooks:task_due:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Each TASK the due index holds (FIX 4749): the due time it holds, and the tick sequence
    /// its release committed, if it has ticked. Key: id16 (TASK).
    HOOKS_TASK_DUE_REVERSE: VaultMeta b"hooks:task_due_reverse:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The tick feed fact hooks follow (FIX 4749): one row per due TASK released; an erase
    /// leaves an erased TASK's row as an empty erased row, and the runner prunes the rows every
    /// binding passed, but an open TASK's own tick. Key: u64be (sequence).
    HOOKS_TICK: VaultMeta b"hooks:tick:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The last tick sequence handed out. Key: ().
    HOOKS_TICK_NEXT: VaultMeta b"hooks:tick_next:v1" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A call a verb hook's ask stopped: the call, its re-validated args, the hook's place in the
    /// chain and the ask handle, Open until a retry resumes it once. Key: id16 (invocation).
    HOOKS_VERB_ASK: VaultMeta b"hooks:verb_ask:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The instrument a credential caller's request was admitted on, pinned beside its stopped
    /// call for the drain to verify again: a slip, its holder's challenge and signature, or a
    /// managed vault's attested owner's person, never a secret and no credential minted for him.
    /// Pruned with the call. Key: id16 (invocation).
    HOOKS_VERB_ASK_WITNESS: VaultMeta b"hooks:verb_ask_witness:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// A verb hook run's saved copy: the exact input its body saw, its read pins and the outcome it
    /// returned. Key: hash32 (run key).
    HOOKS_VERB_RUN: VaultMeta b"hooks:verb_run:v1:" Named Authored [accepts: crate::runtime_hooks::hooks_verb_run_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
}
