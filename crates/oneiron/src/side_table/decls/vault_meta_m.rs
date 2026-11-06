// Declared `vault_meta` tables whose prefix starts with `m`, in prefix order.

side_tables! {
    VAULT_META_M;
    /// Engine-stamped monotonic causality sequence for identity-topology ledger events. Key: ().
    IDENTITY_TOPOLOGY_SEQ: VaultMeta b"m:identity_topology_seq" Raw;
    /// Conservative marker that a zero-head split has ever been recorded, gating an expensive ledger
    /// fold. Key: ().
    IDENTITY_TOPOLOGY_ZERO_HEAD_SEEN: VaultMeta b"m:identity_topology_zero_head_seen" Raw;
    /// The mail messages that landed with their headers only and wait for their bodies, newest
    /// first (FIX 12559). Key: id16(source) + u64be (u64::MAX less the receive time) + blake3
    /// (32) of the provider id.
    MAIL_PACK_BODY_QUEUE: VaultMeta b"mail_pack:body_queue:v1:" Named;
    /// The org compliance search log (FIX 12560): each change to the setting and each search made
    /// under it, recorded before the search answers. Key: u64be sequence.
    MAIL_PACK_COMPLIANCE_EVENT: VaultMeta b"mail_pack:compliance_event:v1:" Named Authored
        => crate::mail_pack::erase_compliance_actor_in_txn;
    /// The org compliance search setting, off when absent (FIX 12560). Key: ().
    MAIL_PACK_COMPLIANCE_SETTING: VaultMeta b"mail_pack:compliance_setting:v1" Named;
    /// One provider message of one mail source: its rows, revisions, stage and presence at the
    /// provider (FIX 12559). Key: id16(source) + blake3 (32) of the provider id.
    MAIL_PACK_OCCURRENCE: VaultMeta b"mail_pack:occurrence:v1:" Named;
    /// The rows each imported mail message landed as (FIX 12559), so an erase of any of them
    /// scrubs that message's occurrence. Key: id16(row) + id16(source) + blake3 (32) of the
    /// provider id.
    MAIL_PACK_OCCURRENCE_ROW: VaultMeta b"mail_pack:occurrence_row:v1:" Named;
    /// One connected mail or calendar source: provider, kind, address, custody name, owner,
    /// audience and what it keeps (FIX 12559). Key: id16(source).
    MAIL_PACK_SOURCE: VaultMeta b"mail_pack:source:v1:" Named
        => crate::mail_pack::erase_source_actor_in_txn;
    /// A source's id by its provider, kind, account and address (FIX 12559). Key: blake3 (32).
    MAIL_PACK_SOURCE_INDEX: VaultMeta b"mail_pack:source_index:v1:" Named;
    /// Where one mail source's import stands: its change anchor, its newest-first copy and its
    /// counts (FIX 12559). Key: id16(source).
    MAIL_PACK_SYNC: VaultMeta b"mail_pack:sync:v1:" Named;
    /// Idle publication delay. Key: ().
    ENTITY_TEXT_INDEXED_IDLE_DELAY_MS: VaultMeta b"manifest:entity_text:indexed_idle_delay_ms" Raw;
    /// FIX 9970: a TURN whose landing could not record its program wake, and why, written in
    /// that landing's commit and cleared when a later landing of the turn evaluates its wake.
    /// Key: id16(turn).
    MEMORY_TURN_WAKE_UNPERSISTED: VaultMeta b"memory:turn_wake_unpersisted:v1:" Named Engine;
    /// One merge batch's proposals, worktree paths, and lifecycle state. Key: hex(repo identity) ":"
    /// hex64(batch id).
    MERGE_QUEUE_BATCH: VaultMeta b"merge_queue:batch:v1:" Named Authored [accepts: crate::merge_queue::merge_queue_batch_accepts_masked];
    /// One merge batch filed under a proposal, run work or run declaration it names, so a run's
    /// enqueue, stage and observe read its own batches by key (FIX 7067). Key: hex(repo
    /// identity) ":" kind ":" id ":" hex64(batch id).
    MERGE_QUEUE_BATCH_INDEX: VaultMeta b"merge_queue:batch_index:v1:" Named Engine;
    /// One object store's checked queue configuration: the approved baseline, the plan frozen
    /// from it and the owner's queued check approval (FIX 6868). Key: hex(repo identity).
    MERGE_QUEUE_CHECK_CONFIG: VaultMeta b"merge_queue:check_config:v1:" Named Authored [accepts: crate::merge_queue::merge_queue_check_config_accepts_masked];
    /// One requested queue init, check or diagnosis: its attempt, generation, status and
    /// receipts (FIX 6868). Key: hex(repo identity) ":" hex64(request digest).
    MERGE_QUEUE_CHECK_WORK: VaultMeta b"merge_queue:check_work:v1:" Named Authored [accepts: crate::merge_queue::merge_queue_check_work_accepts_masked];
    /// One checker receipt filed under its inputs digest and verdict, so a reused, bound or
    /// sealed receipt is read by key (FIX 7349). Key: hex(repo identity) ":" inputs digest ":"
    /// verdict ref (empty for none) ":" hex64(request digest).
    MERGE_QUEUE_RECEIPT_INDEX: VaultMeta b"merge_queue:receipt_index:v1:" Named Engine;
    /// The vault's one opt-in review policy for merge queue work; no row lands on green (FIX
    /// 8268). Key: (). FIX 8519: this entry's scrub takes an erased setter's id out of it.
    MERGE_QUEUE_REVIEW_POLICY: VaultMeta b"merge_queue:review_policy:v1" Named Authored [accepts: crate::merge_queue::merge_queue_review_policy_accepts_masked]
        => crate::merge_queue::erase_review_policy_actor_in_txn;
    /// Repo-scoped merge-queue pointers, workspace graph, and in-flight intent state. Key: hex(repo
    /// identity).
    MERGE_QUEUE_STATE: VaultMeta b"merge_queue:state:v1:" Named;
    /// The reply assertions a MESSAGE born whole (not streamed) kept from its witness write
    /// (FIX 10260): its turn, conversation and writer, and the ids and types its turn asserted.
    /// Key: id16(message).
    MESSAGE_REPLY_ASSERTIONS: VaultMeta b"message_reply_assertions:v1:" Named Engine;
    /// In-flight streamed message recovery seed. Key: id16. FIX 10668: this entry's scrub takes
    /// the signed slip out of a Retry seed's action its erased requester asked.
    MESSAGE_STREAM_ACTIVE: VaultMeta b"message_stream:v1:" Named
        => crate::memory::scrub_stream_seed_actor_in_txn;
    /// Vault default message-streaming policy. Key: ().
    MESSAGE_STREAM_POLICY: VaultMeta b"message_stream_policy:v1" Named;
    /// Latest terminal stream receipt of a message. Key: id16.
    MESSAGE_STREAM_RECEIPT: VaultMeta b"message_stream_receipt:v1:" Named;
    /// Owner-submitted model requests and their terminal receipts. Key: id16(step attempt).
    MODEL_STEP_SUBMISSION: VaultMeta b"model_step:submission:v1:" Named Authored [accepts: crate::store::model_step_submission::model_step_submission_accepts_masked];
    /// Owner-submitted shared model streams: the frozen request and its one durable terminal.
    /// Key: id16(stream).
    MODEL_STREAM: VaultMeta b"model_stream:terminal:v1:" Named Authored [accepts: crate::store::model_stream_row::model_stream_accepts_masked];
}
