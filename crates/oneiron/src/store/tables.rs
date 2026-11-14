//! The side tables `store` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// A control-plane API key record (HMAC-SHA256 digest, scopes, expiry, revoked flag) keyed by its
    /// own digest. Key: hex64.
    AUTH_CONTROL_KEY: SyncState b"auth:control-key:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Marker row (empty value) recording that a legacy 32-hex bearer-token identifier has been
    /// revoked. Key: hex32.
    AUTH_REVOKED_TOKEN_JTI: SyncState b"auth:revoked-token-jti:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// First-seen sidecars per authority entry hash, plus the 'backfill:v1' and 'clock_floor' rows.
    /// Key: string.
    /// Snapshot-local generation of the authority fold cache. Key: ().
    AUTHORITY_CACHE_GENERATION: SyncState b"authlog:cache_generation:v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// One recorded OF-520 ingest-burst check (24 bytes), raised once per peer per observation
    /// window. Key: hex64 ":" u64hex16.
    AUTHLOG_INGEST_CHECK: SyncState b"authlog:ingest_check:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Local sliding-window replay-ingest counter (start/count/raised, 17 bytes) per authority peer
    /// signer. Key: string.
    AUTHLOG_INGEST_COUNT: SyncState b"authlog:ingest_count:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Device-local authority observation policy: stale-roster window, ingest window, ingest check
    /// threshold, log signer bound, log headroom rows, handoffs and ancestor pairs, and the fold's
    /// memory floor (8x u64be; a 3x or 6x row reads with the default bounds). Key: ().
    AUTHLOG_OBSERVATION_POLICY: SyncState b"authlog:observation_policy:duration_v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Durable high-water mark (u64be) of a signer's highest observed authority-log sequence number.
    /// Key: string.
    AUTHLOG_SEQ_HWM: SyncState b"authlog:seq_hwm:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// First-observation receipt recording the signer sequence high-water mark that existed before
    /// this entry hash was first observed. Key: hex64.
    AUTHLOG_SEQ_OBSERVATION: SyncState b"authlog:seq_observation:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Cached minted host-root capability-slip token ("v2.slip."+hex(JSON)) for one host signing key.
    /// Key: `:` + hex.
    AUTHORITY_HOST_ROOT_SLIP_CACHE: SyncState b"authority:host-root-slip:v2" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Host-signed mesh binding projection keyed by hex32 MACHINE id.
    AUTHORITY_MESH_MACHINE: SyncState b"authority:mesh-machine:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Cached minted host-held project.write slip token ("v2.slip."+hex(JSON)) the owner's project
    /// signer uses, for one host signing key. Key: hex64.
    AUTHORITY_OWNER_PROJECT_SLIP_CACHE: SyncState b"authority:owner-project-slip:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The facet a paired credential's writes are born in, as the owner named it on the link
    /// (raw id). Key: hex64 (the slip id).
    AUTHORITY_PAIRING_WRITE_FACET: SyncState b"authority:pairing-write-facet:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// One outstanding single-use pairing/enrollment link, keyed by a keyed-hash of its typed code.
    /// Key: hex64.
    AUTHORITY_PAIRING_PENDING: SyncState b"authority:pairing:" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
    /// The floor of the clock holder proofs are judged on (u64be seconds): the reading the last
    /// admission committed, or the wall time an owner clock recovery set. Key: ().
    AUTHORITY_SLIP_PROOF_CLOCK: SyncState b"authority:slip-proof-clock:v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The earliest signed time a holder proof may carry (u64be seconds): past every evicted
    /// replay nonce, and at least the wall time of the last owner clock recovery. Key: ().
    AUTHORITY_SLIP_PROOF_NOT_BEFORE: SyncState b"authority:slip-proof-not-before:v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Admitted request nonce (empty marker), evicted once the proof clock is a day past its
    /// signed timestamp. Key: u64hex16 ":" hex64.
    AUTHORITY_SLIP_REPLAY_NONCE: SyncState b"authority:slip-replay:v2:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Permanent presence-only marker (empty value) that a FEDERATION_GRANT was positively
    /// withdrawn here (FIX-LIST 5107): read before a carried act's Grant standing. Key: hex32.
    AUTHORITY_WITHDRAWN_GRANT: SyncState b"authority:withdrawn-grant:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Device-only in-progress marker between a received BulkTransfer chunk and its BulkTransferDone.
    /// Key: yyyy-mm.
    SYNC_BULK_TRANSFER_MARKER: SyncState b"bulk:w:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// ARCH-0023b document family: the root document's full CRDT snapshot (server-write-only
    /// meta.windows). Key: ().
    SYNC_D_ROOT: SyncState b"d:root" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Cached HTTP response (status, headers, body) for one Idempotency-Key replay within its 24h
    /// TTL, keyed by principal and header value. Key: hex ":" hex (principal, idempotency key).
    HTTP_IDEMPOTENCY_REPLY: SyncState b"http:idempotency:" LegacyCompact
        [restore: content] [family: dispatch Response] [tier: canonical];
    /// Durable client-named invocation intent or settled JSON outcome, including the caller's
    /// stamps and committed-write count. Key: hex32 (invocation id).
    INVOCATION_CLAIM: SyncState b"http:invocation:" Named
        [restore: content] [family: dispatch Response] [tier: canonical];
    /// This device's stable client id (u64 LE, nonzero), minted once per install and reused as the
    /// sync client's peer id. Key: ().
    IDENTITY_CLIENT_ID: SyncState b"m:client_id" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Cached 32-byte Ed25519 verifying key of this device's receipt key, whose seed is in the
    /// install's keystore slot; a stored value that disagrees with the derived key is corruption.
    /// Dropped wherever the machine id is. Key: ().
    IDENTITY_DEVICE_PK: SyncState b"m:device_pk" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Client-only: last Unix-seconds timestamp this device reached fully-synced status. Key: ().
    SYNC_M_LAST_SYNC: SyncState b"m:last_sync" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// The MACHINE row this install is (16 B entity id), which names its keystore slots; never
    /// synced and never restored from another install. Key: ().
    IDENTITY_MACHINE_ID: SyncState b"m:machine_id" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Cached 32-byte Ed25519 verifying key of this install's machine key, whose seed is in the
    /// install's keystore slot, so a restore with no keys loaded still names its serving machine
    /// (FIX 5472); a stored value that disagrees with the derived key is corruption, never written
    /// over. Dropped wherever the machine id is. Key: ().
    IDENTITY_MACHINE_PK: SyncState b"m:machine_pk" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Crash-safe monotonic counter allocating the next u:w: sequence number for one window. Key:
    /// yyyy-mm.
    SYNC_M_U_SEQ_W: SyncState b"m:u_seq:w:" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// Host config row: the node account-key verdict lease in seconds (u64 big-endian). Absent
    /// means the 60-second default. Key: ().
    MANAGED_ACCOUNT_KEY_LEASE: SyncState b"managed:account-key-lease:v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Marker row admitting a vault as a synthetic canary, the only substitute managed-mode accepts
    /// for the real-tenant isolation preconditions. Key: ().
    MANAGED_CANARY_MARKER: SyncState b"managed:canary:v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Keyed MAC (32 bytes) of the vault's identity metadata under the managed-mode delivered DEK,
    /// sealed on first open and checked on every reopen. Key: ().
    MANAGED_DEK_MAC: SyncState b"managed:dek_mac:v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The generated managed-mode lease scope id (u64 big-endian) for this vault, stable across
    /// reopen. Key: ().
    MANAGED_LEASE_SCOPE: SyncState b"managed:lease_scope:v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The last-persisted revision counter (u64 little-endian) for the managed-mode wake-ledger push
    /// to the supervisor. Key: ().
    MANAGED_LEDGER_REV: SyncState b"managed:ledger_rev:v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// One submitted `ai.video` job (FIX-LIST 465): its rung, provider handle and call, and its end
    /// once a poll saw it, so a restart takes it up again and an ended job answers every poll until
    /// its caller deletes it. Its clips' bytes sit beside it. Key: ticket (`job_` hex24), or ticket
    /// ":part:" index for a clip's bytes.
    MODEL_MEDIA_JOB: SyncState b"models:media-job:v1:" Named
        [restore: live] [family: dispatch Response] [tier: canonical];
    /// Entity waiting for an embedding. Key: hex32.
    PENDING_EMBEDDING_MARKER: SyncState b"pe:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// One admitted peer AUTHORITY_LOG entry's canonical bytes, used to refold that peer's roster
    /// locally. Key: hex64 (peer vault id) ":" hex64 (entry hash).
    PEER_AUTHORITY_ENTRY: SyncState b"peerauth:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Pending tombstone propagation marker. Key: yyyy-mm ":" hex32.
    DELETION_PENDING_TOMBSTONE: SyncState b"pt:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Queued tombstone re-assertion for an entity whose local hard-delete residue reappeared in a
    /// window doc. Key: yyyy-mm ":" hex32 (entity id).
    SYNC_REASSERT_MARKER: SyncState b"ra:w:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One generation of the vault's sealed cloud bundle the home keeps (FIX 922): u64be commit
    /// order (FIX 8885) ‖ u64be bundle length ‖ bundle digest (32) ‖ u64be pad object length ‖ pad
    /// object digest (32), then, when its publisher named a recovery root, the root id (32) ‖ its
    /// anchor key (32). Key: hex48 (the generation).
    SYNC_RESIDENCE_BUNDLE_GENERATION: SyncState b"rb:g:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// One stored part of a kept generation's bundle ("b") or pad object ("k"). Key: hex48 (the
    /// generation) ":" b|k ":" hex16 (offset).
    SYNC_RESIDENCE_BUNDLE_PART: SyncState b"rb:p:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Entity-scoped needs-rematerialization retry flag, set when a CRDT-tombstone purge or a
    /// materialization batch fails. Key: yyyy-mm ":" hex32 (entity id).
    SYNC_REMAT_MARKER: SyncState b"rm:w:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Sidecar on a rm:w: marker proving it originated from replay/quarantine (not a delete-safety
    /// purge failure), so terminal quarantine may discharge it. Key: yyyy-mm ":" hex32 (entity id).
    SYNC_REPLAY_REMAT_MARKER_PROVENANCE: SyncState b"rmp:w:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// This machine's residence choice (sync all or sync what it opened) and when it was made;
    /// node-local, never synced. Key: ().
    SYNC_RESIDENCE_DEVICE_MODE: SyncState b"rs:mode" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The worlds the owner picked for this machine to follow (ARCH-0023b #partial-sync): each
    /// world's 16 id bytes, ascending; node-local, never synced. Key: ().
    SYNC_RESIDENCE_DEVICE_WORLDS: SyncState b"rs:worlds" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// This device's record that it left the shared vault its env holds (OF-158): the notice it
    /// confirmed and the unsynced edits it discarded; local only, never synced. Key: string (the
    /// notice's receipt id).
    SYNC_SHARED_LEAVE_RECEIPT: SyncState b"sl:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// ARCH-0023b document family: the root document's state vector, paired with d:root. Key: ().
    SYNC_SV_ROOT: SyncState b"sv:root" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// A sync window's state vector (document family). Key: yyyy-mm.
    WINDOW_STATE_VECTOR: SyncState b"sv:w:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// ARCH-0023b document family: freshness flag for the root document's persisted state vector.
    /// Key: ().
    SYNC_SVF_ROOT: SyncState b"svf:root" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Whether a sync window's state vector is fresh (document family). Key: yyyy-mm.
    WINDOW_SHALLOW_FENCE: SyncState b"svf:w:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// ARCH-0023b document family: pending root-document CRDT updates applied on top of d:root at
    /// startup; read-only in this crate (written server-side). Key: hex8 (sequence).
    SYNC_U_ROOT: SyncState b"u:root:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// One idempotently recorded usage-metering event for an owner/vault, keyed by its caller-
    /// supplied idempotency key. Key: hex ":" hex ":" hex (owner, vault, idempotency-key).
    USAGE_EVENT: SyncState b"usage:event:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::store::erase_usage_source_in_txn;
    /// One frozen automatic settlement awaiting its final ledger write (FIX 737).
    /// Same named envelope as USAGE_EVENT. Key: hex ":" hex ":" hex
    /// (vault, billing owner, idempotency-key); vault-first covers room-paid owners.
    USAGE_SETTLEMENT_PENDING: SyncState b"usage:retry:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::store::erase_pending_usage_source_in_txn;
    /// A crossed `[limits]` row's question (OF-520) for one minute: the row's bound, the most it
    /// saw, and how many times it was crossed. Key: string (the row's key) ":" u64 (decimal,
    /// zero-padded to 20 digits; window start).
    WIRE_LIMIT_QUESTION: SyncState b"wire:limit-question:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A raised question recording that a wire call-volume window crossed its per-verb or per-actor
    /// threshold, kept once each time another verb or actor crossed (FIX 9531). Key: "seq:" u64
    /// (decimal, zero-padded to 20 digits; the order questions were kept in) | "window:" u64 ":"
    /// u64 ":" u64 (each zero-padded to 20 digits; window start:end, then the question's seq).
    RC42_WIRE_QUESTION: SyncState b"wire:question:v2:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Persisted per-window wire call-volume counters (by verb and by actor) for one observation
    /// window. Key: u64 ":" u64 (decimal, zero-padded to 20 digits; window start:end).
    RC42_WIRE_RECEIPT: SyncState b"wire:window:v2:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Which asset entity currently holds custody of a birthed agent's captured source. Key: id16.
    AGENT_DEF_BIRTH_CUSTODY_OWNED: VaultMeta b"agent_def/birth-custody/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Empty marker indexing birthed-agent children by a captured dependency input (input id then
    /// child id). Key: id16 + id16.
    AGENT_DEF_BIRTH_INPUT: VaultMeta b"agent_def/birth-input/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The store-order index over AUTHORITY_LOG rows (FIX 12369): the sequence a row took when
    /// first stored here, to the row's entity id, so a resumed fold range-scans only the rows
    /// stored past its continuation. Derived in the storing write transaction; runtime-tier.
    /// Key: u64be (the sequence). Value: id16.
    AUTHLOG_STORE_ORDER: VaultMeta b"authlog:store_order:v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// The store-order index's state: whether every row stored before the index existed has
    /// been sequenced, and the next free sequence (9 raw bytes: the flag, then u64be). Key: ().
    AUTHLOG_STORE_ORDER_STATE: VaultMeta b"authlog:store_order_state:v1" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// The id of the newest checkpoint v2 image of this vault's local chain (OF-469). Key: ().
    AUTHORITY_CHECKPOINT_V2_HEAD: VaultMeta b"authority.checkpoint.head.v2" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The checkpoint v2 head this install kept, the authority totals it accounts for, the local
    /// second it was kept at and the root policy this install built it under (OF-469 cutoffs).
    /// Runtime-tier: no checkpoint image carries it. Key: ().
    AUTHORITY_CHECKPOINT_PROGRESS: VaultMeta b"authority.checkpoint.local.progress.v1" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// This install's cumulative count of authority rows first stored here and their canonical
    /// signed body bytes (OF-469 cutoffs). Runtime-tier. Key: ().
    AUTHORITY_CHECKPOINT_TOTALS: VaultMeta b"authority.checkpoint.local.totals.v1" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// One row the adopted checkpoint v2 image covers that this vault did not hold when it
    /// adopted it (OF-469 cutoffs): its arrival is hydration, not growth. Runtime-tier. Key:
    /// hash32.
    AUTHORITY_CHECKPOINT_UNHELD: VaultMeta b"authority.checkpoint.local.unheld.v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// One checkpoint v2 image's canonical bytes (domain, then named MessagePack), keyed by its
    /// unsigned id (OF-469). Key: hash32.
    AUTHORITY_CHECKPOINT_V2_IMAGE: VaultMeta b"authority.checkpoint.v2." Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The checkpoint v2 image this vault adopted (OF-469): the pin from owner-authorized pairing
    /// and the attestations that verified the image; the pin names the image. Key: ().
    AUTHORITY_CHECKPOINT_ADOPTED_PIN: VaultMeta b"authority:checkpoint-adopted-pin:v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// One root's attestation of one authority checkpoint v2 image (OF-469): both signatures and
    /// the root's key binding, with the policy digest it was made under. Key: hash32 (image id) +
    /// root key (suite byte + key bytes).
    AUTHORITY_CHECKPOINT_ATTESTATION: VaultMeta b"authority:checkpoint-attestation:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The newest checkpoint v2 image whose stored attestations reached this vault's own root
    /// policy, and that policy's digest (OF-469). Key: ().
    AUTHORITY_CHECKPOINT_ATTESTED_HEAD: VaultMeta b"authority:checkpoint-attested-head:v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// One eligible root's certified checkpoint SLH-DSA key: the root's classical signature over
    /// this install's hash-based key (OF-469). Key: root key (suite byte + key bytes).
    AUTHORITY_CHECKPOINT_KEY_BINDING: VaultMeta b"authority:checkpoint-key-binding:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The saved fork alarm for one key a held handoff retired, kept until the owner acknowledges
    /// it. Key: string (signer suite ":" key hex).
    AUTHORITY_HANDOFF_ALARM: VaultMeta b"authority:handoff-alarm:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The digest of the leave-notice delegation a settled ReRoot's root signed beside it (FIX
    /// 7932), written in the transaction that settled the handoff and never rewritten. Key:
    /// hash32 (the ReRoot's entry hash).
    AUTHORITY_LEAVE_NOTICE_DELEGATION_BY_HANDOFF: VaultMeta b"authority:leave-notice-delegation-by-handoff:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The last commit a write that changes no content stamped (FIX 6730): its transaction id,
    /// the last content commit's and its class, so a host's telemetry and a backup's own writes
    /// move no backup watermark. Runtime-tier: no image carries it. Key: ().
    BACKUP_CHANGE: VaultMeta b"backup:change:v1" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// FIX 7767: one resident's share of the host-paid allocation as the owner set it, and what
    /// its settled calls charged the allocation generation they ran on. Key: id16 (resident).
    BUDGET_RESIDENT_SHARE: VaultMeta b"budget.resident.share.v1\0" Named Engine
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::store::resident_budget_rows::erase_resident_share_actor_in_txn;
    /// Channel-identity lifecycle receipt ledger. Key: id16.
    CHANNEL_IDENTITY_LIFECYCLE_RECEIPT: VaultMeta b"channel_identity_lifecycle:v0:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::store::erase_channel_identity_receipt_actor_in_txn;
    /// One incarnation of a checkpoint payload compartment (KS-7): its custody generation and
    /// whether it is active, retained or erased. Never a key and never a refcount. Key: subtype
    /// (1) + canonical owner (32) + incarnation (16).
    CHECKPOINT_PAYLOAD_INSTANCE: VaultMeta b"checkpoint_payload:instance:v1:" Named Engine
        [restore: live] [family: structure] [tier: canonical];
    /// Posting-list row of one pending session-generated claim under its producing actor. Key: id16
    /// (producer) + id16.
    CLAIM_PENDING_PRODUCER: VaultMeta b"claim:pending_producer:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Posting-list row of one claim under its predicate's projection index. Key: bytes32 (blake3 of
    /// predicate) + id16.
    CLAIM_PREDICATE_INDEX: VaultMeta b"claim:predicate:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Catalog marker recording that at least one claim uses this predicate. Key: string (predicate
    /// name).
    CLAIM_PREDICATE_NAME: VaultMeta b"claim:predicate_name:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Reverse index: the projection-index keys written for one claim, so they can be removed
    /// together. Key: id16.
    CLAIM_PROJECTION_REVERSE: VaultMeta b"claim:projection_reverse:v1:" LegacyCompact
        [restore: content] [family: unclassified] [tier: canonical];
    /// FIX 9598: an approved Dreamer claim whose VAD consolidation is still owed, written in the
    /// approval's commit and cleared in the consolidation's own. Key: id16 (claim).
    CLAIM_VAD_OWED: VaultMeta b"claim:vad_owed:v1:" Named Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// Posting-list row of one claim under its world (base reality under the reserved base id),
    /// read by the scope-honesty census. Key: id16 (world) + id16 (claim).
    CLAIM_WORLD_INDEX: VaultMeta b"claim:world:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A code run's replay record, keyed by run id. Key: id16.
    CODE_RUN_REPLAY: VaultMeta b"code_run:replay:v1:" Raw Authored [accepts: crate::code_run::code_run_replay_record_accepts_masked]
        // Payload family: A blocked report's captured requests (FIX 6708), a wait's deliveries
        // (FIX 6588) and a conversation check's gate material (FIX 5040); the wait index stays
        // unclassified, as only its settled rows hold a reply, which [`class_for_row`] places row
        // by row (FIX 9179).
        [restore: content] [family: dispatch Response] [tier: canonical];
    /// The reply one parked code-run wait was answered with, and when (JSON). Key: id16(run) +
    /// id16(wait) + be64(generation).
    CODE_RUN_WAIT_DELIVERY: VaultMeta b"code_run:wait_delivery:v1:" Raw Authored [accepts: crate::store::executor_wait_delivery::code_run_wait_delivery_accepts_masked]
        // Payload family: A blocked report's captured requests (FIX 6708), a wait's deliveries
        // (FIX 6588) and a conversation check's gate material (FIX 5040); the wait index stays
        // unclassified, as only its settled rows hold a reply, which [`class_for_row`] places row
        // by row (FIX 9179).
        [restore: content] [family: dispatch Response] [tier: canonical];
    /// Who held each code-run wait's reply (FIX 5718): one row per run delivered a reply of the
    /// wait, at the generation it parked, in one of three states. Kept: the run holds the reply,
    /// for the actor its replies are. Deleted: a soft delete of that actor took it (FIX 15532).
    /// The row keeps the actor only for that actor's hard erase (FIX 6591). Erased: an erase
    /// took it, or a late write found the actor's hard-delete marker. The row names no actor.
    /// Deleted and Erased read as erased, for good. It outlives the wait's waiter and delivery
    /// rows. Key: id16(wait) + id16(run) + be64(generation).
    CODE_RUN_WAIT_HOLDER: VaultMeta b"code_run:wait_holder:v1:" Named Engine
        // Payload family: A code run's response owner and wait holder hold ids, status and an
        // actor's id or its erasure, never the reply (FIX 6589).
        [restore: content] [family: structure] [tier: canonical];
    /// An inbound STOP this replica has not projected yet: its party and channel, which hold a
    /// send until the projection that releases it or the event's delete. Key: id16 (the event).
    COMM_PENDING_STOP: VaultMeta b"comm.pending_stop.v1:" Named
        // Restore class: A STOP's send hold before this replica projected it, keyed by the event:
        // it leaves with an event made after the checkpoint, and a changed one for an event both
        // vaults hold refuses.
        [restore: refuse_image_entities "pending communication STOP"]
        [family: unclassified]
        [tier: canonical];
    /// Time-ordered commitment due-index row. Key: u64be + u8 + id16 + id16.
    COMMITMENT_DUE_PRIMARY: VaultMeta b"commitment_due:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Instance and phase to primary due-row key. Key: id16 + u8.
    COMMITMENT_DUE_REVERSE: VaultMeta b"commitment_due_rev:v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Series-membership history. Key: id16 + u64be + u64be + u32be + id16.
    COMMITMENT_SERIES_INSTANCE: VaultMeta b"commitment_series_instance:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Pending Project due row of a series. Key: id16.
    COMMITMENT_SERIES_PROJECT: VaultMeta b"commitment_series_project:v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// The place a removed epoch summary held in its session's count: the highest removed epoch
    /// and the turn it ended at, no words (OF-013). Key: id16(session).
    COMPACTION_EPOCH_FLOOR: VaultMeta b"compaction:epoch_floor:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Immutable recorded contract baseline snapshot (public API names, schemas, command outputs),
    /// keyed by its own content digest; a differing value under the same id is corruption. Key:
    /// hex64.
    CONTRACT_ORACLE_BASELINE: VaultMeta b"contract_oracle:baseline:v1:" Named Authored [accepts: crate::store::contract_oracle::contract_oracle_baseline_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// Immutable recorded verdict comparing a candidate snapshot against a recorded baseline (diffs
    /// plus test-pass state), keyed by its own content digest. Key: hex64.
    CONTRACT_ORACLE_VERDICT: VaultMeta b"contract_oracle:verdict:v1:" Named Authored [accepts: crate::store::contract_oracle::contract_oracle_verdict_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// Recipient-selected storage-only restriction, independent of legal holds.
    /// Key: id16(record) + bytes32(pact) + bytes16(request nonce).
    COOPERATIVE_RESTRICTION: VaultMeta b"cooperative_deletion:restriction:v1:" Named
        // Restore class: A recipient's restriction stands as the live vault holds it, as the legal
        // holds and use limits beside it do: a restore neither lifts one nor revives one lifted
        // since (FIX 22408).
        [restore: live] [family: unclassified] [tier: canonical];
    /// One revision of a host rule row: the owner's reason on an answered decision ask, the
    /// answer it gives that question about that evidence, and whether it was revoked. Key:
    /// id16 (rule) + u64be(revision).
    DECISION_HOST_RULE: VaultMeta b"decision:host_rule:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::store::decision_rule_rows::erase_rule_actor_in_txn;
    /// Marker that the one-time row-deletion-fence backfill from applied soft-delete markers has
    /// run. Key: ().
    DELETION_ROW_FENCE_BACKFILLED: VaultMeta b"deletion.row_fence.v1.backfilled" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Immutable account/organization owner binding used to scope hosted derivation caches for this
    /// vault. Key: ().
    DERIVATION_OWNER: VaultMeta b"derivation:owner:v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Device-local step progression state (Started/ResponseReceived/Logged); never synced. Key:
    /// id16(attempt) + hash32(step).
    DREAMER_STEP_STATE: VaultMeta b"dreamer:step_state:v1:" Raw Authored [accepts: crate::llm::dreamer_step_state_accepts_masked]
        [restore: content] [family: dispatch Response] [tier: canonical];
    /// DOOR-141 PR2: one effect settled into a turn program's step: its issuing binding, then its
    /// terminal evidence and exact result, or that its end is unknown. FIX 5710: a send's inline
    /// body (`state.Settled.result`) is a KS-2 body-instance client; the wall admits it as its
    /// own part and the ARM entry's scrub clears it, so this entry names no class or scrub.
    /// Key: id16(code run) + id16(step).
    DREAMER_TURN_PROGRAM_STEP: VaultMeta b"dreamer:turn_program:step:v1:" Named
        [restore: content] [family: dispatch Response] [tier: canonical];
    /// The device family and runtime that computed the current embedding vector, outside the space
    /// identity (ARCH-0036). Key: id16.
    EMBEDDING_DEVICE: VaultMeta b"embedding/device/" Named
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// T2 report membership and vectors, keyed by the first ISSUE id.
    FEEDBACK_REPORT_CLUSTER: VaultMeta b"feedback:report-cluster:v1:" Named
        // Payload family: A report cluster's copied member vectors and centroid (FIX 9856), owned
        // by every member ISSUE.
        [restore: content] [family: dispatch Response] [tier: canonical]
        => crate::feedback::intake::forget_report_cluster_source_in_txn;
    /// Per-claim critical confirm invalidation. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice): decode also checks the version
    /// byte and rejects an all-zero claim id, business validation `Named`'s
    /// generic strict-msgpack decode does not run; `RawValue` delegates to
    /// the module's own `encode_critical_confirm_invalidation`/
    /// `decode_critical_confirm_invalidation`.
    CRITICAL_CONFIRM_INVALIDATION: VaultMeta b"gate_critical_invalidation:v0:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Latest verified claim-write retention ancestry, inherited by later decisions on the claim;
    /// the retention-scope module's own layout. Key: id16 (claim).
    GATE_DECISION_CLAIM_CONTEXT: VaultMeta b"gate_decision:claim_context:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Grant-reference index over the gate decision ledger. Key: u64be len + string + id16.
    GATE_DECISION_GRANT_REF_INDEX: VaultMeta b"gate_decision:grant_ref_index:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Latest retain-until stamp (u64be seconds) of a held gate decision partition. Key: 0
    /// (claim-free partition) or 1 + id16 (claim).
    GATE_DECISION_PARTITION_RETAIN_UNTIL: VaultMeta b"gate_decision:partition_retain_until:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// A Gate decision's scrub an erase owes while a restriction keeps the decision's own
    /// partition (FIX 7993, 7994), and when the erase asked: ids and a time only. Key: kind (0 an
    /// erased claim's skeleton, 1 an erased actor's attribution) + id16 (erased source) + id16
    /// (decision).
    GATE_DECISION_PENDING_SCRUB: VaultMeta b"gate_decision:pending_scrub:v1:" Named
        [restore: live] [family: structure] [tier: canonical];
    /// Append-time retention ancestry of one gate decision; the retention-scope module's own
    /// layout. Key: id16 (decision).
    GATE_DECISION_RETENTION_CONTEXT: VaultMeta b"gate_decision:retention_context:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Gate decision ledger row. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice): decode also enforces
    /// `vet_gate_decision_record` (version, notice, receipt-reason and
    /// redaction-shape checks), business validation `Named`'s generic
    /// strict-msgpack decode does not run; `RawValue` delegates to the
    /// module's own `encode_gate_decision`/`decode_gate_decision`.
    GATE_DECISION_LEDGER: VaultMeta b"gate_decision:v0:" Raw Ciphertext
        [restore: content] [family: sealed ClaimDecision] [tier: canonical]
        => crate::store::erase_gate_decision_actor_in_txn;
    /// Claim-keyed gate decision index. Key: id16 + id16.
    GATE_DECISION_CLAIM_INDEX: VaultMeta b"gate_decision_by_claim:v0:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Claim-index backfill flag. Key: ().
    GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE: VaultMeta b"gate_decision_by_claim_backfill_complete" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Per-constituent index over bundle decisions' claim refs; empty value. Key: id16 (claim) +
    /// id16 (decision).
    GATE_DECISION_CLAIM_REF_INDEX: VaultMeta b"gate_decision_by_claim_ref:v0:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A bundle decision's complete constituent claim ids (ascending, distinct). Key: id16.
    GATE_DECISION_CLAIM_REFS: VaultMeta b"gate_decision_claim_refs:v0:" LegacyCompact
        [restore: content] [family: unclassified] [tier: canonical];
    /// Batch preflight decision whose op has not applied yet; never survives a commit. Key: id16.
    GATE_DECISION_UNAPPLIED_PREFLIGHT: VaultMeta b"gate_decision_unapplied_preflight:v0:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Staged deletion authority decision sidecar. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice): decode also enforces
    /// `vet_pending_deletion_gate_decision_record`, a business check
    /// `Named`'s generic strict-msgpack decode does not run; `RawValue`
    /// delegates to the module's own `encode_pending_deletion_gate_decision`/
    /// `decode_pending_deletion_gate_decision`.
    GATE_DELETE_PENDING_SIDECAR: VaultMeta b"gate_delete_pending:v0:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Local deletion tombstone needs an authority sidecar. Key: id16.
    GATE_DELETE_REQUIRED_MARKER: VaultMeta b"gate_delete_required:v0:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Critical-write confirm id to pending claim. Key: bytes32.
    CRITICAL_CONFIRM_INDEX: VaultMeta b"gate_pending:critical_confirm_by_id:v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Critical confirm expiry sweep state. Key: ().
    CRITICAL_CONFIRM_EXPIRY_CURSOR: VaultMeta b"gate_pending:critical_confirm_expiry_cursor:v1" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Critical confirm list sweep state. Key: ().
    CRITICAL_CONFIRM_LIST_CURSOR: VaultMeta b"gate_pending:critical_confirm_list_cursor:v1" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Pending consents grouped by root-group alias. Key: full-string BLAKE3 digest + id16.
    PENDING_GATE_CONSENT_GROUP_INDEX: VaultMeta b"gate_pending:group_index:v2:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Semantic duplicate index of pending consents. Key: bytes32 + id16.
    PENDING_GATE_CONSENT_HASH_INDEX: VaultMeta b"gate_pending:hash_index:v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Index keys created for a pending consent. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice): decode also enforces the
    /// version byte and non-empty run/group keys, business validation
    /// `Named`'s generic strict-msgpack decode does not run; `RawValue`
    /// delegates to the module's own
    /// `encode_pending_gate_consent_index_state`/
    /// `decode_pending_gate_consent_index_state`.
    PENDING_GATE_CONSENT_INDEX_STATE: VaultMeta b"gate_pending:index_state:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Pending consents grouped by run. Key: full-string BLAKE3 digest + id16.
    PENDING_GATE_CONSENT_RUN_INDEX: VaultMeta b"gate_pending:run_index:v2:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Pending consent insertion sequence. Key: id16.
    PENDING_GATE_CONSENT_SEQUENCE: VaultMeta b"gate_pending:sequence:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Pending-consent sequence high-water mark. Key: ().
    PENDING_GATE_CONSENT_SEQUENCE_COUNTER: VaultMeta b"gate_pending:sequence_counter:v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Pending consents ordered by sequence. Key: u64be.
    PENDING_GATE_CONSENT_SEQUENCE_INDEX: VaultMeta b"gate_pending:sequence_index:v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Pending gate-consent tray row. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice): decode also enforces
    /// `vet_pending_gate_consent_record` (version, diff-handle, reason-code
    /// shape checks), business validation `Named`'s generic strict-msgpack
    /// decode does not run; `RawValue` delegates to the module's own
    /// `encode_pending_gate_consent`/`decode_pending_gate_consent`.
    PENDING_GATE_CONSENT: VaultMeta b"gate_pending:v0:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Proposed/reviewed/escalated timestamps for one healer case, feeding oversight coverage counts.
    /// Key: hex32 (case_ref).
    HEALER_ACTIVITY: VaultMeta b"healer:activity:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Latest signed per-vault-device oversight receipt (coverage, review latency, or escalation
    /// rate). Key: u8 (OversightKind tag: 0/1/2).
    HEALER_OVERSIGHT_RECEIPT: VaultMeta b"healer:oversight:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A retirement deadline a door started (a secret lease's expiry, a voice print's retention
    /// deadline, a critical confirm's window), kept for a vault that is not running to know when to
    /// wake. Key: the sweep's tag byte, the deadline (u64 BE), then an id16 per note, so a sweep's
    /// earliest deadline is its first row and two notes of one deadline are two rows. Value: empty.
    HOUSEKEEPING_WAKE: VaultMeta b"housekeeping:wake:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Empty-marker index from a normalized identity hint (name/alias/handle) hashed per entity-kind
    /// to the entity id it names, for lookup-before-mint resolution. Key: u8 + hash32 + id16.
    INGEST_IDENTITY_HINT: VaultMeta b"identity-hint:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Canonical caller-supplied text fields backing one document's bm25 index, used to rebuild
    /// postings. Key: id16.
    INDEX_SOURCE_TEXT: VaultMeta b"index_source:text:v1:" Named
        [restore: content] [family: owner TextSource] [tier: canonical];
    /// One inference snapshot this vault keeps sealed on disk: its manifest, its dependency
    /// set, its byte lengths and hash, its class, reuse and pins. Ids, digests, enums and pins
    /// only: never prompt text, tokens, tensors, credentials or keys. Key: id16 (the catalog id,
    /// drawn at random).
    INFERENCE_SNAPSHOT_CATALOG: VaultMeta b"inference_snapshot:catalog:v1:" Named Engine
        [restore: live] [family: structure] [tier: canonical]
        => crate::store::snapshot_catalog::erase_actor_in_txn;
    /// One conversation's kept snapshots, by catalog id, so a restore reads
    /// only its conversation's rows (FIX 11286): conversation id16 + catalog
    /// id16, empty markers, written in the row's own transaction.
    INFERENCE_SNAPSHOT_CONVERSATION_INDEX: VaultMeta b"inference_snapshot:conversation:v1:" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// Blob birth fingerprint tree used for perceptual/exact duplicate detection on ingest. Key:
    /// id16.
    INGEST_FINGERPRINT: VaultMeta b"ingest-fingerprint:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Run id to queued attempt ids. Key: full-string BLAKE3 digest + id16.
    ATTEMPT_RUN_INDEX: VaultMeta b"job:run_index:v2:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The vault's typed key custody binding (`store::key_custody`): version 1, namespace
    /// (16), vault id (32), then the native absolute root path the custody sits beside; never
    /// key material. Pinned by the first publication with what it protects. Key: ().
    KEY_CUSTODY_BINDING: VaultMeta b"key_custody:binding:v1" Raw
        [restore: live] [family: structure] [tier: canonical];
    /// One erasable custody key's ref-keyed metadata (FIX 8875): its purpose, its parent (the
    /// actor a home handoff key seals for, a grant, or a drafter version, FIX 12569) and its
    /// incarnation; never the key.
    /// Key: bytes32 (the key's random ref).
    KEY_CUSTODY_ERASABLE_REF: VaultMeta b"key_custody:erasable_ref:v1:" Named Engine
        [restore: content] [family: structure] [tier: canonical]
        => crate::store::home_handoff_custody::scrub_actor_in_txn;
    /// A committed intent to retire one custody subject's entries through a generation:
    /// u64be generation, then cause (0 retention, 1 erase). Key: vault id (32) + kind tag (1) +
    /// item.
    KEY_CUSTODY_RETIRE_PENDING: VaultMeta b"key_custody:retire_pending:v1:" Raw
        [restore: live] [family: structure] [tier: canonical];
    /// Vault-scoped structural-kind registration. Key: u8.
    STRUCTURAL_KIND_REGISTRY: VaultMeta b"kind_reg:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Customer holds' legal-hold log: ids, times and reason codes only (OF-470 C3). A host
    /// order's events are in `LEGAL_HOLD_HOST_EVENT`; the owner reads those through
    /// `LegalHold::owner_may_see`. Key: id16 (hold) + u64be (sequence).
    LEGAL_HOLD_EVENT: VaultMeta b"legal_hold:event:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The host-only legal-hold log (OF-470 C2). Runtime-tier: no checkpoint image carries it.
    /// Key: id16 (hold) + u64be (sequence).
    LEGAL_HOLD_HOST_EVENT: VaultMeta b"legal_hold:host:event:v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// A HOST order's standing explicit prospective capture (LEGAL-HOLD-USE = B as a clone,
    /// FIX 13866): its capture binding, term, public recipient key and next outbox ordinal.
    /// Host-only, runtime-tier, carried with the host-order family. Key: id16 (order) + u64be
    /// (generation).
    LEGAL_HOLD_HOST_PROSPECTIVE: VaultMeta b"legal_hold:host:prospective:v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// A new MESSAGE row sealed to its prospective order when it landed, until the HOST
    /// acknowledges its batch or the order ends: clone custody, never vault data. Host-only,
    /// runtime-tier. Key: id16 (order) + u64be (generation) + u64be (ordinal).
    LEGAL_HOLD_HOST_PROSPECTIVE_OUTBOX: VaultMeta b"legal_hold:host:prospective_outbox:v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// A released prospective order generation, so a late reconnect never stands it again.
    /// Content-free. Key: id16 (order) + u64be (generation).
    LEGAL_HOLD_HOST_PROSPECTIVE_RELEASED: VaultMeta b"legal_hold:host:prospective_released:v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// A host-order legal hold Oneiron placed on an authority order (OF-470 C1). Runtime-tier: no
    /// checkpoint image carries it. Key: id16 (hold).
    LEGAL_HOLD_HOST_ROW: VaultMeta b"legal_hold:host:row:v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// A customer legal hold naming records or gate-decision partitions (OF-470). Key: id16
    /// (hold).
    LEGAL_HOLD_ROW: VaultMeta b"legal_hold:row:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Tracker-mirror outbox marker. Key: id16.
    LINEAR_TASK_DIRTY: VaultMeta b"linear.task_dirty.v1/" Raw Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// Tracker-mirror revision counter of a task. Key: id16.
    LINEAR_TASK_REVISION: VaultMeta b"linear.task_revision.v1/" Raw Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// Verified typed writer of a task at its current revision (u64be revision, id16 actor, class
    /// byte). Key: id16.
    LINEAR_TASK_WRITER: VaultMeta b"linear.task_writer.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Owner-submitted model requests and their terminal receipts. Key: id16(step attempt).
    MODEL_STEP_SUBMISSION: VaultMeta b"model_step:submission:v1:" Named Authored [accepts: crate::store::model_step_submission::model_step_submission_accepts_masked]
        // Payload family: A public model-step submission's kept copies (FIX 9929), carried whole
        // (FIX 10461).
        [restore: content] [family: dispatch Response] [tier: canonical];
    /// Marker (empty) that every Published row written before Published rows kept their CAS row
    /// has one. Key: ().
    ORIGIN_CAS_BACKFILL: VaultMeta b"origin:cas_backfill:v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Per-vault random FastCDC boundary-randomization seed (u64 LE). Key: ().
    ORIGIN_LFS_CDC_SEED: VaultMeta b"origin:lfs:cdc:v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Device-local threshold row (u64) of one engine scan. Key: u8 (scan).
    ORIGIN_SCAN_POLICY: VaultMeta b"origin:scan_policy:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Gate outcome of a scheduled outbound attempt's first dispatch. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice): `store::outbound_send_receipt`
    /// only ever relays a caller-encoded `&[u8]` (the encoder is
    /// `crate::memory::outbound::dedupe`'s `serde_json::to_vec`, outside this
    /// table's owning module); binding it `LegacyJson` here would re-encode
    /// already-encoded bytes on every write.
    OUTBOUND_GATE_BINDING: VaultMeta b"outbound_gate_binding:v0:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// An own actor's latest advisory rate crossing per kind. Key: id16 + kind token.
    OWN_RATE_CHECK: VaultMeta b"own_rate.check.v1\0" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime]
        => crate::store::own_rate_rows::erase_check_actor_in_txn;
    /// Every own-rate crossing in the order it was kept, for the host's health check to read
    /// past its cursor (ARCH-0044 C5); kept 30 days. Key: u64be (recorded at) + id16.
    OWN_RATE_CHECK_ORDER: VaultMeta b"own_rate.check_order.v1\0" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime]
        => crate::store::own_rate_rows::erase_check_order_actor_in_txn;
    /// An own actor's act count in its current window per kind. Key: id16 + kind token.
    OWN_RATE_WINDOW: VaultMeta b"own_rate.window.v1\0" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime]
        => crate::store::own_rate_rows::erase_window_actor_in_txn;
    /// An agent hook's ask for a binding wider than its ceiling, and the owner's settlement
    /// (ARCH-0080 §10). Key: id16(binding claim).
    SKILL_HUB_PACK_HOOK_PROPOSAL: VaultMeta b"pack.hook-proposal.v1/" Named
        // Restore class: An ask stands with the binding claims it describes.
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::store::pack_hook_proposal::scrub_hook_proposal_actor_in_txn;
    /// Local-only content-hash pin (32 bytes) to the currently installed pack-byte-map carrier ASSET;
    /// never synced or imported. Key: ().
    PACK_BYTE_MAP_LOCAL_HEAD: VaultMeta b"pack_byte_map:local_head:v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The billing account a PERSON filed as their own, which their room-paid calls bill (FIX
    /// 3332). Key: id16 (PERSON).
    PERSON_BILLING_ACCOUNT: VaultMeta b"person_billing_account:v1:" Named
        // Restore class: A restore never revives a withdrawn filing: the PERSON's live one stands.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::store::person_billing_account::erase_billing_account_actor_in_txn;
    /// Recorded-at clock floor. Key: ().
    PORTS_CLOCK_FLOOR: VaultMeta b"ports:clock_floor:v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Local id allocator floor. Key: ().
    PORTS_ID_FLOOR: VaultMeta b"ports:id_floor:v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Community snapshot rows: meta, node:hex32, members:hex32. Key: string.
    PPR_COMMUNITY_CACHE: VaultMeta b"ppr_community_cache:v0:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Born-from index over row births (Rule A trigger). Key: id16 (trigger ref) + id16 (born row).
    PROVENANCE_BIRTH_BY_TRIGGER: VaultMeta b"provenance:birth_by_trigger:v1:" Raw
        [restore: content] [family: owner ProvenanceBirth] [tier: canonical];
    /// Body descriptor: owner, occurrence, complete/incomplete state. Key: id16 (owner) + id16
    /// (occurrence).
    PROVENANCE_BODY: VaultMeta b"provenance:body:v1:" Named
        [restore: content] [family: owner ProvenanceBody] [tier: canonical];
    /// Who holds a body digest. Key: bytes32 (BLAKE3) + id16 (occurrence).
    PROVENANCE_BODY_DIGEST: VaultMeta b"provenance:body_digest:v1:" Named
        [restore: content] [family: owner ProvenanceBody] [tier: canonical];
    /// KS-2A: a body instance an erase of one of its holders owes a retirement once its last
    /// holder releases it. Key: bytes16 (instance); value: bytes32 (BLAKE3).
    PROVENANCE_BODY_ERASE: VaultMeta b"provenance:body_erase:v1:" Raw
        // Restore class: Erasure state: a restore keeping current authority keeps the current
        // vault's.
        [restore: live] [family: dispatch Body] [tier: canonical];
    /// KS-2A: each body instance an owner's erase retired or owes, for its receipt. Key: id16
    /// (owner) + bytes16 (instance).
    PROVENANCE_BODY_ERASED: VaultMeta b"provenance:body_erased:v1:" Raw
        [restore: live] [family: dispatch Body] [tier: canonical];
    /// KS-2A: an inline ASSET body's instance, bound by the first checkpoint that carries it.
    /// Key: id16 (entity); value: bytes16 (instance).
    PROVENANCE_BODY_INLINE: VaultMeta b"provenance:body_inline:v1:" Raw
        [restore: content] [family: dispatch Body] [tier: canonical];
    /// KS-2A (FIX 6023): every instance a body digest was ever bound under, its current one and
    /// each one an inline/file switch displaced, so a last-holder erase retires every image's
    /// copy. Ids only. Key: bytes32 (BLAKE3) + bytes16 (instance); value: empty.
    PROVENANCE_BODY_INSTANCE: VaultMeta b"provenance:body_instance:v1:" Raw
        // Restore class: A digest's instance history is custody state (FIX 6023): the current
        // vault's is kept.
        [restore: live] [family: structure] [tier: canonical];
    /// A body's instance row (FIX 5348, KS-2A): its instance, format and logical length, and
    /// whether it rests inline; never a key or a wrap of one. Key: bytes32 (BLAKE3).
    PROVENANCE_BODY_KEY: VaultMeta b"provenance:body_key:v1:" Named
        [restore: content] [family: dispatch Body] [tier: canonical];
    /// File digests no descriptor holds, for the body-file collector. Key: bytes32 (BLAKE3).
    PROVENANCE_BODY_RELEASED: VaultMeta b"provenance:body_released:v1:" Named
        [restore: live] [family: structure] [tier: canonical];
    /// KS-2B1: a row-held response's body instance, bound by the first checkpoint that carries
    /// its row. Key: u8 (database) + the row's full key; value: bytes16 (instance) + bytes32
    /// (BLAKE3 of the bytes bound).
    PROVENANCE_BODY_RESPONSE: VaultMeta b"provenance:body_response:v1:" Raw
        // Restore class: A row-held response's binding follows its row (KS-2B1); the obligations
        // are custody state, so a restore keeping current authority keeps the current vault's.
        [restore: content] [family: dispatch Response] [tier: canonical];
    /// KS-2B1: each body instance a row-held response was carried under, by each owner its
    /// write-time stamps name; it outlives the row, so an erase of the owner retires every
    /// image's copy. Key: id16 (owner) + bytes16 (instance); value: the row's carrier.
    PROVENANCE_BODY_RESPONSE_OWNER: VaultMeta b"provenance:body_response_owner:v1:" Raw
        [restore: live] [family: dispatch Response] [tier: canonical];
    /// Each actual historical source of a body's owner, by the real vault instance that
    /// published it; it outlives the live row, so a later erase of the source still finds
    /// the bodies after ActorScrub. Ids only. Key: id16 (source) + id16 (body owner) +
    /// bytes32 (BLAKE3) + bytes16 (instance); value: empty.
    PROVENANCE_BODY_SOURCE: VaultMeta b"provenance:body_source:v1:" Raw
        // Restore class: Historical source facts are custody state: the current vault's is kept.
        [restore: live] [family: structure] [tier: canonical];
    /// One row's immutable birth envelope (Rule A made_by); an erase of its process actor drops
    /// it (FIX 6074). Key: id16.
    PROVENANCE_ROW_BIRTH: VaultMeta b"provenance:row_birth:v1:" Named
        [restore: content] [family: owner ProvenanceBirth] [tier: canonical]
        => crate::provenance::birth::erase_birth_actor_in_txn;
    /// The local secret that keys a destination's withheld-ref handles (Q26 = B). Key: `()`. Never
    /// shipped.
    PROVENANCE_WITHHELD_SECRET: VaultMeta b"provenance:withheld_secret:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Receipt-family index backfill marker. Key: ().
    RECEIPT_FAMILY_INDEX_VERSION: VaultMeta b"receipt_family_index:v1:version" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One recovery kit this vault issued: its homes, passphrase cost, coverage, root, and
    /// whether the owner re-entered its pieces (OF-173). Never a piece, point, tag, passphrase
    /// or seed. Key: hex(kit id).
    RECOVERY_KIT: VaultMeta b"recovery_kit:v1:" Named
        // Restore class: A restore never rolls back which kit is current, or revives a replaced
        // one.
        [restore: live] [family: unclassified] [tier: canonical];
    /// One drawn world kit whose pending row never committed and whose pending piece a
    /// best-effort delete could not remove, named until a settle sweeps the piece
    /// (FIX 12202). Key: hex(kit id); the row holds the kit id.
    RECOVERY_KIT_UNLISTED_SWEEP: VaultMeta b"recovery_kit_unlisted_sweep:v1:" Named
        // Restore class: A restore never revives an already-swept unlisted kit's name (FIX 12202).
        [restore: live] [family: unclassified] [tier: canonical];
    /// Rebuildable projection row: the head set a merged/split identity shell currently resolves to.
    /// Key: id16 (shell id).
    IDENTITY_REDIRECT: VaultMeta b"redirect:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Published base-ledger retrieval run's capture time, for expiry and cap pruning; empty
    /// value. Key: u64be (captured at) + id16 (run id).
    RETRIEVAL_AGE: VaultMeta b"retr_age:v0:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A retrieval run's capture time (u64be), locating its age row. Key: id16 (run id).
    RETRIEVAL_AGE_BY_RUN: VaultMeta b"retr_age_run:v0:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Active reward-tuned blend weights. Key: ().
    ///
    /// Codec fixed to `Raw` (T47 store slice): decode also enforces the
    /// version/provenance shape and re-normalizes the weights, business
    /// checks `Named`'s generic strict-msgpack decode does not run;
    /// `RawValue` delegates to the module's own
    /// `encode_retrieval_blend_weight_table`/`decode_retrieval_blend_weight_table`.
    RETRIEVAL_BLEND_WEIGHTS_ACTIVE: VaultMeta b"retr_blend_weights:v0:active" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Reported retrieval run outcome. Key: id16 ":" string.
    ///
    /// Codec fixed to `Raw` (T47 store slice): decode must also enforce
    /// `RETRIEVAL_TELEMETRY_VERSION`, a business check `Named`'s generic
    /// strict-msgpack decode does not run; `RawValue` delegates to the
    /// module's own `encode_retrieval_outcome`/`decode_retrieval_outcome`.
    RETRIEVAL_OUTCOME: VaultMeta b"retr_out:v0:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Owner-pinned retrieval blend weights no learned update may move. Key: ().
    RETRIEVAL_POLICY_PINS: VaultMeta b"retr_policy_pins:v1:" Named
        // Restore class: The owner's pins go with the blend weights they hold
        // (RETRIEVAL_BLEND_WEIGHTS_ACTIVE, content), so a restore gives back one weight state
        // (FIX 22408).
        [restore: content] [family: unclassified] [tier: canonical];
    /// Account-local contextual retrieval posterior, updated by the Coach at sleep. Key: ().
    RETRIEVAL_POLICY_POSTERIOR: VaultMeta b"retr_policy_posterior:v1:" Named
        // Restore class: Learned retrieval state, content as the active blend weights it goes with
        // (FIX 22408).
        [restore: content] [family: unclassified] [tier: canonical];
    /// Retrieval run telemetry record. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice), for the same reason as
    /// [`RETRIEVAL_OUTCOME`]: decode also enforces the version byte and
    /// `RetrievalState::validate`, so `RawValue` delegates to the existing
    /// `encode_retrieval_run`/`decode_retrieval_run` (kept, and still relied
    /// on directly by `retrieval_telemetry::state_tests`).
    RETRIEVAL_RUN: VaultMeta b"retr_run:v0:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Unpublished context-pack retrieval run. Key: id16.
    RETRIEVAL_RUN_PROVISIONAL: VaultMeta b"retr_run_prov:v0:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Trace fork hash to runs. Key: bytes32 + id16.
    RETRIEVAL_TRACE_FORK_INDEX: VaultMeta b"retr_trace_fork:v0:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Retrieval runs by turn. Key: id16 + u64be + id16.
    RETRIEVAL_TURN_INDEX: VaultMeta b"retr_turn:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Random 32-byte key over every stored retrieval-trace fork hash, minted at the store's first
    /// open. Outside the `retr_` telemetry families, so no telemetry read, purge or export reaches it;
    /// node-local, never synced, and a runtime row no checkpoint image carries. Key: ().
    RETRIEVAL_TRACE_KEY_LOCAL: VaultMeta b"retrieval_trace_key:local:v1" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// One swept saved query's health as its last wake left it (FIX 11250): when and by which pass
    /// it was woken, what that came to, its failures in a row and its lag behind the change it
    /// answered. Key: id16.
    SAVED_QUERY_HEALTH: VaultMeta b"saved_query.health.v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Cached match-evaluator verdict for one (query, entity, evidence) triple. Key: id16 + id16 +
    /// hash32. Encoded as hand-rolled CANONICAL JSON (sorted object keys), not a plain derive, so
    /// the codec is `Raw` rather than `LegacyJson`.
    SAVED_QUERY_MEMO: VaultMeta b"saved_query.memo.v1:" Raw
        // Payload family: A saved query's verdict memo (FIX 10089), carried whole (FIX 10533).
        [restore: content] [family: dispatch Response] [tier: canonical];
    /// Storage schema stamp. Key: ().
    STORAGE_SCHEMA_VERSION: VaultMeta b"schema_version" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// The encrypted input of one active custody change (WILL L04 row 04): the metadata and value
    /// sealed to the change's holder, with the second it was sealed at and the request it is for,
    /// kept to relay until its holder answers. Holds no plaintext. Key: hash32 (the ciphertext
    /// digest the request names).
    /// The terminal fence of one credential an authorized erase reached (KS-6 part 2, FIX 7403):
    /// value-free and permanent, whether its custody discovery is complete (every key its id names
    /// staged to retire) or still owed. Never a value, key, name or count; a re-entered credential
    /// takes a new id. Key: id16 (custody record id).
    SECRET_CUSTODY_ERASE: VaultMeta b"secret_custody:erase:v1:" Raw Engine
        // Restore class: An erased credential's fence stands with the custody it closes (KS-6 part
        // 2).
        [restore: live] [family: structure] [tier: canonical];
    /// Name index mapping a live secret-custody record's name to its EntityId, then the name's
    /// generation high-water as a big-endian u32, kept after the record is gone (FIX 5958). Key:
    /// string (secret name).
    SECRET_CUSTODY_NAME_INDEX: VaultMeta b"secret_custody:name:v1:" Raw Custody
        [restore: refuse "secret custody"] [family: unclassified] [tier: canonical];
    /// The owner's mark that he imported one export secret request's supplement here, which this
    /// install could not sign in the import's writer, with no live machine profile or no install
    /// key loaded (FIX 12291): the owner the import revalidated, the surface he imported from
    /// and the second the import was at, until a pass that can sign carries it or finds nothing
    /// owed. Holds no secret byte, ciphertext, secret name, proof, credential or key. Key: hash32
    /// (the request's entry hash).
    SECRET_CUSTODY_PENDING_IMPORT_MARK: VaultMeta b"secret_custody:pending_import_mark:v1:" Named Engine
        // Restore class: An owed import mark stands with the custody whose relay it ends
        // (FIX 12291).
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::store::pending_import_mark::erase_pending_import_mark_actor_in_txn;
    /// A revoke of one portable custody record this install made but could not carry for the
    /// owner yet, with no live machine profile or no install key loaded (CALLS
    /// CUSTODY_REVOKE_PENDING_CARRY): the owner it is by, the surface he decided on, the second
    /// it was made at and the generation it revoked, until a pass that can sign carries it. Holds
    /// no value and no proof. Key: id16 (custody record id).
    SECRET_CUSTODY_PENDING_REVOKE: VaultMeta b"secret_custody:pending_revoke:v1:" Named Engine
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::store::pending_custody_revoke::erase_pending_revoke_actor_in_txn;
    /// A record whose found keys still owe the owner their needs-you notice: raised at the next
    /// write's commit boundary, then removed. Key: id16 (the record).
    SECRET_FOUND_KEY_DUE: VaultMeta b"secret_found_key_due:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// A custody handle's owner-set display label and its Gate receipt. The custody name stays the
    /// identity; this label changes presentation only and holds no value. Key: id16 (custody record id).
    SECRET_HANDLE_LABEL: VaultMeta b"secret_handle:label:v1:" Named Custody
        [restore: live] [family: unclassified] [tier: canonical];
    /// Owner-authored purpose, admitted by the side-row wall. Key: custody id16.
    SECRET_HANDLE_PURPOSE: VaultMeta b"secret_handle:purpose:v1:" Named Authored [accepts: crate::store::secret_handle_purpose::accepts_masked]
        [restore: live] [family: unclassified] [tier: canonical];
    /// Each custody record's committed known-value history (KS-3): the slot of each entry typed
    /// custody holds for it (`KnownValueEntry`, item = the record's id) with the record generation
    /// it was written at, never a value, length, tag or fingerprint. Canonical, so an image
    /// carries the references and a restore requires every one in current custody; the record's
    /// erase removes them and stages its entries' retirement. Key: id16 (custody record id).
    SECRET_KNOWN_HISTORY: VaultMeta b"secret_known:history:v1:" Raw Engine
        // Restore class: Known-value history references (KS-3) stand with the custody they name.
        // Payload family: KS-3's known-value history references: custody slots and the master's
        // generation, never a payload.
        [restore: live] [family: structure] [tier: canonical];
    /// The known-value index's master key reference (KS-3): the generation of the key typed
    /// custody holds for the index (`KnownValueIndex`), never the key. Committed with the first
    /// value the index keys and kept after the last holder's erase: the master is never minted
    /// again. Key: ().
    SECRET_KNOWN_INDEX: VaultMeta b"secret_known:index:v1" Raw Engine
        // Payload family: KS-3's known-value history references: custody slots and the master's
        // generation, never a payload.
        [restore: live] [family: structure] [tier: canonical];
    /// A file stored with keys in it: each key's span in its bytes, or in a container member it
    /// holds (OF-067 C), the custody record that holds it, and its band (OF-560, owner ruling G04
    /// binary = C2). Key: hash32 (blake3 of the stored bytes).
    SECRET_MASK_SPANS: VaultMeta b"secret_mask:spans:v1:" Named Custody
        [restore: content] [family: unclassified] [tier: canonical];
    /// Points a diagnostic event id at the signed detector run that produced it. Key: id16
    /// Immutable replay evidence for centroid verdicts, keyed by digest hash32.
    SELF_HEAL_CENTROID_EVIDENCE: VaultMeta b"self_heal:centroid_evidence:v1:" Named
        // Payload family: A centroid verdict's copied vectors and run (FIX 10094), owned by every
        // source it copied.
        [restore: content] [family: dispatch Response] [tier: canonical]
        => crate::store::centroid_evidence::erase_centroid_source_in_txn;
    /// First delivered task per idempotency key. Key: bytes32.
    SEND_IDEMPOTENCY_INDEX: VaultMeta b"send_idem:v0:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Latest connector-send receipt of a task. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice): `store::outbound_send_receipt`
    /// only relays a caller-encoded `&[u8]` (`crate::receipt::send_receipt_txn`
    /// already ran `rmp_serde::to_vec_named` before calling in); binding it
    /// `Named` here would re-encode already-encoded bytes on every write.
    SEND_RECEIPT_SUMMARY: VaultMeta b"send_receipt:v0:" Raw Authored [accepts: crate::store::send_receipt_summary_accepts_masked]
        [restore: live] [family: unclassified] [tier: canonical];
    /// Connector-send attempt audit row. Key: id16 + bytes32.
    ///
    /// Codec fixed to `Raw` (T47 store slice), for the same reason as
    /// [`SEND_RECEIPT_SUMMARY`]: `store::send_receipt_audit` relays the same
    /// caller-encoded bytes verbatim.
    SEND_RECEIPT_ATTEMPT_AUDIT: VaultMeta b"send_receipt_attempt:v0:" Raw Authored [accepts: crate::store::send_receipt_attempt_audit_accepts_masked]
        [restore: live] [family: unclassified] [tier: canonical];
    /// An export-first removal's archive, delivered to the removed Owner alone and kept for them
    /// until its term ends (FIX 1300). Key: hex32 (removed Owner) ":" hex32 (receipt id).
    SHARED_ACT_REMOVAL_EXPORT: VaultMeta b"shared-act:removal-export:v1:" Named
        // Restore class: An archive delivered to a removed Owner has left the vault: a restore
        // neither revives a purged one nor drops one still within its term.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::Vault::erase_removal_archive_actor_in_txn;
    /// One delivery of a removal archive a removed person's device took in: its digest, what
    /// it holds and when, never the archive (FIX 11197). Key: hex32 (person) ":" hex32 (receipt
    /// id) ":" decimal (delivery version).
    SHARED_ACT_REMOVAL_IMPORT: VaultMeta b"shared-act:removal-import:v1:" Named
        // Restore class: A device's record of the archives it took in stands with the archives it
        // keeps: a restore neither re-imports one nor forgets one.
        [restore: live] [family: unclassified] [tier: canonical];
    /// Retired presentation id alias. Key: string.
    SHORT_ID_ALIAS: VaultMeta b"short_id_alias:v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Presentation-id grammar generation. Key: ().
    SHORT_ID_GRAMMAR_VERSION: VaultMeta b"short_id_grammar_version" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// Marker (the single byte 1) that one attempt receipt's pack loaded one skill; an erased
    /// skill's markers go. Key: u64be receipt length + receipt string + id16.
    SKILL_RESIDENT_LOADED_SKILL: VaultMeta b"skill:resident_loaded_skill:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::skill::resident::erase_resident_loaded_skill_in_txn;
    /// Lifelong resident owner of one skill id (version byte, has-owner byte, optional owner id16),
    /// kept across deletion. Key: id16.
    SKILL_RESIDENT_OWNER: VaultMeta b"skill:resident_owner:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The actor (id16) one attempt receipt is bound to. Key: string (the receipt id).
    SKILL_RESIDENT_RECEIPT: VaultMeta b"skill:resident_receipt:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One label the attribution judge settled on a terminal attempt's outcome evidence, kept
    /// whatever its subject routing (OF-568 L10): source id, evidence sequence, receipt, actor
    /// and skill (each nil once erased), label, share, judge revision, time. Key: hash32 (blake3
    /// of the terminal pack receipt id) + u64be (evidence sequence).
    SKILL_ATTRIBUTION_CAUSE: VaultMeta b"skill_attribution:cause:v1:" Named Engine
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::store::skill_attribution_causes::erase_attribution_cause_entity_in_txn;
    /// One minted skill-edit proposal awaiting gated apply, keyed by judgment sequence. Key: u64be.
    SKILL_ATTRIBUTION_EDIT_PROPOSAL: VaultMeta b"skill_attribution:edit_proposal:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One recorded outcome-evidence row (hand-rolled MessagePack map) awaiting attribution routing,
    /// keyed by sequence; its skill and its actor are each nil once erased. Key: u64be.
    SKILL_ATTRIBUTION_EVIDENCE: VaultMeta b"skill_attribution:evidence:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::store::skill_attribution_evidence::erase_attribution_evidence_skill_in_txn;
    /// One durable attribution verdict routed from evidence, keyed by evidence sequence; one that
    /// charges an erased skill stays with its subject nil, the edit proposals naming it go, and a
    /// lapse charging an erased actor stays with its subject nil. Key: u64be.
    SKILL_ATTRIBUTION_JUDGMENT: VaultMeta b"skill_attribution:judgment:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::store::skill_attribution_judgments::erase_attribution_judgment_skill_in_txn;
    /// A positive skill proposal: a succeeded deviation or uncovered step that taught its skill;
    /// one naming an erased skill or actor goes. Key: u64be (evidence sequence).
    SKILL_ATTRIBUTION_POSITIVE_PROPOSAL: VaultMeta b"skill_attribution:positive_proposal:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::store::positive_skill_proposals::erase_positive_proposals_in_txn;
    /// One skill's site knowledge a run's browser was shown (FIX 11436): the run, the scope and
    /// seq of the observation, the skill, its revision, the BLAKE3 of the knowledge and when.
    /// Key: id16 (run) + id16 (skill) + be64 (seq) + 8 (scope hash).
    SKILL_ATTRIBUTION_SITE_EXPOSURE: VaultMeta b"skill_attribution:site_exposure:v1:" Named Engine
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::store::site_skill_exposure::erase_site_exposure_in_txn;
    /// Skills citing a source. Key: id16 + id16.
    SKILL_SOURCE_INDEX: VaultMeta b"skill_convert/source_index/v1\0" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Owner-adjudicated held-out claim labels (JSON array of hex ids) reserved for one claim base.
    /// Key: id16.
    SKILL_HUB_CLAIM_REFINEMENT_RESERVE: VaultMeta b"skill_hub/claim-refinement-reserve/v1\0" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Empty-marker index from a skill content hash to every entity holding it, maintained on every
    /// skill put. Key: hash32 + id16.
    SKILL_HUB_CONTENT_HASH_INDEX: VaultMeta b"skill_hub/content_hash_index/v1\0" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Schema-version byte gating the one-time content-hash-index backfill/migration. Key: ().
    SKILL_HUB_CONTENT_HASH_INDEX_SCHEMA_VERSION: VaultMeta b"skill_hub/content_hash_index_schema_version" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Refinement-receipt carrier id to the holder (candidate id, 16 bytes) that owns it. Key: id16.
    SKILL_HUB_REFINEMENT_BINDING: VaultMeta b"skill_hub/refinement-binding/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Permanent claim-refinement origin: blake3 (32 bytes) of the first native Proposed bytes. Key:
    /// id16.
    SKILL_HUB_REFINEMENT_CLAIM_ORIGIN: VaultMeta b"skill_hub/refinement-claim-origin/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Content-free refinement control row (target, bindings, state) for one candidate. Key: id16.
    SKILL_HUB_REFINEMENT_CONTROL: VaultMeta b"skill_hub/refinement-control/v1\0" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Latest local refinement ruling pointer (ruling id16 + carrier id16) for a holder. Key: id16.
    SKILL_HUB_REFINEMENT_LATEST: VaultMeta b"skill_hub/refinement-latest/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Empty marker that a holder owns one refinement-receipt carrier. Key: id16 + id16.
    SKILL_HUB_REFINEMENT_OWNED: VaultMeta b"skill_hub/refinement-owned/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Permanent skill-refinement origin: blake3 (32 bytes) of the first native Candidate bytes.
    /// Key: id16.
    SKILL_HUB_REFINEMENT_SKILL_ORIGIN: VaultMeta b"skill_hub/refinement-skill-origin/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Empty marker that one refinement-receipt carrier id is permanently retired. Key: id16.
    SKILL_HUB_REFINEMENT_SOURCE_RETIRED: VaultMeta b"skill_hub/refinement-source-retired/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Shared-skill merge delta computed for one candidate. Key: id16.
    SKILL_HUB_SHARED_DELTA: VaultMeta b"skill_hub/shared-delta/v1\0" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Source-custody state (live/dead/unseen byte) for one (holder, content hash) pair. Key: id16 +
    /// hash32.
    SKILL_HUB_SOURCE_CUSTODY: VaultMeta b"skill_hub/source-custody/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Storage ABI stamp. Key: ().
    STORAGE_ABI_VERSION: VaultMeta b"storage_abi_version" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// The pinned text analyzer manifest (JSON) and, under '_hash', its SHA-256. Key: string.
    TEXT_ANALYZER_MANIFEST: VaultMeta b"text_analyzer_manifest" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// BM25F field schema hash. Key: ().
    TEXT_BM25_FIELD_SCHEMA_HASH: VaultMeta b"text_bm25_field_schema_hash" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// Text-index schema version stamp. Key: ().
    TEXT_INDEX_SCHEMA_VERSION: VaultMeta b"text_index_schema_version" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// The MESSAGE rows a kept TURN lost to a window demotion (OF-534, FIX 3859), until each is
    /// back with its PartOf edge: derived, local, never synced. Key: id16 (turn).
    TURN_MISSING_MESSAGES: VaultMeta b"turn:missing_messages:v1:" Named
        // Restore class: What a kept TURN lacks is this vault's residency, not history: a restore
        // neither promotes a demoted window nor rebuilds the list (FIX 3859).
        [restore: live] [family: unclassified] [tier: canonical];
    /// What a standing answer rests on beyond its unit, as a source-to-root refresh watcher (an
    /// edit to a neighbour queues the root's arrival). Key: id16(source) + id16(question) +
    /// id16(unit).
    TYPED_QUESTION_RESTS_ON: VaultMeta b"typed_question:rests_on:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Unit-to-question refresh watcher. Key: id16(unit) + id16(question).
    TYPED_QUESTION_UNIT_WATCH: VaultMeta b"typed_question:unit:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Legacy per-entity VAD annotation metadata row (entity_type byte then subject id); no current
    /// write path, only read and deleted for headerless-delete cleanup. Key: u8 + id16.
    AFFECT_VAD_ANNOTATION_META: VaultMeta b"vad_ann:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Archives a vault that shares key custody with another: the image a restore in its place
    /// set aside, and the replacement until it is in that place. An archived vault's handles
    /// refuse every write until an owner activates it as a side vault. Runtime, never
    /// checkpointed. Value: the byte 1 (archived wherever it is), or the byte 2 and an encoded
    /// canonical root (archived unless it is at that root). Key: ().
    VAULT_ARCHIVED_BY_RESTORE: VaultMeta b"vault_archived:v1" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Cleanup marks by id16. 48 bytes: a cleanup run archived a completed queue-record attempt,
    /// pinned to the exact bytes archived and naming the run. 32 bytes: the owner kept a restored
    /// attempt or record at that revision. Key: id16 (AttemptId, or a kept record's entity id).
    VAULT_CLEANUP_ATTEMPT_ARCHIVE: VaultMeta b"vault_cleanup.attempt_archive.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Random 32-byte identity of this store, minted at its first open and compared by every
    /// same-vault check; node-local and never synced, so a replica holds its own. Key: ().
    VAULT_IDENTITY_LOCAL: VaultMeta b"vault_identity:local:v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The BLAKE3 fingerprint of the recipient public key each escrow label was sealed to, kept
    /// after the label retires, so a later add of the same key under another label warns (FIX
    /// 2857). Public facts only. Key: string (label).
    VAULT_KEY_ESCROW_RECIPIENT: VaultMeta b"vault_key:escrow_recipient:v1:" Named
        // Restore class: A restore never resets how the vault key unlocks.
        [restore: live] [family: unclassified] [tier: canonical];
    /// An escrow label retired after its recipient's secret was released, and the owner's receipt
    /// (OF-570, CROSS-ARCH-0022 #ov-custody-backend); nothing is sealed to it again. Key: string
    /// (label).
    VAULT_KEY_ESCROW_RETIRED: VaultMeta b"vault_key:escrow_retired:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The blake3 of the escrow capsule each escrow wrap last handed to the host's outbound spool
    /// (OF-570, CROSS-ARCH-0022 invariant 03). Key: string (wrap id).
    VAULT_KEY_ESCROW_SPOOLED: VaultMeta b"vault_key:escrow_spooled:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The vault data key's commitment and birth (OF-570 E1). Never the key. Key: ().
    VAULT_KEY_STATE: VaultMeta b"vault_key:state:v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// One way to unlock the vault data key: an E0 `VaultDek` envelope and its public
    /// metadata. Key: string (wrap id).
    VAULT_KEY_WRAP: VaultMeta b"vault_key:wrap:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Voice reference pack. Key: string (pack id).
    VOICE_OWNER_REF: VaultMeta b"voice:owner_ref:v1:" Named
        // Payload family: The voice reference bank, every table of it, erased with its subject or
        // creator in every kept copy (FIX 8972).
        [restore: live] [family: dispatch Response] [tier: canonical];
    /// Per-owner index over voice reference bank rows. Key: id16 (owner) + the indexed row's full
    /// key.
    VOICE_OWNER_REF_OWNER_INDEX: VaultMeta b"voice:owner_ref_owner:v1:" Raw
        // Payload family: The voice reference bank, every table of it, erased with its subject or
        // creator in every kept copy (FIX 8972).
        [restore: live] [family: dispatch Response] [tier: canonical];
    /// Voice identity over its reference packs. Key: string (voice id).
    VOICE_REF_IDENTITY: VaultMeta b"voice:ref_identity:v1:" Named
        // Payload family: The voice reference bank, every table of it, erased with its subject or
        // creator in every kept copy (FIX 8972).
        [restore: live] [family: dispatch Response] [tier: canonical];
    /// Voice identity incarnation (16 random bytes), fresh at every birth. Key: string (voice id).
    VOICE_REF_INCARNATION: VaultMeta b"voice:ref_incarnation:v1:" Raw
        // Payload family: The voice reference bank, every table of it, erased with its subject or
        // creator in every kept copy (FIX 8972).
        [restore: live] [family: dispatch Response] [tier: canonical];
    /// A banked voice's current render/provisioning consent decision, apart from recognition
    /// consent. Key: string (voice id).
    VOICE_REF_RENDER_CONSENT: VaultMeta b"voice:ref_render_consent:v1:" Named
        // Restore class: A restore never revives a withdrawn render consent.
        // Payload family: The voice reference bank, every table of it, erased with its subject or
        // creator in every kept copy (FIX 8972).
        [restore: live] [family: dispatch Response] [tier: canonical];
    /// One render decision a voice's subject or designed voice's creator made, kept once and never
    /// rewritten (FIX 4396): the decision, its revision and sequence, and the target pointers it
    /// dropped. Erased with the bank. Key: string (voice id) "\0" string (event id).
    VOICE_REF_RENDER_EVENT: VaultMeta b"voice:ref_render_event:v1:" Named
        // Restore class: Nor its render history, which an erase deleted with the bank.
        // Payload family: The voice reference bank, every table of it, erased with its subject or
        // creator in every kept copy (FIX 8972).
        [restore: live] [family: dispatch Response] [tier: canonical];
    /// Cached voice render-target pointer. Key: string (voice id) "\0" string (target).
    VOICE_REF_TARGET: VaultMeta b"voice:ref_target:v1:" Named
        // Payload family: The voice reference bank, every table of it, erased with its subject or
        // creator in every kept copy (FIX 8972).
        [restore: live] [family: dispatch Response] [tier: canonical];
    /// When a world was soft-deleted here (u64 vault seconds): a pin change still rewraps its keys
    /// for 90 days after, while old bundles restore it. Key: id16 hex (world).
    WORLD_KEY_DELETED: VaultMeta b"world_keys:deleted:v1:" Raw
        // Restore class: A deleted world's delete time follows its shell.
        [restore: content] [family: unclassified] [tier: canonical];
    /// Permanent fact that a world's keys were destroyed with the world, with its ids-only
    /// receipt. Refuses a late pad, a remint and an open for that world. Key: id16 hex (world).
    WORLD_KEY_DESTROYED: VaultMeta b"world_keys:destroyed:v1:" Named
        // Restore class: A destroyed world stays destroyed: no image restores its keys.
        [restore: live] [family: unclassified] [tier: canonical];
}
