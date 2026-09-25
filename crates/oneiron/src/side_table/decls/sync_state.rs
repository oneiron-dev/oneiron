// Declared `sync_state` tables (string keys), in prefix order.

side_tables! {
    SYNC_STATE;
    /// Archived claim-less shell marker. Key: hex32.
    DELETION_ARCHIVE_MARKER: SyncState b"ac:" Raw;
    /// Per-admission disclosure floor: the VV as of the last full-state text-document export to one
    /// selector/peer. Key: hex32 (entity id) [":" hex32 (NOTE head)] ":" hex64 (blake3 of admission
    /// key).
    SYNC_AD_E: SyncState b"ad:e:" Raw;
    /// A control-plane API key record (HMAC-SHA256 digest, scopes, expiry, revoked flag) keyed by its
    /// own digest. Key: hex64.
    AUTH_CONTROL_KEY: SyncState b"auth:control-key:v1:" Named;
    /// Marker row (empty value) recording that a legacy 32-hex bearer-token identifier has been
    /// revoked. Key: hex32.
    AUTH_REVOKED_TOKEN_JTI: SyncState b"auth:revoked-token-jti:" Raw;
    /// First-seen sidecars per authority entry hash, plus the 'backfill:v1' and 'clock_floor' rows.
    /// Key: string.
    AUTHLOG_FIRST_SEEN_SIDECAR: SyncState b"authlog:first_seen:" Raw;
    /// One recorded OF-520 ingest-burst check (24 bytes), raised once per peer per observation
    /// window. Key: hex64 ":" u64hex16.
    AUTHLOG_INGEST_CHECK: SyncState b"authlog:ingest_check:" Raw;
    /// Local sliding-window replay-ingest counter (start/count/raised, 17 bytes) per authority peer
    /// signer. Key: string.
    AUTHLOG_INGEST_COUNT: SyncState b"authlog:ingest_count:" Raw;
    /// Device-local authority observation policy durations: stale-roster window, ingest window,
    /// ingest check threshold (3x u64be). Key: ().
    AUTHLOG_OBSERVATION_POLICY: SyncState b"authlog:observation_policy:duration_v1" Raw;
    /// Durable high-water mark (u64be) of a signer's highest observed authority-log sequence number.
    /// Key: string.
    AUTHLOG_SEQ_HWM: SyncState b"authlog:seq_hwm:" Raw;
    /// First-observation receipt recording the signer sequence high-water mark that existed before
    /// this entry hash was first observed. Key: hex64.
    AUTHLOG_SEQ_OBSERVATION: SyncState b"authlog:seq_observation:" Raw;
    /// Cached minted host-root capability-slip token ("v2.slip."+hex(JSON)) for one host signing key.
    /// Key: `:` + hex.
    AUTHORITY_HOST_ROOT_SLIP_CACHE: SyncState b"authority:host-root-slip:v2" Raw;
    /// One outstanding single-use pairing/enrollment link, keyed by a keyed-hash of its typed code.
    /// Key: hex64.
    AUTHORITY_PAIRING_PENDING: SyncState b"authority:pairing:" LegacyJson;
    /// Admitted request nonce inside the replay window (empty marker), evicted once its signed
    /// timestamp ages out. Key: u64hex16 ":" hex64.
    AUTHORITY_SLIP_REPLAY_NONCE: SyncState b"authority:slip-replay:v2:" Raw;
    /// Cached currency-converted spend budget limit for one owner/vault pair. Key: hex ":" hex
    /// (owner, vault).
    USAGE_BUDGET_LIMIT: SyncState b"budget:usage:rollup:vault:" Named;
    /// Device-only in-progress marker between a received BulkTransfer chunk and its BulkTransferDone.
    /// Key: yyyy-mm.
    SYNC_BULK_TRANSFER_MARKER: SyncState b"bulk:w:" Raw;
    /// An entity document's snapshot (document family). Key: hex32.
    DOCUMENT_SNAPSHOT: SyncState b"d:e:" Raw;
    /// ARCH-0023b document family: the root document's full CRDT snapshot (server-write-only
    /// meta.windows). Key: ().
    SYNC_D_ROOT: SyncState b"d:root" Raw;
    /// A sync window's document snapshot (document family). Key: yyyy-mm (window key).
    WINDOW_SNAPSHOT: SyncState b"d:w:" Raw;
    /// Per-entity text-document subscription row replayed as a REQUEST frame on every reconnect. Key:
    /// hex32 (entity id).
    SYNC_DS_E: SyncState b"ds:e:" Raw;
    /// Local hard-delete marker. Key: hex32.
    DELETION_HARD_DELETE_MARKER: SyncState b"dt:" Raw;
    /// Durable identity/provenance/status of one open or settled document fork. Key: hex32.
    ENTITY_DOC_FORK: SyncState b"entity_doc:v1:fork:" Named;
    /// Shallow Loro snapshot of a fork's diverged content at its opening base. Key: hex32.
    ENTITY_DOC_FORK_SNAPSHOT: SyncState b"entity_doc:v1:fork_snapshot:" Raw;
    /// Immutable citation pin binding a quoted span to its exact causal frontier, keyed by entity
    /// then citation id. Key: hex32 ":" hex32.
    ENTITY_DOC_PIN: SyncState b"entity_doc:v1:pin:" Named;
    /// Review bundle of every fork opened under one text-edit proposal. Key: hex32.
    ENTITY_DOC_PROPOSAL_BUNDLE: SyncState b"entity_doc:v1:proposal:" Named;
    /// Durable proof of one owner-authorized shallow history purge, keyed by entity then receipt id.
    /// Key: hex32 ":" hex32.
    ENTITY_DOC_PURGE_RECEIPT: SyncState b"entity_doc:v1:purge:" Named;
    /// Durable settlement receipt (before/after causal frontier) for one fork's merge/switch/reject
    /// verdict, keyed by entity then receipt id. Key: hex32 ":" hex32.
    ENTITY_DOC_RECEIPT: SyncState b"entity_doc:v1:receipt:" Named;
    /// First-wins stamp recording that a foreign world's federated content stopped refreshing after a
    /// terminal pact transition. Key: hex32 (world id).
    FEDERATION_STALE: SyncState b"fedstale:" Raw;
    /// Registers a foreign world as content delivered by one federation pact, scanned when the pact
    /// goes terminal. Key: hex64 (pact id) ":" hex32 (world id).
    FEDERATION_WORLD_REGISTRATION: SyncState b"fedworld:" Raw;
    /// A sync window needs a full resync. Key: yyyy-mm.
    WINDOW_FULL_RESYNC_MARKER: SyncState b"fr:w:" Raw;
    /// Durable pin forcing a window to export as a history-free snapshot instead of ordinary Loro
    /// history. Key: yyyy-mm.
    SYNC_HISTORY_FREE_WINDOW: SyncState b"hfs:w:" Raw;
    /// Cached HTTP response (status, headers, body) for one Idempotency-Key replay within its 24h
    /// TTL, keyed by principal and header value. Key: hex ":" hex (principal, idempotency key).
    HTTP_IDEMPOTENCY_REPLY: SyncState b"http:idempotency:" LegacyCompact;
    /// Durable provenance row (source/tier/thread/message/surface-event) for one ingested LinkedIn
    /// message. Key: hex16 (same hash as the seen marker).
    LINKEDIN_INBOX_SYNC_PROVENANCE: SyncState b"linkedin:inbox_sync:provenance:v1:" LegacyJson;
    /// Claim-then-finalize dedupe marker for one polled LinkedIn inbox message. Key: hex16 (truncated
    /// blake3 of receiving address/session/thread/message).
    LINKEDIN_INBOX_SYNC_SEEN: SyncState b"linkedin:inbox_sync:seen:v1:" Raw;
    /// Local mirror of one device's REDACTION_AUDIT-stream lease-registry entry from the root doc's
    /// leases map. Key: hex16 (vault_id) ":" hex16 (client_id).
    SYNC_LEASE: SyncState b"ls:" Raw;
    /// This device's stable client id (u64 LE, nonzero), minted once per install and reused as the
    /// sync client's peer id. Key: ().
    IDENTITY_CLIENT_ID: SyncState b"m:client_id" Raw;
    /// Cached 32-byte Ed25519 verifying key derived from this device's signing seed; a stored value
    /// that disagrees with the seed-derived key is corruption. Key: ().
    IDENTITY_DEVICE_PK: SyncState b"m:device_pk" Raw;
    /// This device's 32-byte Ed25519 signing-key seed, stored plaintext and used to sign receipt
    /// attestations. Key: ().
    IDENTITY_DEVICE_SK: SyncState b"m:device_sk" Raw;
    /// Client-only: last Unix-seconds timestamp this device reached fully-synced status. Key: ().
    SYNC_M_LAST_SYNC: SyncState b"m:last_sync" Raw;
    /// Monotonic counter allocating the next u:e: sequence number for one entity's text document.
    /// Key: hex32 (entity id).
    SYNC_M_U_SEQ_E: SyncState b"m:u_seq:e:" Raw;
    /// Crash-safe monotonic counter allocating the next u:w: sequence number for one window. Key:
    /// yyyy-mm.
    SYNC_M_U_SEQ_W: SyncState b"m:u_seq:w:" Raw;
    /// Marker row admitting a vault as a synthetic canary, the only substitute managed-mode accepts
    /// for the real-tenant isolation preconditions. Key: ().
    MANAGED_CANARY_MARKER: SyncState b"managed:canary:v1" Raw;
    /// Keyed MAC (32 bytes) of the vault's identity metadata under the managed-mode delivered DEK,
    /// sealed on first open and checked on every reopen. Key: ().
    MANAGED_DEK_MAC: SyncState b"managed:dek_mac:v1" Raw;
    /// The generated managed-mode lease scope id (u64 big-endian) for this vault, stable across
    /// reopen. Key: ().
    MANAGED_LEASE_SCOPE: SyncState b"managed:lease_scope:v1" Raw;
    /// The last-persisted revision counter (u64 little-endian) for the managed-mode wake-ledger push
    /// to the supervisor. Key: ().
    MANAGED_LEDGER_REV: SyncState b"managed:ledger_rev:v1" Raw;
    /// Marks a policy-manifest contribution as quarantined by an explicit owner action. Key: hex32.
    GATE_MANIFEST_QUARANTINED: SyncState b"manifest:quarantined:" Raw;
    /// Configured thresholds for the wire call-volume observation counters. Key: ().
    RC42_WIRE_MANIFEST: SyncState b"manifest:rc42:wire-observation:v1" Named;
    /// Maps a legacy policy-manifest id forward to its re-authored replacement id. Key: hex32.
    GATE_MANIFEST_REKEY: SyncState b"manifest:rekey:" Raw;
    /// Authenticity hash stamped when a policy manifest is contributed directly (non-replicated).
    /// Key: hex32.
    GATE_MANIFEST_TRUSTED_ORIGIN: SyncState b"manifest:trusted:" Raw;
    /// Durable receipt for one applied/rejected NOTE-operation request, kept for reconnect/reopen.
    /// Key: hex32 (entity id) ":" hex32 (request id).
    SYNC_NC_E: SyncState b"nc:e:" LegacyJson;
    /// Marks a window whose peer-authored NOTE inbox residue was staged, consulted by the note
    /// module's erasure sweep. Key: yyyy-mm (window key).
    SYNC_NOTE_INBOX: SyncState b"note_inbox:v1:" Raw;
    /// Loro snapshot bytes of a proposal (non-live) NOTE document head. Key: hex32(note) ":"
    /// hex32(head).
    NOTE_PROPOSAL_DOC: SyncState b"note_proposal_doc:v1:" Raw;
    /// Idempotent operation receipt for one authenticated NOTE command. Key: hex32(note) ":"
    /// hex32(request id).
    NOTE_RECEIPT_BY_REQUEST: SyncState b"nr:e:" LegacyJson;
    /// Entity waiting for an embedding. Key: hex32.
    PENDING_EMBEDDING_MARKER: SyncState b"pe:" Raw;
    /// One admitted peer AUTHORITY_LOG entry's canonical bytes, used to refold that peer's roster
    /// locally. Key: hex64 (peer vault id) ":" hex64 (entry hash).
    PEER_AUTHORITY_ENTRY: SyncState b"peerauth:" Raw;
    /// Lease fencing one pending-embedding job against a route/token pair. Key: hex32.
    PENDING_EMBEDDING_LEASE: SyncState b"pelease:" Raw;
    /// Deduplicated marker (single byte) recording which sync window a promoted turn's replayed
    /// closure spans, picked up by later sync replay. Key: yyyy-mm ":" hex32.
    OFF_RECORD_PROMOTE_PICKUP_MARKER: SyncState b"pm:" Raw;
    /// Pending tombstone propagation marker. Key: yyyy-mm ":" hex32.
    DELETION_PENDING_TOMBSTONE: SyncState b"pt:" Raw;
    /// Durable unacknowledged local text-document edit frame, cleared once the peer's VV proves
    /// receipt. Key: hex32 (entity id) ":" hex8 (sequence).
    SYNC_QD_E: SyncState b"qd:e:" Raw;
    /// Durable pending semantic NOTE-operation request, replayed until its receipt lands. Key: hex32
    /// (entity id) ":" hex32 (request id).
    SYNC_QN_E: SyncState b"qn:e:" Raw;
    /// Queued tombstone re-assertion for an entity whose local hard-delete residue reappeared in a
    /// window doc. Key: yyyy-mm ":" hex32 (entity id).
    SYNC_REASSERT_MARKER: SyncState b"ra:w:" Raw;
    /// Entity-scoped needs-rematerialization retry flag, set when a CRDT-tombstone purge or a
    /// materialization batch fails. Key: yyyy-mm ":" hex32 (entity id).
    SYNC_REMAT_MARKER: SyncState b"rm:w:" Raw;
    /// Sidecar on a rm:w: marker proving it originated from replay/quarantine (not a delete-safety
    /// purge failure), so terminal quarantine may discharge it. Key: yyyy-mm ":" hex32 (entity id).
    SYNC_REPLAY_REMAT_MARKER_PROVENANCE: SyncState b"rmp:w:" Raw;
    /// An entity document's shallow-since version vector (document family). Key: hex32 (NOTE head
    /// id).
    DOCUMENT_SHALLOW_SINCE: SyncState b"ssv:e:" Raw;
    /// An entity document's state vector (document family). Key: hex32.
    DOCUMENT_STATE_VECTOR: SyncState b"sv:e:" Raw;
    /// ARCH-0023b document family: the root document's state vector, paired with d:root. Key: ().
    SYNC_SV_ROOT: SyncState b"sv:root" Raw;
    /// A sync window's state vector (document family). Key: yyyy-mm.
    WINDOW_STATE_VECTOR: SyncState b"sv:w:" Raw;
    /// ARCH-0023b document family: freshness flag for the root document's persisted state vector.
    /// Key: ().
    SYNC_SVF_ROOT: SyncState b"svf:root" Raw;
    /// Whether a sync window's state vector is fresh (document family). Key: yyyy-mm.
    WINDOW_SHALLOW_FENCE: SyncState b"svf:w:" Raw;
    /// Test-fixture row, never read or written by production code: a cached
    /// minted capability slip for one request-credential recipe id
    /// (`crates/oneiron-server/src/test_credentials.rs`, mounted only as
    /// `#[cfg(test)] mod test_credentials;`). Declared so the generic host
    /// door's declared-table check (`side_table::host_declared_sync_state`)
    /// does not refuse this well-known test fixture prefix. Key: hex64
    /// (blake3 of the fixture's request-recipe id).
    TEST_API_SLIP_CACHE: SyncState b"test:api:slip:" Raw;
    /// Test-fixture row, never read or written by production code: a cached
    /// minted MCP-paired capability-slip token for one pairing label
    /// (`crates/oneiron-server/src/api/tests/support_mcp_credentials.rs`,
    /// reached only from `#[cfg(test)]` code under `api/tests/`). Same
    /// rationale as `TEST_API_SLIP_CACHE`. Key: hex64 (blake3 of the label).
    TEST_MCP_PAIRED_CACHE: SyncState b"test:mcp:paired:" Raw;
    /// One pending update of an entity document (document family). Key: hex32 (entity id) ":" hex8
    /// (sequence).
    DOCUMENT_UPDATE: SyncState b"u:e:" Raw;
    /// ARCH-0023b document family: pending root-document CRDT updates applied on top of d:root at
    /// startup; read-only in this crate (written server-side). Key: hex8 (sequence).
    SYNC_U_ROOT: SyncState b"u:root:" Raw;
    /// ARCH-0023b document family: one durable pending CRDT update for a window, applied on top of
    /// d:w:. Key: yyyy-mm ":" hex8 (sequence).
    SYNC_U_W: SyncState b"u:w:" Raw;
    /// One idempotently recorded usage-metering event for an owner/vault, keyed by its caller-
    /// supplied idempotency key. Key: hex ":" hex ":" hex (owner, vault, idempotency-key).
    USAGE_EVENT: SyncState b"usage:event:" Named;
    /// Aggregated usage-metering rollup totals (cost/units) for one owner/vault pair. Key: hex ":"
    /// hex (owner, vault).
    USAGE_VAULT_ROLLUP: SyncState b"usage:rollup:vault:" Named;
    /// Admitted foreign-import payload retained only while its receipt is Pending, so recovery
    /// survives losing the in-memory stage. Key: hex64.
    VAULT_IMPORT_CONTENT: SyncState b"vault_import_content:v1:" Raw;
    /// Terminal/pending status receipt (hand-rolled MessagePack map) for one foreign vault-import
    /// artifact, keyed by its content-derived receipt id. Key: hex64.
    VAULT_IMPORT_RECEIPT: SyncState b"vault_import_receipt:v1:" Raw;
    /// A raised question recording that a wire call-volume window crossed its per-verb or per-actor
    /// threshold. Key: u64 ":" u64 (decimal, zero-padded to 20 digits; window start:end).
    RC42_WIRE_QUESTION: SyncState b"wire:question:v2:" Named;
    /// Persisted per-window wire call-volume counters (by verb and by actor) for one observation
    /// window. Key: u64 ":" u64 (decimal, zero-padded to 20 digits; window start:end).
    RC42_WIRE_RECEIPT: SyncState b"wire:window:v2:" Named;
}
