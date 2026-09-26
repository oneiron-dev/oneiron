// Declared `vault_meta` tables whose prefix starts with `a` to `c`, in prefix order.

side_tables! {
    VAULT_META_A_C;
    /// A pending cross-relationship access request awaiting the owner's approve/deny decision. Key:
    /// id16.
    ACCESS_REQUEST: VaultMeta b"access-request:v1:" LegacyJson;
    /// Durable SessionEnd distill job for one ended sitting, queued in the same transaction that
    /// closes it and cleared once distilled. Key: id16.
    ACTOR_CLAIMS_DISTILL_PENDING_JOB: VaultMeta b"actor_claims:distill_pending:v1:" Raw;
    /// Rotation cursor (last session id served) for the bounded session-end distill drain pump, so
    /// one budget-limited pass cannot starve later jobs. Key: ().
    ACTOR_CLAIMS_DISTILL_RUNNER_CURSOR: VaultMeta b"actor_claims:distill_runner_cursor:v1" Raw;
    /// Approved board-widened context slice override recorded for one parent attempt. Key: id16.
    AGENT_DISPATCH_WIDEN_SLICE: VaultMeta b"agent.dispatch.slice.v1\0" LegacyJson;
    /// Pending context-widen proposal record, keyed by a hash of the dedupe key or full intent. Key:
    /// hash32.
    AGENT_DISPATCH_WIDEN_INTENT: VaultMeta b"agent.dispatch.widen.v1\0" LegacyJson;
    /// Index from a widen proposal's public content-hash id to its intent row key. Key: hex64.
    AGENT_DISPATCH_WIDEN_PROPOSAL_INDEX: VaultMeta b"agent.dispatch.widen_id.v1\0" Raw;
    /// Dedupe index from a caller-supplied dedupe key to the workflow root attempt id. Key: hash32.
    AGENT_WORKFLOW_DEDUPE: VaultMeta b"agent.workflow.dedupe.v1\0" Raw;
    /// Durable saved-composition record for one inert multi-step workflow wrapper attempt. Key: id16.
    AGENT_WORKFLOW_RECORD: VaultMeta b"agent.workflow.record.v1\0" LegacyJson;
    /// Binds a captured-source ASSET id back to the child agent it was birthed for. Key: id16.
    AGENT_DEF_BIRTH_ASSET_BINDING: VaultMeta b"agent_def/birth-asset-binding/v1\0" Raw;
    /// Which asset entity currently holds custody of a birthed agent's captured source. Key: id16.
    AGENT_DEF_BIRTH_CUSTODY_OWNED: VaultMeta b"agent_def/birth-custody/v1\0" Raw;
    /// Empty marker: a captured dependency input has been retired. Key: id16.
    AGENT_DEF_BIRTH_INPUT_RETIRED: VaultMeta b"agent_def/birth-input-retired/v1\0" Raw;
    /// Empty marker indexing birthed-agent children by a captured dependency input (input id then
    /// child id). Key: id16 + id16.
    AGENT_DEF_BIRTH_INPUT: VaultMeta b"agent_def/birth-input/v1\0" Raw;
    /// Empty marker: an agent's birth source has been retired. Key: id16.
    AGENT_DEF_BIRTH_RETIRED: VaultMeta b"agent_def/birth-retired/v1\0" Raw;
    /// Frozen source-tree identity (source id + skill content hash, 48 raw bytes) recorded at an
    /// agent's genuine local birth. Key: id16.
    AGENT_DEF_PORTABLE_BIRTH: VaultMeta b"agent_def/portable-birth/v1\0" Raw;
    /// Pre-1890 reserved-actor census row, deleted with the census it served; not written by current
    /// code, only deleted once on seed. Key: ().
    AGENT_DEF_DEFAULT_RESERVED_ACTOR_CENSUS_V1: VaultMeta b"agent_def:default_reserved_actor_census:v1" Raw;
    /// Pre-1890 reserved-actor census row, deleted with the census it served; not written by current
    /// code, only deleted once on seed. Key: ().
    AGENT_DEF_RESERVED_ACTOR_CENSUS_V2: VaultMeta b"agent_def:reserved_actor_census:v2" Raw;
    /// Legacy pre-1890 per-vault system-agent enable toggle (single byte 0x00/0x01), consumed once
    /// and deleted by the manifest seeder. Key: string.
    AGENT_DEF_SYSTEM_TOGGLE_LEGACY: VaultMeta b"agent_def:system_toggle:v1:" Raw;
    /// Channel pointer (published/preview) naming the fork hash a codebase artifact currently serves.
    /// Key: channel byte + u16be length + string (artifact id).
    ARTIFACT_POINTER: VaultMeta b"artifact:pointer:v1:" Raw;
    /// Terminal PACK RECEIPT for one attempt run under a skill pack, cited by receipt_ref lookups.
    /// Key: string ("attempt:" + hex32 attempt id).
    ATTEMPT_PACK_RECEIPT: VaultMeta b"attempt_receipt:v1:" Named;
    /// One-shot consumption marker and promotion receipt for a specific authoring strategy's sealed
    /// BEAM measurement. Two shapes share this key over its lifetime (a non-JSON consumption
    /// sentinel, then a JSON receipt) and no reader ever decodes it — every access is a raw
    /// presence or byte-equality check — so the codec is `Raw`, not `LegacyJson`.
    /// Key: hex64 (sha256 hex digest of the content-pinned strategy).
    AUTOREASON_BEAM_ONCE: VaultMeta b"authoring/beam-once/" Raw;
    /// Pointer to the current default (winning) authoring strategy pin and its promotion receipt.
    /// Key: ().
    AUTOREASON_BEAM_DEFAULT: VaultMeta b"authoring/default-beam-winner" LegacyJson;
    /// Content hash of the current head of the local authority-checkpoint chain. Key: ().
    AUTHORITY_CHECKPOINT_HEAD: VaultMeta b"authority.checkpoint.head.v1" Raw;
    /// One durable, quorum-signed authority checkpoint (hand-rolled MessagePack map), keyed by its
    /// content hash. Key: hash32.
    AUTHORITY_CHECKPOINT_ROW: VaultMeta b"authority.checkpoint.v1." Raw;
    /// Asset refcount marker. Key: bytes32 + id16.
    BLOB_ARTIFACT_ASSET_REF: VaultMeta b"blob_artifact:asset_ref:v1:" Raw;
    /// Blob artifact head version. Key: id16.
    BLOB_ARTIFACT_HEAD: VaultMeta b"blob_artifact:head:v1:" Raw;
    /// Edit proposal settlement ledger row. Key: id16 + hash32.
    EDIT_SETTLE_RECORD: VaultMeta b"blob_artifact:settlement:v1:" Raw;
    /// Blob artifact version record. Key: id16 + u64be.
    BLOB_ARTIFACT_VERSION: VaultMeta b"blob_artifact:version:v1:" Raw;
    /// Revision-ref frontier (16 bytes) a board-selection CLAIM was written under, authenticated on
    /// every read. Key: id16.
    BOARD_HISTORY_CLAIM_FRONTIER: VaultMeta b"board_history:claim_frontier:" Raw;
    /// Loro CRDT snapshot backing one owner's board-selection/document history. Key: id16.
    BOARD_HISTORY_DOC: VaultMeta b"board_history:doc:" Raw;
    /// Monotonic compaction horizon (u64be earliest retained turn time) per board-history owner. Key:
    /// id16.
    BOARD_HISTORY_HORIZON: VaultMeta b"board_history:horizon:" Raw;
    /// Last committed (at, learned_at) monotonic stamp per board-history owner, guarding against out-
    /// of-order turns. Key: id16.
    BOARD_HISTORY_LAST: VaultMeta b"board_history:last:" LegacyCompact;
    /// Turn anchor recording the board-history CRDT frontier and selection snapshot a TURN committed.
    /// Key: id16.
    BOARD_HISTORY_TURN: VaultMeta b"board_history:turn:" Named;
    /// Event-type configuration shortcut. Key: hash32.
    BOOKING_EVENT_TYPE_CONFIG_SHORTCUT: VaultMeta b"booking.event_type.v1:" Raw;
    /// Session soft-hold on a slot. Key: hash32.
    BOOKING_HOLD: VaultMeta b"booking.hold.v1:" VersionedNamed;
    /// Booking lifecycle transition receipt. Key: hash32.
    BOOKING_LIFECYCLE_RECEIPT: VaultMeta b"booking.lifecycle.receipt.v1:" VersionedNamed;
    /// Public booking page protected claim marker. Key: id16.
    BOOKING_PUBLIC_PAGE_PROTECTED_CLAIM: VaultMeta b"booking.public_page.protected_claim/" Raw;
    /// Public booking page token index. Key: string.
    BOOKING_PUBLIC_PAGE_TOKEN_INDEX: VaultMeta b"booking.public_page.token/" Raw;
    /// In-transaction booking publication write marker. Key: id16.
    BOOKING_PUBLICATION_WRITE_STAGE: VaultMeta b"booking.public_write.in_txn/" Raw;
    /// Booking token and checkout lease rows (digest domains keep them apart). Key: hash32.
    BOOKING_TOKEN: VaultMeta b"booking.token.v1:" VersionedNamed;
    /// Booking anti-abuse rules, notices, rate counters and slot-list caches. Key: tag NUL + hash32
    /// (rule, notice, rate, cache).
    BOOKING_ANTI_ABUSE: VaultMeta b"booking:anti_abuse:v1:" Raw;
    /// Companion shortlist proposal. Key: bytes32.
    BOOKING_COMPANION_PROPOSAL: VaultMeta b"booking:companion_proposal:v1:" VersionedNamed;
    /// Emergency effect attempt to checkpoint. Key: id16.
    EMERGENCY_EFFECT_LOOKUP: VaultMeta b"booking:emergency_effect:v1:" Raw;
    /// Emergency reschedule instruction. Key: hex64.
    EMERGENCY_INSTRUCTION: VaultMeta b"booking:emergency_instruction:v1:" LegacyJson;
    /// Emergency-affected booking checkpoint. Key: hex64.
    EMERGENCY_ITEM: VaultMeta b"booking:emergency_item:v1:" LegacyJson;
    /// EVENT to pending emergency checkpoint. Key: id16.
    EMERGENCY_PENDING_EVENT_LOOKUP: VaultMeta b"booking:emergency_pending_event:v1:" Raw;
    /// Emergency reschedule plan. Key: hex64.
    EMERGENCY_PLAN: VaultMeta b"booking:emergency_plan:v1:" LegacyJson;
    /// Plans under one instruction. Key: hash32 + id16.
    EMERGENCY_REQUEST_PLAN_INDEX: VaultMeta b"booking:emergency_request_plan:v1:" Raw;
    /// Marker (engine version string) that the built-in bootstrap skill set has been seeded. Key: ().
    SKILL_HUB_BOOTSTRAP_SEED: VaultMeta b"bootstrap_skills/seeded/v1" Raw;
    /// Durable reserve/settle/refund ledger for the RSI research-loop spend budget. Key: ().
    BUDGET_RSI_LINE: VaultMeta b"budget.rsi.line.v1" LegacyJson;
    /// The tenant/account identity a build-cache vault is bound to. Key: ().
    BUILD_CACHE_ACCOUNT: VaultMeta b"build_cache:account:v1" Raw;
    /// A cached build/verify action result, addressed by its content-derived action key; value is a
    /// leading schema-version byte then a positional (non-named) MessagePack sequence. Key: bytes32
    /// (REAPI action key).
    BUILD_CACHE_REAPI_ROW: VaultMeta b"build_cache:reapi:v2:" Raw;
    /// In-flight reservation marker preventing duplicate dispatch of the same build/verify action.
    /// Key: bytes32 (action key).
    BUILD_CACHE_RUNNING_RESERVATION: VaultMeta b"build_cache:running:v2:" Raw;
    /// Calendar connector write-outbox rows and remote object cursors. Key: `row:` or `obj:` +
    /// bytes32.
    CALENDAR_CONNECTOR_WRITE: VaultMeta b"calendar.connector-write.v1:" LegacyJson;
    /// Per-feed poll cursor. Key: bytes32.
    CALENDAR_ICS_FEED_CURSOR: VaultMeta b"calendar.ics-feed.v1:" LegacyJson;
    /// UID-to-EVENT lookup cache. Key: bytes32.
    CALENDAR_PASSPORT_UID_INDEX: VaultMeta b"calendar.passport.v1:" Raw;
    /// Marker that a derived EVENT's source was erased. Key: id16.
    CALENDAR_INVALIDATED_EVENT: VaultMeta b"calendar_invalid:v1:" Raw;
    /// EVENT entity awaiting calendar-origin claim reconciliation after entity/claim/edge replay
    /// settled. Key: id16 (EVENT entity id).
    SYNC_CALENDAR_ORIGIN_PENDING: VaultMeta b"calendar_origin_pending:v1:" Raw;
    /// The currently active campaign compliance rule pack. Key: ().
    CAMPAIGN_COMPLIANCE_ACTIVE: VaultMeta b"campaign:compliance:active:v1" Named;
    /// Durable UTF-8 activation notice for one compliance-pack version, one row per version. Key:
    /// u32be.
    CAMPAIGN_COMPLIANCE_NOTICE: VaultMeta b"campaign:compliance:notice:v1:" Raw;
    /// One staged compliance-pack amendment proposal awaiting an owner stamp. Key: ().
    CAMPAIGN_COMPLIANCE_PENDING: VaultMeta b"campaign:compliance:pending:v1" Named;
    /// Per-saved-query baseline (definition version + scope digest) a campaign enrollment detection
    /// re-derives against. Key: id16.
    CAMPAIGN_ENROLLMENT_BASELINE: VaultMeta b"campaign:enrollment_baseline:v1:" LegacyJson;
    /// One persisted campaign membership-transition detection event awaiting its consequence. Key:
    /// id16.
    CAMPAIGN_ENROLLMENT_EVENT: VaultMeta b"campaign:enrollment_event:v1:" LegacyJson;
    /// Campaign-local MACRO home-node election result. Key: ().
    CAMPAIGN_HOME_NODE_MACRO: VaultMeta b"campaign:home_node_macro:v1" LegacyJson;
    /// Persisted binding from a campaign program to the campaign it belongs to. Key: id16.
    CAMPAIGN_PROGRAM: VaultMeta b"campaign:program:v1:" LegacyJson;
    /// One step of a campaign program: channel/consent/sender binding and optional outward call,
    /// keyed by program then step. Key: id16 + id16.
    CAMPAIGN_PROGRAM_STEP: VaultMeta b"campaign:program_step:v1:" LegacyJson;
    /// Channel-identity autonomy modes, envelopes, graduation evidence and posting heads. Key:
    /// predicate `:` + subject.
    CHANNEL_IDENTITY_AUTONOMY: VaultMeta b"channel_identity_autonomy:v1:" Raw;
    /// Channel-identity lifecycle receipt ledger. Key: id16.
    CHANNEL_IDENTITY_LIFECYCLE_RECEIPT: VaultMeta b"channel_identity_lifecycle:v0:" Named;
    /// Channel-identity selection rule set. Key: ().
    CHANNEL_IDENTITY_SELECTION_RULES: VaultMeta b"channel_identity_selection:v1:rules" Raw;
    /// Per-repository environment blueprint. Key: bytes32.
    CHECKOUT_ENV_BLUEPRINT: VaultMeta b"checkout:env_blueprint:v1:" VersionedNamed;
    /// Checkout lease act. Key: hex32.
    CHECKOUT_LEASE: VaultMeta b"checkout:lease:v1:" Raw;
    /// Checkout settlement receipt. Key: hex32 + decimal + hex64.
    CHECKOUT_SETTLEMENT: VaultMeta b"checkout:settlement:v1:" Raw;
    /// Retired checkout epoch high-water mark. Key: hex32.
    CHECKOUT_TOMBSTONE: VaultMeta b"checkout:tombstone:v1:" Raw;
    /// A destructive claim action (supersede/decay/weaken/stale) parked behind unresolved gate
    /// consent. Key: id16.
    CLAIM_DEFERRED: VaultMeta b"claim.deferred.v1:" Named;
    /// Private local binding digest (row_digest, 32 bytes) proving which writer authored/finalized a
    /// CLAIM row. Key: id16.
    CLAIM_MATERIALIZATION_AUTHORED: VaultMeta b"claim:materialization:authored:v1:" Raw;
    /// Posting-list row of one pending session-generated claim under its producing actor. Key: id16
    /// (producer) + id16.
    CLAIM_PENDING_PRODUCER: VaultMeta b"claim:pending_producer:v1:" Raw;
    /// Posting-list row of one claim under its predicate's projection index. Key: bytes32 (blake3 of
    /// predicate) + id16.
    CLAIM_PREDICATE_INDEX: VaultMeta b"claim:predicate:v1:" Raw;
    /// Catalog marker recording that at least one claim uses this predicate. Key: string (predicate
    /// name).
    CLAIM_PREDICATE_NAME: VaultMeta b"claim:predicate_name:v1:" Raw;
    /// Reverse index: the projection-index keys written for one claim, so they can be removed
    /// together. Key: id16.
    CLAIM_PROJECTION_REVERSE: VaultMeta b"claim:projection_reverse:v1:" LegacyCompact;
    /// Immutable tested snapshot of a code document at one exact operation frontier (document id + op
    /// fold hash). Key: hash32 + hash32.
    CODE_DOCUMENT_FRONTIER: VaultMeta b"code_document:frontier:v1:" Named;
    /// Monotonic rename-generation counter (u64be) for a (repo, path) pair, advanced on rename. Key:
    /// hash32.
    CODE_DOCUMENT_GENERATION: VaultMeta b"code_document:generation:v1:" Raw;
    /// Current durable head snapshot plus full receipt history for one code document. Key: hash32.
    CODE_DOCUMENT_HEAD: VaultMeta b"code_document:head:v1:" Named;
    /// Durable replay-guard receipt for one applied code-file-edit ingress operation. Key: id16.
    CODE_DOCUMENT_INGRESS: VaultMeta b"code_document:ingress:v1:" Named;
    /// Maps a (repo, path) pair (sha256-hashed) to the code-document id currently living at that
    /// path. Key: hash32.
    CODE_DOCUMENT_PATH: VaultMeta b"code_document:path:v1:" Raw;
    /// Registered always-on code-memory contract (interface/policy) for a symbol slot payload. Key:
    /// id16 "\x00" string "\x00" u8 id16.
    CODE_MEMORY_ALWAYS_ON: VaultMeta b"code_memory:always_on:v1:" Raw;
    /// Durable L2 attachment row binding a code-symbol slot value to a note/claim payload (symbol,
    /// slot name, payload tag+id). Key: id16 "\x00" string "\x00" u8 id16.
    CODE_MEMORY_ATTACHMENT: VaultMeta b"code_memory:attachment:v1:" Raw;
    /// Named code-memory slot holding the live (possibly conflicting) values recorded against one
    /// code symbol. Key: id16 "\x00" string.
    CODE_MEMORY_SLOT: VaultMeta b"code_memory:slot:v1:" Raw;
    /// Idempotent receipt of a code-symbol anchor rename/copy transfer (from, to, observed_at, digest
    /// of the transfer identity). Key: id16 + id16 + u64be + hash32.
    CODE_MEMORY_TRANSFER: VaultMeta b"code_memory:transfer:v1:" Raw;
    /// Recorded code-revision fork/branch row. Key: id16.
    CODE_REVISION_FORK: VaultMeta b"code_revision:fork:v1:" Raw;
    /// Index of forks by parent session, empty marker value. Key: id16 + id16.
    CODE_REVISION_FORK_PARENT_INDEX: VaultMeta b"code_revision:fork_parent:v1:" Raw;
    /// A session's current revision-frontier record. Key: id16.
    CODE_REVISION_FRONTIER: VaultMeta b"code_revision:frontier:v1:" Raw;
    /// Cached integrity/hash-fold record for one revision. Key: id16.
    CODE_REVISION_INTEGRITY: VaultMeta b"code_revision:integrity:v1:" Raw;
    /// Index of child revisions by parent revision, empty marker value. Key: id16 + id16.
    CODE_REVISION_PARENT_INDEX: VaultMeta b"code_revision:parent:v1:" Raw;
    /// Immutable receipt of the file-mode-review proposal ids that promoted a revision. Key: id16.
    CODE_REVISION_PROMOTION: VaultMeta b"code_revision:promotion:v1:" LegacyCompact;
    /// Stranded/diverged revision proposal awaiting reconciliation with the head. Key: id16.
    CODE_REVISION_PROPOSAL: VaultMeta b"code_revision:proposal:v1:" Raw;
    /// Finalized code-revision row (hand-rolled MessagePack map). Key: id16.
    CODE_REVISION_RECORD: VaultMeta b"code_revision:record:v1:" Raw;
    /// Index of revisions belonging to a session, empty marker value. Key: id16 + id16.
    CODE_REVISION_SESSION_INDEX: VaultMeta b"code_revision:session:v1:" Raw;
    /// Node-local per-model wire-heal tally, keyed by validated model id. Key: string.
    CODE_RUN_HEAL_COUNT: VaultMeta b"code_run:heal_count:v1:" Raw;
    /// The taint refs beside one raw-output row, keyed by the same content handle, in the same
    /// transaction. Key: string.
    CODE_RUN_RAW_OUTPUT_TAINT: VaultMeta b"code_run:raw_output:taint:v1:" Raw;
    /// A code run's raw output bytes, keyed by their deterministic content handle. Key: string.
    CODE_RUN_RAW_OUTPUT: VaultMeta b"code_run:raw_output:v1:" Raw;
    /// A code run's replay record, keyed by run id. Key: id16.
    CODE_RUN_REPLAY: VaultMeta b"code_run:replay:v1:" Raw;
    /// Per-code-artifact code-symbol manifest row. Key: id16.
    CODE_SYMBOL_MANIFEST: VaultMeta b"code_symbol:manifest:v1:" Raw;
    /// Index of symbol revisions by repo/path/name/fingerprint, empty marker value. Key:
    /// string(repo_ref) "\x00" string(path) "\x00" string(name) "\x00" hash32(fingerprint) "\x00"
    /// id16.
    CODE_SYMBOL_REVISION_INDEX: VaultMeta b"code_symbol:revision:v1:" Raw;
    /// Cache-hit outcome record for one view's build/verify action, keyed by view id and action key.
    /// Key: id16 + bytes32 (view id then build action key).
    CODE_VIEW_BUILD: VaultMeta b"code_view:build:v1:" LegacyJson;
    /// A materialized per-agent code view's receipt: fork hash plus the per-file content-hash
    /// manifest, keyed by view id. Key: id16.
    CODE_VIEW_RECEIPT: VaultMeta b"code_view:receipt:v1:" Named;
    /// Per-codebase-snapshot custody report (encoded via rmp_serde::to_vec_named), keyed by the fork
    /// hash; the const and key builder live in secret_snapshot.rs but the actual put/get/delete call
    /// sites are in codebase/store.rs — flagged as a borderline cross-module row, report per "if
    /// unsure, report it". Key: hex64.
    SECRET_SNAPSHOT_CODEBASE_CUSTODY: VaultMeta b"codebase:custody:v1:" Raw;
    /// Index from a fork hash to the codebase snapshots sharing it. Key: bytes32(fork_hash) + "\x00"
    /// + id16.
    CODEBASE_FORK_INDEX: VaultMeta b"codebase:fork:v1:" Raw;
    /// Index from a project id to the codebase snapshots recorded against it. Key: string(project_id)
    /// + "\x00" + id16.
    CODEBASE_PROJECT_INDEX: VaultMeta b"codebase:project:v1:" Raw;
    /// Index from a repo reference to the codebase snapshots recorded against it. Key: bytes(repo_ref
    /// canonical text) + "\x00" + id16.
    CODEBASE_REPO_INDEX: VaultMeta b"codebase:repo:v1:" Raw;
    /// Index from a codebase scope key to the snapshot and asset entities visible under it. Key:
    /// bytes(scope_key) + "\x00" + id16.
    CODEBASE_SCOPE_INDEX: VaultMeta b"codebase:scope:v1:" Raw;
    /// A codebase snapshot's file manifest, keyed by the CODE_ARTIFACT entity id it snapshots. Key:
    /// id16.
    CODEBASE_SNAPSHOT: VaultMeta b"codebase:snapshot:v1:" Raw;
    /// Monotonic little-endian sequence counter stamped onto comm event/gate/receipt records. Key:
    /// ().
    COMM_EVENT_SEQUENCE: VaultMeta b"comm.event_sequence.v1" Raw;
    /// Node-local shortcut cache mapping a hashed party key to the canonical comm-owned PERSON id
    /// that synced truth currently names for it; repaired from synced truth on a stale or missing
    /// hit. Key: bytes32 (sha256 of party_key).
    COMM_PARTY_INDEX: VaultMeta b"comm.party.v1:" Raw;
    /// Time-ordered commitment due-index row. Key: u64be + u8 + id16 + id16.
    COMMITMENT_DUE_PRIMARY: VaultMeta b"commitment_due:v1:" Raw;
    /// Instance and phase to primary due-row key. Key: id16 + u8.
    COMMITMENT_DUE_REVERSE: VaultMeta b"commitment_due_rev:v1:" Raw;
    /// Series-membership history. Key: id16 + u64be + u64be + u32be + id16.
    COMMITMENT_SERIES_INSTANCE: VaultMeta b"commitment_series_instance:v1:" Raw;
    /// Pending Project due row of a series. Key: id16.
    COMMITMENT_SERIES_PROJECT: VaultMeta b"commitment_series_project:v1:" Raw;
    /// Typed per-tool grant slate draft plus any authenticated-owner overrides. Key: id16.
    CONNECTOR_GRANT_SLATE: VaultMeta b"connector.grant_slate.v1/" LegacyJson;
    /// Idempotent wake-decision record for one connector-event subscription match. Key: hash32.
    CONNECTOR_WAKE_DECISION: VaultMeta b"connector.wake.v1:" LegacyJson;
    /// Permanent catalog-name to key-id index; never deleted on key removal. Key: string(catalog
    /// name).
    CONNECTOR_CATALOG_NAME_INDEX: VaultMeta b"connector_catalog/name/v1\0" Raw;
    /// Lookup index from a normalized connector name to a key id, empty marker value. Key:
    /// string(connector) "\x00" id16.
    CONNECTOR_KEY_CONNECTOR_INDEX: VaultMeta b"connector_key/connector/v1\0" Raw;
    /// Rotation-generation log entry naming the custody ref a connector key pointed at. Key: id16 +
    /// u32be.
    CONNECTOR_KEY_GENERATION_LOG: VaultMeta b"connector_key/generation/v1\0" Raw;
    /// Logical-send admission evidence row proving one exactly-once Sends debit. Key: id16 +
    /// string(logical_send_ref).
    CONNECTOR_KEY_SEND_ADMIT: VaultMeta b"connector_key/send_admit/v1\0" Raw;
    /// Spend-settlement idempotency row for one settlement event id. Key: id16 + string(event_ref).
    CONNECTOR_KEY_SETTLE_EVENT: VaultMeta b"connector_key/settle_event/v1\0" Raw;
    /// Live per-row budget usage counters for a connector key (key rows and compiled-charter cap
    /// rows). Key: id16 + u16be.
    CONNECTOR_KEY_USAGE: VaultMeta b"connector_key/usage/v1\0" Raw;
    /// Standing consent grant. Key: hex64.
    CONSENT_STANDING_GRANT: VaultMeta b"consent.grant.v1:" Raw;
    /// Approve-once marker. Key: bytes32.
    CONSENT_APPROVE_ONCE_MARKER: VaultMeta b"consent.once.v1:" Raw;
    /// Parked authority-widening request. Key: hex64.
    CONSENT_WIDEN_PROPOSAL: VaultMeta b"consent.widen.v1:" LegacyJson;
    /// Marker for a ruled conflict packet. Key: bytes32.
    CLAIM_CONFLICT_RESOLUTION: VaultMeta b"consent_bundle.claim_conflict.resolved.v1:" Raw;
    /// Content-addressed claim-conflict review packet. Key: bytes32.
    CLAIM_CONFLICT_PACKET: VaultMeta b"consent_bundle.claim_conflict.v1:" LegacyJson;
    /// Vault-local content-addressed store of a recoverable full tool/agent output blob. Key: hash32.
    COMPACTION_OUTPUT_BLOB: VaultMeta b"context:output:v1:" Raw;
    /// Immutable derived text summary of one output, keyed by source content hash and summarization-
    /// recipe hash. Key: hash32 + hash32.
    COMPACTION_OUTPUT_SUMMARY: VaultMeta b"context:summary:v1:" Raw;
    /// One actor-private versioned board block (actor, section-name length+bytes, block ref) appended
    /// under an admitted plugin section. Key: id16 + u64be + string + id16.
    CONTEXT_BOARD_PLUGIN_BLOCK: VaultMeta b"context_board.block.v1:" LegacyJson;
    /// Immutable recorded contract baseline snapshot (public API names, schemas, command outputs),
    /// keyed by its own content digest; a differing value under the same id is corruption. Key:
    /// hex64.
    CONTRACT_ORACLE_BASELINE: VaultMeta b"contract_oracle:baseline:v1:" Named;
    /// Immutable recorded verdict comparing a candidate snapshot against a recorded baseline (diffs
    /// plus test-pass state), keyed by its own content digest. Key: hex64.
    CONTRACT_ORACLE_VERDICT: VaultMeta b"contract_oracle:verdict:v1:" Named;
    /// Transient in-txn permit binding a legacy ChildOf-append record id to the conversation it may
    /// append to. Key: id16.
    CONVERSATION_DAG_APPEND_PERMIT: VaultMeta b"conversation_dag:append_in_txn:v1:" Raw;
    /// Append-only pin of a DAG record's body hash (kind, occurred range, body) so a replay cannot
    /// rewrite an existing record's content. Key: id16.
    CONVERSATION_DAG_BODY_PIN: VaultMeta b"conversation_dag:body_pin:" Raw;
    /// Per-record pointer marking a DAG record canonical (points to its successor), or absent for
    /// terminal. Key: id16.
    CONVERSATION_DAG_CANONICAL: VaultMeta b"conversation_dag:canonical:v1:" Raw;
    /// Per-conversation pointer to the current local-head DAG record id. Key: id16.
    CONVERSATION_DAG_LOCAL_HEAD: VaultMeta b"conversation_dag:local_head:v1:" Raw;
    /// Single-byte [1] marker that a conversation has adopted the DAG record model. Key: id16.
    CONVERSATION_DAG_MIGRATED: VaultMeta b"conversation_dag:migrated:v1:" Raw;
    /// Row count / next-sequence counter (u64be) for a conversation's membership ledger. Key: id16.
    CONVERSATION_MEMBERSHIP_SEQ: VaultMeta b"conversation_membership:seq:v1:" Raw;
    /// One append-only membership-ledger event (join/leave/history-visibility change) for a
    /// conversation, keyed by conversation then sequence. Key: id16 + u64be.
    CONVERSATION_MEMBERSHIP_ROW: VaultMeta b"conversation_membership:v1:" Named;
    /// Deduplicated set of contact refs reachable for a (party, channel class) pair. Key:
    /// hash32(sha256).
    COUNTERPARTY_CONTACT_PARTY_CHANNEL_INDEX: VaultMeta b"counterparty.contact.party_channel.v1:" Raw;
    /// Lookup index from (identity ref, normalized counterparty) to the contact entity id. Key: id16
    /// + hash32(sha256).
    COUNTERPARTY_CONTACT_INDEX: VaultMeta b"counterparty_contact.index.v1:" Raw;
}
