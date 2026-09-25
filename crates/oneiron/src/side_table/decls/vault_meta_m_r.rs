// Declared `vault_meta` tables whose prefix starts with `m` to `r`, in prefix order.

side_tables! {
    VAULT_META_M_R;
    /// Engine-stamped monotonic causality sequence for identity-topology ledger events. Key: ().
    IDENTITY_TOPOLOGY_SEQ: VaultMeta b"m:identity_topology_seq" Raw;
    /// Conservative marker that a zero-head split has ever been recorded, gating an expensive ledger
    /// fold. Key: ().
    IDENTITY_TOPOLOGY_ZERO_HEAD_SEEN: VaultMeta b"m:identity_topology_zero_head_seen" Raw;
    /// Idle publication delay. Key: ().
    ENTITY_TEXT_INDEXED_IDLE_DELAY_MS: VaultMeta b"manifest:entity_text:indexed_idle_delay_ms" Raw;
    /// One merge batch's proposals, worktree paths, and lifecycle state. Key: hex(repo identity) ":"
    /// hex64(batch id).
    MERGE_QUEUE_BATCH: VaultMeta b"merge_queue:batch:v1:" Named;
    /// Repo-scoped merge-queue pointers, workspace graph, and in-flight intent state. Key: hex(repo
    /// identity).
    MERGE_QUEUE_STATE: VaultMeta b"merge_queue:state:v1:" Named;
    /// In-flight streamed message recovery seed. Key: id16.
    MESSAGE_STREAM_ACTIVE: VaultMeta b"message_stream:v1:" Named;
    /// Vault default message-streaming policy. Key: ().
    MESSAGE_STREAM_POLICY: VaultMeta b"message_stream_policy:v1" Named;
    /// Latest terminal stream receipt of a message. Key: id16.
    MESSAGE_STREAM_RECEIPT: VaultMeta b"message_stream_receipt:v1:" Named;
    /// Named entity secondary index. Key: byte + (u64be|id16) + id16.
    PORTS_NAMED_ENTITY_INDEX: VaultMeta b"named_entity:v1:" Raw;
    /// Saved oplog version-vector floor an authority rebase cannot cross past a scrub. Key:
    /// hex32(id).
    NOTE_ERASE_AUTHORITY_FLOOR: VaultMeta b"note.erase/authority-floor/" Raw;
    /// Fence marking a citing document's dependency on an erased source until scrubbed. Key:
    /// hex32(citing) ":" hex32(erased source).
    NOTE_ERASE_PENDING: VaultMeta b"note.erase/pending/" Raw;
    /// Marker that a NOTE/CLAIM source has been citation-erased. Key: hex32(id).
    NOTE_ERASE_SOURCE: VaultMeta b"note.erase/source/" Raw;
    /// The one blessed, person-stamped brief-kind policy contract. Key: ().
    NOTE_BRIEF_KIND_CONTRACT: VaultMeta b"note.kind/brief/v1" LegacyJson;
    /// Reverse citation-pin index keyed by the citing document; value points at NOTE_PIN_SOURCE's
    /// key. Key: hex32(citing) ":" hex32(document) ":" hex64(hash).
    NOTE_PIN_CITING: VaultMeta b"note.pin/citing/" Raw;
    /// Reverse citation-pin index keyed by the cited claim; value points at NOTE_PIN_SOURCE's key.
    /// Key: hex32(claim) ":" hex32(citing) ":" hex64(hash).
    NOTE_PIN_CLAIM: VaultMeta b"note.pin/claim/" Raw;
    /// Pending (pre-admission) citation-request dependency, keyed by the citing document. Key:
    /// hex32(citing) ":" hex32(request).
    NOTE_PIN_REQUEST_CITING: VaultMeta b"note.pin/request/citing/" LegacyJson;
    /// Pending citation-request index keyed by the cited claim. Key: hex32(claim) ":" hex32(citing)
    /// ":" hex32(request).
    NOTE_PIN_REQUEST_CLAIM: VaultMeta b"note.pin/request/claim/" Raw;
    /// Pending citation-request index keyed by the cited source document. Key: hex32(document) ":"
    /// hex32(citing) ":" hex32(request).
    NOTE_PIN_REQUEST_SOURCE: VaultMeta b"note.pin/request/source/" Raw;
    /// Reverse citation-pin row keyed by the cited source document. Key: hex32(document) ":"
    /// hex32(citing) ":" hex64(hash).
    NOTE_PIN_SOURCE: VaultMeta b"note.pin/source/" LegacyJson;
    /// Recorded NOTE fork awaiting review/decision. Key: id16(fork head).
    NOTE_FORK: VaultMeta b"note_fork:v1:" Named;
    /// A NOTE's current head document id and head-move sequence number. Key: id16.
    NOTE_HEAD: VaultMeta b"note_head:v1:" Raw;
    /// Marker: one row per head document a NOTE's text plane ever held (for erasure completeness).
    /// Key: id16 + id16.
    NOTE_HEAD_DOC: VaultMeta b"note_head_doc:v1:" Raw;
    /// PACK-registered NOTE kind descriptor (extraction/context/retention defaults). Key:
    /// string(kind).
    NOTE_KIND: VaultMeta b"note_kind:v1:" Named;
    /// Review bundle grouping several fork proposals under one shared explainer. Key: id16(bundle
    /// id).
    NOTE_PROPOSAL_BUNDLE: VaultMeta b"note_proposal:v1:" Named;
    /// Durable head-move (merge/switch/reject) receipt. Key: id16(receipt id).
    NOTE_RECEIPT: VaultMeta b"note_receipt:v1:" Named;
    /// Durable retry receipt recording the outcome of promoting one off-record turn into base
    /// storage. Key: id16.
    OFF_RECORD_PROMOTE_RECEIPT: VaultMeta b"offrecord_promote:v0:" Named;
    /// Immutable one-time organization-administration power grant (admins and their allowed powers).
    /// Key: hex32 (org_ref).
    ORG_ADMIN_POLICY: VaultMeta b"org.admin.v1." LegacyJson;
    /// Owner-controlled origin residence/epoch/writer authority for one repository. Key: id16.
    ORIGIN_AUTHORITY: VaultMeta b"origin:authority:v1:" Named;
    /// Epoch-bound publication permit stamp (u64be epoch), authorizing one publication under the
    /// current authority epoch. Key: id16.
    ORIGIN_AUTHORITY_PERMIT: VaultMeta b"origin:authority_permit:v1:" Raw;
    /// Compare-and-swap ownership claim binding one (repo, ref, old_oid, new_oid) triple to its
    /// owning publication id (value = id16). Key: id16 "\x00" string "\x00" string "\x00" string.
    ORIGIN_CAS_INTENT: VaultMeta b"origin:cas_intent:v1:" Raw;
    /// Tamper-detection proof hash (32 bytes) pinning one repo.change claim's exact byte content at
    /// publication time. Key: id16.
    ORIGIN_CHANGE_RECEIPT: VaultMeta b"origin:change_receipt:v1:" Raw;
    /// Crash-idempotent receipt of the file operations one push landed against one ref, keyed by
    /// provenance then blake3(ref_name). Key: id16 ":" hash32.
    ORIGIN_CODE_OPERATIONS: VaultMeta b"origin:code_operations:v1:" LegacyCompact;
    /// Stable Git commit projection (oid hex text) of one finalized engine CodeRevision. Key: string
    /// ":" id16.
    ORIGIN_ENGINE_EXPORT: VaultMeta b"origin:engine_export:v1:" Raw;
    /// One logical owner's reservation of a physical git keep-ref (value = u64be learned_at),
    /// reference-counting when the object may be released. Key: id16 "\x00" string "\x00" string
    /// "\x00" string.
    ORIGIN_KEEP_OWNER: VaultMeta b"origin:keep_owner:v1:" Raw;
    /// Per-vault random FastCDC boundary-randomization seed (u64 LE). Key: ().
    ORIGIN_LFS_CDC_SEED: VaultMeta b"origin:lfs:cdc:v1" Raw;
    /// Forward index (empty marker): which owners still reference one chunk hash. Key: hash32 + id16.
    ORIGIN_LFS_CHUNK_REF: VaultMeta b"origin:lfs:chunk-ref:v1:" Raw;
    /// Marks an ASSET entity as an internal LFS chunk and records its content hash (32 bytes). Key:
    /// id16.
    ORIGIN_LFS_CHUNK_MARK: VaultMeta b"origin:lfs:chunk:v1:" Raw;
    /// Permanent tombstone (empty marker) for one deleted LFS object id, blocking resurrection. Key:
    /// hash32.
    ORIGIN_LFS_DELETED: VaultMeta b"origin:lfs:deleted:v1:" Raw;
    /// Queue (empty marker) of upload owners whose chunk references are pending garbage collection.
    /// Key: id16.
    ORIGIN_LFS_GC_QUEUE: VaultMeta b"origin:lfs:gc:v1:" Raw;
    /// Reverse pointer (32-byte oid) from an LFS manifest ASSET back to its object id. Key: id16.
    ORIGIN_LFS_MANIFEST_REVERSE: VaultMeta b"origin:lfs:manifest:v1:" Raw;
    /// Durable LFS object record: asset id, size, created time, ref owner (48 raw bytes). Key:
    /// hash32.
    ORIGIN_LFS_OBJECT: VaultMeta b"origin:lfs:object:v1:" Raw;
    /// Reverse index (empty marker): which chunk hashes one upload-journal owner references, for
    /// garbage collection. Key: id16 + hash32.
    ORIGIN_LFS_OWNER_REF: VaultMeta b"origin:lfs:owner-ref:v1:" Raw;
    /// Attaches one LFS object id to one git ref in one repository (value = learned_at u64 LE). Key:
    /// id16 "\x00" string "\x00" hash32.
    ORIGIN_LFS_REF: VaultMeta b"origin:lfs:ref:v1:" Raw;
    /// Crash-recoverable heartbeat journal (oid32+timestamp8, 40 bytes) for one in-progress streamed
    /// LFS upload. Key: id16.
    ORIGIN_LFS_UPLOAD_JOURNAL: VaultMeta b"origin:lfs:upload:v1:" Raw;
    /// Durable journal row for one origin ref-publication attempt, across its
    /// Prepared/Published/Failed/Conflicted lifecycle. Key: id16.
    ORIGIN_PUBLICATION_RECORD: VaultMeta b"origin:publication:v1:" Named;
    /// Producer receipt pinning the exact encoded admission/outcome evidence claim body for one
    /// receive-pack operation. Key: id16.
    ORIGIN_RECEIVE_PACK_EVIDENCE: VaultMeta b"origin:receive_pack_evidence:v1:" Raw;
    /// Crash-durable per-push intent journal recording every proposed ref move before any effect
    /// lands, keyed by repo identity then operation id. Key: string + id16.
    ORIGIN_RECEIVE_PACK_INTENT: VaultMeta b"origin:receive_pack_intent:v1:" Named;
    /// The publication currently advertised for one repository's ref name (value = id16). Key: id16
    /// "\x00" string.
    ORIGIN_VISIBLE_REF: VaultMeta b"origin:visible_ref:v1:" Raw;
    /// Best-effort de-duplication lease for one authorized-outbound recovery sweep. Key: ().
    OUTBOUND_AUTHORIZED_RECOVERY_LEASE: VaultMeta b"outbound:authorized_recovery_lease:v1" Raw;
    /// Unique index from one logical dispatch call to its immutable intent id. Key: id16(attempt) +
    /// u64be(call seq).
    OUTBOUND_INTENT_ATTEMPT_INDEX: VaultMeta b"outbound:intent_attempt:v1:" Raw;
    /// Format-version marker gating the attempt index; a non-empty unindexed ledger fails closed.
    /// Key: ().
    OUTBOUND_INTENT_ATTEMPT_FORMAT: VaultMeta b"outbound:intent_attempt_format" Raw;
    /// Durable outbound-send intent ledger row: state machine, endpoint binding, and accounting. Key:
    /// hash32.
    OUTBOUND_INTENT_LEDGER_RECORD: VaultMeta b"outbound:intent_ledger:v2:" Raw;
    /// Gate outcome of a scheduled outbound attempt's first dispatch. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice): `store::outbound_send_receipt`
    /// only ever relays a caller-encoded `&[u8]` (the encoder is
    /// `crate::memory::outbound::dedupe`'s `serde_json::to_vec`, outside this
    /// table's owning module); binding it `LegacyJson` here would re-encode
    /// already-encoded bytes on every write.
    OUTBOUND_GATE_BINDING: VaultMeta b"outbound_gate_binding:v0:" Raw;
    /// Index from a principal reference to every standing outbound grant naming it. Key: u16be(len) +
    /// string(principal_ref) + id16.
    OUTBOUND_GRANT_PRINCIPAL_INDEX: VaultMeta b"outbound_grant/principal/v1\0" Raw;
    /// Per-envelope usage/rate-window accounting shared by every standing grant naming that envelope.
    /// Key: bytes (channel-identity envelope ref).
    OUTBOUND_GRANT_CHANNEL_IDENTITY_USAGE: VaultMeta b"outbound_grant:channel_identity_usage:v1:" Raw;
    /// Installed knowledge-pack receipt, keyed by pack name. Key: string.
    SKILL_HUB_PACK_INSTALL: VaultMeta b"pack.install.v1/" LegacyJson;
    /// Index from a claim predicate name to the pack name that owns it (exclusivity check). Key:
    /// string.
    SKILL_HUB_PACK_PREDICATE: VaultMeta b"pack.predicate.v1/" Raw;
    /// Local-only content-hash pin (32 bytes) to the currently installed pack-byte-map carrier ASSET;
    /// never synced or imported. Key: ().
    PACK_BYTE_MAP_LOCAL_HEAD: VaultMeta b"pack_byte_map:local_head:v1" Raw;
    /// A device-local held policy-classification item pending human moderation. Key: hex64 (blake3
    /// hash of caller/row/content-hash/frontier-hash).
    POLICY_HOLD_QUEUE: VaultMeta b"policy-hold:v1:" LegacyJson;
    /// Change-log record. Key: id16.
    PORTS_CHANGE: VaultMeta b"ports:change:v1:" Named;
    /// Change-log by actor index. Key: id16 + u64be + id16.
    PORTS_CHANGE_BY_ACTOR: VaultMeta b"ports:change_actor:v1:" Raw;
    /// Change-log by entity index. Key: id16 + u64be + id16.
    PORTS_CHANGE_BY_ENTITY: VaultMeta b"ports:change_entity:v1:" Raw;
    /// Recorded-at clock floor. Key: ().
    PORTS_CLOCK_FLOOR: VaultMeta b"ports:clock_floor:v1" Raw;
    /// Derived entity dependency. Key: id16 + u64be + id16.
    PORTS_DEPENDENCY: VaultMeta b"ports:dependency:v1:" Raw;
    /// Reverse dependency index. Key: id16 + id16 + u64be.
    PORTS_DEPENDENCY_REVERSE: VaultMeta b"ports:dependency_reverse:v1:" Raw;
    /// Local id allocator floor. Key: ().
    PORTS_ID_FLOOR: VaultMeta b"ports:id_floor:v1" Raw;
    /// Stale derived entity marker. Key: id16.
    PORTS_STALE: VaultMeta b"ports:stale:v1:" Raw;
    /// Deletion-intent tombstone. Key: id16.
    PORTS_TOMBSTONE: VaultMeta b"ports:tombstone:v1:" Raw;
    /// Community snapshot rows: meta, node:hex32, members:hex32. Key: string.
    PPR_COMMUNITY_CACHE: VaultMeta b"ppr_community_cache:v0:" Raw;
    /// Change-log event recording a project's home-room membership transition. Key: id16 (project) +
    /// id16 (change event id).
    PROJECT_ROOM_CHANGES: VaultMeta b"project.room_changes.v1/" Named;
    /// Index from a project's derived home room back to the project that owns it. Key: id16 (derived
    /// home-room id).
    PROJECT_ROOM_OWNER: VaultMeta b"project.room_owner.v1/" Raw;
    /// The root project's entity id, seeded once at first boot. Key: ().
    PROJECT_ROOT: VaultMeta b"project.root.v1" Raw;
    /// Disposable cache: which PERSON actor currently represents one provider key. Key: bytes32
    /// (sha256 of provider key).
    PROVIDER_ACTOR_INDEX: VaultMeta b"provider_confidence/actor/v1\0" Raw;
    /// Disposable cache: the newest active actor.confidence_prior claim id for one provider key. Key:
    /// bytes32 (sha256 of provider key).
    PROVIDER_PRIOR_HEAD_INDEX: VaultMeta b"provider_confidence/prior_head/v1\0" Raw;
    /// Scope self-demotion log. Key: u64be + id16.
    RAMP_DEMOTION: VaultMeta b"ramp_demote:v1:" Named;
    /// Clean-streak floor override. Key: id16.
    RAMP_FLOOR: VaultMeta b"ramp_floor:v1:" Raw;
    /// Door-recorded ruling log. Key: u64be + id16.
    RAMP_OUTCOME: VaultMeta b"ramp_outcome:v1:" Named;
    /// Per-scope outcome statistics. Key: id16.
    RAMP_STATS: VaultMeta b"ramp_stats:v1:" Named;
    /// Split/facet claim-reassignment row keyed by the origin entity, event, and claim; the only
    /// record of a SPLIT assignment. Key: id16 (origin) + id16 (event) + id16 (claim).
    REASSIGNMENT_ORIGIN: VaultMeta b"reassign:v1:o:" Raw;
    /// Same reassignment inverted by destination head, so claims_assigned_to can prefix-scan by head
    /// instead of origin. Key: id16 (target head) + id16 (event) + id16 (claim).
    REASSIGNMENT_TARGET: VaultMeta b"reassign:v1:t:" Raw;
    /// Binds one archived receipt-source ASSET to the inert holder CLAIM it documents. Key: id16
    /// (archive source id).
    RECEIPT_ARCHIVE_BINDING: VaultMeta b"receipt/archive-binding/v1\0" Raw;
    /// Marks a holder CLAIM whose archived receipt-source closure has been retired (and its payload
    /// erased). Key: id16.
    RECEIPT_ARCHIVE_HOLDER_RETIRED: VaultMeta b"receipt/archive-holder-retired/v1\0" Raw;
    /// Index of archived receipt-source ids currently owned by one holder claim. Key: id16 (holder) +
    /// id16 (source).
    RECEIPT_ARCHIVE_OWNED: VaultMeta b"receipt/archive-owned/v1\0" Raw;
    /// Dedupe slot: which archived receipt-source id currently occupies one (holder, body hash,
    /// receipt id) triple. Key: id16 (holder) + hex64 (body sha256, as text) + string (receipt id).
    RECEIPT_ARCHIVE_SLOT: VaultMeta b"receipt/archive-slot/v1\0" Raw;
    /// Marks one archived receipt-source ASSET id as retired (payload erased or never delivered).
    /// Key: id16.
    RECEIPT_ARCHIVE_SOURCE_RETIRED: VaultMeta b"receipt/archive-source-retired/v1\0" Raw;
    /// Receipt-family index backfill marker. Key: ().
    RECEIPT_FAMILY_INDEX_VERSION: VaultMeta b"receipt_family_index:v1:version" Raw;
    /// Rebuildable projection row: the head set a merged/split identity shell currently resolves to.
    /// Key: id16 (shell id).
    IDENTITY_REDIRECT: VaultMeta b"redirect:v1:" Raw;
    /// Repo-conflict claim to reconciliation task. Key: id16.
    REPO_CONFLICT_RECONCILIATION_INDEX: VaultMeta b"repo_conflict:reconciliation:v1:" Raw;
    /// Durable per-operation oplog entry (prepared/committed/failed mutation record), keyed by (repo
    /// key hash, seq as 16 lowercase hex chars). Key: hex64 ":" hex16.
    REPO_MUTATION_OPLOG: VaultMeta b"repo_mutation:oplog:v1:" Named;
    /// Durable per-operation code proposal (file change plus critic evidence), keyed by proposal
    /// claim id. Key: id16.
    REPO_MUTATION_PROPOSAL: VaultMeta b"repo_mutation:proposal:v1:" Named;
    /// Pointer from one repo's (repo key hash, oplog seq) to the proposal id it is bound to. Key:
    /// hex64 ":" u64be.
    REPO_MUTATION_PROPOSAL_OP: VaultMeta b"repo_mutation:proposal_op:v1:" Raw;
    /// Reviewed-stack batch state for one repo identity/batch pair. Key: string ":" string.
    REPO_MUTATION_REVIEWED_STACK: VaultMeta b"repo_mutation:reviewed_stack:v1:" Named;
    /// Monotonic oplog sequence counter for one repo, keyed by a hash of its canonical repo key. Key:
    /// hex64.
    REPO_MUTATION_SEQ: VaultMeta b"repo_mutation:seq:v1:" Raw;
    /// Captured pre-action repo-tree snapshot, keyed by its fork hash. Key: hex64.
    REPO_MUTATION_SNAPSHOT: VaultMeta b"repo_mutation:snapshot:v1:" Named;
    /// Log of checkpoint restore/wake/migrate events, one row per epoch. Key: u64be(sequence).
    RESTORE_EPOCH: VaultMeta b"restore:epoch:v1:" Named;
    /// Active reward-tuned blend weights. Key: ().
    ///
    /// Codec fixed to `Raw` (T47 store slice): decode also enforces the
    /// version/provenance shape and re-normalizes the weights, business
    /// checks `Named`'s generic strict-msgpack decode does not run;
    /// `RawValue` delegates to the module's own
    /// `encode_retrieval_blend_weight_table`/`decode_retrieval_blend_weight_table`.
    RETRIEVAL_BLEND_WEIGHTS_ACTIVE: VaultMeta b"retr_blend_weights:v0:active" Raw;
    /// Reported retrieval run outcome. Key: id16 ":" string.
    ///
    /// Codec fixed to `Raw` (T47 store slice): decode must also enforce
    /// `RETRIEVAL_TELEMETRY_VERSION`, a business check `Named`'s generic
    /// strict-msgpack decode does not run; `RawValue` delegates to the
    /// module's own `encode_retrieval_outcome`/`decode_retrieval_outcome`.
    RETRIEVAL_OUTCOME: VaultMeta b"retr_out:v0:" Raw;
    /// Retrieval run telemetry record. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice), for the same reason as
    /// [`RETRIEVAL_OUTCOME`]: decode also enforces the version byte and
    /// `RetrievalState::validate`, so `RawValue` delegates to the existing
    /// `encode_retrieval_run`/`decode_retrieval_run` (kept, and still relied
    /// on directly by `retrieval_telemetry::state_tests`).
    RETRIEVAL_RUN: VaultMeta b"retr_run:v0:" Raw;
    /// Unpublished context-pack retrieval run. Key: id16.
    RETRIEVAL_RUN_PROVISIONAL: VaultMeta b"retr_run_prov:v0:" Raw;
    /// Trace fork hash to runs. Key: bytes32 + id16.
    RETRIEVAL_TRACE_FORK_INDEX: VaultMeta b"retr_trace_fork:v0:" Raw;
    /// Retrieval runs by turn. Key: id16 + u64be + id16.
    RETRIEVAL_TURN_INDEX: VaultMeta b"retr_turn:v1:" Raw;
    /// Blake3 stamp of a written claim body, used to detect a review verdict claim edited outside its
    /// producer. Key: id16.
    CRITIC_REVIEW_CLAIM_TRUST: VaultMeta b"review:claim:v1:" Raw;
    /// Cached review verdict/triage/artifacts for a review request, keyed by a hash of the request's
    /// identity tuple. Key: hash32.
    CRITIC_REVIEW_RESULT: VaultMeta b"review:result:v1:" Named;
    /// Index from a review verdict claim id back to its CRITIC_REVIEW_RESULT row key. Key: id16.
    CRITIC_REVIEW_RESULT_ID: VaultMeta b"review:result_id:v1:" Raw;
    /// Claim-before-speaking receipt naming which actor may respond to one addressed turn. Key: id16
    /// (turn id).
    ROOMS_CLAIM: VaultMeta b"rooms.claim.v1/" LegacyJson;
    /// Chronological index of non-branch (thread-root) turns, walked in reverse for the canonical
    /// room head. Key: id16 (room) + u64be (at) + id16 (turn).
    ROOMS_HEADS: VaultMeta b"rooms.heads.v1/" Raw;
    /// Chronological index of every turn in a room, walked for paged message history. Key: id16
    /// (room) + u64be (at) + id16 (turn).
    ROOMS_HISTORY: VaultMeta b"rooms.history.v1/" Raw;
    /// Maps a host-configured platform handle to the one present actor it addresses within a room.
    /// Key: id16 (room id) + bytes (platform handle).
    ROOMS_HANDLE: VaultMeta b"rooms.platform_handle.v1/" Raw;
    /// Single-response-per-claim guard: which turn already answered one claimed parent turn. Key:
    /// id16 (parent turn id).
    ROOMS_RESPONSE: VaultMeta b"rooms.response.v1/" Raw;
    /// One addressed room turn (actor, addressed agents, message ids, reply/thread links). Key: id16
    /// (turn id).
    ROOMS_TURN: VaultMeta b"rooms.turn.v1/" LegacyJson;
}
