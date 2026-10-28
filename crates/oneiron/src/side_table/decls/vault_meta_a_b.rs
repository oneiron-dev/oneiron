// Declared `vault_meta` tables whose prefix starts with `a` or `b`, in prefix order.

side_tables! {
    VAULT_META_A_B;
    /// A pending cross-relationship access request awaiting the owner's approve/deny decision. Key:
    /// id16.
    ACCESS_REQUEST: VaultMeta b"access-request:v1:" LegacyJson;
    /// Durable SessionEnd distill job for one ended sitting, queued in the same transaction that
    /// closes it and cleared once distilled. Key: id16.
    ACTOR_CLAIMS_DISTILL_PENDING_JOB: VaultMeta b"actor_claims:distill_pending:v1:" Raw;
    /// Rotation cursor (last session id served) for the bounded session-end distill drain pump, so
    /// one budget-limited pass cannot starve later jobs. Key: ().
    ACTOR_CLAIMS_DISTILL_RUNNER_CURSOR: VaultMeta b"actor_claims:distill_runner_cursor:v1" Raw;
    /// Named typed calls' durable queued/held status and terminal outcome, keyed by
    /// hash32(actor, class, invocation); never execution authority.
    ADMISSION_INTENT: VaultMeta b"admission:intent:v1:" Named Engine;
    /// Per-agent, per-unit launch spend calibration folded from settled launches. Key: string.
    AGENT_DISPATCH_SPEND_CALIBRATION: VaultMeta b"agent.dispatch.calibration.v1\0" LegacyJson;
    /// FIX 1380: one running child's comm widening, its per-reach asks to its parent and the
    /// reach the parent approved. Key: id16.
    AGENT_DISPATCH_COMM_WIDEN: VaultMeta b"agent.dispatch.comm.v1\0" Named Engine
        => crate::agent_dispatch::erase_comm_widen_actor_in_txn;
    /// Resumable partial-result hold for one gracefully stopped spawn (OF-541). Key: id16.
    AGENT_DISPATCH_PLAN_HOLD: VaultMeta b"agent.dispatch.hold.v1\0" LegacyJson;
    /// FIX 3694: the owner's applied prompt continuation of one failed agent attempt: the card,
    /// ask and diagnostic it answered, the approving owner and when, the approval's fingerprint
    /// and id, and the successor attempt it enqueued. Key: id16(failed attempt).
    AGENT_DISPATCH_PROMPT_INJECT: VaultMeta b"agent.dispatch.prompt_inject.v1\0" Named Engine;
    /// OF-544: the confession objectives one claimed agent run was asked, chosen at its first
    /// claim and read back at every later one (a continued run inherits its predecessor's). Key:
    /// id16(attempt).
    AGENT_DISPATCH_RUN_OBJECTIVES: VaultMeta b"agent.dispatch.run_objectives.v1\0" Named Engine;
    /// Approved board-widened context slice override recorded for one parent attempt. Key: id16.
    AGENT_DISPATCH_WIDEN_SLICE: VaultMeta b"agent.dispatch.slice.v1\0" LegacyJson Authored;
    /// One node of a launch's spend lease tree (root launch or child attempt). Key: string.
    AGENT_DISPATCH_SPEND_SCOPE: VaultMeta b"agent.dispatch.spend.v1\0" LegacyJson;
    /// Pending context-widen proposal record, keyed by a hash of the dedupe key or full intent. Key:
    /// hash32.
    AGENT_DISPATCH_WIDEN_INTENT: VaultMeta b"agent.dispatch.widen.v1\0" LegacyJson Authored
        [refs: WIDEN_INTENT_REFS];
    /// Index from a widen proposal's public content-hash id to its intent row key. Key: hex64.
    AGENT_DISPATCH_WIDEN_PROPOSAL_INDEX: VaultMeta b"agent.dispatch.widen_id.v1\0" Raw;
    /// Dedupe index from a caller-supplied dedupe key to the workflow root attempt id. Key: hash32.
    AGENT_WORKFLOW_DEDUPE: VaultMeta b"agent.workflow.dedupe.v1\0" Raw;
    /// Durable saved-composition record for one inert multi-step workflow wrapper attempt. Key: id16.
    AGENT_WORKFLOW_RECORD: VaultMeta b"agent.workflow.record.v1\0" LegacyJson Authored
        [refs: WORKFLOW_RECORD_REFS];
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
    /// What an agent id answers to on every later put, across a delete: the widest ceiling a
    /// row at the id may hold (one byte, 0 proposed, 1 auto), then the 16-byte parent row it was
    /// born forked from, if any. Key: id16.
    AGENT_DEF_ID_PIN: VaultMeta b"agent_def/id-pin/v1\0" Raw;
    /// Frozen source-tree identity (source id + skill content hash, 48 raw bytes) recorded at an
    /// agent's genuine local birth. Key: id16.
    AGENT_DEF_PORTABLE_BIRTH: VaultMeta b"agent_def/portable-birth/v1\0" Raw;
    /// FIX 4472: the model an agent's last wake ran on, so a wake on another model notes it in
    /// the agent's own diary. Key: id16(agent).
    AGENT_DEF_WAKE_MODEL: VaultMeta b"agent_def/wake-model/v1\0" Named;
    /// Pre-1890 reserved-actor census row, deleted with the census it served; not written by current
    /// code, only deleted once on seed. Key: ().
    AGENT_DEF_DEFAULT_RESERVED_ACTOR_CENSUS_V1: VaultMeta b"agent_def:default_reserved_actor_census:v1" Raw;
    /// Pre-1890 reserved-actor census row, deleted with the census it served; not written by current
    /// code, only deleted once on seed. Key: ().
    AGENT_DEF_RESERVED_ACTOR_CENSUS_V2: VaultMeta b"agent_def:reserved_actor_census:v2" Raw;
    /// Legacy pre-1890 per-vault system-agent enable toggle (single byte 0x00/0x01), consumed once
    /// and deleted by the manifest seeder. Key: string.
    AGENT_DEF_SYSTEM_TOGGLE_LEGACY: VaultMeta b"agent_def:system_toggle:v1:" Raw;
    /// The anchor a thread held before one re-anchor sweep moved it onto a version, so a restore
    /// of that earlier version reattaches it by exact stored identity. Key: id16 (artifact) +
    /// id16 (thread) + u64be (the version it moved to).
    ANNOTATION_PRIOR_ANCHOR: VaultMeta b"anchored_annotation:prior:v1:" Named;
    /// A detached comment's snapshot of the text it was anchored on, for the Unattached list and
    /// the exact-words reattach offer. Key: id16 (artifact) + id16 (thread).
    ANNOTATION_UNATTACHED: VaultMeta b"anchored_annotation:unattached:v1:" Named;
    /// Channel pointer (published/preview) naming the fork hash a codebase artifact currently serves.
    /// Key: channel byte + u16be length + string (artifact id).
    ARTIFACT_POINTER: VaultMeta b"artifact:pointer:v1:" Raw;
    /// Immutable publish admission receipt keyed by publish entity id16.
    ARTIFACT_PUBLISH_ADMISSION: VaultMeta b"artifact:publish:admission:v1:" LegacyJson;
    /// A replica's serving descriptor of one published blob version: content hash, export name
    /// and media type, nothing else (FIX 1195). Key: id16 (artifact) + u64be (version).
    ARTIFACT_SERVING_BLOB: VaultMeta b"artifact:serving:blob:v1:" Named;
    /// The change id (16 bytes) of this channel pointer's change whose publication has not
    /// reached the sync server yet (FIX 9575). Key: channel byte + u16be length + string
    /// (artifact id).
    ARTIFACT_SYNC_OUTBOX: VaultMeta b"artifact:sync:outbox:v1:" Named;
    /// Live attempt's frozen execution context and append-only use witnesses. Key: attempt id16.
    ATTEMPT_PACK_ATTRIBUTION: VaultMeta b"attempt_attribution:v1:" Named Authored;
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
    /// The id of the newest checkpoint v2 image of this vault's local chain (OF-469). Key: ().
    AUTHORITY_CHECKPOINT_V2_HEAD: VaultMeta b"authority.checkpoint.head.v2" Raw;
    /// What this home's root signed for a linked machine's own checkpoint image (FIX 5195): the
    /// image id, the posture and policy it was made under, the attestation and the local second
    /// the machine last asked for it. A reply cache, so a last part whose answer the machine's RPC
    /// timeout lost is answered from it on the machine's next pass; no image bytes, never the
    /// delivery cache or the attestation table. Runtime-tier. Key: the machine's id16 + root key
    /// (suite byte + key bytes).
    AUTHORITY_CHECKPOINT_COUNTERSIGN: VaultMeta b"authority.checkpoint.local.countersign.v1:" Named;
    /// The checkpoint v2 head this install kept, the authority totals it accounts for, the local
    /// second it was kept at and the root policy this install built it under (OF-469 cutoffs).
    /// Runtime-tier: no checkpoint image carries it. Key: ().
    AUTHORITY_CHECKPOINT_PROGRESS: VaultMeta b"authority.checkpoint.local.progress.v1" Named;
    /// What a root held here signed for a home's checkpoint head (FIX 5109): the image, the
    /// posture and policy it was made under, where its delivery stands, and the attestation
    /// until the home reports the root accepted. A delivery cache, rebuilt by signing again;
    /// never the attestation table. Runtime-tier. Key: home tag (1 then the home's machine id,
    /// or 0 then zeros for a home that proved none) + root key (suite byte + key bytes).
    AUTHORITY_CHECKPOINT_ROOT_DELIVERY: VaultMeta b"authority.checkpoint.local.root-delivery.v1:" Named;
    /// This install's cumulative count of authority rows first stored here and their canonical
    /// signed body bytes (OF-469 cutoffs). Runtime-tier. Key: ().
    AUTHORITY_CHECKPOINT_TOTALS: VaultMeta b"authority.checkpoint.local.totals.v1" Named;
    /// One row the adopted checkpoint v2 image covers that this vault did not hold when it
    /// adopted it (OF-469 cutoffs): its arrival is hydration, not growth. Runtime-tier. Key:
    /// hash32.
    AUTHORITY_CHECKPOINT_UNHELD: VaultMeta b"authority.checkpoint.local.unheld.v1:" Raw;
    /// One checkpoint v2 image's canonical bytes (domain, then named MessagePack), keyed by its
    /// unsigned id (OF-469). Key: hash32.
    AUTHORITY_CHECKPOINT_V2_IMAGE: VaultMeta b"authority.checkpoint.v2." Raw;
    /// One signed authority row a repair page staged while this vault's history is incomplete
    /// (OF-469): no held history, admitted only when the stage closes the gap. Key: hash32.
    AUTHORITY_HISTORY_STAGE: VaultMeta b"authority.history.stage.v1:" Raw;
    /// The checkpoint v2 image this vault adopted (OF-469): the pin from owner-authorized pairing
    /// and the attestations that verified the image; the pin names the image. Key: ().
    AUTHORITY_CHECKPOINT_ADOPTED_PIN: VaultMeta b"authority:checkpoint-adopted-pin:v1" Named;
    /// One root's attestation of one authority checkpoint v2 image (OF-469): both signatures and
    /// the root's key binding, with the policy digest it was made under. Key: hash32 (image id) +
    /// root key (suite byte + key bytes).
    AUTHORITY_CHECKPOINT_ATTESTATION: VaultMeta b"authority:checkpoint-attestation:v1:" Named;
    /// The newest checkpoint v2 image whose stored attestations reached this vault's own root
    /// policy, and that policy's digest (OF-469). Key: ().
    AUTHORITY_CHECKPOINT_ATTESTED_HEAD: VaultMeta b"authority:checkpoint-attested-head:v1" Named;
    /// One eligible root's certified checkpoint SLH-DSA key: the root's classical signature over
    /// this install's hash-based key (OF-469). Key: root key (suite byte + key bytes).
    AUTHORITY_CHECKPOINT_KEY_BINDING: VaultMeta b"authority:checkpoint-key-binding:v1:" Named;
    /// The saved fork alarm for one key a held handoff retired, kept until the owner acknowledges
    /// it. Key: string (signer suite ":" key hex).
    AUTHORITY_HANDOFF_ALARM: VaultMeta b"authority:handoff-alarm:v1:" Raw;
    /// One claim-authoring campaign (OF-366): its strategy skill pin, fixed config, strategy pin
    /// and BEAM promotion receipt. Key: id16 (root attempt).
    AUTORESEARCH_AUTHORING: VaultMeta b"autoresearch:authoring:v1:" Named;
    /// One finalized claim-authoring tournament run: winner, landed approval, team receipt ref,
    /// terminal receipt ref and settled outcome. Key: id16 (root attempt) + id16 (run attempt).
    AUTORESEARCH_AUTHORING_RUN: VaultMeta b"autoresearch:authoring_run:v1:" Named;
    /// One autoresearch candidate's held-out basis, its one sealed confirmation (consumed before
    /// the cohort is released) and its promotion receipt. Key: id16 (root attempt) + id16
    /// (candidate attempt).
    AUTORESEARCH_BASIS: VaultMeta b"autoresearch:basis:v1:" Named;
    /// One bound autoresearch campaign: its ruler, goal pin, policy digest, cohort and budget
    /// share, written once. Key: id16 (root attempt).
    AUTORESEARCH_BINDING: VaultMeta b"autoresearch:binding:v1:" Named;
    /// One autoresearch host continuation (FIX 886): the bootstrap measure or one selection
    /// round's work, its pending tasks, the run in flight with its reservation, and the runs it
    /// dispatched. Key: id16 (root attempt) + u64be (0 bootstrap, n + 1 round n).
    AUTORESEARCH_CONTINUATION: VaultMeta b"autoresearch:continuation:v1:" Named
        => crate::autoreason_campaign::research::erase_release_source_rows_in_txn;
    /// One held-out selection benchmark of an autoresearch parent-selection estimator version
    /// against the DGM formula, recorded once. Key: string (estimator version).
    AUTORESEARCH_ESTIMATOR: VaultMeta b"autoresearch:estimator:v1:" Named;
    /// One autoresearch experiment node annotating an existing attempt: lineage, candidate pin,
    /// search and held-out evidence, buggy, weave and prune receipts. Key: id16 (root attempt) +
    /// id16 (node attempt).
    AUTORESEARCH_NODE: VaultMeta b"autoresearch:node:v1:" Named;
    /// Immutable output descriptor and original placement/scoring receipts. Key: root attempt id16.
    AUTORESEARCH_OUTPUT_ARCHIVE: VaultMeta b"autoresearch:output-archive:v1:" Named;
    /// Exact output refs produced by one campaign replay arm. Key: root id16 + node id16.
    AUTORESEARCH_OUTPUT_REPLAY: VaultMeta b"autoresearch:output-replay:v1:" Named;
    /// One RSI reservation an autoresearch campaign holds or held. Key: id16 (root attempt) +
    /// id16 (reservation id).
    AUTORESEARCH_RESERVATION: VaultMeta b"autoresearch:reservation:v1:" Named;
    /// One autoresearch selection round's receipt. Key: id16 (root attempt) + u64be (round).
    AUTORESEARCH_ROUND: VaultMeta b"autoresearch:round:v1:" Named;
    /// The last commit a write that changes no content stamped (FIX 6730): its transaction id,
    /// the last content commit's and its class, so a host's telemetry and a backup's own writes
    /// move no backup watermark. Runtime-tier: no image carries it. Key: ().
    BACKUP_CHANGE: VaultMeta b"backup:change:v1" Named;
    /// This store's backup incarnation: 16 random bytes minted at its first backup, which a
    /// backup watermark carries so a restored or recreated store never compares equal to an
    /// older one. Runtime-tier: no image carries it. Key: ().
    BACKUP_INCARNATION: VaultMeta b"backup:incarnation:v1" Named;
    /// Asset refcount marker. Key: bytes32 + id16.
    BLOB_ARTIFACT_ASSET_REF: VaultMeta b"blob_artifact:asset_ref:v1:" Raw;
    /// Born-from projection: one row per version whose made_by names a trigger (task or ask) or
    /// whose provenance names an agent run, read backwards from the source. Key: bytes17 (source
    /// kind byte + id16 or the run ref's blake3 prefix) + id16 (artifact) + u64be (version).
    BLOB_ARTIFACT_BORN_FROM: VaultMeta b"blob_artifact:born_from:v1:" Named;
    /// `BLOB_ARTIFACT_VERSION_CLAIM` keyed by artifact, so an artifact's delete reads its own
    /// bytes without a scan. Key: id16 (artifact) + bytes32.
    BLOB_ARTIFACT_CLAIMED_HASH: VaultMeta b"blob_artifact:claimed_hash:v1:" Raw;
    /// Native slide and shape id high-water marks of one deck artifact, raised at each settled
    /// deck transaction (ARCH-0077 managed id history). Key: id16.
    BLOB_ARTIFACT_DECK_ID_MARKS: VaultMeta b"blob_artifact:deck_id_marks:v1:" Named;
    /// Blob artifact head version. Key: id16.
    BLOB_ARTIFACT_HEAD: VaultMeta b"blob_artifact:head:v1:" Raw;
    /// Monotonic last version, retained after deletion. Key: id16; value: u64be.
    BLOB_ARTIFACT_HIGHWATER: VaultMeta b"blob_artifact:highwater:v1:" Raw;
    /// Edit proposal settlement ledger row. Key: id16 + hash32.
    EDIT_SETTLE_RECORD: VaultMeta b"blob_artifact:settlement:v1:" Raw;
    /// Blob artifact version record. Key: id16 + u64be.
    BLOB_ARTIFACT_VERSION: VaultMeta b"blob_artifact:version:v1:" Raw;
    /// Which artifacts hold which bytes: one row per artifact and content hash a `blob.version`
    /// claim named here, replicated claims included, kept until the artifact's delete. Key:
    /// bytes32 + id16 (artifact).
    BLOB_ARTIFACT_VERSION_CLAIM: VaultMeta b"blob_artifact:version_claim:v1:" Raw;
    /// Revision-ref frontier (16 bytes) a board-selection CLAIM was written under, authenticated on
    /// every read. Key: id16.
    BOARD_HISTORY_CLAIM_FRONTIER: VaultMeta b"board_history:claim_frontier:" Raw;
    /// Loro CRDT snapshot backing one owner's board-selection/document history. Key: id16.
    BOARD_HISTORY_DOC: VaultMeta b"board_history:doc:" Raw;
    /// Marker that compaction folded a TURN, so its board never reconstructs, whether it was recorded
    /// before or after the fold. Key: id16.
    BOARD_HISTORY_FOLDED: VaultMeta b"board_history:folded:" Raw;
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
    /// CUA E8b: a browser program admission job's receipt, and the program a filing in its run
    /// filed, written in that filing's write: references and a typed outcome only. Key: id16.
    BROWSER_PROGRAM_ADMISSION: VaultMeta b"browser.program.admission.v1\0" Named Engine;
    /// CUA E8a: the source authority a solved browser run was captured under, by its evidence
    /// claim: scope, group digest, credential reference and witness digest, and the signed
    /// binding itself until an admission job that used it ends (CUA E8b). Key: id16.
    BROWSER_PROGRAM_AUTHORITY: VaultMeta b"browser.program.authority.v1\0" Named Engine
        => crate::browser_library::erase_authority_actor_in_txn;
    /// CUA E8a: a replay library program whose library runs failed, live or retired, with its
    /// site hash, group digest and generation. Key: id16.
    BROWSER_PROGRAM_FAILURE: VaultMeta b"browser.program.failure.v1\0" Named Engine;
    /// CUA E8: a candidate program's induction already proposed, by its input fingerprint. Key:
    /// hash32.
    BROWSER_PROGRAM_SEEN: VaultMeta b"browser.program.seen.v1\0" Named Engine;
    /// CUA E8a: a live replay library program covering a solved group. Key: hash32 (group) +
    /// id16.
    BROWSER_SOLVED_COVERAGE: VaultMeta b"browser.solved.coverage.v1\0" Named Engine;
    /// CUA E8a: a solved group's full scoped key with its changed and processed generations.
    /// Key: hash32 (group).
    BROWSER_SOLVED_DIRTY: VaultMeta b"browser.solved.dirty.v1\0" Named Authored
        => crate::browser_library::erase_dirty_actor_in_txn;
    /// CUA E8a: one solved run's evidence claim in its group: its run and capture time, never its
    /// body. Key: hash32 (group) + id16.
    BROWSER_SOLVED_GROUP: VaultMeta b"browser.solved.group.v1\0" Named Engine;
    /// A replay library program a retire took out, with whose word, when and why. Key: id16.
    BROWSER_WORKFLOW_RETIRED: VaultMeta b"browser.workflow.retired.v1\0" Named Authored
        => crate::browser_library::erase_retired_actor_in_txn;
    /// Replay library program a solved browser run became, with its two checks' proof. Key: hash32 (site) + id16.
    BROWSER_WORKFLOW: VaultMeta b"browser.workflow.v1\0" Named Authored
        => crate::browser_library::erase_workflow_actor_in_txn;
    /// FIX 7767: one resident's share of the host-paid allocation as the owner set it, and what
    /// its settled calls charged the allocation generation they ran on. Key: id16 (resident).
    BUDGET_RESIDENT_SHARE: VaultMeta b"budget.resident.share.v1\0" Named Engine
        => crate::llm::erase_resident_share_actor_in_txn;
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
}
