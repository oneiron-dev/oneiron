// Declared `vault_meta` tables whose prefix starts with `s` to `z`, in prefix order.

side_tables! {
    VAULT_META_S_Z;
    /// Node-local fast-path watermark (epoch u64be + content digest) for one (query, entity) pair's
    /// last-applied membership epoch. Key: id16 + id16.
    SAVED_QUERY_WATERMARK: VaultMeta b"saved_query.epoch.v1:" Raw;
    /// Durable append-only membership-transition event history for one (query, entity) pair, keyed by
    /// epoch. Key: id16 + id16 + u64be. Encoded as hand-rolled CANONICAL JSON (sorted object keys),
    /// not a plain derive, so the codec is `Raw` rather than `LegacyJson`.
    SAVED_QUERY_MEMBERSHIP_EVENT: VaultMeta b"saved_query.event.v1:" Raw;
    /// Cached match-evaluator verdict for one (query, entity, evidence) triple. Key: id16 + id16 +
    /// hash32. Encoded as hand-rolled CANONICAL JSON (sorted object keys), not a plain derive, so
    /// the codec is `Raw` rather than `LegacyJson`.
    SAVED_QUERY_MEMO: VaultMeta b"saved_query.memo.v1:" Raw;
    /// Operator-supplied predicate rewrite map for one compliance/definition pack move
    /// (from_pack@from_version->to_pack@to_version). Key: string "@" string "->" string "@" string.
    SAVED_QUERY_PACK_MIGRATION_MAP: VaultMeta b"saved_query.packmap.v1:" LegacyJson;
    /// Receipt of one pack-drift repair action (auto-migration, rewrite proposal, or pause) taken
    /// against a saved query. Key: id16. Encoded as hand-rolled CANONICAL JSON (sorted object keys),
    /// not a plain derive, so the codec is `Raw` rather than `LegacyJson`.
    SAVED_QUERY_REPAIR: VaultMeta b"saved_query.repair.v1:" Raw;
    /// Storage schema stamp. Key: ().
    STORAGE_SCHEMA_VERSION: VaultMeta b"schema_version" Raw;
    /// The scope-stamp sweep over stored claims has run. Key: ().
    SCOPE_STAMP_SWEEP_DONE: VaultMeta b"scope:claim-codec:v2" Raw;
    /// The scope-stamp sweep over policy manifests has run. Key: ().
    SCOPE_POLICY_SWEEP_DONE: VaultMeta b"scope:policy-manifest:v1.2" Raw;
    /// Record-scope revision counter (u64 little-endian), bumped on every stamp change. Key: ().
    SCOPE_RECORD_REVISION: VaultMeta b"scope:record:revision:v1" Raw;
    /// Retired digest-bound record-scope stamp. #1224 moved stamps to `scope:record:v2:` and no longer
    /// reads these rows; a vault stamped before it still holds them. Key: id16.
    SCOPE_RECORD_V1: VaultMeta b"scope:record:v1:" LegacyJson;
    /// Birth-position scope stamp (kind, birth facet, worlds/facets/bands/audience/sensitivity) for
    /// one stored record, used by scoped read/export/delete. Key: id16.
    SCOPE_RECORD: VaultMeta b"scope:record:v2:" LegacyJson;
    /// Active scope-summary projection and its last observed input hash. Key: hash32.
    SCOPE_SUMMARY_PROJECTION: VaultMeta b"scope_summary:projection:v1:" Named;
    /// Owner-approved summary-purpose descriptor. Key: string (descriptor id).
    SCOPE_SUMMARY_PURPOSE: VaultMeta b"scope_summary:purpose:v1:" Named;
    /// Atomic summary/landing result of one queued declaration. Key: AttemptId.
    SCOPE_SUMMARY_RESULT: VaultMeta b"scope_summary:result:v1:" Named;
    /// Name index mapping a live secret-custody record's name to its EntityId. Key: string (secret
    /// name).
    SECRET_CUSTODY_NAME_INDEX: VaultMeta b"secret_custody:name:v1:" Raw Custody;
    /// The latest owner-signed custody transition this vault signed of one portable credential
    /// (OF-422): the record without its value, the value sealed to each machine mine here. Key:
    /// hex32(entity id).
    SECRET_CUSTODY_TRANSITION: VaultMeta b"secret_custody:transition:v1:" Raw Custody;
    /// Forward sidecar of secret taint-refs attached to one piece of build exhaust. Key: hex32(entity
    /// id).
    SECRET_EXHAUST_TAINT: VaultMeta b"secret_exhaust_taint:v1:" Raw;
    /// T1/T2 secret-materialization lease row (escalation ladder to local registration). Key:
    /// hex32(lease id).
    SECRET_LEASE: VaultMeta b"secret_lease:v1:" Raw;
    /// Durable receipt written before a secret value is returned from materialization. Key:
    /// hex32(receipt id).
    SECRET_MATERIALIZATION_RECEIPT: VaultMeta b"secret_lease_receipt:v1:" Raw;
    /// T2 local-file registration for a materialized secret, read wholesale for snapshot exclusion.
    /// Key: hex32(lease id).
    SECRET_LOCAL_REGISTRATION: VaultMeta b"secret_local:v1:" Raw;
    /// Where a mask on write found the secret one custody record holds: the record, the field and
    /// the key's kind (OF-560). Key: id16 (custody record id).
    SECRET_MASK_ORIGIN: VaultMeta b"secret_mask:origin:v1:" Named Custody;
    /// A file stored with keys in it: each key's span in its bytes and the custody record that
    /// holds it, and its band (OF-560, owner ruling G04 binary = C2). Key: hash32 (blake3 of the
    /// stored bytes).
    SECRET_MASK_SPANS: VaultMeta b"secret_mask:spans:v1:" Named Custody;
    /// Durable attestation of one secret rotate-or-revoke op; carries no value bytes. Key:
    /// hex32(receipt id).
    SECRET_ROTATION_RECEIPT: VaultMeta b"secret_rotation_receipt:v1:" Raw;
    /// Points a diagnostic event id at the signed detector run that produced it. Key: id16
    /// Immutable replay evidence for centroid verdicts, keyed by digest hash32.
    SELF_HEAL_CENTROID_EVIDENCE: VaultMeta b"self_heal:centroid_evidence:v1:" Named;
    /// When a host detector graded one telemetry window under one wording. Key: bytes32
    /// (blake3 of the tier, the detector policy and the window's run ids).
    SELF_HEAL_DETECTOR_WINDOW: VaultMeta b"self_heal:detector_window:v1:" Raw;
    /// Owner-reviewed T3 finding by family string, colon and diagnostic id16.
    SELF_HEAL_DISTILL: VaultMeta b"self_heal:distill:" Named;
    /// Immutable attempt confession, audit draw and independently checked findings. Key: id16.
    SELF_HEAL_ATTEMPT_SEAL: VaultMeta b"self_heal:seal:v1:" Named;
    /// (diagnostic event id).
    SELF_HEAL_SIGNED_EVENT: VaultMeta b"self_heal:signed:v2:event:" Raw;
    /// A host-signed scheduled detector run receipt, keyed by its content digest. Key: bytes32
    /// (blake3 digest of the signed detector run).
    SELF_HEAL_SIGNED_RUN: VaultMeta b"self_heal:signed:v2:run:" Named;
    /// First delivered task per idempotency key. Key: bytes32.
    SEND_IDEMPOTENCY_INDEX: VaultMeta b"send_idem:v0:" Raw;
    /// Latest connector-send receipt of a task. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice): `store::outbound_send_receipt`
    /// only relays a caller-encoded `&[u8]` (`crate::receipt::send_receipt_txn`
    /// already ran `rmp_serde::to_vec_named` before calling in); binding it
    /// `Named` here would re-encode already-encoded bytes on every write.
    SEND_RECEIPT_SUMMARY: VaultMeta b"send_receipt:v0:" Raw Authored;
    /// Connector-send attempt audit row. Key: id16 + bytes32.
    ///
    /// Codec fixed to `Raw` (T47 store slice), for the same reason as
    /// [`SEND_RECEIPT_SUMMARY`]: `store::send_receipt_audit` relays the same
    /// caller-encoded bytes verbatim.
    SEND_RECEIPT_ATTEMPT_AUDIT: VaultMeta b"send_receipt_attempt:v0:" Raw Authored;
    /// Open SESSION per actor and machine. Key: actor id16 + machine id16.
    SESSION_LIFECYCLE_OPEN: VaultMeta b"session_lifecycle:v0:open:" Raw;
    /// Per-session lifecycle clock record (started_at, last_activity, ended_at, end_reason), keyed by
    /// SESSION entity id. Key: id16.
    SESSION_LIFECYCLE_RECORD: VaultMeta b"session_lifecycle:v0:record:" Named;
    /// TURN to SESSION membership row. Key: id16.
    SESSION_TURN_MEMBERSHIP: VaultMeta b"session_lifecycle:v0:turn_session:" Raw;
    /// SESSION to TURN membership index. Key: id16 + id16.
    SESSION_TURNS: VaultMeta b"session_turns:v1:" Raw;
    /// One client-readable customization-settings change-notification event. Key: u64be (sequence).
    CUSTOMIZATION_EVENT: VaultMeta b"settings:customization:v1:event:" Named Authored;
    /// Monotonic sequence counter for customization change-notification events. Key: ().
    CUSTOMIZATION_EVENT_SEQUENCE: VaultMeta b"settings:customization:v1:event_sequence" Raw;
    /// Persisted four-layer (accent/type/mode/world) client customization profile. Key: ().
    CUSTOMIZATION_SETTINGS: VaultMeta b"settings:customization:v1:profile" Named Authored;
    /// OF-365: the owner's disclosure-mode knob (always_ask / auto / always_yes; absent means
    /// auto). Value: the mode's ASCII name. Key: ().
    DISCLOSURE_OFFER_MODE: VaultMeta b"settings:disclosure:v1:offer_mode" Raw;
    /// Owner-set action-mode policy: the state-index window and its mode bands (OF-335).
    /// Key: ().
    DREAMER_ACTION_MODE_POLICY: VaultMeta b"settings:dreamer:action_mode:v1" LegacyJson;
    /// Owner-set rubric dial for the memory-curator maintenance pass. Key: ().
    DREAMER_CURATOR_RUBRIC: VaultMeta b"settings:dreamer:curator:rubric:v1" LegacyJson Authored;
    /// Owner-set retune thresholds for the tuning-harness evaluation loop. Key: ().
    DREAMER_HARNESS_THRESHOLDS: VaultMeta b"settings:dreamer:harness:thresholds:v1" LegacyJson;
    /// Owner-set cadence dial for the proactivity digest. Key: ().
    DREAMER_PROACTIVITY_CADENCE: VaultMeta b"settings:dreamer:proactivity:cadence:v1" LegacyJson;
    /// Owner-confirmed digest policy claim revision. Key: id16, value: hash32.
    DREAMER_PROACTIVITY_CONFIRMED: VaultMeta b"settings:dreamer:proactivity:confirmed:v1:" Raw;
    /// Owner-confirmed presentation row. Key: singleton.
    DREAMER_PROACTIVITY_PRESENTATION: VaultMeta b"settings:dreamer:proactivity:presentation:v1" LegacyJson Authored;
    /// Owner-set projector surprise policy. Key: ().
    DREAMER_PROJECTOR_POLICY: VaultMeta b"settings:dreamer:projector-policy:v1" LegacyJson;
    /// Owner-set continuous sieve policy. Key: ().
    DREAMER_SIEVE_POLICY: VaultMeta b"settings:dreamer:sieve-policy:v1" LegacyJson;
    /// Owner-set relationship-stewardship rules. Key: ().
    DREAMER_STEWARDSHIP_RULES: VaultMeta b"settings:dreamer:stewardship:rules:v1" LegacyJson Authored;
    /// Owner on/off dial for proactive Dreamer plugin suggestions. Key: ().
    PLUGIN_SUGGESTIONS_ENABLED: VaultMeta b"settings:dreamer:v1:plugin_suggestions_enabled" Raw;
    /// Owner-controlled wake thresholds. Key: ().
    DREAMER_WAKE_POLICY: VaultMeta b"settings:dreamer:wake-policy:v1" LegacyJson;
    /// Dial: distinct-receipt count K needed before the substitution miner acts on a cluster. Key:
    /// ().
    EDIT_DISTANCE_MINER_K: VaultMeta b"settings:edit_distance:v1:miner_k" Raw;
    /// Owner-set inbox review dial (exceptions-only vs review-all), house per-feature dial pattern.
    /// Key: ().
    INBOX_REVIEW_DIAL: VaultMeta b"settings:inbox:v1:review_dial" Raw;
    /// The owner's standing quota fallback for one model offer (OF-305): the engine model id its
    /// calls go to while the offer is parked, set by a `use_fallback` answer. Owner policy, kept
    /// apart from the deployment's runtime cooldowns. Key: hex64 (the offer's cooldown key).
    MODEL_OWNER_FALLBACK: VaultMeta b"settings:models:v1:fallback:" Raw Authored;
    /// Publisher share dial: explicit owner-set enabled/disabled token. Key: ().
    EDIT_DISTANCE_PUBLISHER_ENABLED: VaultMeta b"settings:publisher:v1:enabled" Raw;
    /// Install-profile default for the publisher share dial. Key: ().
    EDIT_DISTANCE_PUBLISHER_INSTALL_DEFAULT: VaultMeta b"settings:publisher:v1:install_default" Raw;
    /// Owner-set posterior-lower-bound floor below which a skill's reliability triggers a quarantine
    /// proposal. Key: ().
    SKILL_RELIABILITY_FLOOR: VaultMeta b"settings:skill:v1:reliability_floor" Raw;
    /// An owner's funded judge-ask minutes (u32be). Key: id16 (owner).
    SKILL_OPTIMIZE_JUDGE_MINUTES: VaultMeta b"settings:skill_optimize:judge_minutes:v1:" Raw;
    /// Accepted edits per Dreamer cycle. Key: ().
    SKILL_EDIT_CYCLE_CAP: VaultMeta b"settings:skill_optimize:v1:cycle_cap" Raw;
    /// Minimum attributed outcomes before optimization. Key: ().
    SKILL_OPTIMIZE_MIN_OUTCOMES: VaultMeta b"settings:skill_optimize:v1:min_outcomes" Raw;
    /// Persisted activation-risk threshold dial for skill-scan consent escalation. Key: ().
    SKILL_SCAN_ACTIVATION_RISK_THRESHOLD: VaultMeta b"settings:skill_scan:v1:activation_risk_threshold" Raw;
    /// Local, engine-written provenance and monotonic revocation latch for one admitted brief share
    /// (issuer, gate decision id, effect-target digest, revocation state), proving the row was
    /// created through the share door and not a generic grant write. Key: id16.
    SHARE_BRIEF_ADMISSION: VaultMeta b"share:brief:admission:v1:" Raw;
    /// One-way deletion fence for a brief identity. Key: id16; value: the one-byte marker `1`.
    SHARE_BRIEF_DELETE_RESERVATION: VaultMeta b"share:brief:deleting:v1:" Raw;
    /// The born-with text one brief share lets travel (OF-491), fixed in the transaction that
    /// admits the share. Key: id16(share).
    SHARE_BRIEF_TRAVEL: VaultMeta b"share:brief:travel:v1:" Named;
    /// One artifact export's travel receipt (OF-491): the copy, its digest, who sent it and the
    /// born-with fields that left with it; never the exported bytes. Key: u64be(sequence).
    SHARE_EXPORT_TRAVEL: VaultMeta b"share:export:travel:v1:" Named;
    /// One-time record of the initial membership/policy defaults applied when a shared vault was
    /// created. Key: ().
    /// One Member's request or Admin's proposal to erase a record of a shared vault. Key: hex32
    /// (ask id).
    SHARED_ACT_ERASE_ASK: VaultMeta b"shared-act:erase-ask:v1:" Raw;
    /// One member's notice of a pending shared act. Key: hex32 (member id) ":" hex32 (act id).
    SHARED_ACT_EVENT: VaultMeta b"shared-act:event:v1:" Raw;
    /// One Owner's notice that a waiting shared act matured. Key: hex32 (owner id) ":" hex32 (act
    /// id).
    SHARED_ACT_MATURED: VaultMeta b"shared-act:matured:v1:" Raw;
    /// One recipient's notice of an executed shared act or membership change. Key: hex32 (recipient
    /// id) ":" hex32 (receipt id).
    SHARED_ACT_OUTCOME: VaultMeta b"shared-act:outcome:v1:" Raw;
    /// The execution receipt of one shared act or membership change. Key: hex32 (receipt id).
    SHARED_ACT_RECEIPT: VaultMeta b"shared-act:receipt:v1:" Raw;
    /// A pending shared act awaiting its members' objection window. Key: hex32 (act id).
    SHARED_ACT_RECORD: VaultMeta b"shared-act:record:v1:" Raw;
    SHARED_VAULT_CREATION: VaultMeta b"shared-vault:creation:v1" LegacyJson;
    /// The executed delete-the-vault act and its backup retention deadline. Key: ().
    SHARED_VAULT_DELETION: VaultMeta b"shared-vault:deleted:v1" LegacyJson;
    /// One invitation of a person into the shared vault, pending until they accept, decline or an
    /// `add_member` holder withdraws it. Key: hex32 (invitee id) ":" hex32 (invitation id).
    SHARED_VAULT_INVITATION: VaultMeta b"shared-vault:invitation:v1:" Raw;
    /// Retired presentation id alias. Key: string.
    SHORT_ID_ALIAS: VaultMeta b"short_id_alias:v1\0" Raw;
    /// Presentation-id grammar generation. Key: ().
    SHORT_ID_GRAMMAR_VERSION: VaultMeta b"short_id_grammar_version" Raw;
    /// Last short-id counter per entity type. Key: u8.
    SHORT_ID_COUNTER: VaultMeta b"sid_counter:" Raw;
    /// A callable helper's standing promotion verdict (Self-Harness splits, reliability check,
    /// the exact content hash it scored). Key: id16 (skill entity).
    SKILL_CALLABLE_GATE: VaultMeta b"skill:callable_gate:v1:" Named;
    /// One attempt an exploration trial routed to its proposal: the charge it reserved against the
    /// goal claim's exploration slice and, once its spend scope settles, what it spent (MessagePack
    /// named map). Key: id16 (attempt).
    SKILL_EXPLORATION_ROUTE: VaultMeta b"skill:exploration_route:v1:" Named;
    /// What skill trials charged one goal claim's exploration slice, and the overruns its owner
    /// approved (MessagePack named map). Key: id16 (goal claim).
    SKILL_EXPLORATION_SLICE: VaultMeta b"skill:exploration_slice:v1:" Named;
    /// The proposal whose exploration trial an active skill serves (MessagePack string). Key: id16
    /// (incumbent skill).
    SKILL_EXPLORATION_TARGET: VaultMeta b"skill:exploration_target:v1:" Named;
    /// One optimizer proposal's exploration trial: its basis, exposure bound, routed runs, overrun
    /// ask and state (MessagePack named map). Key: id16 (proposal).
    SKILL_EXPLORATION_TRIAL: VaultMeta b"skill:exploration_trial:v1:" Named;
    /// Marker (the single byte 1) that one attempt receipt's pack loaded one skill. Key: u64be
    /// receipt length + receipt string + id16.
    SKILL_RESIDENT_LOADED_SKILL: VaultMeta b"skill:resident_loaded_skill:v1:" Raw;
    /// Lifelong resident owner of one skill id (version byte, has-owner byte, optional owner id16),
    /// kept across deletion. Key: id16.
    SKILL_RESIDENT_OWNER: VaultMeta b"skill:resident_owner:v1:" Raw;
    /// The actor (id16) one attempt receipt is bound to. Key: string (the receipt id).
    SKILL_RESIDENT_RECEIPT: VaultMeta b"skill:resident_receipt:v1:" Raw;
    /// Persisted audit report of a judge run against the held-out fixture set, keyed by run time then
    /// evidence sequence. Key: u64be + u64be.
    SKILL_ATTRIBUTION_AUDIT: VaultMeta b"skill_attribution:audit:v1:" Raw;
    /// Highest evidence sequence (u64be) the attribution projector has already routed. Key: ().
    SKILL_ATTRIBUTION_CURSOR: VaultMeta b"skill_attribution:cursor:v1" Raw;
    /// Replacement judge revision (UTF-8) marking one routed judgment as displaced. Key: u64be
    /// (evidence sequence).
    SKILL_ATTRIBUTION_DISPLACED_JUDGE: VaultMeta b"skill_attribution:displaced_judge:v1:" Raw;
    /// Fence on a displaced attribution judge revision: its replacement revision (UTF-8). Key:
    /// string (the displaced revision).
    SKILL_ATTRIBUTION_DISPLACED_REVISION: VaultMeta b"skill_attribution:displaced_revision:v1:" Raw;
    /// One minted skill-edit proposal awaiting gated apply, keyed by judgment sequence. Key: u64be.
    SKILL_ATTRIBUTION_EDIT_PROPOSAL: VaultMeta b"skill_attribution:edit_proposal:v1:" Raw;
    /// One recorded outcome-evidence row (hand-rolled MessagePack map) awaiting attribution routing,
    /// keyed by sequence. Key: u64be.
    SKILL_ATTRIBUTION_EVIDENCE: VaultMeta b"skill_attribution:evidence:v1:" Raw;
    /// Monotonic counter (u64be) minting the next evidence sequence number. Key: ().
    SKILL_ATTRIBUTION_EVIDENCE_SEQUENCE: VaultMeta b"skill_attribution:evidence_sequence:v1" Raw;
    /// Judge revision (UTF-8) that routed one judgment, stamped once. Key: u64be (evidence
    /// sequence).
    SKILL_ATTRIBUTION_JUDGE_REVISION: VaultMeta b"skill_attribution:judge_revision:v1:" Raw;
    /// One durable attribution verdict routed from evidence, keyed by evidence sequence. Key: u64be.
    SKILL_ATTRIBUTION_JUDGMENT: VaultMeta b"skill_attribution:judgment:v1:" Raw;
    /// Frozen anchored pack outcome, eligible used lineage chains and shares. Key: credit receipt id.
    SKILL_ATTRIBUTION_LATE_CREDIT: VaultMeta b"skill_attribution:late_credit:v1:" Named;
    /// The highest attribution evidence sequence the positive lane has read. Key: ().
    SKILL_ATTRIBUTION_POSITIVE_CURSOR: VaultMeta b"skill_attribution:positive_cursor:v1" Named;
    /// A positive skill proposal: a succeeded deviation or uncovered step that taught its skill.
    /// Key: u64be (evidence sequence).
    SKILL_ATTRIBUTION_POSITIVE_PROPOSAL: VaultMeta b"skill_attribution:positive_proposal:v1:" Named;
    /// Highest judgment sequence (u64be) the sweep has already applied to skill-reliability/actor-
    /// claim projections. Key: ().
    SKILL_ATTRIBUTION_SWEEP_APPLIED_CURSOR: VaultMeta b"skill_attribution:sweep_applied:v1" Raw;
    /// Idempotency marker (single byte) recording that a receipt's attribution evidence has already
    /// been captured. Key: string.
    SKILL_ATTRIBUTION_SWEEP_RECEIPT_CAPTURED: VaultMeta b"skill_attribution:sweep_receipt:v1:" Raw;
    /// Resume cursor (receipt-id text bytes) for the in-progress task-attribution receipt-page scan.
    /// Key: ().
    SKILL_ATTRIBUTION_SWEEP_SCAN_CURSOR: VaultMeta b"skill_attribution:sweep_scan:v1" Raw;
    /// One outcome the attribution judge left `unclear`, with each unclear hunk's reason, share and
    /// note, awaiting Dreamer clustering. Key: string (lane ":" reference).
    SKILL_ATTRIBUTION_UNCLEAR: VaultMeta b"skill_attribution:unclear:v1:" Raw;
    /// Skills citing a source. Key: id16 + id16.
    SKILL_SOURCE_INDEX: VaultMeta b"skill_convert/source_index/v1\0" Raw;
    /// Staleness note of a skill. Key: id16.
    SKILL_STALE_NOTE: VaultMeta b"skill_convert/stale_note/v1\0" Raw;
    /// Append-only history of hub-admission receipts, keyed by receipt id. Key: string.
    SKILL_HUB_ADMISSION_HISTORY: VaultMeta b"skill_hub/admission-history/v1\0" LegacyJson;
    /// Latest hub-admission receipt for one candidate entity. Key: id16.
    SKILL_HUB_ADMISSION_RECEIPT: VaultMeta b"skill_hub/admission-receipt/v1\0" LegacyJson;
    /// Cached capability-surface projection for a hub-derived skill entity. Key: id16.
    SKILL_HUB_CAPABILITY: VaultMeta b"skill_hub/capability/v1\0" Raw;
    /// Owner-adjudicated held-out claim labels (JSON array of hex ids) reserved for one claim base.
    /// Key: id16.
    SKILL_HUB_CLAIM_REFINEMENT_RESERVE: VaultMeta b"skill_hub/claim-refinement-reserve/v1\0" LegacyJson;
    /// Empty-marker index from a skill content hash to every entity holding it, maintained on every
    /// skill put. Key: hash32 + id16.
    SKILL_HUB_CONTENT_HASH_INDEX: VaultMeta b"skill_hub/content_hash_index/v1\0" Raw;
    /// Schema-version byte gating the one-time content-hash-index backfill/migration. Key: ().
    SKILL_HUB_CONTENT_HASH_INDEX_SCHEMA_VERSION: VaultMeta b"skill_hub/content_hash_index_schema_version" Raw;
    /// Hub-import receipt for one entity, keyed by (entity, source hub id, hash of the source ref
    /// string). Key: id16 + id16 + hash32.
    SKILL_HUB_IMPORT_RECEIPT: VaultMeta b"skill_hub/import-receipt/v1\0" LegacyJson;
    /// Owner blocking rule (`0` off, `1` on) on one canonical marketplace content hash. Key: hash32.
    SKILL_HUB_MARKETPLACE_BLOCKED_HASH: VaultMeta b"skill_hub/marketplace-blocked-hash/v1\0" Raw;
    /// Revision (u64be) of the owner's code auto-install switch, bound into each change's consent.
    /// Key: ().
    SKILL_HUB_MARKETPLACE_CODE_AUTO_INSTALL_REVISION: VaultMeta b"skill_hub/marketplace-code-auto-install-revision/v1" Raw;
    /// Owner switch (`0` off, `1` on) for auto-installing code-bearing marketplace folders. Key: ().
    SKILL_HUB_MARKETPLACE_CODE_AUTO_INSTALL: VaultMeta b"skill_hub/marketplace-code-auto-install/v1" Raw;
    /// Origin marker for a hub-materialized skill (imported flag, optional forked-from parent id);
    /// survives deletion so it cannot be laundered by delete/recreate. Key: id16.
    SKILL_HUB_ORIGIN: VaultMeta b"skill_hub/origin/v1\0" Raw;
    /// Persisted hub package sidecar (custom MAGIC-framed binary envelope) for a skill entity. Key:
    /// id16.
    SKILL_HUB_PACKAGE: VaultMeta b"skill_hub/package/v1\0" Raw;
    /// One hub ref's sync policy and its seen/trusted revisions (ARCH-0053 §7). Key: id16 +
    /// string ref.
    SKILL_HUB_REF_SYNC: VaultMeta b"skill_hub/ref-sync/v1\0" LegacyJson;
    /// Refinement-receipt carrier id to the holder (candidate id, 16 bytes) that owns it. Key: id16.
    SKILL_HUB_REFINEMENT_BINDING: VaultMeta b"skill_hub/refinement-binding/v1\0" Raw;
    /// Permanent claim-refinement origin: blake3 (32 bytes) of the first native Proposed bytes. Key:
    /// id16.
    SKILL_HUB_REFINEMENT_CLAIM_ORIGIN: VaultMeta b"skill_hub/refinement-claim-origin/v1\0" Raw;
    /// Content-free refinement control row (target, bindings, state) for one candidate. Key: id16.
    SKILL_HUB_REFINEMENT_CONTROL: VaultMeta b"skill_hub/refinement-control/v1\0" LegacyJson;
    /// Empty marker that a refinement holder's custody is permanently closed. Key: id16.
    SKILL_HUB_REFINEMENT_HOLDER_RETIRED: VaultMeta b"skill_hub/refinement-holder-retired/v1\0" Raw;
    /// Latest local refinement ruling pointer (ruling id16 + carrier id16) for a holder. Key: id16.
    SKILL_HUB_REFINEMENT_LATEST: VaultMeta b"skill_hub/refinement-latest/v1\0" Raw;
    /// Empty marker that a holder owns one refinement-receipt carrier. Key: id16 + id16.
    SKILL_HUB_REFINEMENT_OWNED: VaultMeta b"skill_hub/refinement-owned/v1\0" Raw;
    /// Permanent skill-refinement origin: blake3 (32 bytes) of the first native Candidate bytes.
    /// Key: id16.
    SKILL_HUB_REFINEMENT_SKILL_ORIGIN: VaultMeta b"skill_hub/refinement-skill-origin/v1\0" Raw;
    /// Empty marker that one refinement-receipt carrier id is permanently retired. Key: id16.
    SKILL_HUB_REFINEMENT_SOURCE_RETIRED: VaultMeta b"skill_hub/refinement-source-retired/v1\0" Raw;
    /// Shared-skill merge delta computed for one candidate. Key: id16.
    SKILL_HUB_SHARED_DELTA: VaultMeta b"skill_hub/shared-delta/v1\0" LegacyJson;
    /// Append-only history of shared-skill merge receipts, keyed by receipt id. Key: string.
    SKILL_HUB_SHARED_MERGE_HISTORY: VaultMeta b"skill_hub/shared-merge-history/v1\0" LegacyJson;
    /// Latest shared-skill merge receipt for one candidate entity. Key: id16.
    SKILL_HUB_SHARED_MERGE_RECEIPT: VaultMeta b"skill_hub/shared-merge-receipt/v1\0" LegacyJson;
    /// Fixed 48-byte carrier/hash binding recorded for a pending or materialized source holder. Key:
    /// id16.
    SKILL_HUB_SOURCE_BINDING: VaultMeta b"skill_hub/source-binding/v1\0" Raw;
    /// Source-custody state (live/dead/unseen byte) for one (holder, content hash) pair. Key: id16 +
    /// hash32.
    SKILL_HUB_SOURCE_CUSTODY: VaultMeta b"skill_hub/source-custody/v1\0" Raw;
    /// Empty-marker that a source holder's custody has been permanently retired. Key: id16.
    SKILL_HUB_SOURCE_RETIRED: VaultMeta b"skill_hub/source-retired/v1\0" Raw;
    /// Portable goal-axis identity of a skill under optimization. Key: id16.
    SKILL_OPTIMIZE_GOAL: VaultMeta b"skill_optimize/goal/v1\0" Raw;
    /// A proposal's live goal-axis report, bound to its bodies, evidence and plan (MessagePack
    /// named map). Key: id16 (proposal).
    SKILL_OPTIMIZE_LIVE_AXES: VaultMeta b"skill_optimize/live_axes/v1\0" Raw;
    /// Optimizer-birth marker. Key: id16.
    SKILL_OPTIMIZE_ORIGIN_MARKER: VaultMeta b"skill_optimize/origin/v1\0" Raw;
    /// A proposal's offline preflight: its floor and cost axes and the honesty floor scored on the
    /// held-out set before any live run, and whether every floor held, bound to both bodies, the
    /// evidence and the goal revision (MessagePack named map). Key: id16 (proposal).
    SKILL_OPTIMIZE_PREFLIGHT: VaultMeta b"skill_optimize/preflight/v1\0" Named;
    /// A skill goal's join to a project's goal record (MessagePack named map). Key: id16 (goal).
    SKILL_OPTIMIZE_PROJECT_GOAL: VaultMeta b"skill_optimize/project_goal/v1\0" Raw;
    /// A vault owner's dismissal of one learned goal-revision proposal under the goal claim in
    /// force (MessagePack named map). Key: id16 (project) + question digest (64 hex).
    SKILL_OPTIMIZE_PROJECT_GOAL_DISMISSED: VaultMeta b"skill_optimize/project_goal_dismissed/v1\0" Raw;
    /// A learned preference proposed for a project's goal record (MessagePack named map). Key:
    /// id16 (project) + id16 (row).
    SKILL_OPTIMIZE_PROJECT_GOAL_PROPOSAL: VaultMeta b"skill_optimize/project_goal_proposal/v1\0" Raw;
    /// One pending skill-edit tradeoff ask (MessagePack named map: pending proposal, question, bound
    /// Jev verdict). Key: id16 (proposal).
    SKILL_OPTIMIZE_TRADEOFF_ASK: VaultMeta b"skill_optimize/tradeoff_ask/v1\0" Raw;
    /// Learned owner tradeoff preferences of one goal (MessagePack named map). Key: id16 (goal).
    SKILL_OPTIMIZE_TRADEOFF_PREFERENCES: VaultMeta b"skill_optimize/tradeoff_preferences/v1\0" Raw;
    /// Skill-edit gate verdict ledger row. Key: id16.
    SKILL_EDIT_VERDICT: VaultMeta b"skill_optimize/verdict/v1\0" Raw;
    /// Replacement judge revision (UTF-8) marking one skill-edit verdict as displaced. Key: id16
    /// (verdict id).
    SKILL_OPTIMIZE_DISPLACED_JUDGE: VaultMeta b"skill_optimize:displaced_judge:v1:" Raw;
    /// Fence on a displaced candidate judge revision: its replacement revision (UTF-8). Key: string
    /// (the displaced revision).
    SKILL_OPTIMIZE_DISPLACED_REVISION: VaultMeta b"skill_optimize:displaced_revision:v1:" Raw;
    /// One eval case in a seat's derivation ledger (MessagePack named map). Key: id16 (case).
    SKILL_OPTIMIZE_EVAL_CASE: VaultMeta b"skill_optimize:eval_case:v1:" Raw;
    /// One date-cut sealed eval cohort (MessagePack named map). Key: id16 (cohort).
    SKILL_OPTIMIZE_EVAL_COHORT: VaultMeta b"skill_optimize:eval_cohort:v1:" Raw;
    /// One counted serving of a sealed eval cohort (MessagePack named map). Key: id16 (cohort) +
    /// id16 (exposure).
    SKILL_OPTIMIZE_EVAL_EXPOSURE: VaultMeta b"skill_optimize:eval_exposure:v1:" Raw;
    /// One eval source family and its purpose (MessagePack named map). Key: id16 (family).
    SKILL_OPTIMIZE_EVAL_FAMILY: VaultMeta b"skill_optimize:eval_family:v1:" Raw;
    /// One owner-label ask a waiting decision put (MessagePack named map). Key: sha256 of the
    /// decision and the case.
    SKILL_OPTIMIZE_EVAL_LABEL_ASK: VaultMeta b"skill_optimize:eval_label_ask:v1:" Raw;
    /// The eval family a source root belongs to, per seat. Key: seat token + NUL + root; value:
    /// id16 (family).
    SKILL_OPTIMIZE_EVAL_ROOT: VaultMeta b"skill_optimize:eval_root:v1:" Raw;
    /// One proposed judge-calibration A/B ask (JSON). Key: bytes32 (ask id).
    SKILL_OPTIMIZE_JUDGE_ASK: VaultMeta b"skill_optimize:judge_ask:v1:" LegacyJson;
    /// One human pick over a delivered ask, the label anchor (JSON). Key: bytes32 (ask id).
    SKILL_OPTIMIZE_JUDGE_LABEL: VaultMeta b"skill_optimize:judge_label:v1:" LegacyJson;
    /// One Coach training offer snapshot for a seat (OF-577), written once. Key: id16 (offer).
    SKILL_OPTIMIZE_OFFER: VaultMeta b"skill_optimize:offer:v1:" Named;
    /// The vault owner's one answer to a training offer, with any switch or train intent. Key:
    /// id16 (offer).
    SKILL_OPTIMIZE_OFFER_ANSWER: VaultMeta b"skill_optimize:offer_answer:v1:" Named;
    /// One check of a training offer's promise against later receipts. Key: id16 (offer) + id16
    /// (check).
    SKILL_OPTIMIZE_OFFER_CHECK: VaultMeta b"skill_optimize:offer_check:v1:" Named;
    /// The amendment verdict replacing one attempt's outcome row (MessagePack map: amendment
    /// receipt, `skill_defect` share, event time). Key: the outcome row's full stored key, table
    /// prefix included.
    SKILL_RELIABILITY_AMENDED: VaultMeta b"skill_reliability:amended:v1:" Raw;
    /// Lease-bound callable invocation witness of one caller step (MessagePack map: executor,
    /// version, success, result digest). Key: id16 (skill) + u16be length + receipt string +
    /// u64be step seq.
    SKILL_RELIABILITY_CALL_INVOCATION: VaultMeta b"skill_reliability:call_invocation:v1:" Raw;
    /// Marker (MessagePack map naming the displaced and replacement judge revisions) that one
    /// outcome row's weight is superseded. Key: the outcome row's full stored key, table prefix
    /// included.
    SKILL_RELIABILITY_DISPLACED_JUDGE: VaultMeta b"skill_reliability:displaced_judge:v1:" Raw;
    /// Imported (alpha, beta) reliability base this vault's own outcome ledger cannot reproduce,
    /// node-local and never synced. Key: id16.
    SKILL_RELIABILITY_IMPORTED_BASE: VaultMeta b"skill_reliability:imported_base:v1:" Raw;
    /// The imported reliability base of one named executor's arm. Key: id16 + u16be length +
    /// executor string.
    SKILL_RELIABILITY_PAIRED_IMPORTED_BASE: VaultMeta b"skill_reliability:imported_base:v2:" Raw;
    /// Durable per-(skill, receipt) attributed-outcome ledger row, keyed so a re-run over the same
    /// judgment cannot double-count. Key: id16 + string.
    SKILL_RELIABILITY_OUTCOME: VaultMeta b"skill_reliability:outcome:v1:" Raw;
    /// The same outcome row for a named executor's arm. Key: id16 + u16be length + executor string +
    /// receipt string.
    SKILL_RELIABILITY_PAIRED_OUTCOME: VaultMeta b"skill_reliability:outcome:v2:" Raw;
    /// Durable handle for one named (agent, world) companion standing-context block. Key: hex64
    /// (blake3 of prefix+agent+world).
    STANDING_BLOCK: VaultMeta b"standing.block.v1:" LegacyJson;
    /// Blake3 digest stamp of the last claim body that produced a subject's composite state-index
    /// claim, used to detect out-of-band claim edits. Key: id16.
    AFFECT_STATE_COMPOSITE_PRODUCER: VaultMeta b"state:composite:producer:v1:" Raw;
    /// Storage ABI stamp. Key: ().
    STORAGE_ABI_VERSION: VaultMeta b"storage_abi_version" Raw;
    /// Per-generation stream receipt keyed by its receipt ref. Key: hex32 ":" hex32.
    MESSAGE_STREAM_RECEIPT_BY_REF: VaultMeta b"stream:v1:" Named;
    /// Which turns' saved tag sets name one entity, real or provisional: derived, local, never
    /// synced. Empty marker. Key: entity id16 + turn id16.
    TAGGING_MENTION_REF: VaultMeta b"tagging:mention_ref:v1:" Raw;
    /// A provisional entity the tagger's save minted on an identity-key miss: local like the tags,
    /// never synced, until it is confirmed into a real entity. Key: id16.
    TAGGING_PROVISIONAL: VaultMeta b"tagging:provisional:v1:" Named;
    /// Local identity-hint index over the provisional entities, keyed as the engine's identity
    /// index is. Empty marker. Key: kind byte + blake3(hint) + id16.
    TAGGING_PROVISIONAL_HINT: VaultMeta b"tagging:provisional_hint:v1:" Raw;
    /// One turn's saved tag set under its derivation envelope: unconfirmed mentions, the turn's
    /// mood and merge evidence. Derived, local, never synced. Key: turn id16.
    TAGGING_TAG_SET: VaultMeta b"tagging:tags:v1:" Named;
    /// Owner/question-class ask band and consumed receipt markers. Key: id16 + u16be + class [+ ':' id16].
    TASK_ASK_BAND: VaultMeta b"tasks.ask.band.v1:" Raw;
    /// Local ed25519 seed (32 bytes) that signs one ask group's option-link words. Key: id16 (group).
    TASK_ASK_LINK_SIGNER: VaultMeta b"tasks.ask.link_signer.v1:" Raw;
    /// One option-link bearer row (group, person, revision, state). Key: blake3 hash32 of the token.
    TASK_ASK_OPTION_LINK: VaultMeta b"tasks.ask.option_link.v1:" Named;
    /// A person's current option-link bearer: the full token row key. Key: id16 (group) + id16
    /// (person).
    TASK_ASK_OPTION_SEAT: VaultMeta b"tasks.ask.option_seat.v1:" Raw;
    /// `b"1"` marker that a person voided their option link. Key: id16 (group) + id16 (person).
    TASK_ASK_OPTION_VOID: VaultMeta b"tasks.ask.option_void.v1:" Raw;
    /// Highest acknowledged option-link void generation (u64be). Key: id16 (group).
    TASK_ASK_OPTION_VOID_ACK: VaultMeta b"tasks.ask.option_void_ack.v1:" Raw;
    /// Option-link void generation (u64be). Key: id16 (group).
    TASK_ASK_OPTION_VOID_GENERATION: VaultMeta b"tasks.ask.option_void_generation.v1:" Raw;
    /// Node-local ask origin entity id. Key: ().
    TASK_ASK_ORIGIN: VaultMeta b"tasks.ask.origin.v1" Raw;
    /// Per-trap ask-void proof committed before a peer-result signal: u64 BE generation. Key: id16.
    TASK_ASK_PEER_VOID_TRAP: VaultMeta b"tasks.ask.peer_void_trap.v1:" Raw;
    /// Soft-confirm notice delivery state of one guest. Key: id16 (group) + id16 (person).
    TASK_ASK_SOFT_CONFIRM_DELIVERY: VaultMeta b"tasks.ask.soft_confirm.delivery.v1/" Named;
    /// Round-robin cursor of the soft-confirm retry sweep: the last visited delivery key suffix
    /// (id16 group + id16 person). Key: ().
    TASK_ASK_SOFT_CONFIRM_DELIVERY_CURSOR: VaultMeta b"tasks.ask.soft_confirm.delivery_cursor.v1" Raw;
    /// By-owner index backfill marker. Key: ().
    TASK_BY_OWNER_BACKFILLED: VaultMeta b"tasks.by_owner.backfilled.v1" Raw;
    /// Owner's tasks forward index. Key: id16 + id16 + id16.
    TASK_BY_OWNER_FORWARD: VaultMeta b"tasks.by_owner.v1/" Raw;
    /// Marker that the one-time consult party fact migration has run. Key: ().
    TASK_CONSULT_PARTY_BACKFILLED: VaultMeta b"tasks.consult_party.backfilled.v1" Raw;
    /// Per-actor task-create rate window. Key: id16 + u64be.
    TASK_CREATE_RATE_WINDOW: VaultMeta b"tasks.create.rate.v1\0" Raw;
    /// The creator attempt a create's agent TASK lands under (OF-532): parent attempt, its project
    /// and run tag, witnessed beside a gated create's proposal or a wave planning attempt. Key: id16
    /// (the proposal claim, or the id a wave planning attempt derives).
    TASK_CREATE_ORIGIN: VaultMeta b"tasks.create_origin.v1/" Named;
    /// Presence marker: an authority fact of this task was refused at admission because its id
    /// was deleted here first, so the task's facts read as a refusal. Key: id16 (task).
    TASK_FACT_SUPPRESSED: VaultMeta b"tasks.fact_suppressed.v1/" Raw;
    /// Follow-up stage idempotency marker. Key: id16 + \x00 + string.
    TASK_FOLLOW_UP_MARKER: VaultMeta b"tasks.followup.v1\0" Raw;
    /// Owner-authority fact to forward index key. Key: id16.
    TASK_OWNER_FACT_REVERSE: VaultMeta b"tasks.owner_fact.v1/" Raw;
    /// Display handle for a peer actor. Key: id16.
    TASK_PEER_HANDLE: VaultMeta b"tasks.peer.handle.v1\0" Raw;
    /// The skill tradeoff a project ask carries: proposal, question digest, project, task, question
    /// turn and whether the gate settled it or it went void. Key: id16 (ask group).
    TASK_PROJECT_TRADEOFF_ASK: VaultMeta b"tasks.project_tradeoff.ask.v1/" Named;
    /// The home-room TURN one skill tradeoff question was witnessed as, ids reserved before the
    /// speak. Key: id16 (proposal) + id16 (project) + question digest (64 hex).
    TASK_PROJECT_TRADEOFF_TURN: VaultMeta b"tasks.project_tradeoff.turn.v1/" Named;
    /// One try's journaled report: the request and the receipt it was first answered with.
    /// Key: id16 (attempt) + u64 (attempt count) + bytes32 (reporter, TASK and report key).
    TASK_REPORT_JOURNAL: VaultMeta b"tasks.report.journal.v1/" Named;
    /// Task symbol-overlap declaration. Key: id16.
    TASK_SYMBOL_LEASE: VaultMeta b"tasks.symbol_lease.v1/" LegacyJson;
    /// Registered external ask wait. Key: id16 + bytes32.
    TASK_ASK_WAIT: VaultMeta b"tasks.wait/" Named;
    /// Consult fan-out plan. Key: hex32.
    TASK_FANOUT_RUN: VaultMeta b"tasks/fanout/v1/" Named;
    /// Retired consult fan-out policy carrier; the policy manifest now governs.
    /// Declared so bytes written by older engines stay owned. Key: ().
    TASK_FANOUT_POLICY: VaultMeta b"tasks/fanout_policy/v1" Named;
    /// One run's market: signed referee, lease shares, central ledger, submissions and result.
    /// Key: string (team reference).
    TEAM_MARKET: VaultMeta b"team:market:v1:" Named;
    /// A workflow skill's binding to the coordination pattern it teaches, with its works-well-for
    /// line. Key: id16 (skill entity).
    TEAM_PATTERN_SKILL: VaultMeta b"team:pattern_skill:v1:" Named;
    /// One team run's receipt (type, pattern, models, shape, who decided, coverage, confessions,
    /// anchored outcome). Key: string (team reference).
    TEAM_RECEIPT: VaultMeta b"team:receipt:v1:" Named;
    /// The pinned text analyzer manifest (JSON) and, under '_hash', its SHA-256. Key: string.
    TEXT_ANALYZER_MANIFEST: VaultMeta b"text_analyzer_manifest" Raw;
    /// BM25F field schema hash. Key: ().
    TEXT_BM25_FIELD_SCHEMA_HASH: VaultMeta b"text_bm25_field_schema_hash" Raw;
    /// Text-index schema version stamp. Key: ().
    TEXT_INDEX_SCHEMA_VERSION: VaultMeta b"text_index_schema_version" Raw;
    /// Current owner-approved training checkpoint per model role. Key: serialized role string.
    TRAINING_PACK_ROLE: VaultMeta b"training_pack:role:v1:" Named;
    /// Pinned corpus, compute, dispatch and evaluation of one training job. Key: id16 (run).
    TRAINING_PACK_RUN: VaultMeta b"training_pack:run:v1:" Named;
    /// Immutable owner-approved role-swap receipt. Key: id16 (receipt).
    TRAINING_PACK_SWAP: VaultMeta b"training_pack:swap:v1:" Named;
    /// One open, answered or superseded "may I reach your trusted contact?" ask, raised by a
    /// `RouteToHelp` the person's dial or the row's tier says to ask about first. Key: id16(ask).
    TRUSTED_CONTACT_ASK: VaultMeta b"trusted_contact.ask.v1:" Named;
    /// One trusted-contact notice the engine staged, by its fire ref: the witness that claim and
    /// dispatch require, so a notice queued any other way is never sent. Key: id16(fire).
    TRUSTED_CONTACT_FIRE: VaultMeta b"trusted_contact.fire.v1:" Named;
    /// A person's trusted contact: the PERSON named, how to reach them, the fixed notice, the
    /// dial, and both sides' consent or revocation. Key: id16(person) + id16(contact).
    TRUSTED_CONTACT_RELATION: VaultMeta b"trusted_contact.relation.v1:" Named;
    /// The trusted-contact tier the owner gave one `RouteToHelp` policy row. Key: string (row ref).
    TRUSTED_CONTACT_TIER: VaultMeta b"trusted_contact.tier.v1:" Named;
    /// A typed body's Loro snapshot at its head. Key: id16 (entity).
    TYPED_BODY_DOC: VaultMeta b"typed_body:doc:v1:" Raw;
    /// Work on a typed body away from its head: opener, base frontier and state. Key: id16
    /// (entity) + id16 (fork).
    TYPED_BODY_FORK: VaultMeta b"typed_body:fork:v1:" Named;
    /// An open typed-body fork's Loro snapshot. Key: id16 (entity) + id16 (fork).
    TYPED_BODY_FORK_DOC: VaultMeta b"typed_body:fork_doc:v1:" Raw;
    /// An entity's typed body: its schema tag, birth and head frontiers and commit count. Key:
    /// id16 (entity).
    TYPED_BODY_HEAD: VaultMeta b"typed_body:head:v1:" Named;
    /// A standing artifact question's last ask of one artifact: the head versions it read and
    /// the proposal its answers wait under. Key: id16(question) + id16(artifact).
    TYPED_QUESTION_ARTIFACT_ASKED: VaultMeta b"typed_question:artifact_asked:v1:" Named;
    /// Typed question versions, heads, answers and labels. Key: id16(question) ":version:" u32be.
    /// Pending refresh for a question/unit pair. Key: id16(question) + id16(unit).
    TYPED_QUESTION_PENDING: VaultMeta b"typed_question:pending:v1:" Raw;
    /// What a standing answer rests on beyond its unit, as a source-to-root refresh watcher (an
    /// edit to a neighbour queues the root's arrival). Key: id16(source) + id16(question) +
    /// id16(unit).
    TYPED_QUESTION_RESTS_ON: VaultMeta b"typed_question:rests_on:v1:" Raw;
    /// The sources a unit's latest standing answer rests on, so the next answer replaces their
    /// watchers. Key: id16(question) + id16(unit).
    TYPED_QUESTION_ROOT_SOURCES: VaultMeta b"typed_question:root_sources:v1:" Named;
    /// Unit-to-question refresh watcher. Key: id16(unit) + id16(question).
    TYPED_QUESTION_UNIT_WATCH: VaultMeta b"typed_question:unit:v1:" Raw;
    TYPED_QUESTION: VaultMeta b"typed_question:v1:" Named;
    /// Reverse watch index from an outcome predicate to the questions learning from it. Key:
    /// string(predicate) "\x00" id16(question).
    TYPED_QUESTION_WATCH: VaultMeta b"typed_question:watch:v1:" Raw;
    /// Legacy per-entity VAD annotation metadata row (entity_type byte then subject id); no current
    /// write path, only read and deleted for headerless-delete cleanup. Key: u8 + id16.
    AFFECT_VAD_ANNOTATION_META: VaultMeta b"vad_ann:" Named;
    /// Archives a vault that shares key custody with another: the image a restore in its place
    /// set aside, and the replacement until it is in that place. An archived vault's handles
    /// refuse every write until an owner activates it as a side vault. Runtime, never
    /// checkpointed. Value: the byte 1 (archived wherever it is), or the byte 2 and an encoded
    /// canonical root (archived unless it is at that root). Key: ().
    VAULT_ARCHIVED_BY_RESTORE: VaultMeta b"vault_archived:v1" Raw;
    /// Marks a completed queue-record attempt as archived, pinned to the exact bytes archived. Key:
    /// id16 (AttemptId).
    VAULT_CLEANUP_ATTEMPT_ARCHIVE: VaultMeta b"vault_cleanup.attempt_archive.v1/" Raw;
    /// One recorded vault-cleanup decision (accepted/auto), listing archived and skipped candidates.
    /// Key: id16.
    VAULT_CLEANUP_DIGEST: VaultMeta b"vault_cleanup.digest.v1:" Raw;
    /// Mint-time evidence pinning a PERSON as extraction-produced and eligible for the claimless-
    /// person cleanup arm. Key: id16 (PERSON id).
    VAULT_CLEANUP_EXTRACTION_PERSON: VaultMeta b"vault_cleanup.extraction_person.v1:" Raw;
    /// Owner-set cleanup posture: propose-first (default) vs auto-with-digest. Key: ().
    VAULT_CLEANUP_POSTURE: VaultMeta b"vault_cleanup.posture.v1" Raw;
    /// Open vault-cleanup archive proposal awaiting owner accept/reject. Key: id16.
    VAULT_CLEANUP_PROPOSAL: VaultMeta b"vault_cleanup.proposal.v1:" Raw;
    /// Durable cleanup-scan result for one attempt, closing the job-commit-to-queue-settlement crash
    /// gap. Key: id16 (AttemptId).
    VAULT_CLEANUP_RUN: VaultMeta b"vault_cleanup.run.v1:" Raw;
    /// Rotating per-arm scan cursor (one row per CLEANUP_CHECKS entity type, plus one literal
    /// "attempt" row for the completed-queue-record arm); both suffix shapes share this one prefix by
    /// design and cannot collide (1 byte vs 7 ASCII bytes). Key: u8 (entity-type byte) OR literal
    /// string "attempt".
    VAULT_CLEANUP_SCAN_CURSOR: VaultMeta b"vault_cleanup.scan.v1:" Raw;
    /// Index of archived attempts under one TASK, used to restore them together when the task is
    /// touched. Key: string (task hex) "/" id16 (AttemptId).
    VAULT_CLEANUP_TASK_ATTEMPT_ARCHIVE: VaultMeta b"vault_cleanup.task_attempt_archive.v1/" Raw;
    /// Owner-adjustable retention period for completed TASK queue records before archival
    /// eligibility. Key: ().
    VAULT_CLEANUP_TASK_RETENTION_DAYS: VaultMeta b"vault_cleanup.task_retention_days.v1" Raw;
    /// Test-only marker that closes the automatic-cleanup release blockers. Key: ().
    VAULT_CLEANUP_TEST_BLOCKERS_CLOSED: VaultMeta b"vault_cleanup.test_blockers_closed" Raw;
    /// Random 32-byte identity of this store, minted at its first open and compared by every
    /// same-vault check; node-local and never synced, so a replica holds its own. Key: ().
    VAULT_IDENTITY_LOCAL: VaultMeta b"vault_identity:local:v1" Raw;
    /// The blake3 of the escrow capsule each escrow wrap last handed to the host's outbound spool
    /// (OF-570, CROSS-ARCH-0022 invariant 03). Key: string (wrap id).
    VAULT_KEY_ESCROW_SPOOLED: VaultMeta b"vault_key:escrow_spooled:v1:" Named;
    /// The vault data key's commitment and birth (OF-570 E1). Never the key. Key: ().
    VAULT_KEY_STATE: VaultMeta b"vault_key:state:v1" Named;
    /// One way to unlock the vault data key: an E0 `VaultDek` envelope and its public
    /// metadata. Key: string (wrap id).
    VAULT_KEY_WRAP: VaultMeta b"vault_key:wrap:v1:" Named;
    /// Voice reference pack. Key: string (pack id).
    VOICE_OWNER_REF: VaultMeta b"voice:owner_ref:v1:" Named;
    /// Per-owner index over voice reference bank rows. Key: id16 (owner) + the indexed row's full
    /// key.
    VOICE_OWNER_REF_OWNER_INDEX: VaultMeta b"voice:owner_ref_owner:v1:" Raw;
    /// Voice identity over its reference packs. Key: string (voice id).
    VOICE_REF_IDENTITY: VaultMeta b"voice:ref_identity:v1:" Named;
    /// Voice identity incarnation (16 random bytes), fresh at every birth. Key: string (voice id).
    VOICE_REF_INCARNATION: VaultMeta b"voice:ref_incarnation:v1:" Raw;
    /// A banked voice's current render/provisioning consent decision, apart from recognition
    /// consent. Key: string (voice id).
    VOICE_REF_RENDER_CONSENT: VaultMeta b"voice:ref_render_consent:v1:" Named;
    /// Cached voice render-target pointer. Key: string (voice id) "\0" string (target).
    VOICE_REF_TARGET: VaultMeta b"voice:ref_target:v1:" Named;
    /// Voice consent decision event. Key: id16 + digest16.
    VOICE_IDENTITY_CONSENT: VaultMeta b"voice_identity.consent.v1:" Raw;
    /// Voice print records and the active-space pointer per subject. Key: id16 [+ digest16].
    VOICE_IDENTITY_PRINT: VaultMeta b"voice_identity.print.v1:" Raw;
    /// Resolved session speaker roster. Key: digest16.
    VOICE_IDENTITY_ROSTER: VaultMeta b"voice_identity.roster.v1:" Raw;
    /// Enrollment sample row. Key: digest16.
    VOICE_IDENTITY_SAMPLE: VaultMeta b"voice_identity.sample.v1:" Raw;
    /// Wave-plan cut index. Key: bytes32.
    TASK_WAVE_PLAN_INDEX: VaultMeta b"wave.task.v1/" Raw;
    /// Weave digest of one reader. Key: reader kind byte + id16 + u64be.
    WEAVE_DIGEST: VaultMeta b"weave:digest:v1:" Raw;
    /// Source-to-digest invalidation index. Key: source id16 ‖ digest key.
    WEAVE_DIGEST_SOURCE: VaultMeta b"weave:digest_source:v1:" Raw;
    /// Weave digest schedule of one reader. Key: reader kind byte + id16.
    WEAVE_DIGEST_SCHEDULE: VaultMeta b"weave:schedule:v1:" Raw;
    /// One immutable wrong-link label filed from a live weave report. Key: edge ref (33 bytes) +
    /// id16 (label receipt id).
    WEAVE_WRONG_LINK_LABEL: VaultMeta b"weave:wrong-link:v1:" Named;
    /// Guards a companion PERSON against being claimed by a second principal's onboarding. Key: id16
    /// (companion person id).
    WORKSPACE_ROSTER_COMPANION_PRINCIPAL: VaultMeta b"workspace_roster:companion_principal:v1:" Raw;
    /// One onboarded member's roster row (actor, optional companion person/actor/facet, identity).
    /// Key: string (workspace_ref) "\x00" hex32 (person id).
    WORKSPACE_ROSTER_MEMBER: VaultMeta b"workspace_roster:member:v1:" Raw;
    /// Guards one member's workspace-onboarding slot against a second onboarding with different
    /// inputs. Key: string (workspace_ref) "\x00" id16 (person id).
    WORKSPACE_ROSTER_MEMBER_INTENT: VaultMeta b"workspace_roster:member_intent:v1:" Raw;
    /// Idempotency journal tracking one member-onboarding request's progress through the pinned step
    /// ladder. Key: string (caller-supplied onboarding_id).
    WORKSPACE_ONBOARDING: VaultMeta b"workspace_roster:onboarding:v1:" Raw;
    /// Per-workspace roster preset (org, venture name, house actor/identity, house display name).
    /// Key: string (workspace_ref).
    WORKSPACE_ROSTER_PRESET: VaultMeta b"workspace_roster:preset:v1:" Raw;
    /// Permanent fact that a world's keys were destroyed with the world, with its ids-only
    /// receipt. Refuses a late pad, a remint and an open for that world. Key: id16 hex (world).
    WORLD_KEY_DESTROYED: VaultMeta b"world_keys:destroyed:v1:" Named;
    /// A reader's own Loro document of one sealed private-world window: the history its sealed
    /// packets continue. Purged with the world. Key: hex32 (world) ":" string (window label).
    WORLD_KEY_SEALED_MIRROR: VaultMeta b"world_keys:mirror:v1:" Raw;
    /// When a shelved sealed packet was retired (u64be vault seconds); it is purged 30 days on.
    /// Key: hex64 (tag) ":" hex64 (packet digest).
    WORLD_KEY_SEALED_RETIRED: VaultMeta b"world_keys:sealed-retired:v1:" Raw;
    /// The newest shelved sealed packet of one window (its shelf id, `tag:digest` hex), so a
    /// relay node that may not read the world can answer a reader's request for that window.
    /// Key: string (window label).
    WORLD_KEY_SEALED_WINDOW: VaultMeta b"world_keys:sealed-window:v1:" Raw;
    /// One sealed packet of a private world's window, kept for a reader by a node that may not
    /// read the world (OF-570). Key: hex64 (tag) ":" hex64 (packet digest).
    WORLD_KEY_SEALED: VaultMeta b"world_keys:sealed:v1:" Raw Ciphertext;
}
