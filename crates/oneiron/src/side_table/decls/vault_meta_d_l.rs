// Declared `vault_meta` tables whose prefix starts with `d` to `l`, in prefix order.

side_tables! {
    VAULT_META_D_L;
    /// Immutable account/organization owner binding used to scope hosted derivation caches for this
    /// vault. Key: ().
    DERIVATION_OWNER: VaultMeta b"derivation:owner:v1" Raw;
    /// Enforcement-truth per-counterparty-contact disclosure scope row (rmpv-encoded), dual-written
    /// with an owner-visible claim. Key: id16.
    DISCLOSURE_SCOPE: VaultMeta b"disclosure.scope.v1:" Raw;
    /// Owner Tier-A mark row for an entity (value = marked_at u64 LE), dual-written with an owner-
    /// visible claim. Key: id16.
    DISCLOSURE_TIER_A: VaultMeta b"disclosure.tier_a.v1:" Raw;
    /// Classifier-derived annotation (derivation envelope + annotation body) for one imported docs
    /// page/asset. Key: hex32 ":" hex32.
    INGEST_DOCS_ANNOTATION: VaultMeta b"docs-annotation:v1:" LegacyJson;
    /// Stable-ref index from a deterministic docs-extraction id (corpus/page/segment) to the minted
    /// entity id. Key: string.
    INGEST_DOCS_EXTRACTION: VaultMeta b"docs-extraction:v1:" Raw;
    /// Set of chunk/summary member content-refs recorded for one imported docs asset. Key: hex32.
    INGEST_DOCS_MEMBERSHIP: VaultMeta b"docs-membership:v1:" LegacyJson;
    /// Private binding proving an SDK-facing detached step (no engine-owned run) belongs to its
    /// actor/subject/step hash. Key: id16(attempt).
    DREAMER_DETACHED_STEP: VaultMeta b"dreamer.detached_step.v1/" Raw;
    /// Marker that the one-time durable-milestone-index backfill pass has run. Key: ().
    DREAMER_MILESTONE_INDEX_BACKFILLED: VaultMeta b"dreamer.milestone_index.v1.backfilled" Raw;
    /// Durable milestone-index candidate row (empty-value marker) for an attempt, ordered by (at,
    /// learned_at, claim_id); only indexed once the milestone claim is bound to its attempt. Key:
    /// id16 + u64be + u64be + id16.
    DREAMER_MILESTONE_INDEX_CANDIDATE: VaultMeta b"dreamer.milestone_index.v1.c:" Raw;
    /// Pointer from a milestone claim id back to its DREAMER_MILESTONE_INDEX_CANDIDATE row key. Key:
    /// id16.
    DREAMER_MILESTONE_INDEX_CLAIM: VaultMeta b"dreamer.milestone_index.v1.i:" Raw;
    /// Pointer to the single vault-owned Dreamer principal actor entity id. Key: ().
    DREAMER_AUTHORITY_ACTOR: VaultMeta b"dreamer:authority:v1:actor" Raw;
    /// Stamp binding one attempt id to the Dreamer principal, facet, and gate-decision receipt that
    /// admitted it. Key: id16.
    DREAMER_AUTHORITY_ATTEMPT: VaultMeta b"dreamer:authority:v1:attempt:" LegacyJson;
    /// Named token-budget counter row (total/remaining/reserved units) keyed by budget id. Key:
    /// string.
    DREAMER_BUDGET: VaultMeta b"dreamer:budget:" Raw;
    /// Reservation of budget units against one child attempt, keyed by (budget id, attempt id). Key:
    /// u16be + string + id16.
    DREAMER_BUDGET_RESERVATION: VaultMeta b"dreamer:budget_reservation:" Raw;
    /// Operator-set predicate key rules governing which claim keys the consolidator may fold;
    /// defaults from key_defaults.json when absent. Key: ().
    DREAMER_CONSOLIDATION_KEY_RULES: VaultMeta b"dreamer:consolidation:keys:v1" LegacyJson;
    /// Operator-set consolidation candidate-selection config (strength weights, caps). Key: ().
    DREAMER_CONSOLIDATION_SELECTION: VaultMeta b"dreamer:consolidation:selection:v1" LegacyJson;
    /// Private run-tree-scoped critique artifact for one branch attempt, keyed by attempt id and
    /// artifact id; written independently by both the generic critic reviewer and the Dreamer
    /// tournament with the identical prefix and key layout (see WHERE) - worth a second look for
    /// accidental collision if the same (attempt, artifact_id) pair is ever used from both callers.
    /// Key: id16 + u16be + string.
    CRITIC_ARTIFACT: VaultMeta b"dreamer:critic:v1:" Named;
    /// Per-scope, per-partition consolidation cursor row. Key: u8 + hash32.
    DREAMER_CURSOR: VaultMeta b"dreamer:cursor:v1:" Raw;
    /// Branch-scoped reflection-gap queue namespaced by partition hash and the branch's
    /// relationship/project scope axes. Key: hex64 ":" hex32-or-"none" ":" hex32-or-"none" ":"
    /// hash32.
    DREAMER_GAP_BRANCH: VaultMeta b"dreamer:gap-branch:v1:" Raw;
    /// Global reflection-gap queue row keyed by a hash of (kind, subject). Key: hash32.
    DREAMER_GAP: VaultMeta b"dreamer:gap:v1:" Raw;
    /// Prior tuning-harness evaluation baseline for a config artifact, used to reject
    /// stale/regressive re-evaluation. Key: id16.
    DREAMER_HARNESS_EVAL_BASELINE: VaultMeta b"dreamer:harness:eval-baseline:v1:" LegacyJson;
    /// Elected MACRO-scope home-node designation (node_id, class, elected_at). Key: ().
    DREAMER_HOME_NODE: VaultMeta b"dreamer:home_node_macro:v1" Raw;
    /// Parked (paused) attempt row (reason, park_owner, parked_at) keyed by attempt id. Key: id16.
    DREAMER_PARKED: VaultMeta b"dreamer:parked:" Raw;
    /// Private step-only wait binding for one (task, trap) pair. Key: id16(task ref) + id16(trap
    /// ref).
    DREAMER_PEER_WAIT: VaultMeta b"dreamer:peer_wait:v1:" Raw;
    /// Reverse pointer from a peer-wait trap anchor claim to its bound task ref. Key: id16(trap
    /// anchor claim).
    DREAMER_PEER_WAIT_TRAP: VaultMeta b"dreamer:peer_wait_trap:v1:" Raw;
    /// Dreamer prefilter screening policy. Key: ().
    PREFILTER_CONFIG: VaultMeta b"dreamer:prefilter:config:v1" Named;
    /// Turn to screening round index. Key: string ":" id16.
    PREFILTER_MEMBER: VaultMeta b"dreamer:prefilter:member:v1:" Raw;
    /// Prefilter round rollup. Key: bytes32.
    PREFILTER_ROUND: VaultMeta b"dreamer:prefilter:round:v1:" Named;
    /// Prefilter skip receipt. Key: bytes32 + id16.
    PREFILTER_SKIP: VaultMeta b"dreamer:prefilter:skip:v1:" Named;
    /// One emitted proactivity digest, keyed by its content-derived id. Key: hash32.
    DREAMER_PROACTIVITY_DIGEST: VaultMeta b"dreamer:proactivity:digest:v1:" LegacyJson;
    /// Rolling proactivity-digest emission state (last_emitted timestamp). Key: ().
    DREAMER_PROACTIVITY_STATE: VaultMeta b"dreamer:proactivity:state:v1" LegacyJson;
    /// Owner approval/decline record for a representation proposal review. Key: id16.
    DREAMER_REPRESENTATION_APPROVAL: VaultMeta b"dreamer:representation:v1:approval:" LegacyJson;
    /// Evidence-citing user-voice representation proposal record, keyed by proposal claim id. Key:
    /// id16.
    DREAMER_REPRESENTATION_PROPOSAL: VaultMeta b"dreamer:representation:v1:proposal:" LegacyJson;
    /// Parent/child attempt-tree edge row (parent_attempt, created_at) keyed by attempt id. Key:
    /// id16.
    DREAMER_RUN_TREE: VaultMeta b"dreamer:run_tree:" Raw;
    /// Pinned effective scope attenuation bound to one Dreamer attempt, inherited by retry
    /// successors. Key: id16.
    DREAMER_SELECTION_SCOPE: VaultMeta b"dreamer:selection_scope:v1:" LegacyJson;
    /// Dreamer step index rows, plus the 'i:' sub-index. Key: bytes.
    DREAMER_STEP_INDEX: VaultMeta b"dreamer:step_index:v1:" Raw;
    /// Device-local step progression state (Started/ResponseReceived/Logged); never synced. Key:
    /// id16(attempt) + hash32(step).
    DREAMER_STEP_STATE: VaultMeta b"dreamer:step_state:v1:" Raw;
    /// Per-round branch tournament evidence row (verdict, synthesis/critique/veto artifact ids) for
    /// one candidate. Key: u16be+string(run_id) + id16 + u16be + u8 + u16be+string(candidate_ref).
    DREAMER_TOURNAMENT_EVIDENCE: VaultMeta b"dreamer:tournament:v1:" Named;
    /// Private binding of a Budget/Consent trap anchor claim to its owning step. Key: id16(anchor
    /// claim).
    DREAMER_TRAP_BINDING: VaultMeta b"dreamer:trap_binding:v1:" Raw;
    /// Per-scope (micro/meso/macro) consolidation watermark: last learned_at/turn_id progress. Key:
    /// u8.
    DREAMER_WATERMARK: VaultMeta b"dreamer:watermark:v1:" Raw;
    /// Write-once Δ side-ledger row for one receipt: a captured edit-distance measurement (canonical
    /// JSON), or the literal marker "uncaptured" when capture was attempted and failed. Key: string.
    EDIT_DISTANCE_AMENDMENT_DELTA: VaultMeta b"edit_distance/amendment_delta/v1\0" Raw;
    /// Recorded routing/attribution evidence for one amendment receipt. Key: string.
    EDIT_DISTANCE_AMENDMENT_EVIDENCE: VaultMeta b"edit_distance/amendment_evidence/v1\0" Raw;
    /// Judge-routed classification of one amendment's edit distance/preference class. Key: string.
    EDIT_DISTANCE_AMENDMENT_JUDGMENT: VaultMeta b"edit_distance/amendment_judgment/v1\0" Raw;
    /// Live edit-cost head for a (predicate, subject, scope) tuple; the retraction ledger for re-
    /// judged receipts. Key: string "\x00" hex32 "\x00" string.
    EDIT_DISTANCE_EDIT_COST_TARGET: VaultMeta b"edit_distance/edit_cost_target/v1\0" Raw;
    /// Dial: agreeing-ruling count needed to auto-propose a standing escalation policy. Key: ().
    EDIT_DISTANCE_ESCALATION_STANDING_N: VaultMeta b"edit_distance/escalation/standing_n/dial/v1" Raw;
    /// Append-only ruled-escalation ledger row, scope-major (scope digest then UUIDv7 row id) so one
    /// scope's history is a contiguous range. Key: id16 + id16.
    EDIT_DISTANCE_ESCALATION: VaultMeta b"edit_distance/escalation/v1\0" Raw;
    /// Standing escalation policy for one (scope, trigger) pair, keyed by what the row governs. Key:
    /// id16 + u8.
    EDIT_DISTANCE_ESCALATION_POLICY: VaultMeta b"edit_distance/escalation_policy/v1\0" Raw;
    /// Publisher digest-interview session state, keyed by the digest artifact id. Key: id16.
    EDIT_DISTANCE_INTERVIEW_SESSION: VaultMeta b"edit_distance/interview_session/v1\0" Raw;
    /// Stored publisher issue-signature (category, artifact, version, model, counts, content hash).
    /// Key: id16.
    EDIT_DISTANCE_ISSUE_SIGNATURE: VaultMeta b"edit_distance/issue_signature/v1\0" Raw;
    /// Send-state token (pending/sent/etc) for a publisher issue signature. Key: id16.
    EDIT_DISTANCE_ISSUE_SIGNATURE_SEND: VaultMeta b"edit_distance/issue_signature_send/v1\0" Raw;
    /// Persisted amendment-judge audit report (total/passed/abstained), ordered oldest-first by (at,
    /// sequence). Key: u64be + u64be.
    EDIT_DISTANCE_JUDGE_AUDIT: VaultMeta b"edit_distance/judge_audit/v1\0" Raw;
    /// Monotonic counter behind EDIT_DISTANCE_JUDGE_AUDIT's sequence half. Key: ().
    EDIT_DISTANCE_JUDGE_AUDIT_SEQUENCE: VaultMeta b"edit_distance/judge_audit_sequence/v1" Raw;
    /// Mint-mark preventing a re-mint of the same substitution cluster, keyed by cluster handle. Key:
    /// hash32.
    EDIT_DISTANCE_MINER_MINT_MARK: VaultMeta b"edit_distance/miner_mint_mark/v1\0" Raw;
    /// Mined skill-edit proposal awaiting owner decision, keyed by proposal id. Key: id16.
    EDIT_DISTANCE_MINER_SKILL_EDIT: VaultMeta b"edit_distance/miner_skill_edit/v1\0" Raw;
    /// Global work-gate watermark for the substitution-miner pass. Key: ().
    EDIT_DISTANCE_MINER_WATERMARK: VaultMeta b"edit_distance/miner_watermark/v1" Raw;
    /// Minted phrasing/preference proposal born from a judged amendment. Key: string.
    EDIT_DISTANCE_PREFERENCE_PROPOSAL: VaultMeta b"edit_distance/preference_proposal/v1\0" Raw;
    /// Immutable owner-bound decision on an inbox/amendment intake item, keyed by receipt id. Key:
    /// string.
    EDIT_DISTANCE_PRINCIPAL_DECISION: VaultMeta b"edit_distance/principal_decision/v1\0" Raw;
    /// Finalized proposal-text artifact (span attributions, actor/class per span), write-once keyed
    /// by artifact ref. Key: id16.
    EDIT_DISTANCE_PROPOSAL_ARTIFACT: VaultMeta b"edit_distance/proposal_artifact/v1\0" Raw;
    /// Rebuildable training-reservoir candidate index row, keyed by the proposal artifact's entity
    /// id. Key: id16.
    EDIT_DISTANCE_RESERVOIR_CANDIDATE: VaultMeta b"edit_distance/reservoir_candidate/v1\0" Raw;
    /// Training-reservoir export-receipt ledger row. Key: id16.
    EDIT_DISTANCE_RESERVOIR_EXPORT: VaultMeta b"edit_distance/reservoir_export/v1\0" Raw;
    /// Per-(task class, model version) routing score aggregate. Key: string "\x00" string.
    EDIT_DISTANCE_ROUTING_AGGREGATE: VaultMeta b"edit_distance/routing_aggregate/v1\0" Raw;
    /// Run-to-generation membership binding, keyed by receipt id. Key: string.
    EDIT_DISTANCE_ROUTING_MEMBER: VaultMeta b"edit_distance/routing_member/v1\0" Raw;
    /// Per-task-class rollout rung state. Key: string.
    EDIT_DISTANCE_ROUTING_RUNG: VaultMeta b"edit_distance/routing_rung/v1\0" Raw;
    /// Model-version stamp new routing folds are recorded against. Key: ().
    EDIT_DISTANCE_ROUTING_SERVING_MODEL: VaultMeta b"edit_distance/routing_serving_model/v1" Raw;
    /// Stranded edit proposal. Key: id16 + hash32.
    EDIT_SETTLE_STRANDED_PROPOSAL: VaultMeta b"edit_settle:stranded:v1:" Named;
    /// Where the current reconciled embedding vector was filled (on-device/owner-server/third-party).
    /// Key: id16.
    EMBEDDING_LOCALITY: VaultMeta b"embedding/locality/" Raw;
    /// Pointer from an entity to its owning document, plus generation/pending-update counters. Key:
    /// hex32.
    ENTITY_DOC_HEAD: VaultMeta b"entity_doc:v1:head:" Named;
    /// Retained revision history document. Key: id16.
    ENTITY_REVISION_DOC: VaultMeta b"entity_revision:doc:" Raw;
    /// Pinned revision frontier. Key: id16 + rev16.
    ENTITY_REVISION_FRONTIER: VaultMeta b"entity_revision:frontier:" Raw;
    /// Revision hash to owning entity. Key: rev16.
    ENTITY_REVISION_IDENTITY: VaultMeta b"entity_revision:identity:" Raw;
    /// Staged text/vector index inputs. Key: id16.
    ENTITY_REVISION_PENDING_INDEX_INPUTS: VaultMeta b"entity_revision:index_inputs:" Named;
    /// Staged phonetic codes. Key: id16.
    ENTITY_REVISION_PENDING_PHONETIC: VaultMeta b"entity_revision:phonetic:" Named;
    /// Live vs indexed revision pointers. Key: id16.
    ENTITY_REVISION_STATE: VaultMeta b"entity_revision:state:" Named;
    /// Esign machine actor id. Key: ().
    ESIGN_ARTIFACT_ACTOR: VaultMeta b"esign.artifact_actor.v1" Raw;
    /// Esign document audit event. Key: id16 + u64be.
    ESIGN_AUDIT: VaultMeta b"esign.audit.v1/" LegacyJson;
    /// Signing capability row. Key: bytes32.
    ESIGN_CAPABILITY_TOKEN: VaultMeta b"esign.capability.v1/" LegacyJson;
    /// Esign outbound dispatch marker. Key: bytes32.
    ESIGN_DISPATCH_MARKER: VaultMeta b"esign.dispatch.v1/" Raw;
    /// Signature image byte budget. Key: id16.
    ESIGN_IMAGE_BYTES_BUDGET: VaultMeta b"esign.image_bytes.v1/" Raw;
    /// Signing principal set owner stamp. Key: ().
    ESIGN_PRINCIPAL_OWNER_STAMP: VaultMeta b"esign.principal.owner_stamp.v1" Raw;
    /// Signing principal. Key: hex32.
    ESIGN_PRINCIPAL: VaultMeta b"esign.principal.v1/" LegacyJson;
    /// Public ceremony rate counter. Key: hex32 [/ string].
    ESIGN_PUBLIC_RATE: VaultMeta b"esign.public_rate.v1/" Raw;
    /// Recipient live capability index. Key: id16 + string.
    ESIGN_RECIPIENT_CAPABILITY_INDEX: VaultMeta b"esign.recipient_capability.v1/" Raw;
    /// Completed seal attempt result. Key: id16.
    ESIGN_SEAL_RESULT: VaultMeta b"esign.seal_result.v1/" LegacyJson;
    /// Sealed document manifest. Key: id16.
    ESIGN_SEALED_DOCUMENT: VaultMeta b"esign.sealed.v1/" LegacyJson;
    /// Signature image ownership marker. Key: id16 + string + string.
    ESIGN_SIGNATURE_IMAGE_BINDING: VaultMeta b"esign.signature_image.v1/" Raw;
    /// Binding proof tying a restored foreign expression-preference claim to the exact local row it
    /// reconstructed. Key: id16.
    EXPRESSION_ARCHIVE_BINDING: VaultMeta b"expression/archive-binding/v1\0" Raw;
    /// Open feedback-review-item queue row awaiting triage. Key: id16.
    FEEDBACK_QUEUE: VaultMeta b"feedback:queue:v1:" Named;
    /// Dedup index from a feedback bundle's content digest to the review item id that first recorded
    /// it. Key: hex64.
    FEEDBACK_RECEIVED_DIGEST: VaultMeta b"feedback:received:v1:" Raw;
    /// Per-actor foreign-introduction ceiling and widen state for an owner-bound agent introduction.
    /// Key: id16.
    GATE_FOREIGN_AGENT_INTRODUCTION: VaultMeta b"gate.foreign-agent.v1:" Named;
    /// Cached configuration window (seconds) for the receipt-derived auto-checker signal; no engine
    /// write path found in this repo, likely operator-provisioned. Key: ().
    GATE_AUTO_SIGNALS_WINDOW: VaultMeta b"gate:auto_signals:window:v1" LegacyJson;
    /// Per-claim critical confirm invalidation. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice): decode also checks the version
    /// byte and rejects an all-zero claim id, business validation `Named`'s
    /// generic strict-msgpack decode does not run; `RawValue` delegates to
    /// the module's own `encode_critical_confirm_invalidation`/
    /// `decode_critical_confirm_invalidation`.
    CRITICAL_CONFIRM_INVALIDATION: VaultMeta b"gate_critical_invalidation:v0:" Raw;
    /// Grant-reference index over the gate decision ledger. Key: u64be len + string + id16.
    GATE_DECISION_GRANT_REF_INDEX: VaultMeta b"gate_decision:grant_ref_index:v1:" Raw;
    /// Gate decision ledger row. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice): decode also enforces
    /// `vet_gate_decision_record` (version, notice, receipt-reason and
    /// redaction-shape checks), business validation `Named`'s generic
    /// strict-msgpack decode does not run; `RawValue` delegates to the
    /// module's own `encode_gate_decision`/`decode_gate_decision`.
    GATE_DECISION_LEDGER: VaultMeta b"gate_decision:v0:" Raw;
    /// Claim-keyed gate decision index. Key: id16 + id16.
    GATE_DECISION_CLAIM_INDEX: VaultMeta b"gate_decision_by_claim:v0:" Raw;
    /// Claim-index backfill flag. Key: ().
    GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE: VaultMeta b"gate_decision_by_claim_backfill_complete" Raw;
    /// Staged deletion authority decision sidecar. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice): decode also enforces
    /// `vet_pending_deletion_gate_decision_record`, a business check
    /// `Named`'s generic strict-msgpack decode does not run; `RawValue`
    /// delegates to the module's own `encode_pending_deletion_gate_decision`/
    /// `decode_pending_deletion_gate_decision`.
    GATE_DELETE_PENDING_SIDECAR: VaultMeta b"gate_delete_pending:v0:" Raw;
    /// Local deletion tombstone needs an authority sidecar. Key: id16.
    GATE_DELETE_REQUIRED_MARKER: VaultMeta b"gate_delete_required:v0:" Raw;
    /// Critical-write confirm id to pending claim. Key: bytes32.
    CRITICAL_CONFIRM_INDEX: VaultMeta b"gate_pending:critical_confirm_by_id:v1:" Raw;
    /// Critical confirm expiry sweep state. Key: ().
    CRITICAL_CONFIRM_EXPIRY_CURSOR: VaultMeta b"gate_pending:critical_confirm_expiry_cursor:v1" Raw;
    /// Critical confirm list sweep state. Key: ().
    CRITICAL_CONFIRM_LIST_CURSOR: VaultMeta b"gate_pending:critical_confirm_list_cursor:v1" Raw;
    /// Pending consents grouped by root-group alias. Key: u64be len + string + id16.
    PENDING_GATE_CONSENT_GROUP_INDEX: VaultMeta b"gate_pending:group_index:v1:" Raw;
    /// Semantic duplicate index of pending consents. Key: bytes32 + id16.
    PENDING_GATE_CONSENT_HASH_INDEX: VaultMeta b"gate_pending:hash_index:v1:" Raw;
    /// Index keys created for a pending consent. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice): decode also enforces the
    /// version byte and non-empty run/group keys, business validation
    /// `Named`'s generic strict-msgpack decode does not run; `RawValue`
    /// delegates to the module's own
    /// `encode_pending_gate_consent_index_state`/
    /// `decode_pending_gate_consent_index_state`.
    PENDING_GATE_CONSENT_INDEX_STATE: VaultMeta b"gate_pending:index_state:v1:" Raw;
    /// Pending consents grouped by run. Key: u64be len + string + id16.
    PENDING_GATE_CONSENT_RUN_INDEX: VaultMeta b"gate_pending:run_index:v1:" Raw;
    /// Pending consent insertion sequence. Key: id16.
    PENDING_GATE_CONSENT_SEQUENCE: VaultMeta b"gate_pending:sequence:v1:" Raw;
    /// Pending-consent sequence high-water mark. Key: ().
    PENDING_GATE_CONSENT_SEQUENCE_COUNTER: VaultMeta b"gate_pending:sequence_counter:v1" Raw;
    /// Pending consents ordered by sequence. Key: u64be.
    PENDING_GATE_CONSENT_SEQUENCE_INDEX: VaultMeta b"gate_pending:sequence_index:v1:" Raw;
    /// Pending gate-consent tray row. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice): decode also enforces
    /// `vet_pending_gate_consent_record` (version, diff-handle, reason-code
    /// shape checks), business validation `Named`'s generic strict-msgpack
    /// decode does not run; `RawValue` delegates to the module's own
    /// `encode_pending_gate_consent`/`decode_pending_gate_consent`.
    PENDING_GATE_CONSENT: VaultMeta b"gate_pending:v0:" Raw;
    /// Durable journal record of one prepared/applied/failed git ref, stage, or worktree effect. Key:
    /// hex64(repo identity) ":" hex64(record key).
    GIT_WIRE_RECORD: VaultMeta b"git_wire:record:v2:" Named;
    /// Append-only offer-answer log for consent-graduation ramps, scope-major then UUIDv7 row id.
    /// Key: id16 + id16.
    EDIT_DISTANCE_GRADUATION_ANSWER: VaultMeta b"graduation_answer:v1:" Raw;
    /// Runtime consent-graduation threshold override for one ramp pattern, keyed by a digest of the
    /// pattern text. Key: id16.
    EDIT_DISTANCE_GRADUATION_THRESHOLD: VaultMeta b"graduation_threshold:v1:" Raw;
    /// Proposed/reviewed/escalated timestamps for one healer case, feeding oversight coverage counts.
    /// Key: hex32 (case_ref).
    HEALER_ACTIVITY: VaultMeta b"healer:activity:v1:" Named;
    /// Durable failure-ladder case authenticating one healer admission, bound to its lease-fenced
    /// failed attempt. Key: hex32 (case_ref).
    HEALER_CASE: VaultMeta b"healer:case:v1:" Named;
    /// Per-actor healer-submission counter and burst-check flag. Key: id16 (actor).
    SELF_HEAL_HEALER_COUNT: VaultMeta b"healer:count:" Named;
    /// Latest signed per-vault-device oversight receipt (coverage, review latency, or escalation
    /// rate). Key: u8 (OversightKind tag: 0/1/2).
    HEALER_OVERSIGHT_RECEIPT: VaultMeta b"healer:oversight:v1:" Named;
    /// An external healer's repair proposal record and its review state. Key: id16.
    SELF_HEAL_HEALER_PROPOSAL: VaultMeta b"healer:proposal:" Named;
    /// A human-ratified patch pull-request record for a released healer proposal. Key: id16.
    SELF_HEAL_HEALER_RELEASE: VaultMeta b"healer:release:" Named;
    /// Per-actor per-run healer receipt: submitted proposals and reversal state. Key: id16 + bytes32
    /// (actor then blake3 hash of run name).
    SELF_HEAL_HEALER_RUN: VaultMeta b"healer:run:" Named;
    /// Follow-up reminder/escalation cursor state for one human task. Key: id16.
    HUMAN_TASK_FOLLOWUP: VaultMeta b"human_task.followup.v1\0" Raw;
    /// Idempotency marker recording which signal/surface-event a wait's response already produced.
    /// Key: id16.
    HUMAN_TASK_WAIT_SIGNAL: VaultMeta b"human_task.wait.signal.v1\0" Raw;
    /// Active binding from a human task to the trap claim awaiting its response. Key: id16.
    HUMAN_TASK_WAIT_BINDING: VaultMeta b"human_task.wait.v1\0" Raw;
    /// Empty-marker index from a normalized identity hint (name/alias/handle) hashed per entity-kind
    /// to the entity id it names, for lookup-before-mint resolution. Key: u8 + hash32 + id16.
    INGEST_IDENTITY_HINT: VaultMeta b"identity-hint:v1:" Raw;
    /// Caller-supplied phonetic codes retained to recompute an entity's phonetic postings on
    /// reindex/delete. Key: id16.
    BATCH_PHONETIC_INDEX_SOURCE: VaultMeta b"index_source:phonetic:v1:" Named;
    /// Canonical caller-supplied text fields backing one document's bm25 index, used to rebuild
    /// postings. Key: id16.
    INDEX_SOURCE_TEXT: VaultMeta b"index_source:text:v1:" Named;
    /// Blob birth fingerprint tree used for perceptual/exact duplicate detection on ingest. Key:
    /// id16.
    INGEST_FINGERPRINT: VaultMeta b"ingest-fingerprint:v1:" LegacyJson;
    /// Run id to queued attempt ids. Key: u64be len + string + id16.
    ATTEMPT_RUN_INDEX: VaultMeta b"job:run_index:v1:" Raw;
    /// Vault-scoped structural-kind registration. Key: u8.
    STRUCTURAL_KIND_REGISTRY: VaultMeta b"kind_reg:" Raw;
    /// Tracker issue id to task id. Key: string.
    LINEAR_ISSUE_REVERSE: VaultMeta b"linear.issue.v1/" Raw;
    /// Tracker pull-page cursor. Key: ().
    LINEAR_PULL_CURSOR: VaultMeta b"linear.pull_cursor.v1" Raw;
    /// Tracker-mirror outbox marker. Key: id16.
    LINEAR_TASK_DIRTY: VaultMeta b"linear.task_dirty.v1/" Raw;
    /// Tracker-mirror revision counter of a task. Key: id16.
    LINEAR_TASK_REVISION: VaultMeta b"linear.task_revision.v1/" Raw;
    /// Task to tracker issue link state. Key: id16.
    LINEAR_SYNC_LINK: VaultMeta b"linear_sync:link:v3:" LegacyJson;
    /// The vault's pinned model-role manifest (role bindings, tier/route defaults). Key: ().
    LLM_MANIFEST: VaultMeta b"llm:manifest:v2" LegacyJson;
    /// Priced model-catalog row: wire format, cost, and cached benchmark scores. Key: string(model
    /// id).
    LLM_REGISTRY_ROW: VaultMeta b"llm:registry:v1:" LegacyJson;
    /// Per-vault narrow-only resident route overrides, cleared when the manifest is replaced. Key:
    /// ().
    LLM_RESIDENT_ROUTES: VaultMeta b"llm:resident_routes:v1" LegacyJson;
    /// Rolling window (max 64) of recent benchmark score-change diffs for one model. Key:
    /// string(model id) "\x00".
    LLM_SCORE_DIFFS: VaultMeta b"llm:scores:v1:" LegacyJson;
}
