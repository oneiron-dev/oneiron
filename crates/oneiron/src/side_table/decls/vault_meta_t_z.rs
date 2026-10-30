// Declared `vault_meta` tables whose prefix starts with `t` to `z`, in prefix order.

side_tables! {
    VAULT_META_T_Z;
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
    /// The review decision an owner accepted of a TASK no write had settled yet (FIX 11757),
    /// which the TASK's settlement names as its anchor: the first one, kept after the settlement
    /// as history and gone with the TASK's erase. Key: id16 (TASK).
    TASK_ACCEPTED_REVIEW: VaultMeta b"tasks.accepted_review.v1/" Named Engine;
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
    /// One bound try's library program (CUA E4): the record its first lease resolved its TASK's
    /// handle to, with the TASK's arguments, or why there is none; the brief stamp and done-means
    /// it was leased under; and what its strict run came to. Copied from the admitted brief, and
    /// gone with its TASK's hard erase. Key: id16 (attempt).
    TASK_BROWSER_WORKFLOW_ATTEMPT: VaultMeta b"tasks.browser_workflow.attempt.v1/" Named Admitted;
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
    /// The lifecycle receipts naming one TASK, by time (FIX 3270), written with each receipt in
    /// its own transaction. Value: one role byte, 1 on the receipt of the write that settled the
    /// TASK (FIX 3272), else 0. Key: id16 (TASK) + u64be (occurred_at) + string (receipt id).
    TASK_LIFECYCLE_RECEIPT_BY_TASK: VaultMeta b"tasks.lifecycle_receipt.by_task.v1/" Raw;
    /// Every lifecycle receipt by time (FIX 3271), written with each receipt in its own
    /// transaction, so a query reads the newest first. Empty marker. Key: u64be (occurred_at) +
    /// string (receipt id).
    TASK_LIFECYCLE_RECEIPT_BY_TIME: VaultMeta b"tasks.lifecycle_receipt.by_time.v1/" Raw;
    /// One mutating task-highway call's `TaskLifecycle` receipt (OF-220), projected as the receipt
    /// family reads it, written in the call's own transaction. Key: string (the receipt id,
    /// `task_lifecycle:` + 32 hex).
    TASK_LIFECYCLE_RECEIPT: VaultMeta b"tasks.lifecycle_receipt.v1/" Named
        => crate::task_verb::erase_lifecycle_actor_in_txn;
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
    TASK_REPORT_JOURNAL: VaultMeta b"tasks.report.journal.v1/" Named
        => crate::task_verb::erase_report_actor_in_txn;
    /// Task symbol-overlap declaration. Key: id16.
    TASK_SYMBOL_LEASE: VaultMeta b"tasks.symbol_lease.v1/" LegacyJson;
    /// One pending training offer asked of one owner (OF-577): the question TURN and MESSAGE ids
    /// and time reserved before the witness, the owner's conversation, and the ask group once
    /// admitted. Key: id16 (offer) + id16 (owner) + offer digest (64 hex).
    TASK_TRAINING_OFFER_ASK: VaultMeta b"tasks.training_offer_ask.v1/" Named;
    /// The training offer ask one ask group carries, by its reservation key. Key: id16 (ask group).
    TASK_TRAINING_OFFER_ASK_GROUP: VaultMeta b"tasks.training_offer_ask_group.v1/" Named;
    /// One Scored training run's result asked of one owner (OF-577): the question ids reserved
    /// before the witness, the frozen swap expectation, the ask group once admitted and its state.
    /// Key: id16 (run) + id16 (owner) + result digest (64 hex).
    TASK_TRAINING_SWAP_ASK: VaultMeta b"tasks.training_swap_ask.v1/" Named;
    /// The training swap ask one ask group carries, by its reservation key. Key: id16 (ask group).
    TASK_TRAINING_SWAP_ASK_GROUP: VaultMeta b"tasks.training_swap_ask_group.v1/" Named;
    /// Registered external ask wait. Key: id16 + bytes32.
    TASK_ASK_WAIT: VaultMeta b"tasks.wait/" Named
        => crate::task_verb::erase_wait_actor_in_txn;
    /// Fan-out launch held for, or launched past, the approval mode: its frozen payload, plan,
    /// statement, pause or width-check row and ruling (OF-393). Key: hex32 (launch ref).
    TASK_FANOUT_LAUNCH: VaultMeta b"tasks/fanout/launch.v1/" Named
        => crate::task_verb::erase_launch_actor_in_txn;
    /// Consult fan-out plan. Key: hex32.
    TASK_FANOUT_RUN: VaultMeta b"tasks/fanout/v1/" Named;
    /// Retired consult fan-out policy carrier; the policy manifest now governs.
    /// Declared so bytes written by older engines stay owned. Key: ().
    TASK_FANOUT_POLICY: VaultMeta b"tasks/fanout_policy/v1" Named;
    /// A team deliverable's owner review: team, leader, root TASK, output revision, reviewed
    /// claim fingerprint and what the review asks. Key: id16 (reviewed claim).
    TEAM_DELIVERABLE: VaultMeta b"team:deliverable:v1:" Named;
    /// One run's market: signed referee, lease shares, central ledger, submissions and result.
    /// Key: string (team reference).
    TEAM_MARKET: VaultMeta b"team:market:v1:" Named;
    /// A workflow skill's binding to the coordination pattern it teaches, with its works-well-for
    /// line. Key: id16 (skill entity).
    TEAM_PATTERN_SKILL: VaultMeta b"team:pattern_skill:v1:" Named;
    /// One team run's receipt (type, pattern, models, shape, who decided, coverage, confessions,
    /// anchored outcome). Key: string (team reference).
    TEAM_RECEIPT: VaultMeta b"team:receipt:v1:" Named
        => crate::learning::erase_team_receipt_scope_in_txn;
    /// One team start as the host saw it: stamp, leader, root TASK, queued members and widenings.
    /// Key: string (leader attempt hex, `:`, team reference).
    TEAM_RUN: VaultMeta b"team:run:v1:" Named;
    /// The pinned text analyzer manifest (JSON) and, under '_hash', its SHA-256. Key: string.
    TEXT_ANALYZER_MANIFEST: VaultMeta b"text_analyzer_manifest" Raw;
    /// BM25F field schema hash. Key: ().
    TEXT_BM25_FIELD_SCHEMA_HASH: VaultMeta b"text_bm25_field_schema_hash" Raw;
    /// Text-index schema version stamp. Key: ().
    TEXT_INDEX_SCHEMA_VERSION: VaultMeta b"text_index_schema_version" Raw;
    /// Current owner-approved training checkpoint per model role. Key: serialized role string.
    TRAINING_PACK_ROLE: VaultMeta b"training_pack:role:v1:" Named
        => crate::training_pack::erase_role_actor_in_txn;
    /// Pinned corpus, compute, dispatch and evaluation of one training job. Key: id16 (run).
    TRAINING_PACK_RUN: VaultMeta b"training_pack:run:v1:" Named
        => crate::training_pack::erase_run_id_in_txn;
    /// Immutable owner-approved role-swap receipt. Key: id16 (receipt).
    TRAINING_PACK_SWAP: VaultMeta b"training_pack:swap:v1:" Named
        => crate::training_pack::erase_swap_actor_in_txn;
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
    /// The MESSAGE rows a kept TURN lost to a window demotion (OF-534, FIX 3859), until each is
    /// back with its PartOf edge: derived, local, never synced. Key: id16 (turn).
    TURN_MISSING_MESSAGES: VaultMeta b"turn:missing_messages:v1:" Named;
    /// A TURN owed a tag pass that a physical tear, with no vault in hand, could not mark (FIX
    /// 6262), until the tagging reconciler's upkeep marks it: derived, local, never synced. Empty
    /// marker. Key: id16 (turn).
    TURN_TAG_OWED: VaultMeta b"turn:tag_owed:v1:" Raw;
    /// A typed body's Loro snapshot at its head. Key: id16 (entity).
    TYPED_BODY_DOC: VaultMeta b"typed_body:doc:v1:" Raw;
    /// Work on a typed body away from its head: opener, base frontier and state. Key: id16
    /// (entity) + id16 (fork).
    TYPED_BODY_FORK: VaultMeta b"typed_body:fork:v1:" Named
        => crate::typed_body::erase_fork_actor_in_txn;
    /// An open typed-body fork's Loro snapshot. Key: id16 (entity) + id16 (fork).
    TYPED_BODY_FORK_DOC: VaultMeta b"typed_body:fork_doc:v1:" Raw;
    /// An entity's typed body: its schema tag, birth and head frontiers and commit count. Key:
    /// id16 (entity).
    TYPED_BODY_HEAD: VaultMeta b"typed_body:head:v1:" Named;
    /// Who made one typed-body commit: its actor and MadeBy, or its time alone once that actor
    /// was erased; the commit's message names no one. Key: id16 (entity) + u64be (commit peer).
    TYPED_BODY_RECEIPT: VaultMeta b"typed_body:receipt:v1:" Named
        => crate::typed_body::erase_receipt_actor_in_txn;
    /// A standing artifact question's last ask of one artifact: the head versions it read and
    /// the proposal its answers wait under. Key: id16(question) + id16(artifact).
    TYPED_QUESTION_ARTIFACT_ASKED: VaultMeta b"typed_question:artifact_asked:v1:" Named;
    /// A question's asks in commit order (FIX 2337): each graph answer by its claim, and
    /// each artifact ask with the pins it read and its proposal, a failed one too. Its
    /// high-water mark is a `TYPED_QUESTION` row. Key: id16(question) + u64be(sequence).
    TYPED_QUESTION_ASK_HISTORY: VaultMeta b"typed_question:ask_history:v1:" Named
        => crate::llm::decision::questions::erase_ask_history_actor_in_txn;
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
    /// FIX 11231: one graph unit's person ask, kept while it waits and once its holder's
    /// answer landed on the unit: the question, principal and unit it decides, the declined
    /// decision it went up from, and the answer claim that landed. Key: u64be(ask sequence).
    TYPED_QUESTION_UNIT_ASK: VaultMeta b"typed_question:unit_ask:v1:" Named;
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
    /// Cleanup marks by id16. 48 bytes: a cleanup run archived a completed queue-record attempt,
    /// pinned to the exact bytes archived and naming the run. 32 bytes: the owner kept a restored
    /// attempt or record at that revision. Key: id16 (AttemptId, or a kept record's entity id).
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
    /// touched. Key: BLAKE3 derive_key of the task reference (32) then id16 (AttemptId).
    VAULT_CLEANUP_TASK_ATTEMPT_ARCHIVE: VaultMeta b"vault_cleanup.task_attempt_archive.v1/" Raw;
    /// Owner-adjustable retention period for completed TASK queue records before archival
    /// eligibility. Key: ().
    VAULT_CLEANUP_TASK_RETENTION_DAYS: VaultMeta b"vault_cleanup.task_retention_days.v1" Raw;
    /// Test-only marker that closes the automatic-cleanup release blockers. Key: ().
    VAULT_CLEANUP_TEST_BLOCKERS_CLOSED: VaultMeta b"vault_cleanup.test_blockers_closed" Raw;
    /// Random 32-byte identity of this store, minted at its first open and compared by every
    /// same-vault check; node-local and never synced, so a replica holds its own. Key: ().
    VAULT_IDENTITY_LOCAL: VaultMeta b"vault_identity:local:v1" Raw;
    /// The BLAKE3 fingerprint of the recipient public key each escrow label was sealed to, kept
    /// after the label retires, so a later add of the same key under another label warns (FIX
    /// 2857). Public facts only. Key: string (label).
    VAULT_KEY_ESCROW_RECIPIENT: VaultMeta b"vault_key:escrow_recipient:v1:" Named;
    /// An escrow label retired after its recipient's secret was released, and the owner's receipt
    /// (OF-570, CROSS-ARCH-0022 #ov-custody-backend); nothing is sealed to it again. Key: string
    /// (label).
    VAULT_KEY_ESCROW_RETIRED: VaultMeta b"vault_key:escrow_retired:v1:" Named;
    /// The blake3 of the escrow capsule each escrow wrap last handed to the host's outbound spool
    /// (OF-570, CROSS-ARCH-0022 invariant 03). Key: string (wrap id).
    VAULT_KEY_ESCROW_SPOOLED: VaultMeta b"vault_key:escrow_spooled:v1:" Named;
    /// The vault data key's commitment and birth (OF-570 E1). Never the key. Key: ().
    VAULT_KEY_STATE: VaultMeta b"vault_key:state:v1" Named;
    /// One way to unlock the vault data key: an E0 `VaultDek` envelope and its public
    /// metadata. Key: string (wrap id).
    VAULT_KEY_WRAP: VaultMeta b"vault_key:wrap:v1:" Named;
    /// One vault shape apply's journal (ARCH-0070): its plan items and how each landed, so a torn
    /// apply resumes. Key: string (the plan's frontier, hex).
    VAULT_SHAPE_APPLY: VaultMeta b"vault_shape:apply:v1:" Named;
    /// One entity kind's wire declaration as a vault shape apply landed it (ARCH-0070, FIX 2300):
    /// whether the kind is declared on the wire, by whom and when. Key: string (the kind's name).
    VAULT_SHAPE_WIRE: VaultMeta b"vault_shape:wire:v1:" Named;
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
    /// One render decision a voice's subject or designed voice's creator made, kept once and never
    /// rewritten (FIX 4396): the decision, its revision and sequence, and the target pointers it
    /// dropped. Erased with the bank. Key: string (voice id) "\0" string (event id).
    VOICE_REF_RENDER_EVENT: VaultMeta b"voice:ref_render_event:v1:" Named;
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
    /// An owner's own behaviour with one period of his digest, for the Coach's digest settings
    /// rule (FIX 5495): when its due notice reached him and when he first opened it, no digest
    /// text. Key: id16 (owner) + u64be (scheduled_for).
    WEAVE_DIGEST_BEHAVIOUR: VaultMeta b"weave:digest_behaviour:v1:" Named;
    /// One Coach change to an owner's digest rhythm or section order (FIX 5495): proposed,
    /// applied under his Grant, answered or undone, with the settings before and after. Key: id16
    /// (owner) + id16 (change).
    WEAVE_DIGEST_SETTING_CHANGE: VaultMeta b"weave:digest_setting_change:v1:" Named;
    /// An owner's digest settings generation, the Coach's last evaluation of him and his own
    /// feedback (FIX 5495). Key: id16 (owner).
    WEAVE_DIGEST_SETTINGS: VaultMeta b"weave:digest_settings:v1:" Named;
    /// Source-to-digest invalidation index. Key: source id16 ‖ digest key.
    WEAVE_DIGEST_SOURCE: VaultMeta b"weave:digest_source:v1:" Raw;
    /// Weave digest schedule of one reader. Key: reader kind byte + id16.
    WEAVE_DIGEST_SCHEDULE: VaultMeta b"weave:schedule:v1:" Raw;
    /// One immutable wrong-item label (a claim, project or budget row) filed from a live weave
    /// report. Key: id16 (item id) + id16 (label receipt id).
    WEAVE_WRONG_ITEM_LABEL: VaultMeta b"weave:wrong-item:v1:" Named;
    /// One immutable wrong-link label filed from a live weave report. Key: edge ref (33 bytes) +
    /// id16 (label receipt id).
    WEAVE_WRONG_LINK_LABEL: VaultMeta b"weave:wrong-link:v1:" Named;
    /// The owner's web connector switch (FIX 11598): which provider serves `connector.web.*`, on
    /// whose key. Absent means Tavily on the deploy's backend key. Key: ().
    WEB_CONNECTOR_SETTING: VaultMeta b"web_connector:setting:v1" Named;
    /// One usage row per web connector call: provider, tool, key source, latency, cost and the
    /// provider's request id; never the query, URL or results. Key: u64 BE (ms) + id16.
    WEB_CONNECTOR_USAGE: VaultMeta b"web_connector:usage:v1:" Named;
    /// Guards a companion PERSON against being claimed by a second principal's onboarding. Key: id16
    /// (companion person id).
    WORKSPACE_ROSTER_COMPANION_PRINCIPAL: VaultMeta b"workspace_roster:companion_principal:v1:" Raw
        => crate::workspace_roster::erase_companion_principal_actor_in_txn;
    /// One onboarded member's roster row (actor, optional companion person/actor/facet, identity).
    /// Key: string (workspace_ref) "\x00" hex32 (person id).
    WORKSPACE_ROSTER_MEMBER: VaultMeta b"workspace_roster:member:v1:" Raw
        => crate::workspace_roster::erase_member_actor_in_txn;
    /// Guards one member's workspace-onboarding slot against a second onboarding with different
    /// inputs. Key: string (workspace_ref) "\x00" id16 (person id).
    WORKSPACE_ROSTER_MEMBER_INTENT: VaultMeta b"workspace_roster:member_intent:v1:" Raw
        => crate::workspace_roster::erase_member_intent_actor_in_txn;
    /// Idempotency journal tracking one member-onboarding request's progress through the pinned step
    /// ladder. Key: string (caller-supplied onboarding_id).
    WORKSPACE_ONBOARDING: VaultMeta b"workspace_roster:onboarding:v1:" Raw;
    /// Per-workspace roster preset (org, venture name, house actor/identity, house display name).
    /// Key: string (workspace_ref).
    WORKSPACE_ROSTER_PRESET: VaultMeta b"workspace_roster:preset:v1:" Raw;
    /// When a world was soft-deleted here (u64 vault seconds): a pin change still rewraps its keys
    /// for 90 days after, while old bundles restore it. Key: id16 hex (world).
    WORLD_KEY_DELETED: VaultMeta b"world_keys:deleted:v1:" Raw;
    /// Permanent fact that a world's keys were destroyed with the world, with its ids-only
    /// receipt. Refuses a late pad, a remint and an open for that world. Key: id16 hex (world).
    WORLD_KEY_DESTROYED: VaultMeta b"world_keys:destroyed:v1:" Named;
    /// A reader's own Loro document of one sealed private-world window, which the sealed cloud
    /// bundle's world section carries whole (FIX 922). Purged with an erased world. Key: hex32
    /// (world) ":" string (window label).
    WORLD_KEY_SEALED_MIRROR: VaultMeta b"world_keys:mirror:v1:" Raw;
    /// Which version of one sealed window's mirror last landed here in full, and under which
    /// forward pass (FIX 6509), or that the window's rows here were removed since (FIX 5506): a
    /// take of that version under that pass skips its forward pass. Purged with an erased world.
    /// Key: hex32 (world) ":" string (window label).
    WORLD_KEY_SEALED_MIRROR_LANDED: VaultMeta b"world_keys:mirror_landed:v1:" Raw;
}
