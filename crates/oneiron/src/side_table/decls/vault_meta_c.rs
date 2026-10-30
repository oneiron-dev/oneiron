// Declared `vault_meta` tables whose prefix starts with `c`, in prefix order.

side_tables! {
    VAULT_META_C;
    /// Calendar connector write-outbox rows and remote object cursors. Key: `row:` or `obj:` +
    /// bytes32.
    /// Owner-installed CalDAV seats, cursors and kill switches. Key: seat name.
    CALENDAR_CONNECTOR_SEAT: VaultMeta b"calendar.connector-seat.v1:" Named;
    CALENDAR_CONNECTOR_WRITE: VaultMeta b"calendar.connector-write.v1:" LegacyJson Authored;
    /// Owner-installed ICS feed configuration and last public completion. Key: system name.
    CALENDAR_ICS_FEED_CONFIG: VaultMeta b"calendar.ics-feed-config.v1:" Named;
    /// Per-feed poll cursor. Key: bytes32.
    CALENDAR_ICS_FEED_CURSOR: VaultMeta b"calendar.ics-feed.v1:" LegacyJson Authored;
    /// UID-to-EVENT lookup cache. Key: bytes32.
    /// Host-installed iMIP submission endpoint and custody name. Key: ().
    CALENDAR_IMIP_TRANSPORT: VaultMeta b"calendar.imip-transport.v1" Named;
    /// Owner-configured post-meeting outcome grace. Key: ().
    CALENDAR_OUTCOME_POLICY: VaultMeta b"calendar.outcome-policy.v1" Named;
    CALENDAR_PASSPORT_UID_INDEX: VaultMeta b"calendar.passport.v1:" Raw;
    /// Marker that a derived EVENT's source was erased. Key: id16.
    CALENDAR_INVALIDATED_EVENT: VaultMeta b"calendar_invalid:v1:" Raw;
    /// EVENT entity awaiting calendar-origin claim reconciliation after entity/claim/edge replay
    /// settled. Key: id16 (EVENT entity id).
    SYNC_CALENDAR_ORIGIN_PENDING: VaultMeta b"calendar_origin_pending:v1:" Raw;
    /// One wire call's lasting receipt (OF-538): who called on which credential, which verb, how
    /// it ended, and digests of what was asked and answered; never the bodies. Key: id16.
    CALL_RECEIPT: VaultMeta b"call_receipt:v1:" Named Authored
        => crate::Vault::erase_call_receipt_actor_in_txn;
    /// The currently active campaign compliance rule pack. Key: ().
    CAMPAIGN_COMPLIANCE_ACTIVE: VaultMeta b"campaign:compliance:active:v1" Named;
    /// Durable UTF-8 activation notice for one compliance-pack version, one row per version. Key:
    /// u32be.
    CAMPAIGN_COMPLIANCE_NOTICE: VaultMeta b"campaign:compliance:notice:v1:" Raw;
    /// One staged compliance-pack amendment proposal awaiting an owner stamp. Key: ().
    CAMPAIGN_COMPLIANCE_PENDING: VaultMeta b"campaign:compliance:pending:v1" Named;
    /// Caller-bound compliance amendment, owner decision or verification receipt. Key: id16.
    CAMPAIGN_COMPLIANCE_RECEIPT: VaultMeta b"campaign:compliance:receipt:v1:" Named;
    /// One campaign enrollment outbound call's prepared request, retained before its first ask
    /// (FIX 6424 part 2a): its target's ids and epoch, its body's digest, its sender and the event
    /// row it was first asked under; ids and digests only. Key: id16(consequence) + u64be(call
    /// seq) + the request's 32-byte digest.
    CAMPAIGN_ENROLLMENT_ASK: VaultMeta b"campaign:enrollment_ask:v1:" Raw;
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
    CHANNEL_IDENTITY_LIFECYCLE_RECEIPT: VaultMeta b"channel_identity_lifecycle:v0:" Named
        => crate::store::erase_channel_identity_receipt_actor_in_txn;
    /// One channel-identity lifecycle request, kept by its ref before its ask (FIX 6424 part 3):
    /// the actor, the verb, its input's or request's digest, the identity it was given and when
    /// that was requested and, once applied, the receipt it answered, the identity's body and
    /// facts (an address among them) as that apply committed them. Dropped with the identity's
    /// erase or retirement and by its actor's erase. Key: id16 (request ref).
    CHANNEL_IDENTITY_LIFECYCLE_REQUEST: VaultMeta b"channel_identity_lifecycle_request:v1:" Named
        => crate::channel_identity_lifecycle::erase_lifecycle_request_actor_in_txn;
    /// Channel-identity selection rule set. Key: ().
    CHANNEL_IDENTITY_SELECTION_RULES: VaultMeta b"channel_identity_selection:v1:rules" Raw
        => crate::channel_identity_selection::erase_rule_actor_in_txn;
    /// A self agent's per-reply chat breakpoint (FIX 4465 D): the answering agent, its reader,
    /// the conversation and branch, the request its rung sent and the digest of its offer, and
    /// the retained turns and summaries it was read from, by revision. Host-only; read only to
    /// reuse the prefix for the reply's Continue and Retry. Key: id16(conversation) +
    /// id16(message) + id16(stream generation).
    CHAT_BREAKPOINT: VaultMeta b"chat_breakpoint:v1:" Named Authored;
    /// Per-repository environment blueprint. Key: bytes32.
    CHECKOUT_ENV_BLUEPRINT: VaultMeta b"checkout:env_blueprint:v1:" VersionedNamed;
    /// Checkout lease act. Key: hex32.
    CHECKOUT_LEASE: VaultMeta b"checkout:lease:v1:" Raw;
    /// Checkout settlement receipt. Key: hex32 + decimal + hex64.
    CHECKOUT_SETTLEMENT: VaultMeta b"checkout:settlement:v1:" Raw;
    /// Retired checkout epoch high-water mark. Key: hex32.
    CHECKOUT_TOMBSTONE: VaultMeta b"checkout:tombstone:v1:" Raw;
    /// The vault's last sealed checkpoint: its sequence and signed commitment's
    /// BLAKE3, which the next one names as predecessor (OF-570 (e)). Key: ().
    CHECKPOINT_CHAIN_HEAD: VaultMeta b"checkpoint_chain:head:v1" Named;
    /// One incarnation of a checkpoint payload compartment (KS-7): its custody generation and
    /// whether it is active, retained or erased. Never a key and never a refcount. Key: subtype
    /// (1) + canonical owner (32) + incarnation (16).
    CHECKPOINT_PAYLOAD_INSTANCE: VaultMeta b"checkpoint_payload:instance:v1:" Named Engine;
    /// Two-slot channel assignment index: occupant id16 then predecessor id16, all-zero for an
    /// empty slot. Key: bytes32 (blake3 of the length-framed channel and address).
    CHANNEL_IDENTITY_ASSIGNMENT: VaultMeta b"cid_assign:v1:" Raw;
    /// Deletion evidence (the single byte 1) for a soft-erased channel identity's retained
    /// header-only shell, staged with slot removal. Key: id16.
    CHANNEL_IDENTITY_ASSIGNMENT_ERASED: VaultMeta b"cid_assign_erased:v1:" Raw;
    /// A destructive claim action (supersede/decay/weaken/stale) parked behind unresolved gate
    /// consent. Key: id16.
    CLAIM_DEFERRED: VaultMeta b"claim.deferred.v1:" Named;
    /// Immutable before/after revision binding for an accepted supersession. Key: old id16 + new id16.
    CLAIM_SUPERSESSION_DIFF: VaultMeta b"claim.supersession_diff.v1:" Raw;
    /// A host re-root's carry of one MACHINE claim's signed history: the carried birth digest
    /// (32 bytes), then the content hash (32 bytes) of the handoff packet the move signed for it.
    /// Written by that move only; retired with the history on delete. Key: id16 (target claim).
    CLAIM_MACHINE_HISTORY_CARRY: VaultMeta b"claim:machine-history-carry:v1:" Raw;
    /// The pinned signed handoff (encoded `ClaimHistoryHandoff`) that roots one MACHINE claim's
    /// signed birth and transition history. Key: id16 (target claim).
    CLAIM_MACHINE_HISTORY_PIN: VaultMeta b"claim:machine-history-pin:v1:" Raw;
    /// Empty marker indexing one MACHINE claim's signed history control rows under their target.
    /// Key: id16 (target claim) + id16 (control).
    CLAIM_MACHINE_HISTORY_TARGET: VaultMeta b"claim:machine-history-target:v1:" Raw;
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
    /// FIX 9598: an approved Dreamer claim whose VAD consolidation is still owed, written in the
    /// approval's commit and cleared in the consolidation's own. Key: id16 (claim).
    CLAIM_VAD_OWED: VaultMeta b"claim:vad_owed:v1:" Named Engine;
    /// One cloud registration slot's value-free binding (G7): the owner who linked it, the pinned
    /// issuer and audience, the verified cloud subject, its phase and fenced generation. Kept after
    /// a logout or a replacement until the owner's erase, which takes the slot. Key: id16 (slot).
    CLOUD_REGISTRATION: VaultMeta b"cloud_registration:v1:" Named
        => crate::secret_custody::erase_cloud_registration_actor_in_txn;
    /// One agent-health card (OF-568): the Coach's merged evidence, routing and outcome for one
    /// actor, signal and task. Key: id16 actor, signal code byte, id16 task (zeros for none).
    COACH_AGENT_HEALTH_CARD: VaultMeta b"coach:agent_health_card:v1:" Named
        => crate::dreamer_runner::maintenance::agent_health::erase_actor_sources_in_txn;
    /// An agent's `self.report_blocked` receipt waiting for the Coach's Issues job. Key: id16 of
    /// the receipt.
    COACH_BLOCKED_ISSUE: VaultMeta b"coach:blocked_issue:v1:" Named;
    /// One `self.report_blocked` receipt a durable run filed, and when, kept after the Coach
    /// settles it, so a failing attempt's ladder case carries its own reports (OF-418). Key: id16
    /// of the run, then id16 of the receipt.
    COACH_BLOCKED_RUN: VaultMeta b"coach:blocked_run:v1:" Raw;
    /// The source a `self.report_blocked` receipt's code fix replays (FIX 2343): the instructions,
    /// briefing and task of the model request the run's host bound before the call, whole, or
    /// none for a caller that gave this engine no request, with the run, reporter and scope.
    /// Kept after the Coach settles the report. Key: id16 of the receipt. FIX 1662: the same
    /// table keeps the request a code fix replays exactly: a receipt row names it by its hash and
    /// keeps it whole when no replay capsule of the run holds it, and a step row keeps a durable
    /// step's request, masked, before its call. Key: b's', id16 of the attempt, the step's hash,
    /// be64 of the lease generation, be32 of the call.
    COACH_BLOCKED_SOURCE: VaultMeta b"coach:blocked_source:v1:" Named Authored
        => crate::self_heal::blocked_reports::erase_blocked_source_actor_in_txn;
    /// Where the Coach's contribution checks resume: the credit key and target (a loaded skill or
    /// a used edge's two ends) of the last candidate a pass put to its replay host, cleared once a
    /// pass reaches the end of the credit table, or by an erase of an entity it names. Key: ().
    COACH_CONTRIBUTION_CURSOR: VaultMeta b"coach:contribution_cursor:v1" Named
        => crate::dreamer_runner::maintenance::erase_contribution_cursor_in_txn;
    /// The Coach's issue for one positive model finding (OF-418 L3): its DIAGNOSTIC, tier,
    /// family, class and recipe revision, its exact ordered runs with their replay hashes, the
    /// decision receipts that raised it, the gate decisions its results link, the producer its
    /// recorded links prove, its recurrence key and its retries. Kept after the Coach files it;
    /// it waits while no `COACH_ISSUE_SETTLED` row names it. Key: id16 of the issue.
    COACH_DIAGNOSTIC_ISSUE: VaultMeta b"coach:diagnostic_issue:v1:" Named;
    /// Each COACH_DIAGNOSTIC_ISSUE under its recurrence key, written with it (FIX 7343). Key:
    /// the key's 32 bytes, then id16 of the issue.
    COACH_DIAGNOSTIC_ISSUE_BY_KEY: VaultMeta b"coach:diagnostic_issue_by_key:v1:" Raw;
    /// What was observed of a model finding's issue (OF-418 L3), append-only: an owner's closed
    /// answer to its proposal, as the claim's gate row records it. Key: id16 of the issue, then
    /// hash32 of the fact.
    COACH_ISSUE_EVIDENCE: VaultMeta b"coach:issue_evidence:v1:" Named;
    /// The proposed heal the Coach filed for a blocked report, a failure-ladder case or a model
    /// finding's issue, so a replay files none twice. Key: id16 of the receipt, the case or the
    /// issue.
    COACH_ISSUE_SETTLED: VaultMeta b"coach:issue_settled:v1:" Named;
    /// A blocked report filed while a `coach.issues` attempt held its lease (FIX 1554): the
    /// attempt's lease generation, consumed in the commit that settles it, which queues one
    /// successor, reconcile-only wakes too (FIX 7343). Key: id16 of the attempt.
    COACH_ISSUES_REDRIVE: VaultMeta b"coach:issues_redrive:v1:" Named;
    /// A case where a person changed the decision ladder's answer, kept until the Coach's
    /// person-threshold run reads it. Key: id16 of the source the host bound the answer to.
    COACH_PERSON_CHANGED: VaultMeta b"coach:person_changed:v1:" Named;
    /// When the Coach's person-threshold run read a source's record, so a replay never counts
    /// twice. Key: id16.
    COACH_PERSON_CHANGED_READ: VaultMeta b"coach:person_changed_read:v1:" Raw;
    /// A hash of the turns the Coach's room upkeep last declared a room's summary from, so an
    /// unchanged room is not declared again. Key: id16 of the room.
    COACH_ROOM_UPKEEP_DECLARED: VaultMeta b"coach:room_upkeep_declared:v1:" Raw;
    /// The last site-skill candidate filed for one (site, scope), with its content fingerprint and
    /// source evidence (FIX 7606). Key: hash32 (site) + hash32 (scope).
    COACH_SITE_SKILL_SEEN: VaultMeta b"coach:site_skill_seen:v1:" Named;
    /// A quick pick that later proved wrong: a case where a person changed an answer the
    /// ladder gave without thinking more, kept until the Coach's think-threshold run reads it
    /// (FIX 2437). Key: id16 of the source the host bound the answer to.
    COACH_THINK_MISSED: VaultMeta b"coach:think_missed:v1:" Named;
    /// When the Coach's think-threshold run read a source's record, so a replay never counts
    /// twice. Key: id16.
    COACH_THINK_MISSED_READ: VaultMeta b"coach:think_missed_read:v1:" Raw;
    /// When the Coach last climbed (or first saw) a pending skill tradeoff ask, so it climbs one
    /// rung per reminder window. Key: id16 of the ask's proposal.
    COACH_TRADEOFF_CLIMB: VaultMeta b"coach:tradeoff_climb:v1:" Raw;
    /// Immutable tested snapshot of a code document at one exact operation frontier (document id + op
    /// fold hash). Key: hash32 + hash32.
    CODE_DOCUMENT_FRONTIER: VaultMeta b"code_document:frontier:v1:" Named;
    /// Monotonic rename-generation counter (u64be) for a (repo, path) pair, advanced on rename. Key:
    /// hash32.
    CODE_DOCUMENT_GENERATION: VaultMeta b"code_document:generation:v1:" Raw;
    /// Current durable head snapshot plus full receipt history for one code document. Key: hash32.
    CODE_DOCUMENT_HEAD: VaultMeta b"code_document:head:v1:" Named
        => crate::code_document::erase_head_actor_in_txn;
    /// Durable replay-guard receipt for one applied code-file-edit ingress operation. Key: id16.
    CODE_DOCUMENT_INGRESS: VaultMeta b"code_document:ingress:v1:" Named
        => crate::code_document::erase_ingress_actor_in_txn;
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
    /// Node-local executor coverage bound to a minted epoch SUMMARY (fixed 73-byte frame). Key:
    /// id16(run) + id16(summary).
    CODE_RUN_COMPACTION: VaultMeta b"code_run:compaction:v1:" Raw;
    /// One code consent wait (DOOR-079): the binding minted beside its held effect (run and
    /// write site, request and frozen digests, original caller and instrument, the pending
    /// connector call), its ask, the parked step's seal, the owner's first answer, the effect
    /// gate's admission and the settlement. Only `code_run::consent_wait` writes it. Key:
    /// id16(wait).
    CODE_RUN_CONSENT_WAIT: VaultMeta b"code_run:consent_wait:v1:" Named Engine;
    /// A successor attempt's approved continuation of a failed run (FIX 3694): the Failed
    /// predecessor, its run, the step the child starts at, the owner's approval, the approved
    /// prompt and its digest, the start body's digest and its capsule's lease generation. Key:
    /// id16(successor attempt).
    CODE_RUN_CONTINUATION: VaultMeta b"code_run:continuation:v1:" Named Authored;
    /// One contribution check's matched-fork rows (FIX 3028, FIX 2870): each fork's receipt (the
    /// capsule it regenerated, its request hash, model, seed, response body ref, anchor hash, the
    /// outcome, goal revision and axis it was scored for, and its score), or why the pair is
    /// unavailable for good. Key: hash32(attempt receipt, outcome, goal revision, axis, target) +
    /// string(row: `with_skill`, `without_skill` or `unavailable`).
    CODE_RUN_CONTRIBUTION_FORK: VaultMeta b"code_run:contribution_fork:v1:" Named Engine;
    /// Which executor run's fold a fold-words dependent stands for: the dependency walk reaches
    /// it when a record the fold's summary came from is withdrawn (fixed 24-byte frame: id16(run)
    /// + fold u64 BE). Key: id16(dependent).
    CODE_RUN_FOLD_WORDS: VaultMeta b"code_run:fold_words:v1:" Raw;
    /// Node-local fold ledger of one executor run: its marks, compact ask, folds and unfold
    /// appends (JSON). Key: id16(run).
    CODE_RUN_FOLDS: VaultMeta b"code_run:folds:v1:" Raw;
    /// Node-local per-model wire-heal tally, keyed by validated model id. Key: string.
    CODE_RUN_HEAL_COUNT: VaultMeta b"code_run:heal_count:v1:" Raw Engine;
    /// DOOR-141 PR3b: a turn program's resume checkpoint, joined to its code run's checkpoint
    /// commit: the head (the pinned program it replays, the record position and state hash its
    /// last entry committed, the applied and injected positions, its page count and the wait it
    /// parked on) and keyed pages listing each settled call by its record row, request digest
    /// and the delivered wait reply answering it. Refs and digests only, never an effect's body.
    /// Key: id16(code run) + be64(kind: 0 head, 1 page) + be64(page).
    CODE_RUN_PROGRAM_RESUME: VaultMeta b"code_run:program_resume:v1:" Named;
    /// The secret scan's hit in one raw-output body (its reason string), keyed by the same
    /// content handle; absent for a body it found nothing in. Key: string.
    CODE_RUN_RAW_OUTPUT_SECRET: VaultMeta b"code_run:raw_output:secret:v1:" Raw;
    /// The taint refs beside one raw-output row, keyed by the same content handle, in the same
    /// transaction. Key: string.
    CODE_RUN_RAW_OUTPUT_TAINT: VaultMeta b"code_run:raw_output:taint:v1:" Raw;
    /// A code run's raw output bytes, keyed by their deterministic content handle. Key: string.
    CODE_RUN_RAW_OUTPUT: VaultMeta b"code_run:raw_output:v1:" Raw;
    /// The worlds of the rows one code run was served (FIX 6130): its header (tag 0: the capture
    /// epochs still open and why the ledger misses rows) and one row per world a served row sat
    /// in (tag 1 + id16(world): the bridge positions it was served at). Ids and positions only.
    /// Key: id16(run) + u8 tag [+ id16(world)].
    CODE_RUN_READ_WORLD: VaultMeta b"code_run:read_world:v1:" Named Engine;
    /// A code run's fold receipt (ARCH-0079 #reader-forks): the source and range a fold read,
    /// the jobs it named, the ranges read, unread and read short, its cutoff, recipe, summary
    /// tree and taint dependencies (JSON). Key: id16(owner run) + id16(folded occurrence).
    CODE_RUN_READER_FOLD: VaultMeta b"code_run:reader_fold:v1:" Raw;
    /// The index rows of a code run's reader children, by a one-byte tag: `c` id16(parent) +
    /// be64(ordinal) + id16(task) (children in spawn order), `f` id16(parent) + handle -> id16(task)
    /// (findings), `q` be64(enqueued ms) + id16(task) (the queue), `w` id16(task) + id16(set)
    /// (a child's waits), `d` be64(due ms) + id16(set or task) -> `s` or `j` (the due sweep).
    CODE_RUN_READER_INDEX: VaultMeta b"code_run:reader_index:v1:" Raw;
    /// One reader child of a code run: its binding, state, generation and latest finding (JSON).
    /// Key: id16(task).
    CODE_RUN_READER_JOB: VaultMeta b"code_run:reader_job:v1:" Raw Authored;
    /// A code run's reader row: its children's clock, fixed at its first spawn, their spend scope
    /// and its counts (JSON). Key: id16(run).
    CODE_RUN_READER_PARENT: VaultMeta b"code_run:reader_parent:v1:" Raw;
    /// One wait over a code run's reader children, and its first done reduction (JSON). Key:
    /// id16(set).
    CODE_RUN_READER_WAIT: VaultMeta b"code_run:reader_wait:v1:" Raw Authored;
    /// A code run's replay record, keyed by run id. Key: id16.
    CODE_RUN_REPLAY: VaultMeta b"code_run:replay:v1:" Raw Authored;
    /// A canonical attempt's step replay capsule (FIX 3028): the request the step sent by its body
    /// ref and hash, each skill exposure in it, its seed and the rung that answered it. Key:
    /// id16(attempt) + be64(lease generation) + be64(step).
    CODE_RUN_REPLAY_CAPSULE: VaultMeta b"code_run:replay_capsule:v1:" Named Authored
        => crate::code_run::erase_capsule_actor_in_txn;
    /// Whose reply content one code-run replay record holds (FIX 5718): the run it is (its own,
    /// or a write receipt's run) and the actor its host stamped, or Erased once that actor's erase
    /// took it. The capsule table's scrub erases it. Key: id16(record).
    CODE_RUN_RESPONSE_OWNER: VaultMeta b"code_run:response_owner:v1:" Named Engine;
    /// A summary a code run's `summarize` made: its task and its text's occurrence (JSON). Key:
    /// bytes32(memo: BLAKE3 of the members' occurrences and ranges, and the recipe).
    CODE_RUN_SUMMARY_MEMO: VaultMeta b"code_run:summary_memo:v1:" Raw Authored;
    /// One program step's type feedback (FIX 8277): its check's state, measures and diagnostics
    /// or the run's body holding them, the preparation note, the actor the run ran as and the
    /// checker incarnation a pending check belongs to. Key: id16(run) + be64(step) +
    /// be64(invocation).
    CODE_RUN_TYPE_DIAGNOSTICS: VaultMeta b"code_run:type_diagnostics:v1:" Named Authored
        => crate::code_run::erase_type_diagnostics_actor_in_txn;
    /// The reply one parked code-run wait was answered with, and when (JSON). Key: id16(run) +
    /// id16(wait) + be64(generation).
    CODE_RUN_WAIT_DELIVERY: VaultMeta b"code_run:wait_delivery:v1:" Raw Authored;
    /// Who held each code-run wait's reply (FIX 5718): one row per run delivered a reply of the
    /// wait, at the generation it parked, naming the actor its run's replies are, or Erased once
    /// that actor's erase took them. It outlives the wait's waiter and delivery rows. The capsule
    /// table's scrub erases it. Key: id16(wait) + id16(run) + be64(generation).
    CODE_RUN_WAIT_HOLDER: VaultMeta b"code_run:wait_holder:v1:" Named Engine;
    /// The code runs parked on a wait (`p` + id16(wait) + id16(run), value be64(generation)) and
    /// the reply the wait settled with (`s` + id16(wait), value JSON). Key: u8 tag + id16 [+ id16].
    CODE_RUN_WAIT_INDEX: VaultMeta b"code_run:wait_index:v1:" Raw Authored;
    /// Node-local C9 trap a host bound to one parked code-run wait, woken in the commit that
    /// delivers it (fixed layout). Key: id16(run) + id16(wait) + be64(generation).
    CODE_RUN_WAIT_TRAP: VaultMeta b"code_run:wait_trap:v1:" Raw;
    /// Per-code-artifact code-symbol manifest row. Key: id16.
    CODE_SYMBOL_MANIFEST: VaultMeta b"code_symbol:manifest:v1:" Raw
        => crate::code_symbol::erase_manifest_actor_in_txn;
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
    /// An inbound STOP this replica has not projected yet: its party and channel, which hold a
    /// send until the projection that releases it or the event's delete. Key: id16 (the event).
    COMM_PENDING_STOP: VaultMeta b"comm.pending_stop.v1:" Named;
    /// Time-ordered commitment due-index row. Key: u64be + u8 + id16 + id16.
    COMMITMENT_DUE_PRIMARY: VaultMeta b"commitment_due:v1:" Raw;
    /// Instance and phase to primary due-row key. Key: id16 + u8.
    COMMITMENT_DUE_REVERSE: VaultMeta b"commitment_due_rev:v1:" Raw;
    /// Where the owner's own commitment reminders go, and the owner's civil
    /// clock for their delivery windows (OF-187). Key: ().
    COMMITMENT_REMINDER_ROUTE: VaultMeta b"commitment_reminder_route:v1" Named;
    /// Series-membership history. Key: id16 + u64be + u64be + u32be + id16.
    COMMITMENT_SERIES_INSTANCE: VaultMeta b"commitment_series_instance:v1:" Raw;
    /// Pending Project due row of a series. Key: id16.
    COMMITMENT_SERIES_PROJECT: VaultMeta b"commitment_series_project:v1:" Raw;
    /// A conversation's landed self-written summary (FIX 4465 D): its epoch, the SESSION's turn
    /// range and the host's record of what wrote it, conversation evidence included; no words.
    /// Key: id16(summary).
    COMPACTION_CONVERSATION_RECEIPT: VaultMeta b"compaction:conversation_receipt:v1:" Named Engine;
    /// The place a removed epoch summary held in its session's count: the highest removed epoch
    /// and the turn it ended at, no words (OF-013). Key: id16(session).
    COMPACTION_EPOCH_FLOOR: VaultMeta b"compaction:epoch_floor:v1:" Named;
    /// One connector credential slot's issuer binding and issuer change (FIX 988). Key: id16.
    CONNECTOR_CREDENTIAL_BINDING: VaultMeta b"connector.credential_binding.v1/" Named;
    /// The connector key a stamped slate is bound to (16-byte key id). Key: id16(slate).
    CONNECTOR_GRANT_SLATE_BINDING: VaultMeta b"connector.grant_slate.binding.v1/" Raw;
    /// A per-grant key's holder narrows of the slate its calls meet (FIX 987). Key: id16(key).
    CONNECTOR_SLATE_HOLDER_NARROW: VaultMeta b"connector.grant_slate.holder_narrow.v1/" Named;
    /// One logical connector call's typed scope exceed and its ruling (FIX 988). Key: id16.
    CONNECTOR_SLATE_SCOPE_SIGNAL: VaultMeta b"connector.grant_slate.scope_signal.v1/" Named;
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
    /// Owner-reason rule behind a derived standing grant. Key: string (grant ref) ":" id16 (rule
    /// decision id).
    CONSENT_OWNER_REASON_RULE: VaultMeta b"consent.owner_reason.v1:" Named;
    /// Parked authority-widening request. Key: hex64.
    CONSENT_WIDEN_PROPOSAL: VaultMeta b"consent.widen.v1:" LegacyJson;
    /// Marker for a ruled conflict packet. Key: bytes32.
    CLAIM_CONFLICT_RESOLUTION: VaultMeta b"consent_bundle.claim_conflict.resolved.v1:" Raw;
    /// Content-addressed claim-conflict review packet. Key: bytes32.
    CLAIM_CONFLICT_PACKET: VaultMeta b"consent_bundle.claim_conflict.v1:" LegacyJson;
    /// Immutable derived text summary of one output, keyed by source content hash and summarization-
    /// recipe hash. Key: hash32 + hash32.
    COMPACTION_OUTPUT_SUMMARY: VaultMeta b"context:summary:v1:" Raw;
    /// One actor-private versioned board block (actor, section-name length+bytes, block ref) appended
    /// under an admitted plugin section. Key: id16 + u64be + string + id16.
    CONTEXT_BOARD_PLUGIN_BLOCK: VaultMeta b"context_board.block.v1:" LegacyJson Authored;
    /// Session scratchpad pointers: the `scratchpad` NOTE each (actor, session) writes (tag 1), the
    /// actor's one unsealed pad (tag 2) and every pad with its author and session (tag 3); the
    /// seal is NOTE_SEAL. Key: u8 tag + id16 [+ string].
    CONTEXT_BOARD_SCRATCHPAD: VaultMeta b"context_board.scratchpad.v1:" Named;
    /// Immutable recorded contract baseline snapshot (public API names, schemas, command outputs),
    /// keyed by its own content digest; a differing value under the same id is corruption. Key:
    /// hex64.
    CONTRACT_ORACLE_BASELINE: VaultMeta b"contract_oracle:baseline:v1:" Named Authored;
    /// Immutable recorded verdict comparing a candidate snapshot against a recorded baseline (diffs
    /// plus test-pass state), keyed by its own content digest. Key: hex64.
    CONTRACT_ORACLE_VERDICT: VaultMeta b"contract_oracle:verdict:v1:" Named Authored;
    /// Actor id (id16) that created a room; an unrooted vault reads it as the room's owner. Key:
    /// id16 (room).
    CONVERSATION_CREATOR: VaultMeta b"conversation:creator:v1:" Raw;
    /// Per-person room erasure fence: `[1]` while the sweep is in flight, `[2]` once it completed.
    /// Key: id16 (room) + id16 (person).
    CONVERSATION_ERASED_PERSON: VaultMeta b"conversation:erased_person:v1:" Raw;
    /// Durable room (id16) of a MESSAGE, kept after its incident edges are purged. Key: id16
    /// (message).
    CONVERSATION_MESSAGE_OWNER: VaultMeta b"conversation:message_owner:v1:" Raw;
    /// Host-local room role grant of one current member. Key: id16 (room) + id16 (person).
    CONVERSATION_ROLE_GRANT: VaultMeta b"conversation:role_grant:v1:" Named;
    /// Single-byte `[1]` marker that the room role door is rewriting a room body, set and cleared
    /// inside its write transaction. Key: id16 (room).
    CONVERSATION_ROLE_UPDATE: VaultMeta b"conversation:role_update:" Raw;
    /// Transient in-txn permit binding a legacy ChildOf-append record id to the conversation it may
    /// append to. Key: id16.
    CONVERSATION_DAG_APPEND_PERMIT: VaultMeta b"conversation_dag:append_in_txn:v1:" Raw;
    /// Append-only pin of a DAG record's body hash (kind, occurred range, body) so a replay cannot
    /// rewrite an existing record's content. Key: id16.
    CONVERSATION_DAG_BODY_PIN: VaultMeta b"conversation_dag:body_pin:" Raw;
    /// Per-record pointer marking a DAG record canonical (points to its successor), or absent for
    /// terminal. Key: id16.
    CONVERSATION_DAG_CANONICAL: VaultMeta b"conversation_dag:canonical:v1:" Raw;
    /// Single-byte `[1]` reverse Parent witness kept when a DAG record is purged, by parent then
    /// child. Key: id16 (parent) + id16 (child).
    CONVERSATION_DAG_ERASED_CHILD: VaultMeta b"conversation_dag:erased_child:v1:" Raw;
    /// SpawnedBy anchor (id16) of a session whose anchoring DAG record was purged. Key: id16
    /// (session).
    CONVERSATION_DAG_ERASED_SPAWN: VaultMeta b"conversation_dag:erased_spawn:v1:" Raw;
    /// Content-free topology pin (room, parent, session, thread flag, PERSON author) of a soft- or
    /// hard-erased DAG record. Key: id16 (record).
    CONVERSATION_DAG_ERASED_TOPOLOGY: VaultMeta b"conversation_dag:erased_topology:v1:" Named;
    /// Per-conversation pointer to the current local-head DAG record id. Key: id16.
    CONVERSATION_DAG_LOCAL_HEAD: VaultMeta b"conversation_dag:local_head:v1:" Raw;
    /// Single-byte [1] marker that a conversation has adopted the DAG record model. Key: id16.
    CONVERSATION_DAG_MIGRATED: VaultMeta b"conversation_dag:migrated:v1:" Raw;
    /// Durable room (id16) of a room TURN, kept after its ChildOf edge is deleted or purged. Key:
    /// id16 (TURN).
    CONVERSATION_DAG_ROOM_OWNER: VaultMeta b"conversation_dag:room_owner:v1:" Raw;
    /// Cached thread projection of a trunk: `[1]`, root id16, reply count u64be, last reply at
    /// u64be. Key: id16 (trunk).
    CONVERSATION_DAG_THREAD_META: VaultMeta b"conversation_dag:thread_meta:v1:" Raw;
    /// Single-byte `[1]` marker that a trunk's cached thread projection is stale. Key: id16.
    CONVERSATION_DAG_THREAD_META_DIRTY: VaultMeta b"conversation_dag:thread_meta_dirty:v1:" Raw;
    /// Row count / next-sequence counter (u64be) for a conversation's membership ledger. Key: id16.
    CONVERSATION_MEMBERSHIP_SEQ: VaultMeta b"conversation_membership:seq:v1:" Raw;
    /// One append-only membership-ledger event (join/leave/history-visibility change) for a
    /// conversation, keyed by conversation then sequence. Key: id16 + u64be.
    CONVERSATION_MEMBERSHIP_ROW: VaultMeta b"conversation_membership:v1:" Named;
    /// One courtesy deletion ask a former peer sent, filed for the owner's review with the owner's
    /// answer once given (OF-273). Key: bytes32(pact) + bytes16(nonce).
    COOPERATIVE_DELETION_INCOMING: VaultMeta b"cooperative_deletion:incoming:v1:" Named;
    /// The sender's delivery record for one courtesy deletion ask to one recipient: request id,
    /// connection id, pseudonymous recipient id, status and timestamps only (OF-273). Key:
    /// bytes16(nonce) + bytes32(recipient pseudonym).
    COOPERATIVE_DELETION_NOTICE: VaultMeta b"cooperative_deletion:notice:v1:" Named;
    /// One signed ReRoot row of a pact's former peer, kept because it extends the walk from the
    /// key the pact pinned to the root that peer's courtesy asks and answers now carry (FIX 3014).
    /// Key: bytes32(pact) + hash32(authority entry).
    COOPERATIVE_DELETION_SUCCESSION: VaultMeta b"cooperative_deletion:succession:v1:" Named;
    /// Deduplicated set of contact refs reachable for a (party, channel class) pair. Key:
    /// hash32(sha256).
    COUNTERPARTY_CONTACT_PARTY_CHANNEL_INDEX: VaultMeta b"counterparty.contact.party_channel.v1:" Raw;
    /// Lookup index from (identity ref, normalized counterparty) to the contact entity id. Key: id16
    /// + hash32(sha256).
    COUNTERPARTY_CONTACT_INDEX: VaultMeta b"counterparty_contact.index.v1:" Raw;
    /// Terminal custom-agent dispatch failure classification. Key: id16(attempt).
    CUSTOM_AGENT_FAILURE: VaultMeta b"custom-agent:failure:v1:" Raw;
}
