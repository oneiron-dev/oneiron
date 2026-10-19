// Declared `vault_meta` tables whose prefix starts with `f` to `l`, in prefix order.

side_tables! {
    VAULT_META_F_L;
    /// One sealed FIX6 code-fix export (an invented example or a candidate fix's result) waiting
    /// for the host to drain it, with the worlds it touched; never real chat text. Key: id16.
    FAILURE_SIGNALS_CODE_FIX: VaultMeta b"failure_signals:code_fix:v1:" Named;
    /// The Coach's code-fix work on one failure case and its local verdicts: the invented
    /// example's and the candidate fix's, kept after the export queue drains. Never real chat
    /// text. Key: id16(case key).
    FAILURE_SIGNALS_CODE_FIX_WORK: VaultMeta b"failure_signals:code_fix_work:v1:" Named;
    /// A diagnostic already counted into the tier-1 failure aggregate, and when it observed; a
    /// later capture of the same diagnostic counts nothing (OF-380). Key: id16 (diagnostic id).
    FAILURE_SIGNALS_TIER1_COUNTED: VaultMeta b"failure_signals:tier1_counted:v1:" Raw;
    /// One tier-1 failure count not yet delivered to the publisher, kept across restarts: the
    /// count (u64be), then its content-free dimensions as JSON. Key: bytes32 (blake3 of that
    /// JSON).
    FAILURE_SIGNALS_TIER1_COUNTS: VaultMeta b"failure_signals:tier1_counts:v1:" Raw;
    /// The actor bound to the active content write transaction, deleted before commit. Key: ().
    FEDERATION_ACTOR_CONTENT_INFLIGHT: VaultMeta b"federation:actor-content:inflight:v1" Raw;
    /// An ask guest's FEDERATION_GRANT the owner withdrew: the guest it conferred on and when, so
    /// a repeat revoke reports the first (OF-232). Key: id16 (grant).
    FEDERATION_GUEST_REVOKE: VaultMeta b"federation:guest_revoke:v1:" Named;
    /// The owner's confidence scale for claims one federation peer sends, this device's local
    /// truth (OF-149). Key: id16(peer principal).
    FEDERATION_PEER_CONFIDENCE: VaultMeta b"federation:peer_confidence:v1:" Named;
    /// One note the open feedback inbox took, kept for the triage sweep. Key: u64be(sequence).
    FEEDBACK_INBOX: VaultMeta b"feedback:inbox:v1:" Named;
    /// An owner feedback preview as it was shown, kept until it expires (FIX 5212): its exact
    /// bytes, encoding and digest, the digest of the bundle as built before filtering, and the
    /// owner and route it was previewed for. A send reads it back and never filters again.
    /// Key: u64be(issued at) + bytes32(approval component digest).
    FEEDBACK_PREVIEW: VaultMeta b"feedback:preview:v1:" Named;
    /// Open feedback-review-item queue row awaiting triage. Key: id16.
    FEEDBACK_QUEUE: VaultMeta b"feedback:queue:v1:" Named;
    /// Dedup index from a feedback bundle's content digest to the review item id that first recorded
    /// it. Key: hex64.
    FEEDBACK_RECEIVED_DIGEST: VaultMeta b"feedback:received:v1:" Raw;
    /// Universal report arrivals; review lives on the ISSUE entity. Key: u64be + id16.
    FEEDBACK_REPORT_ARRIVAL: VaultMeta b"feedback:report-arrival:v1:" Named;
    /// T2 report membership and vectors, keyed by the first ISSUE id.
    FEEDBACK_REPORT_CLUSTER: VaultMeta b"feedback:report-cluster:v1:" Named;
    /// Owner disclosure preference, keyed by the resolved publisher reference.
    FEEDBACK_REPORT_DISCLOSURE: VaultMeta b"feedback:report-disclosure:v1:" Named;
    /// Host-stamped subject provenance or owner routing policy. Key: subject reference.
    FEEDBACK_REPORT_ROUTE: VaultMeta b"feedback:report-route:v1:" Named;
    /// A folder the owner attached as a standing source of notes (OF-554): the folder, its
    /// include patterns, default kind, source and trust tier, and its last rescan. Key: hex16
    /// (hash of the folder).
    FOLDER_SOURCE: VaultMeta b"folder-source:attached:v1:" Named
        => crate::note::erase_folder_source_actor_in_txn;
    /// What an attached folder's rescans know of one file: its note, the hash of its text and of
    /// what the vault took from it, and whether it landed, waits as a fork or was retracted.
    /// Key: string (`folder hash:path`, a long path by its hash).
    FOLDER_SOURCE_FILE: VaultMeta b"folder-source:file:v1:" Named;
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
    /// Latest verified claim-write retention ancestry, inherited by later decisions on the claim;
    /// the retention-scope module's own layout. Key: id16 (claim).
    GATE_DECISION_CLAIM_CONTEXT: VaultMeta b"gate_decision:claim_context:v1:" Raw;
    /// Grant-reference index over the gate decision ledger. Key: u64be len + string + id16.
    GATE_DECISION_GRANT_REF_INDEX: VaultMeta b"gate_decision:grant_ref_index:v1:" Raw;
    /// Latest retain-until stamp (u64be seconds) of a held gate decision partition. Key: 0
    /// (claim-free partition) or 1 + id16 (claim).
    GATE_DECISION_PARTITION_RETAIN_UNTIL: VaultMeta b"gate_decision:partition_retain_until:v1:" Raw;
    /// Append-time retention ancestry of one gate decision; the retention-scope module's own
    /// layout. Key: id16 (decision).
    GATE_DECISION_RETENTION_CONTEXT: VaultMeta b"gate_decision:retention_context:v1:" Raw;
    /// Gate decision ledger row. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice): decode also enforces
    /// `vet_gate_decision_record` (version, notice, receipt-reason and
    /// redaction-shape checks), business validation `Named`'s generic
    /// strict-msgpack decode does not run; `RawValue` delegates to the
    /// module's own `encode_gate_decision`/`decode_gate_decision`.
    GATE_DECISION_LEDGER: VaultMeta b"gate_decision:v0:" Raw Ciphertext
        => crate::store::erase_gate_decision_actor_in_txn;
    /// Claim-keyed gate decision index. Key: id16 + id16.
    GATE_DECISION_CLAIM_INDEX: VaultMeta b"gate_decision_by_claim:v0:" Raw;
    /// Claim-index backfill flag. Key: ().
    GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE: VaultMeta b"gate_decision_by_claim_backfill_complete" Raw;
    /// Per-constituent index over bundle decisions' claim refs; empty value. Key: id16 (claim) +
    /// id16 (decision).
    GATE_DECISION_CLAIM_REF_INDEX: VaultMeta b"gate_decision_by_claim_ref:v0:" Raw;
    /// A bundle decision's complete constituent claim ids (ascending, distinct). Key: id16.
    GATE_DECISION_CLAIM_REFS: VaultMeta b"gate_decision_claim_refs:v0:" LegacyCompact;
    /// Batch preflight decision whose op has not applied yet; never survives a commit. Key: id16.
    GATE_DECISION_UNAPPLIED_PREFLIGHT: VaultMeta b"gate_decision_unapplied_preflight:v0:" Raw;
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
    /// Owner-confirmed voice disclosure grant offer. Key: hex64 nonce.
    GENUI_VOICE_GRANT_OFFER: VaultMeta b"genui.voice_grant_offer.v1:" LegacyJson;
    GIT_WIRE_RECORD: VaultMeta b"git_wire:record:v2:" Named;
    /// Node-local Gmail page cursor keyed by lower-case hex identity id. Key: hex32.
    GMAIL_MAILBOX_CURSOR: VaultMeta b"gmail:mailbox_cursor:v1:" LegacyJson;
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
    SELF_HEAL_HEALER_PROPOSAL: VaultMeta b"healer:proposal:" Named Authored;
    /// A human-ratified patch pull-request record for a released healer proposal. Key: id16.
    SELF_HEAL_HEALER_RELEASE: VaultMeta b"healer:release:" Named;
    /// Per-actor per-run healer receipt: submitted proposals and reversal state. Key: id16 + bytes32
    /// (actor then blake3 hash of run name).
    SELF_HEAL_HEALER_RUN: VaultMeta b"healer:run:" Named Authored;
    /// The history import ledger: one row per imported source message (the conversation it landed
    /// in, its MESSAGE and TURN ids, the hash of what was imported, its revision). Key: string
    /// (`source:native message id`).
    INGEST_HISTORY_LEDGER: VaultMeta b"history-import:v1:" Named Authored;
    /// A hook block: the rows one AddBlock pins for a recipient's board deliveries, its lifetime
    /// and its consumption. Key: id16 (block).
    HOOKS_BLOCK: VaultMeta b"hooks:block:v1:" Named Authored;
    /// An owner check a hook's causal chain raised (a cycle or a deep chain). Key: hash32 (run key).
    HOOKS_CHECK: VaultMeta b"hooks:check:v1:" Named;
    /// A fact hook's cursor in one source. Key: id16 (binding) + u8 (source).
    HOOKS_CURSOR: VaultMeta b"hooks:cursor:v1:" Named;
    /// The vault's `hooks.enabled` switch; absent is on. Key: ().
    HOOKS_ENABLED: VaultMeta b"hooks:enabled:v1" Named;
    /// The owner's grant on one hook binding. Key: id16 (binding).
    HOOKS_GRANT: VaultMeta b"hooks:grant:v1:" Named;
    /// Queued work a hook run saved before its cursor moved, and whether it landed. Key: hash32
    /// (run key).
    HOOKS_INTENT: VaultMeta b"hooks:intent:v1:" Named Authored;
    /// The hook chain behind a row a hook landed. Key: id16 (row).
    HOOKS_LINEAGE: VaultMeta b"hooks:lineage:v1:" Named;
    /// A hook run's saved result and pinned input. Key: hash32 (run key).
    HOOKS_MEMO: VaultMeta b"hooks:memo:v1:" Named Authored;
    /// A hook run's Hook receipt. Key: hash32 (run key).
    HOOKS_RECEIPT: VaultMeta b"hooks:receipt:v1:" Named Authored;
    /// A hook's regen record: the contract its last good body passed under, its intent, and a
    /// regen decision waiting to be enacted. Key: id16 (binding).
    HOOKS_REGEN: VaultMeta b"hooks:regen:v1:" Named Authored;
    /// Each hook binding's runs in commit order, each naming its saved row: a fact run's memo or
    /// a verb run's saved copy. Key: id16 (binding) + u64be (commit time, Unix ms) + hash32 (run
    /// key).
    HOOKS_RUN_INDEX: VaultMeta b"hooks:run_index:v1:" Named;
    /// The settlement feed fact hooks follow: one row per settled proposal. Key: u64be (sequence).
    HOOKS_SETTLED: VaultMeta b"hooks:settled:v1:" Named;
    /// The last settlement sequence handed out. Key: ().
    HOOKS_SETTLED_NEXT: VaultMeta b"hooks:settled_next:v1" Named;
    /// A call a verb hook's ask stopped: the call, its re-validated args, the hook's place in the
    /// chain and the ask handle, Open until a retry resumes it once. Key: id16 (invocation).
    HOOKS_VERB_ASK: VaultMeta b"hooks:verb_ask:v1:" Named;
    /// The instrument a credential caller's request was admitted on, pinned beside its stopped
    /// call for the drain to verify again: a slip, its holder's challenge and signature, never a
    /// secret. Pruned with the call. Key: id16 (invocation).
    HOOKS_VERB_ASK_WITNESS: VaultMeta b"hooks:verb_ask_witness:v1:" Named;
    /// A verb hook run's saved copy: the exact input its body saw, its read pins and the outcome it
    /// returned. Key: hash32 (run key).
    HOOKS_VERB_RUN: VaultMeta b"hooks:verb_run:v1:" Named Authored;
    /// One engine housekeeping sweep's schedule: when it is next due, when its last run finished,
    /// and whether a run is in flight. Key: string (the sweep's code).
    HOUSEKEEPING_SCHEDULE: VaultMeta b"housekeeping:v1:" Named;
    /// A retirement deadline a door started (a secret lease's expiry, a voice print's retention
    /// deadline, a critical confirm's window), kept for a vault that is not running to know when to
    /// wake. Key: the sweep's tag byte, the deadline (u64 BE), then an id16 per note, so a sweep's
    /// earliest deadline is its first row and two notes of one deadline are two rows. Value: empty.
    HOUSEKEEPING_WAKE: VaultMeta b"housekeeping:wake:v1:" Raw;
    /// Follow-up reminder/escalation cursor state for one human task. Key: id16.
    HUMAN_TASK_FOLLOWUP: VaultMeta b"human_task.followup.v1\0" Raw;
    /// The TASK whose follow-up cursor the due sweep read last: the next wake pass resumes after
    /// it. Key: ().
    HUMAN_TASK_FOLLOWUP_SWEEP: VaultMeta b"human_task.followup_sweep.v1" Raw;
    /// Idempotency marker recording which signal/surface-event a wait's response already produced.
    /// Key: id16.
    HUMAN_TASK_WAIT_SIGNAL: VaultMeta b"human_task.wait.signal.v1\0" Raw;
    /// Active binding from a human task to the trap claim awaiting its response. Key: id16.
    HUMAN_TASK_WAIT_BINDING: VaultMeta b"human_task.wait.v1\0" Raw;
    /// Empty-marker index from a normalized identity hint (name/alias/handle) hashed per entity-kind
    /// to the entity id it names, for lookup-before-mint resolution. Key: u8 + hash32 + id16.
    INGEST_IDENTITY_HINT: VaultMeta b"identity-hint:v1:" Raw;
    /// One sensitive-topic cluster of imported claims (OF-492): its topic label, the claims
    /// and import reviews seen in it, and whether it was found clear, asked of the owner
    /// (the frozen question, evidence and options) or settled as a standing rule. Key: id16
    /// (the topic id).
    IMPORT_AUDIENCE_CLUSTER: VaultMeta b"import-audience:cluster:v1:" Named;
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
    /// The next tagging marker's sequence number, a part of its derived id, so no marker id is
    /// ever drawn twice, even once a settled marker has left the job ledger. Key: (). Value: u64be.
    TAGGING_MARKER_SEQUENCE: VaultMeta b"job:tagging_marker_seq:v1" Raw;
    /// A turn's recorded tagging traces, oldest first: job state, never synced. Key: turn id16
    /// (sixteen zero bytes for a marker whose payload named no turn) + u64be sequence.
    TAGGING_TRACE: VaultMeta b"job:tagging_trace:v1:" Named;
    /// Empty-marker age index over the tagging traces. Key: u64be recorded-at + turn id16 + u64be
    /// sequence.
    TAGGING_TRACE_AGE: VaultMeta b"job:tagging_trace_age:v1:" Raw;
    /// The vault's typed key custody binding (`store::key_custody`): version 1, namespace
    /// (16), vault id (32), then the native absolute root path the custody sits beside; never
    /// key material. Pinned by the first publication with what it protects. Key: ().
    KEY_CUSTODY_BINDING: VaultMeta b"key_custody:binding:v1" Raw;
    /// A committed intent to retire one custody subject's entries through a generation:
    /// u64be generation, then cause (0 retention, 1 erase). Key: vault id (32) + kind tag (1) +
    /// item.
    KEY_CUSTODY_RETIRE_PENDING: VaultMeta b"key_custody:retire_pending:v1:" Raw;
    /// Vault-scoped structural-kind registration. Key: u8.
    STRUCTURAL_KIND_REGISTRY: VaultMeta b"kind_reg:" Raw;
    /// A `learning.*` cell's key, estimate form and what counted. Key: cell digest (32 bytes).
    LEARNING_CELL: VaultMeta b"learning:cell:v1:" Named;
    /// Subject index over `learning.*` cells (value: the member). Key: subject id16 + cell digest.
    LEARNING_CELL_SUBJECT: VaultMeta b"learning:cell_subject:v1:" Named;
    /// Owner seed or pin over one spawn choice (model, width, pattern or budget) at a goal, a
    /// project, a task type or the vault (value, weight in runs, setter, why). Key: string (choice
    /// "\0" mode, then the scope).
    LEARNING_CHOICE: VaultMeta b"learning:choice:v1:" Raw
        => crate::learning_setting_choice::erase_choice_actor_in_txn;
    /// A team's derived coordination cost (wait by reason, reuse delay, duplicate work): a
    /// diagnostic, never a score. Key: string (team reference).
    LEARNING_COORDINATION: VaultMeta b"learning:coordination:v1:" Named;
    /// An audit's label that two pieces of one team's work duplicated each other. Key: string
    /// (team reference "\0" first "\0" second).
    LEARNING_DUPLICATE_LABEL: VaultMeta b"learning:duplicate_label:v1:" Named;
    /// One admitted anchored outcome for a `learning.*` cell. Key: cell digest + receipt string.
    LEARNING_EVIDENCE: VaultMeta b"learning:evidence:v1:" Named;
    /// A judge swap's fitted score map, applied as a projection. Key: string (old judge revision).
    LEARNING_JUDGE_CONVERSION: VaultMeta b"learning:judge_conversion:v1:" Named;
    /// A `learning.*` cell's engine-written prior (origin, value, weight in runs). Key: cell digest.
    LEARNING_PRIOR: VaultMeta b"learning:prior:v1:" Named;
    /// Owner seed or pin over one learned-setting catalog row (value, weight in runs, setter, why).
    /// Key: string (setting key "\0" mode).
    LEARNING_SETTING: VaultMeta b"learning:setting:v1:" Raw
        => crate::learning_setting::erase_setting_actor_in_txn;
    /// The vault-scope `learning.setting` fit, cached beside its claim for hot readers. Key: string
    /// (setting key).
    LEARNING_SETTING_FIT: VaultMeta b"learning:setting_fit:v1:" Named;
    /// The customer holds an owner's lift-and-erase confirm lifted from one record, until its
    /// deletion receipt completes (OF-470 C4). Key: id16 (record).
    LEGAL_HOLD_ERASE_LINK: VaultMeta b"legal_hold:erase_link:v1:" Named;
    /// The owner-visible legal-hold log: ids, times and reason codes only (OF-470 C3). Key: id16
    /// (hold) + u64be (sequence).
    LEGAL_HOLD_EVENT: VaultMeta b"legal_hold:event:v1:" Named;
    /// The host orders an owner's confirmed erase met (OF-470 C4). Host-only and runtime-tier:
    /// no checkpoint image carries it. Key: id16 (record).
    LEGAL_HOLD_HOST_ERASE_LINK: VaultMeta b"legal_hold:host:erase_link:v1:" Named;
    /// The host-only legal-hold log (OF-470 C2). Runtime-tier: no checkpoint image carries it.
    /// Key: id16 (hold) + u64be (sequence).
    LEGAL_HOLD_HOST_EVENT: VaultMeta b"legal_hold:host:event:v1:" Named;
    /// A host-order legal hold Oneiron placed on an authority order (OF-470 C1). Runtime-tier: no
    /// checkpoint image carries it. Key: id16 (hold).
    LEGAL_HOLD_HOST_ROW: VaultMeta b"legal_hold:host:row:v1:" Named;
    /// What a standing host-order hold holds; the value is empty. Key: held key (1 + id16, or 17
    /// zero bytes for the claim-free gate partition) + id16 (hold).
    LEGAL_HOLD_HOST_TARGET: VaultMeta b"legal_hold:host:target:v1:" Raw;
    /// An owner-confirmed erase a host order keeps waiting; it names no hold. Key: id16 (record).
    LEGAL_HOLD_PENDING_ERASE: VaultMeta b"legal_hold:pending_erase:v1:" Named;
    /// A customer legal hold naming records or gate-decision partitions (OF-470). Key: id16
    /// (hold).
    LEGAL_HOLD_ROW: VaultMeta b"legal_hold:row:v1:" Named;
    /// What a standing customer hold holds; the value is empty. Key: held key (1 + id16, or 17
    /// zero bytes for the claim-free gate partition) + id16 (hold).
    LEGAL_HOLD_TARGET: VaultMeta b"legal_hold:target:v1:" Raw;
    /// A record kept after a refused privacy erasure, serving only that legal reason (OF-470 C6).
    /// Key: id16 (record).
    LEGAL_HOLD_USE_LIMIT: VaultMeta b"legal_hold:use_limit:v1:" Named;
    /// Vault-scoped authored lens prompt keyed by the lens entity id16.
    LENS_INTENT: VaultMeta b"lens/intent/v1\0" Named;
    /// One proposed pack lens: its frozen compiled tree, the pack/skill slot and pack content
    /// hash it is bound to, and who proposed it. It mounts only once the owner selects it. Key:
    /// id16 (lens).
    LENS_PROPOSAL: VaultMeta b"lens/proposal/v1\0" Named
        => crate::lens::erase_proposal_actor_in_txn;
    /// The owner's consented selection of one proposed lens revision for a pack/skill slot.
    /// Key: string (pack name "\0" skill id hex).
    LENS_SLOT: VaultMeta b"lens/slot/v1\0" Named
        => crate::lens::erase_slot_actor_in_txn;
    /// Tracker issue id to task id. Key: string.
    LINEAR_ISSUE_REVERSE: VaultMeta b"linear.issue.v1/" Raw;
    /// One TASK's mirror control (OF-427 C6): whether it is opted out, its mapping revision and
    /// its last mapping edit. Key: id16 (TASK).
    LINEAR_MIRROR_CONTROL: VaultMeta b"linear.mirror_control.v1/" Named Engine
        => crate::linear_sync::erase_mirror_control_actor_in_txn;
    /// One mirror event (OF-427): a webhook delivery, a sent push, a mapping edit or a title
    /// edit, with its external evidence and receipt. Key: direction byte + 32-byte digest.
    LINEAR_MIRROR_EVENT: VaultMeta b"linear.mirror_event.v1/" Named
        => crate::linear_sync::erase_mirror_event_actor_in_txn;
    /// One TASK's mirror events by time; the value is empty. Key: id16 (TASK) + u64be (at) +
    /// 33-byte event key.
    LINEAR_MIRROR_EVENT_BY_TASK: VaultMeta b"linear.mirror_event_by_task.v1/" Raw;
    /// Tracker pull-page cursor. Key: ().
    LINEAR_PULL_CURSOR: VaultMeta b"linear.pull_cursor.v1" Raw Authored;
    /// Tracker-mirror outbox marker. Key: id16.
    LINEAR_TASK_DIRTY: VaultMeta b"linear.task_dirty.v1/" Raw Engine;
    /// Tracker-mirror revision counter of a task. Key: id16.
    LINEAR_TASK_REVISION: VaultMeta b"linear.task_revision.v1/" Raw Engine;
    /// Verified typed writer of a task at its current revision (u64be revision, id16 actor, class
    /// byte). Key: id16.
    LINEAR_TASK_WRITER: VaultMeta b"linear.task_writer.v1/" Raw;
    /// Digest of the Linear effect request an operation id was first authorized for. Key: 32-byte
    /// operation id.
    LINEAR_EFFECT_AUTHORIZED: VaultMeta b"linear:effect_authorized:v1/" Raw;
    /// Task to tracker issue link state. Key: id16.
    LINEAR_SYNC_LINK: VaultMeta b"linear_sync:link:v4:" LegacyJson Authored;
    /// The vault's pinned model-role manifest (role bindings, tier/route defaults). Key: ().
    /// Owner-reviewed role binding offers with their retained trial evidence. Key: id16.
    LLM_BINDING_PROPOSAL: VaultMeta b"llm:binding_proposal:v1:" Named;
    /// The current immutable catalog revision. Key: ().
    LLM_CATALOG_HEAD: VaultMeta b"llm:catalog_head:v1" Named;
    /// Pinned catalog prices, scores and refresh diffs. Key: revision string.
    LLM_CATALOG_REVISION: VaultMeta b"llm:catalog_revision:v1:" Named;
    /// Measured description scores keyed inside one singleton map. Key: ().
    LLM_DESCRIPTION_MEASUREMENTS: VaultMeta b"llm:description_measurements:v1" LegacyJson Authored;
    /// Vault-owned description policy. Key: ().
    LLM_DESCRIPTION_POLICY: VaultMeta b"llm:description_policy:v1" LegacyJson Authored;
    /// Durable re-ask keyed by 64-character hex identity.
    LLM_DESCRIPTION_REASK: VaultMeta b"llm:description_reask:v1:" LegacyJson;
    /// Training provenance and checkpoint pin for the installed distilled encoder. Key: ().
    LLM_ENCODER_EXPORT: VaultMeta b"llm:encoder_export:v1" Named;
    /// The passing extraction-teacher probe approval behind the pinned teacher. Key: ().
    LLM_EXTRACTION_TEACHER_PROBE: VaultMeta b"llm:extraction_teacher_probe:v1" LegacyJson;
    LLM_MANIFEST: VaultMeta b"llm:manifest:v2" LegacyJson;
    /// Revision-pinned description of one registered model, read by seat routing. Key:
    /// string(model id).
    LLM_MODEL_DESCRIPTION: VaultMeta b"llm:model_description:v1:" LegacyJson Authored;
    /// Held-out model trial, billed evidence and switch offer. Key: question id16 + trial id16.
    LLM_MODEL_TRIAL: VaultMeta b"llm:model_trial:v1:" Named;
    /// Vault-local per-purpose and voice-lane inference defaults table. Key: ().
    LLM_PURPOSE_DEFAULTS: VaultMeta b"llm:purpose_defaults:v1" LegacyJson;
    /// Priced model-catalog row: wire format, cost, and cached benchmark scores. Key: string(model
    /// id).
    LLM_REGISTRY_ROW: VaultMeta b"llm:registry:v1:" LegacyJson Authored;
    /// Per-vault narrow-only resident route overrides, cleared when the manifest is replaced. Key:
    /// ().
    LLM_RESIDENT_ROUTES: VaultMeta b"llm:resident_routes:v1" LegacyJson;
    /// One routed seat selected and pinned by caller-chosen bounded seat id.
    LLM_ROUTED_SEAT: VaultMeta b"llm:routed_seat:v1:" LegacyJson Authored;
    /// A run's immutable model-seat pin and choice receipt, committed before its first provider
    /// call. Key: id16 (run).
    LLM_RUN_SEAT: VaultMeta b"llm:run_seat:v1:" LegacyJson;
    /// Rolling window (max 64) of recent benchmark score-change diffs for one model. Key:
    /// string(model id) "\x00".
    LLM_SCORE_DIFFS: VaultMeta b"llm:scores:v1:" LegacyJson Authored;
    /// The catalog revision pinned when a held-out trial was nominated. Key: id16.
    LLM_TRIAL_CATALOG: VaultMeta b"llm:trial_catalog:v1:" Named;
}
