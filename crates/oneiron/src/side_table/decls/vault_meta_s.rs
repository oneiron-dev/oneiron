// Declared `vault_meta` tables whose prefix starts with `s`, in prefix order.

side_tables! {
    VAULT_META_S;
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
    /// One row of an Arc's durable work generation (FIX 7509 PR3): its manifest, a part's progress or
    /// its assembly, as refs, pins, ranges and step refs only. Key: string (work id hex + typed suffix).
    SCOPE_SUMMARY_ARC_WORK: VaultMeta b"scope_summary:arc_work:v1:" Named;
    /// Active scope-summary projection and its last observed input hash. Key: hash32.
    SCOPE_SUMMARY_PROJECTION: VaultMeta b"scope_summary:projection:v1:" Named;
    /// Owner-approved summary-purpose descriptor. Key: string (descriptor id).
    SCOPE_SUMMARY_PURPOSE: VaultMeta b"scope_summary:purpose:v1:" Named;
    /// Atomic summary/landing result of one queued declaration. Key: AttemptId.
    SCOPE_SUMMARY_RESULT: VaultMeta b"scope_summary:result:v1:" Named;
    /// The encrypted input of one active custody change (WILL L04 row 04): the metadata and value
    /// sealed to the change's holder, with the second it was sealed at and the request it is for,
    /// kept to relay until its holder answers. Holds no plaintext. Key: hash32 (the ciphertext
    /// digest the request names).
    SECRET_CUSTODY_INPUT: VaultMeta b"secret_custody:input:v1:" Raw Ciphertext;
    /// Name index mapping a live secret-custody record's name to its EntityId, then the name's
    /// generation high-water as a big-endian u32, kept after the record is gone (FIX 5958). Key:
    /// string (secret name).
    SECRET_CUSTODY_NAME_INDEX: VaultMeta b"secret_custody:name:v1:" Raw Custody;
    /// What one custody request's executor committed (WILL L04 row 04): the digest of the custody
    /// transition it signed and the rotation receipt it wrote, immutable once written, beside the
    /// latest transition by id. A retry finds it and changes nothing. Key: hash32 (the request's
    /// entry hash).
    SECRET_CUSTODY_OUTPUT: VaultMeta b"secret_custody:output:v1:" Raw Engine;
    /// A revoke of one portable custody record this install made but could not carry for the
    /// owner yet, with no live machine profile or no install key loaded (CALLS
    /// CUSTODY_REVOKE_PENDING_CARRY): the owner it is by, the surface he decided on, the second
    /// it was made at and the generation it revoked, until a pass that can sign carries it. Holds
    /// no value and no proof. Key: id16 (custody record id).
    SECRET_CUSTODY_PENDING_REVOKE: VaultMeta b"secret_custody:pending_revoke:v1:" Named Engine
        => crate::secret_custody::erase_pending_revoke_actor_in_txn;
    /// The rewrap request whose bindings this vault took into one custody record it holds as a
    /// receiver (CALLS CUSTODY_REBIND_PENDING_FLOOR): a replay of its carrier never applies again,
    /// while a carrier kept as this vault's latest whose bindings the live floor refused stays
    /// pending. Canonical (FIX 5337): a checkpoint carries it with the record it was taken into,
    /// and a restore over a live vault keeps the live vault's. Key: hex32(entity id).
    SECRET_CUSTODY_REBIND: VaultMeta b"secret_custody:rebind:v1:" Raw Engine;
    /// The latest owner-signed custody transition this vault signed of one portable credential
    /// (OF-422): the record without its value, the value sealed to each machine mine here. Key:
    /// hex32(entity id).
    SECRET_CUSTODY_TRANSITION: VaultMeta b"secret_custody:transition:v1:" Raw Custody;
    /// Forward sidecar of secret taint-refs attached to one piece of build exhaust. Key: hex32(entity
    /// id).
    SECRET_EXHAUST_TAINT: VaultMeta b"secret_exhaust_taint:v1:" Raw;
    /// The keys a mask on write lifted out of one record or file, each with its handle, its kind,
    /// where it sat and what the owner did about it (OF-560's found-key notice). Holds no value.
    /// Key: id16 (the record, or the file's ASSET).
    SECRET_FOUND_KEY: VaultMeta b"secret_found_key:v1:" Named
        => crate::secret_custody::erase_found_key_actor_in_txn;
    /// A record whose found keys still owe the owner their needs-you notice: raised at the next
    /// write's commit boundary, then removed. Key: id16 (the record).
    SECRET_FOUND_KEY_DUE: VaultMeta b"secret_found_key_due:v1:" Named;
    /// Each custody record's committed known-value history (KS-3): the slot of each entry typed
    /// custody holds for it (`KnownValueEntry`, item = the record's id) with the record generation
    /// it was written at, never a value, length, tag or fingerprint. Canonical, so an image
    /// carries the references and a restore requires every one in current custody; the record's
    /// erase removes them and stages its entries' retirement. Key: id16 (custody record id).
    SECRET_KNOWN_HISTORY: VaultMeta b"secret_known:history:v1:" Raw Engine;
    /// The known-value index's master key reference (KS-3): the generation of the key typed
    /// custody holds for the index (`KnownValueIndex`), never the key. Committed with the first
    /// value the index keys and kept after the last holder's erase: the master is never minted
    /// again. Key: ().
    SECRET_KNOWN_INDEX: VaultMeta b"secret_known:index:v1" Raw Engine;
    /// T1/T2 secret-materialization lease row (escalation ladder to local registration). Key:
    /// hex32(lease id).
    SECRET_LEASE: VaultMeta b"secret_lease:v1:" Raw
        => crate::secret_lease::erase_lease_actor_in_txn;
    /// A value-free grant a secret lease's holder redeems (FIX 4313): the custody record, the
    /// value generation it pins, the holder principal and run, the effector, the target and the
    /// expiry, and for a T1/T2 grant the lease it rides. Key: id16 (grant id).
    SECRET_LEASE_GRANT: VaultMeta b"secret_lease_grant:v1:" Named Engine
        => crate::secret_lease::erase_secret_grant_actor_in_txn;
    /// Durable receipt written before a secret value is returned from materialization. Key:
    /// hex32(receipt id).
    SECRET_MATERIALIZATION_RECEIPT: VaultMeta b"secret_lease_receipt:v1:" Raw
        => crate::secret_lease::erase_receipt_actor_in_txn;
    /// A carrier row the historical lift sweep marked (OF-067): the bytes it marked, by their
    /// hash, the detector's reason and the parts its readers withhold. The carrier keeps its
    /// bytes. Holds no value. Key: the carrier table's name, a colon, then its row key.
    SECRET_LIFT_MARK: VaultMeta b"secret_lift:mark:v1:" Named Engine;
    /// The needs-you notice the lift sweep raised last for its open proposals: the run that raised
    /// it and each owner's inbox row, acknowledged once none is open (OF-067). Key: ().
    SECRET_LIFT_NOTICE: VaultMeta b"secret_lift:notice:v1" Named Engine;
    /// A hit the historical lift sweep could not place, filed for the owner: the record or row
    /// that holds it, the detector's reason and why the sweep left it, and once closed, when, by
    /// whom and why (OF-067). Holds no value. Key: the family's code, a zero byte, `h` for a
    /// retained-history proposal or `r` for the row's own, then the row's key.
    SECRET_LIFT_PROPOSAL: VaultMeta b"secret_lift:proposal:v1:" Named;
    /// One finished lift sweep run's owner receipt: counts per family, never a value or a digest
    /// (OF-067). Key: id16 (run id).
    SECRET_LIFT_RECEIPT: VaultMeta b"secret_lift:receipt:v1:" Named;
    /// The lift sweep run in progress: its trigger and its `(family, last key)` cursor (OF-067).
    /// Key: ().
    SECRET_LIFT_RUN: VaultMeta b"secret_lift:run:v1" Named;
    /// T2 local-file registration for a materialized secret, read wholesale for snapshot exclusion.
    /// Key: hex32(lease id).
    SECRET_LOCAL_REGISTRATION: VaultMeta b"secret_local:v1:" Raw;
    /// Where a mask on write found the secret one custody record holds: the record, the field and
    /// the key's kind (OF-560). Key: id16 (custody record id).
    SECRET_MASK_ORIGIN: VaultMeta b"secret_mask:origin:v1:" Named Custody;
    /// A file stored with keys in it: each key's span in its bytes, or in a container member it
    /// holds (OF-067 C), the custody record that holds it, and its band (OF-560, owner ruling G04
    /// binary = C2). Key: hash32 (blake3 of the stored bytes).
    SECRET_MASK_SPANS: VaultMeta b"secret_mask:spans:v1:" Named Custody;
    /// One reveal of a secret's value by its handle: the agent's ask, the owner's answer and the
    /// lease that delivered it, or the owner's own read with its reason (OF-560). Holds no value.
    /// Key: id16 (reveal id).
    SECRET_REVEAL: VaultMeta b"secret_reveal:v1:" Named
        => crate::secret_custody::erase_reveal_actor_in_txn;
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
    /// The T2 the host's detector pass registered for one family from its reviewed T3 findings,
    /// with the closed-form T1 that graduated it (OF-418). Key: the family string.
    SELF_HEAL_MINTED: VaultMeta b"self_heal:minted:v1:" Named;
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
    /// Per-session lifecycle clock record (started_at, last_activity, ended_at, end_reason) and its
    /// bound speakers (FIX 2015), keyed by SESSION entity id. Key: id16.
    SESSION_LIFECYCLE_RECORD: VaultMeta b"session_lifecycle:v0:record:" Named
        => crate::session_lifecycle::erase_session_speaker_actor_in_txn;
    /// TURN to SESSION membership row. Key: id16.
    SESSION_TURN_MEMBERSHIP: VaultMeta b"session_lifecycle:v0:turn_session:" Raw;
    /// SESSION to TURN membership index. Key: id16 + id16.
    SESSION_TURNS: VaultMeta b"session_turns:v1:" Raw;
    /// The owner's backup setting (FIX 5621): whether a running server backs up on its own, the
    /// hours between and the newest kept, one row for the whole choice. Absent is no choice, and
    /// the deployment's `[backup]` section decides. Key: ().
    BACKUP_POLICY: VaultMeta b"settings:backup:v1:policy" Named;
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
    /// The owner's Responses `store` switch (OF-602): on, a provider keeps each response and a
    /// reconnected socket resumes the chain. Absent is off. Key: ().
    MODEL_OWNER_RESPONSES_STORE: VaultMeta b"settings:models:v1:responses_store" Named;
    /// The owner's act on a vault-wide setting (the dreamer's wake policy, the inference
    /// defaults), recorded in the commit that changed it (WILL-PLAN L13 row 01). Key:
    /// u64be(sequence).
    POLICY_SETTING_ACT: VaultMeta b"settings:owner_act:v1:" Named;
    /// Publisher share dial: explicit owner-set enabled/disabled token. Key: ().
    EDIT_DISTANCE_PUBLISHER_ENABLED: VaultMeta b"settings:publisher:v1:enabled" Raw;
    /// Install-profile default for the publisher share dial. Key: ().
    EDIT_DISTANCE_PUBLISHER_INSTALL_DEFAULT: VaultMeta b"settings:publisher:v1:install_default" Raw;
    /// The owner's switch over an Admin deleting a private room thread (FIX 6382): `false` turns
    /// it off. Absent is on. Key: ().
    ROOM_THREADS_ADMIN_DELETE: VaultMeta b"settings:rooms:v1:admin_delete" Named;
    /// The owner's switch over an Admin walking into a private room thread (FIX 6382): `false`
    /// turns it off. Absent is on. Key: ().
    ROOM_THREADS_ADMIN_WALK_IN: VaultMeta b"settings:rooms:v1:admin_walk_in" Named;
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
    SHARE_BRIEF_ADMISSION: VaultMeta b"share:brief:admission:v1:" Raw
        => crate::share::erase_admission_actor_in_txn;
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
    /// One proposed shared-act policy change and its live editors' answers (DOOR-129). Key: hex32
    /// (change id).
    SHARED_ACT_POLICY_CHANGE: VaultMeta b"shared-act:policy-change:v1:" Named;
    /// The execution receipt of one shared act or membership change. Key: hex32 (receipt id).
    SHARED_ACT_RECEIPT: VaultMeta b"shared-act:receipt:v1:" Raw;
    /// A pending shared act awaiting its members' objection window. Key: hex32 (act id).
    SHARED_ACT_RECORD: VaultMeta b"shared-act:record:v1:" Raw;
    /// An export-first removal's archive, delivered to the removed Owner alone and kept for them
    /// until its term ends (FIX 1300). Key: hex32 (removed Owner) ":" hex32 (receipt id).
    SHARED_ACT_REMOVAL_EXPORT: VaultMeta b"shared-act:removal-export:v1:" Named;
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
    /// One label the attribution judge settled on a terminal attempt's outcome evidence, kept
    /// whatever its subject routing (OF-568 L10): source id, evidence sequence, receipt, actor
    /// (nil once erased), skill, label, share, judge revision, time. Key: hash32 (blake3 of the
    /// terminal pack receipt id) + u64be (evidence sequence).
    SKILL_ATTRIBUTION_CAUSE: VaultMeta b"skill_attribution:cause:v1:" Named Engine
        => crate::skill_attribution::erase_attribution_cause_actor_in_txn;
    /// One matched-fork contribution check: the verdict and the pair it was read from (both fork
    /// receipts and results, the anchor, the axis). Key: string (attempt receipt "\0" skill hex
    /// "\0" axis).
    SKILL_ATTRIBUTION_CONTRIBUTION_CHECK: VaultMeta b"skill_attribution:contribution_check:v1:" Named;
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
    /// The near-copy audit one eval cohort was cut with: refs, scores and coverage, never text.
    /// Key: id16 (cohort).
    SKILL_OPTIMIZE_EVAL_CUT_AUDIT: VaultMeta b"skill_optimize:eval_cut_audit:v1:" Named;
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
    /// The judge rubric the label anchor was last reconciled with: its text digest and the
    /// `judge` revision read (MessagePack named map). Key: ().
    SKILL_OPTIMIZE_JUDGE_RUBRIC: VaultMeta b"skill_optimize:judge_rubric:v1" Named;
    /// One Coach training offer snapshot for a seat (OF-577), written once. Key: id16 (offer).
    /// Its scrub drops an erased row from every offer's and check's source rows.
    SKILL_OPTIMIZE_OFFER: VaultMeta b"skill_optimize:offer:v1:" Named
        => crate::skill_optimize::erase_offer_source_in_txn;
    /// The vault owner's one answer to a training offer, with any switch or train intent. Key:
    /// id16 (offer).
    SKILL_OPTIMIZE_OFFER_ANSWER: VaultMeta b"skill_optimize:offer_answer:v1:" Named;
    /// An immutable owner-nominated seat/candidate pin for a Coach offer. Key: id16.
    SKILL_OPTIMIZE_OFFER_CANDIDATE: VaultMeta b"skill_optimize:offer_candidate:v1:" Named;
    /// One check of a training offer's promise against later receipts. Key: id16 (offer) + id16
    /// (check).
    SKILL_OPTIMIZE_OFFER_CHECK: VaultMeta b"skill_optimize:offer_check:v1:" Named;
    /// A counted own-seat pilot and its immutable measured sufficiency card. Key: id16.
    SKILL_OPTIMIZE_OFFER_PILOT: VaultMeta b"skill_optimize:offer_pilot:v1:" Named;
    /// The stock switch an offer's approval bound: the replaced and new role bindings, and any
    /// undo. Key: id16 (offer).
    SKILL_OPTIMIZE_OFFER_SWITCH: VaultMeta b"skill_optimize:offer_switch:v1:" Named
        => crate::skill_optimize::erase_switch_actor_in_txn;
    /// The prepared training run an approved Train offer handed off, with the exact spec the
    /// owner authorized. Key: id16 (offer).
    SKILL_OPTIMIZE_OFFER_TRAINING: VaultMeta b"skill_optimize:offer_training:v1:" Named;
    /// The owner's final pick between a blind preference pair's two responses (preferred side,
    /// picker, time). Key: string (pair reference).
    SKILL_OPTIMIZE_RESPONSE_PAIR: VaultMeta b"skill_optimize:response_pair:v1:" Named;
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
    /// A planned spawn under one asker's intent key (DOOR-111): the asker, the original ask and
    /// its digest, the custody phase and fence, the placed stamp and plan receipt or the kept
    /// refusal, and a launched team's frozen start and pack and its leader runs' exposures. An
    /// actor's erase forgets the asker and keeps the row. Key: blake3 (32) of the framed asker,
    /// parent and intent key.
    SPAWN_PLANNED_INTENT: VaultMeta b"spawn:planned_intent:v1:" Named
        => crate::agent_dispatch::AgentDispatcher::erase_planned_intent_actor_in_txn;
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
    /// Born-with text a copy from another vault carried for one row: the fields its sharer let
    /// travel (OF-491), prose only, never a ref. Key: id16 (the row).
    SYNC_BORN_WITH_CARRIED: VaultMeta b"sync:born_with:carried:v1:" Named;
}
