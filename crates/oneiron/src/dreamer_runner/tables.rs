//! The side tables `dreamer_runner` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One agent-health card (OF-568): the Coach's merged evidence, routing and outcome for one
    /// actor, signal and task. Key: id16 actor, signal code byte, id16 task (zeros for none).
    COACH_AGENT_HEALTH_CARD: VaultMeta b"coach:agent_health_card:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::dreamer_runner::maintenance::agent_health::erase_actor_sources_in_txn;
    /// Each agent-health card under every reviewer receipt it holds (FIX 10880): the
    /// `health_review:` digest of each `review_outcomes` receipt. Key: digest32 + id16(actor) +
    /// u8(signal) + id16(task).
    COACH_AGENT_HEALTH_CARD_BY_RECEIPT: VaultMeta b"coach:agent_health_card_by_receipt:v1:" Raw
        // Payload family: Id-only membership indexes, restored with the rows they index.
        [restore: content] [family: structure] [tier: canonical];
    /// Each live agent-health card under every reviewer revision it names
    /// (FIX 10434): `reviewer_revisions`. Key: id16(revision) + id16(actor) + u8(signal) +
    /// id16(task).
    COACH_AGENT_HEALTH_CARD_BY_REVIEWER: VaultMeta b"coach:agent_health_card_by_reviewer:v1:" Raw
        // Payload family: Id-only membership indexes, restored with the rows they index.
        [restore: content] [family: structure] [tier: canonical];
    /// Each live agent-health card under every row its standing Coach draft was written from
    /// (FIX 10434): `draft_source_rows`. Key: id16(source) + id16(actor) + u8(signal) +
    /// id16(task).
    COACH_AGENT_HEALTH_CARD_BY_SOURCE: VaultMeta b"coach:agent_health_card_by_source:v1:" Raw
        // Payload family: Id-only membership indexes, restored with the rows they index.
        [restore: content] [family: structure] [tier: canonical];
    /// The latest wake waiting for a free live health-review slot (FIX 9224).
    /// Key: target attempt id16 + big-endian lease generation4.
    COACH_AGENT_HEALTH_LIVE_PENDING: VaultMeta b"coach:agent_health_live_pending:v1:" Named Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// One agent-health review state's frozen DIAGNOSTICs and evidence ids (FIX 8082), shared by
    /// every outcome receipt of that state. Ids only. Key: the `health_review:` digest32.
    COACH_AGENT_HEALTH_REVIEW_STATE: VaultMeta b"coach:agent_health_review_state:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Where the Coach's unclear-note clustering resumes (FIX 7824): the unclear-ledger key of the
    /// last outcome a pass finished, cleared at the ledger's end. Key: ().
    COACH_ATTRIBUTION_LABEL_CURSOR: VaultMeta b"coach:attribution_label_cursor:v1" Named Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// One unclear note the Coach's same-pattern choice judged (FIX 7824): its scope's group hash,
    /// the pattern it joined (none when it names no pattern) and the fingerprint it was judged
    /// at. No note text. Key: u32be length + unclear-ledger key + u32be note index.
    COACH_ATTRIBUTION_LABEL_MEMBER: VaultMeta b"coach:attribution_label_member:v1:" Named Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// One recurring unclear-note pattern within one scope (FIX 7824): the note it is shown by
    /// and the proposal filed for it, which suppresses a second filing. No note text. Key: group
    /// hash32 + pattern id16.
    COACH_ATTRIBUTION_LABEL_PATTERN: VaultMeta b"coach:attribution_label_pattern:v1:" Named Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// One note's support for a pattern (FIX 7824), with the outcome identity it counts as. Key:
    /// group hash32 + pattern id16 + the member key.
    COACH_ATTRIBUTION_LABEL_SUPPORT: VaultMeta b"coach:attribution_label_support:v1:" Named Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// Where the Coach's contribution checks resume: the credit key and target (a loaded skill or
    /// a used edge's two ends) of the last candidate a pass put to its replay host, cleared once a
    /// pass reaches the end of the credit table, or by an erase of an entity it names. Key: ().
    COACH_CONTRIBUTION_CURSOR: VaultMeta b"coach:contribution_cursor:v1" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::dreamer_runner::maintenance::erase_contribution_cursor_in_txn;
    /// A hash of the fold defaults the Coach last suggested for one agent type, so an unchanged
    /// habit is not suggested again (FIX 12572). Key: id16 of the AGENT_DEF row.
    COACH_FOLD_SUGGESTED: VaultMeta b"coach:fold_suggested:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A blocked report filed while a `coach.issues` attempt held its lease (FIX 1554): the
    /// attempt's lease generation, consumed in the commit that settles it, which queues one
    /// successor, reconcile-only wakes too (FIX 7343). Key: id16 of the attempt.
    COACH_ISSUES_REDRIVE: VaultMeta b"coach:issues_redrive:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// When the Coach's person-threshold run read a source's record, so a replay never counts
    /// twice. Key: id16.
    COACH_PERSON_CHANGED_READ: VaultMeta b"coach:person_changed_read:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A hash of the turns the Coach's room upkeep last declared a room's summary from, so an
    /// unchanged room is not declared again. Key: id16 of the room.
    COACH_ROOM_UPKEEP_DECLARED: VaultMeta b"coach:room_upkeep_declared:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The last site-skill candidate filed for one (site, scope), with its content fingerprint and
    /// source evidence (FIX 7606). Key: hash32 (site) + hash32 (scope).
    COACH_SITE_SKILL_SEEN: VaultMeta b"coach:site_skill_seen:v1:" Named
        [restore: content] [family: unregistered] [tier: canonical];
    /// A quick pick that later proved wrong: a case where a person changed an answer the
    /// ladder gave without thinking more, kept until the Coach's think-threshold run reads it
    /// (FIX 2437). Key: id16 of the source the host bound the answer to.
    COACH_THINK_MISSED: VaultMeta b"coach:think_missed:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::dreamer_runner::maintenance::coach::erase_person_changed_principal_in_txn;
    /// When the Coach's think-threshold run read a source's record, so a replay never counts
    /// twice. Key: id16.
    COACH_THINK_MISSED_READ: VaultMeta b"coach:think_missed_read:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// When the Coach last climbed (or first saw) a pending skill tradeoff ask, so it climbs one
    /// rung per reminder window. Key: id16 of the ask's proposal.
    COACH_TRADEOFF_CLIMB: VaultMeta b"coach:tradeoff_climb:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// FIX 10766: every milestone claim by the attempt its value names, bound or not; written and
    /// dropped beside the durable index. Key: id16(attempt) + id16(claim).
    DREAMER_MILESTONE_INDEX_ATTEMPT_CLAIM: VaultMeta b"dreamer.milestone_index.v1.a:" Named Engine
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Marker that the one-time durable-milestone-index backfill pass has run. Key: ().
    DREAMER_MILESTONE_INDEX_BACKFILLED: VaultMeta b"dreamer.milestone_index.v1.backfilled" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Durable milestone-index candidate row (empty-value marker) for an attempt, ordered by (at,
    /// learned_at, claim_id); only indexed once the milestone claim is bound to its attempt. Key:
    /// id16 + u64be + u64be + id16.
    DREAMER_MILESTONE_INDEX_CANDIDATE: VaultMeta b"dreamer.milestone_index.v1.c:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Pointer from a milestone claim id back to its DREAMER_MILESTONE_INDEX_CANDIDATE row key. Key:
    /// id16.
    DREAMER_MILESTONE_INDEX_CLAIM: VaultMeta b"dreamer.milestone_index.v1.i:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// FIX 10766: the attempt each DREAMER_MILESTONE_INDEX_ATTEMPT_CLAIM row's claim names, for
    /// the door that drops it. Key: id16(claim).
    DREAMER_MILESTONE_INDEX_CLAIM_ATTEMPT: VaultMeta b"dreamer.milestone_index.v1.n:" Named Engine
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Pointer to the single vault-owned Dreamer principal actor entity id. Key: ().
    DREAMER_AUTHORITY_ACTOR: VaultMeta b"dreamer:authority:v1:actor" Raw
        [restore: refuse "machine identities"] [family: unclassified] [tier: canonical];
    /// Stamp binding one attempt id to the Dreamer principal, facet, and gate-decision receipt that
    /// admitted it. Key: id16.
    DREAMER_AUTHORITY_ATTEMPT: VaultMeta b"dreamer:authority:v1:attempt:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Named token-budget counter row (total/remaining/reserved units) keyed by budget id. Key:
    /// string.
    DREAMER_BUDGET: VaultMeta b"dreamer:budget:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Reservation of budget units against one child attempt, keyed by (budget id, attempt id). Key:
    /// u16be + string + id16.
    DREAMER_BUDGET_RESERVATION: VaultMeta b"dreamer:budget_reservation:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Paid-step receipt keyed by attempt id16 + step hash32. Value: one-byte marker.
    DREAMER_BUDGET_STEP_CHARGE: VaultMeta b"dreamer:budget_step_charge:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// FIX 4453: the last owner-set free-time boundary this node opened a cycle for, and the
    /// cycle still open. Key: id16 (agent definition).
    DREAMER_FREE_TIME_CLOCK: VaultMeta b"dreamer:free_time:clock:v1:" Named
        // Restore class: FIX 4453: the owner's free-time policy and the boundary its last cycle
        // opened at stand as the live vault holds them, so no image restores a spent allowance;
        // cycles, bindings and receipts are history.
        [restore: live] [family: unclassified] [tier: canonical];
    /// FIX 4453: one free-time cycle: its policy snapshot, period, root spend scope, items, the
    /// agent's note to its human (its own words, admitted at the wall) and its own-time choice.
    /// Key: id16 (agent) + u64be (boundary).
    DREAMER_FREE_TIME_CYCLE: VaultMeta b"dreamer:free_time:cycle:v1:" Named Authored [accepts: crate::dreamer_runner::dreamer_free_time_cycle_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// FIX 4453: the immutable binding of one free-time item attempt to its agent, cycle, item,
    /// label and spend scope, stamped when its cycle opened. Key: id16 (attempt).
    DREAMER_FREE_TIME_ITEM: VaultMeta b"dreamer:free_time:item:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// FIX 4453: the owner's free-time policy for one agent: the total per cycle, the cycle's
    /// clock and zone, an optional pinned split and the owner's act. Key: id16 (agent definition).
    /// FIX 5664: this entry's scrub erases the actor's rows in all five free-time families
    /// (policy, clock, cycle, item, receipt), so the other four name none.
    DREAMER_FREE_TIME_POLICY: VaultMeta b"dreamer:free_time:policy:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::dreamer_runner::erase_free_time_actor_in_txn;
    /// FIX 4453: one free-time item's terminal receipt, by label; the floor reads these. Key:
    /// id16 (agent) + id16 (cycle) + id16 (item).
    DREAMER_FREE_TIME_RECEIPT: VaultMeta b"dreamer:free_time:receipt:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Prior tuning-harness evaluation baseline for a config artifact, used to reject
    /// stale/regressive re-evaluation. Key: id16.
    DREAMER_HARNESS_EVAL_BASELINE: VaultMeta b"dreamer:harness:eval-baseline:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// The host's last MACRO home-node candidate set, as it supplied it, which an owner's home
    /// pick re-elects over (DOOR-101 PR2a). Node-local; a restore never takes it from an image.
    /// Key: ().
    DREAMER_HOME_CANDIDATES: VaultMeta b"dreamer:home_candidates:v1" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Elected MACRO-scope home-node designation (node_id, class, elected_at). Key: ().
    DREAMER_HOME_NODE: VaultMeta b"dreamer:home_node_macro:v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One open identity ask: a saved mention the Dreamer could not settle, or one an agent must
    /// act on now (OF-123). Key: hash32(turn, message, span). Its scrub also reaches the hints
    /// and the identity rows of DREAMER_MAINTENANCE_APPLIED (FIX 8707).
    DREAMER_IDENTITY_ASK: VaultMeta b"dreamer:identity:v1:ask:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::dreamer_runner::maintenance::identity::erase_actor_sources_in_txn;
    /// Each open identity ask under every id its erase reads (FIX 10376):
    /// its turn, message, candidates, provisional and surfaced turn. Key:
    /// id16(source) + hash32(ask key).
    DREAMER_IDENTITY_ASK_BY_SOURCE: VaultMeta b"dreamer:identity:v1:ask_by_source:" Raw
        // Payload family: Id-only membership indexes, restored with the rows they index.
        [restore: content] [family: structure] [tier: canonical];
    /// The identity re-check's page cursor: the last TURN a nightly pass read. Key: ().
    DREAMER_IDENTITY_CURSOR: VaultMeta b"dreamer:identity:v1:cursor" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A settled identity's context hint: each answered mention's own name, the words around it
    /// and its span, for the entity it named. Key: u8(kind) + hash32(name) + id16(entity).
    DREAMER_IDENTITY_HINT: VaultMeta b"dreamer:identity:v1:hint:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Each saved identity hint under every id its erase reads (FIX 10376):
    /// the entity it named and each contribution's turn and message. Key:
    /// id16(source) + u8(kind) + hash32(name) + id16(entity).
    DREAMER_IDENTITY_HINT_BY_SOURCE: VaultMeta b"dreamer:identity:v1:hint_by_source:" Raw
        // Payload family: Id-only membership indexes, restored with the rows they index.
        [restore: content] [family: structure] [tier: canonical];
    /// Each background identity disposition's inverse under every id its
    /// erase reads (FIX 10376): the ask copy's ids, the held provisionals'
    /// ids/origins/spans, the settled entity and the hint copies' spans.
    /// Key: id16(source) + hash32(ask key = the APPLIED IdentityAsk target).
    DREAMER_IDENTITY_INVERSE_BY_SOURCE: VaultMeta b"dreamer:identity:v1:inverse_by_source:" Raw
        // Payload family: Id-only membership indexes, restored with the rows they index.
        [restore: content] [family: structure] [tier: canonical];
    /// The original mention and its resolving evidence, written with the link.
    /// Key: id16(turn) + hash32(message, span).
    DREAMER_IDENTITY_RESOLUTION: VaultMeta b"dreamer:identity:v1:resolution:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// OF-023: one Dreamer maintenance write applied at once: its kind, attempt, the finding's
    /// revision, the before-state its effect changed, its receipt and, once the owner reverts
    /// it, the revert. Key: id16 (finding).
    DREAMER_MAINTENANCE_APPLIED: VaultMeta b"dreamer:maintenance:applied:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Due-time index of hinted provider-outage parks. Key: u64be(due at) + id16(attempt).
    DREAMER_OUTAGE_DUE: VaultMeta b"dreamer:outage_due:v1:" Named Engine
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// One model seat's durable availability row: whether the seat may take work, its
    /// refusal generation, its latest reset, when it last moved and what moved it. Key: id16.
    MODEL_SEAT_STATE: VaultMeta b"llm:model_seat_state:v1:" Named Engine
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Seats with a reported reset, so the sweep releases what is due. Key: u64be(reset) + id16.
    MODEL_SEAT_RESET_DUE: VaultMeta b"llm:model_seat_reset_due:v1:" Named Engine
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Seat parks by seat, so one available write wakes every park of its seat. Key: id16 + id16.
    MODEL_SEAT_WAITS: VaultMeta b"llm:model_seat_waits:v1:" Named Engine
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Parked (paused) attempt row (reason, park_owner, parked_at) keyed by attempt id. Key: id16.
    DREAMER_PARKED: VaultMeta b"dreamer:parked:" Raw Authored [accepts: crate::dreamer_runner::dreamer_parked_accepts_masked]
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// One emitted proactivity digest, keyed by its content-derived id. Key: hash32.
    DREAMER_PROACTIVITY_DIGEST: VaultMeta b"dreamer:proactivity:digest:v1:" LegacyJson Authored [accepts: crate::dreamer_runner::dreamer_proactivity_digest_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// Time (u64 BE) of the last digest that delivered judge asks to one recipient. Key: id16.
    DREAMER_PROACTIVITY_JUDGE_ASKS: VaultMeta b"dreamer:proactivity:judge_asks:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Rolling proactivity-digest emission state (last_emitted timestamp). Key: ().
    DREAMER_PROACTIVITY_STATE: VaultMeta b"dreamer:proactivity:state:v1" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// OF-420: one project's tree upkeep for one body of its evidence: the project's tree in force
    /// it revised, the Candidate revision, the reserve its fit left out, what was stored and
    /// scored, and how it settled. A settled row keeps that evidence from minting again. Key:
    /// id16 (project) + hash32 (evidence).
    DREAMER_PROJECT_TREE_UPKEEP: VaultMeta b"dreamer:project-tree-upkeep:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Owner approval/decline record for a representation proposal review. Key: id16.
    DREAMER_REPRESENTATION_APPROVAL: VaultMeta b"dreamer:representation:v1:approval:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::dreamer_runner::maintenance::representation::erase_approval_actor_in_txn;
    /// Evidence-citing user-voice representation plan from when it is queued: its packet, the
    /// owner it is for and its landing, keyed by proposal claim id. Key: id16.
    DREAMER_REPRESENTATION_PROPOSAL: VaultMeta b"dreamer:representation:v1:proposal:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::dreamer_runner::maintenance::representation::erase_proposal_actor_in_txn;
    /// OF-490: the resident one dreaming attempt runs as, its own stamp, and the Gate receipt that
    /// admitted it. Key: id16 (attempt).
    DREAMER_RESIDENT_ATTEMPT: VaultMeta b"dreamer:resident:attempt:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Parent/child attempt-tree edge row (parent_attempt, created_at) keyed by attempt id. Key:
    /// id16.
    DREAMER_RUN_TREE: VaultMeta b"dreamer:run_tree:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// When a host draft was scheduled for one stewardship reach-out. Key: id16(reach-out claim),
    /// value: u64be.
    DREAMER_STEWARDSHIP_DRAFTED: VaultMeta b"dreamer:stewardship:v1:drafted:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// FIX 5735: each turn program admission by its waking actor, written with the admission.
    /// Key: id16(actor) + hash32(admission).
    DREAMER_TURN_PROGRAM_ACTOR_ADMISSION: VaultMeta b"dreamer:turn_program:actor_admission:v1:"
        Named Engine
        // Restore class: FIX 5735: each index stands as the rows it names do.
        [restore: live] [family: structure] [tier: canonical];
    /// FIX 5735: each turn program attempt by the actor its stamp names, written with the stamp.
    /// Key: id16(actor) + id16(attempt).
    DREAMER_TURN_PROGRAM_ACTOR_ATTEMPT: VaultMeta b"dreamer:turn_program:actor_attempt:v1:"
        Named Engine
        [restore: content] [family: structure] [tier: canonical];
    /// FIX 5774: each owed turn program wake by its waking actor, written and deleted with the
    /// wake. Key: id16(actor) + id16(turn) + id16(registration).
    DREAMER_TURN_PROGRAM_ACTOR_WAKE: VaultMeta b"dreamer:turn_program:actor_wake:v1:"
        Named Engine
        [restore: content] [family: structure] [tier: canonical];
    /// DOOR-141: one turn program admission: the sealed wake, its Gate receipt, and the attempt it
    /// queued or why it was refused. Key: hash32(actor, registration, revision, turn).
    DREAMER_TURN_PROGRAM_ADMISSION: VaultMeta b"dreamer:turn_program:admission:v1:" Named
        // Restore class: DOOR-141: a consumed wake stays consumed, as a spent one-shot does, so no
        // restore re-admits a program its turn already woke.
        [restore: live] [family: unclassified] [tier: canonical];
    /// DOOR-141: one armed turn program: its actor, the conversation its turns wake it from, and its
    /// pinned callable SKILL entry with its revision. Key: id16(actor) + id16(registration).
    DREAMER_TURN_PROGRAM_ARM: VaultMeta b"dreamer:turn_program:arm:v1:" Named
        // Restore class: Arming is the actor's standing intent: kept as the live vault holds it,
        // never resurrected or dropped by an image.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::dreamer_runner::erase_turn_program_actor_in_txn;
    /// DOOR-141: the waking actor one turn program attempt runs as, never a base-agent stamp, and
    /// the admission that bound it. Key: id16(attempt).
    DREAMER_TURN_PROGRAM_ATTEMPT: VaultMeta b"dreamer:turn_program:attempt:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// FIX 6062: each try the turn program runtime holds, by its hold's kind, written and deleted
    /// beside its DREAMER_PARKED row. Key: u8(hold) + id16(attempt).
    DREAMER_TURN_PROGRAM_HOLD: VaultMeta b"dreamer:turn_program:hold:v1:" Named Engine
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// DOOR-141 PR2: one turn program's code run: the try that entered it, the admission that
    /// fixed it, its lifecycle and result, and the checkpoint frontier it last committed.
    /// Key: id16(code run).
    DREAMER_TURN_PROGRAM_RUN: VaultMeta b"dreamer:turn_program:run:v1:" Named
        // Restore class: DOOR-141 PR2: a program's run and its settled steps are execution
        // progress; the effects they join keep their own (LIVE) classes.
        [restore: content] [family: unclassified] [tier: canonical];
    /// FIX 7188: a try the owner stopped whose Pending sends its Stop's own write did not mark
    /// Abandoned: the abandon it still owes, retried by the program kind's admission chain and
    /// cleared once it lands. Key: id16(attempt).
    DREAMER_TURN_PROGRAM_STOP_OWED: VaultMeta b"dreamer:turn_program:stop_owed:v1:" Named
        // Restore class: FIX 7188: an owner Stop's owed abandon works on the outbound ledger, which
        // stands as the live vault holds it; so does what it still owes.
        [restore: live] [family: structure] [tier: canonical];
    /// Untangle slice 6.8c: each timer turn program's next due time, written and deleted with its
    /// arming's. Key: u64be(due time) + id16(actor) + id16(registration).
    DREAMER_TURN_PROGRAM_TIMER_DUE: VaultMeta b"dreamer:turn_program:timer_due:v1:" Named Engine
        // Restore class: the due index stands as the armings it names do.
        [restore: live] [family: structure] [tier: canonical];
    /// Untangle slice 6.8c: each idle or feed turn program, by its trigger's kind, written and
    /// deleted with its arming. Key: u8(kind) + id16(actor) + id16(registration).
    DREAMER_TURN_PROGRAM_TRIGGER: VaultMeta b"dreamer:turn_program:trigger:v1:" Named Engine
        // Restore class: the trigger index stands as the armings it names do.
        [restore: live] [family: structure] [tier: canonical];
    /// FIX 5838: each turn program admission by the turn whose wake it admitted, written with the
    /// admission. Key: id16(turn) + hash32(admission).
    DREAMER_TURN_PROGRAM_TURN_ADMISSION: VaultMeta b"dreamer:turn_program:turn_admission:v1:"
        Named Engine
        // Restore class: FIX 5838: the turn index stands as the admissions it names do.
        [restore: live] [family: structure] [tier: canonical];
    /// DOOR-141: a wake a landed turn owes an armed program, recorded in that turn's own commit and
    /// consumed by its admission. Key: id16(turn) + id16(registration).
    DREAMER_TURN_PROGRAM_WAKE: VaultMeta b"dreamer:turn_program:wake:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The Coach's code-fix work on one failure case and its local verdicts: the invented
    /// example's and the candidate fix's, kept after the export queue drains. Never real chat
    /// text. Key: id16(case key).
    FAILURE_SIGNALS_CODE_FIX_WORK: VaultMeta b"failure_signals:code_fix_work:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Owner-set action-mode policy: the state-index window and its mode bands (OF-335).
    /// Key: ().
    DREAMER_ACTION_MODE_POLICY: VaultMeta b"settings:dreamer:action_mode:v1" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
    /// Owner-set rubric dial for the memory-curator maintenance pass. Key: ().
    DREAMER_CURATOR_RUBRIC: VaultMeta b"settings:dreamer:curator:rubric:v1" LegacyJson Authored [accepts: crate::dreamer_runner::dreamer_curator_rubric_accepts_masked]
        [restore: live] [family: unclassified] [tier: canonical];
    /// Owner-set retune thresholds for the tuning-harness evaluation loop. Key: ().
    DREAMER_HARNESS_THRESHOLDS: VaultMeta b"settings:dreamer:harness:thresholds:v1" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
    /// Owner-set cadence dial for the proactivity digest. Key: ().
    DREAMER_PROACTIVITY_CADENCE: VaultMeta b"settings:dreamer:proactivity:cadence:v1" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
    /// Owner-confirmed digest policy claim revision. Key: id16, value: hash32.
    DREAMER_PROACTIVITY_CONFIRMED: VaultMeta b"settings:dreamer:proactivity:confirmed:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Owner-confirmed presentation row. Key: singleton.
    DREAMER_PROACTIVITY_PRESENTATION: VaultMeta b"settings:dreamer:proactivity:presentation:v1" LegacyJson Authored [accepts: crate::dreamer_runner::dreamer_proactivity_presentation_accepts_masked]
        [restore: live] [family: unclassified] [tier: canonical];
    /// Owner-set relationship-stewardship rules. Key: ().
    DREAMER_STEWARDSHIP_RULES: VaultMeta b"settings:dreamer:stewardship:rules:v1" LegacyJson Authored [accepts: crate::dreamer_runner::dreamer_stewardship_rules_accepts_masked]
        [restore: live] [family: unclassified] [tier: canonical];
}
