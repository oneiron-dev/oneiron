//! The side tables `skill_optimize` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The Coach's tradeoff router (FIX-LIST 817): each route call it handed a project's leader.
    /// Key: string (proposal hex32 ":" project hex32 ":" question digest).
    SKILL_TRADEOFF_ROUTE: SyncState b"skill:tradeoff:route:v1:" Named;
    /// An owner's funded judge-ask minutes (u32be). Key: id16 (owner).
    SKILL_OPTIMIZE_JUDGE_MINUTES: VaultMeta b"settings:skill_optimize:judge_minutes:v1:" Raw;
    /// Accepted edits per Dreamer cycle. Key: ().
    SKILL_EDIT_CYCLE_CAP: VaultMeta b"settings:skill_optimize:v1:cycle_cap" Raw;
    /// Minimum attributed outcomes before optimization. Key: ().
    SKILL_OPTIMIZE_MIN_OUTCOMES: VaultMeta b"settings:skill_optimize:v1:min_outcomes" Raw;
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
    /// Optimizer-birth marker. Key: id16.
    SKILL_OPTIMIZE_ORIGIN_MARKER: VaultMeta b"skill_optimize/origin/v1\0" Raw;
    /// A proposal's offline preflight: its floor and cost axes and the honesty floor scored on the
    /// held-out set before any live run, and whether every floor held, bound to both bodies, the
    /// evidence and the goal revision (MessagePack named map). Key: id16 (proposal).
    SKILL_OPTIMIZE_PREFLIGHT: VaultMeta b"skill_optimize/preflight/v1\0" Named;
    /// Skill-edit gate verdict ledger row. Key: id16.
    SKILL_EDIT_VERDICT: VaultMeta b"skill_optimize/verdict/v1\0" Raw;
    /// Replacement judge revision (UTF-8) marking one skill-edit verdict as displaced. Key: id16
    /// (verdict id).
    SKILL_OPTIMIZE_DISPLACED_JUDGE: VaultMeta b"skill_optimize:displaced_judge:v1:" Raw;
    /// Fence on a displaced candidate judge revision: its replacement revision (UTF-8). Key: string
    /// (the displaced revision).
    SKILL_OPTIMIZE_DISPLACED_REVISION: VaultMeta b"skill_optimize:displaced_revision:v1:" Raw;
    /// The near-copy audit one eval cohort was cut with: refs, scores and coverage, never text.
    /// Key: id16 (cohort).
    SKILL_OPTIMIZE_EVAL_CUT_AUDIT: VaultMeta b"skill_optimize:eval_cut_audit:v1:" Named;
    /// One paired eval measurement: its frozen request, state, case legs, family summaries and
    /// card (MessagePack named map). Key: bytes32 (request digest).
    SKILL_OPTIMIZE_EVAL_MEASUREMENT: VaultMeta b"skill_optimize:eval_measurement:v1:" Named;
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
    /// id16 (offer). Its scrub leaves an erased actor's answers naming no one.
    SKILL_OPTIMIZE_OFFER_ANSWER: VaultMeta b"skill_optimize:offer_answer:v1:" Named
        => crate::skill_optimize::erase_offer_answer_actor_in_txn;
    /// An immutable owner-nominated seat/candidate pin for a Coach offer. Key: id16.
    SKILL_OPTIMIZE_OFFER_CANDIDATE: VaultMeta b"skill_optimize:offer_candidate:v1:" Named;
    /// One check of a training offer's promise against later receipts. Key: id16 (offer) + id16
    /// (check).
    SKILL_OPTIMIZE_OFFER_CHECK: VaultMeta b"skill_optimize:offer_check:v1:" Named;
    /// A counted own-seat pilot and its immutable measured sufficiency card. Key: id16.
    SKILL_OPTIMIZE_OFFER_PILOT: VaultMeta b"skill_optimize:offer_pilot:v1:" Named
        => crate::skill_optimize::erase_pilot_source_in_txn;
    /// The stock switch an offer's approval bound: the replaced and new role bindings, and any
    /// undo. Key: id16 (offer).
    SKILL_OPTIMIZE_OFFER_SWITCH: VaultMeta b"skill_optimize:offer_switch:v1:" Named
        => crate::skill_optimize::erase_switch_actor_in_txn;
    /// The prepared training run an approved Train offer handed off, with the exact spec the
    /// owner authorized. Key: id16 (offer). Its scrub leaves an erased actor's handoffs naming
    /// no one.
    SKILL_OPTIMIZE_OFFER_TRAINING: VaultMeta b"skill_optimize:offer_training:v1:" Named
        => crate::skill_optimize::erase_offer_training_actor_in_txn;
    /// The owner's final pick between a blind preference pair's two responses (preferred side,
    /// picker, time). Key: string (pair reference).
    SKILL_OPTIMIZE_RESPONSE_PAIR: VaultMeta b"skill_optimize:response_pair:v1:" Named;
}
