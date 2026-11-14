//! Check-in: one mechanism for every act that may need an ask
//! (ONEIRON-ARCH-0082; owner ruling ROLES-CHECKIN = A, 2026-11-10).
//!
//! A **power** is a verb an actor holds in a grant. A **role** is a preset: a
//! set of powers plus a default check-in mode per act class. **Check-in**
//! answers one question before an act: go now, wait for a proof from the
//! ladder, open a proposal, or the actor lacks the power.
//!
//! This first build (ARCH-0082 #build, PR 1) holds:
//! * [`CheckInMode`], the three modes and their meet (the strictest wins);
//! * [`ACT_CLASS`], the shipped act table, with the catastrophe floor's C rows
//!   and the fixed F row;
//! * [`ROLE_PRESET`] and [`RolePreset::default_for`], the shipped default
//!   mode per role and act class;
//! * [`check_in`], which resolves power, mode and rung 0, then runs the
//!   unsure test (rung 1) the caller injects.
//! * [`verb_act_class()`], the act class each verb row states (PR 2, P2.1);
//!   nothing reads it to decide an act yet.
//! * [`PendingCheckIn`], the durable handle of an act that waits (PR 2,
//!   P2.2: 2b and 2d): its rungs above rung 1, the wait per person rung from
//!   the `check_in` policy row ([`CheckInPolicy`]), the asker's longer wait
//!   and `until`, a holder's extension and answer, and canon's table "When
//!   nobody answers", each transition receipted (`check_in` receipts).
//! * the ladder from verified records (PR 2, P2.2: 2c): rung 2 the grantor,
//!   rung 3 the other holders of the grantor's role, rung 4 the owners; a
//!   holder answers while its live grant and its own check-in admit the act,
//!   and an agent holder's verdict comes from its caller.
//!
//! * the host that wakes a due check-in (PR 2, P2.3: 2e): each housekeeping
//!   pass advances the open rows due by now, in due order, and the vault's
//!   wake reads the first due row.
//! * the asking side of the agent verbs `vault.check_in.preflight` and
//!   `vault.check_in.open` (PR 2, P2.3: 2f): the act class from the verb's
//!   own row, the role and power from the caller's own live Grant, an
//!   always-unsure test, and an open that a repeat of the same saved call
//!   finds again by its natural key.
//! * the answer verb `vault.check_in.answer` (PR 2, P2.3: 2l): a person
//!   pinned on the current rung settles the ask over its exact effect on
//!   their own human proof; the same answer again echoes the settlement.
//!
//! Fan-out admission is the first caller, through [`check_in_with_mode`],
//! because its mode comes from its own manifest rows. The change path and
//! the key and quorum proofs are later builds.

mod act_class;
mod asker;
mod chain;
mod effect;
mod mode;
mod pending;
mod policy;
mod receipt;
mod resolve;
mod role_preset;
pub(crate) mod tables;
mod verb_act_class;
mod waits;
mod wake;
mod widen;

pub use act_class::{ACT_CLASS, ActClass, ActClassRow, ModelCheck, ProofKind, UndoClass};
pub(crate) use asker::{AskVerdict, judge_ask_in_txn};
// The chain 2e's host builds; until then only `test_doors::check_in` does.
#[cfg_attr(not(oneiron_test_support), allow(unused_imports))]
pub(crate) use chain::{AgentHolderVerdict, NoAgentVerdict, VerifiedChain};
pub use effect::{
    CheckInDecision, owner_add_effect_digest, owner_remove_effect_digest,
    ownership_transfer_effect_digest, record_erase_effect_digest, vault_delete_effect_digest,
};
pub(crate) use effect::{
    DoorAct, DoorCheckIn, owner_own_proof_decision, person_door_check_in_in_txn,
    spend_applied_check_in_in_txn,
};
pub use mode::CheckInMode;
pub use pending::{
    CapturedWait, DelayWindow, DelayWindowOpen, EligibleBasis, Extension, HolderAnswer, HolderKind,
    HolderReply, Objection, OpenPendingCheckIn, PendingCheckIn, PendingState, Rung, RungEntry,
    RungHolder, RungMembers,
};
pub(crate) use pending::{
    answer_pending_check_in_in_txn, erase_pending_check_in_actor_in_txn,
    keyed_pending_check_in_in_txn, open_keyed_pending_check_in_in_txn, pending_check_in_in_txn,
};
// The doors 2c and 2e-2l call; until then only `test_doors::check_in` does.
#[cfg_attr(not(oneiron_test_support), allow(unused_imports))]
pub(crate) use pending::{
    RungResolver, consume_pending_check_in_in_txn, extend_pending_check_in_in_txn,
    open_pending_check_in_in_txn, record_objection_in_txn,
};
pub(crate) use policy::{CHECK_IN_ROW_KEY, CheckInPolicyRead};
pub use policy::{
    CHECK_IN_ROW_VERSION, CheckInPolicy, CheckInScope, ClassWait, DEFAULT_RUNG_WAIT_SECS,
    RungWaitRow, WaitSource,
};
pub(crate) use receipt::{check_in_receipts, erase_check_in_receipt_actor_in_txn};
pub use resolve::{
    CheckInAnswer, CheckInRequest, GoReason, ModeSource, ResolvedMode, UnsureTest, WaitReason,
    check_in, check_in_with_mode, resolve_mode,
};
pub use role_preset::{ROLE_PRESET, RoleDefault, RolePreset, RolePresetRow};
pub use verb_act_class::{VerbActClass, verb_act_class};
pub use waits::CheckInTransition;
#[cfg_attr(not(oneiron_test_support), allow(unused_imports))]
pub(crate) use waits::advance_pending_check_in_in_txn;
#[cfg(oneiron_test_support)]
pub(crate) use wake::due_rows;
pub(crate) use wake::next_check_in_due_at;

// The erase doors' apply shape (2k2; P25-SHAPE Q1 = A).
pub(crate) use effect::{AppliedCheckIn, owner_act_decision_in_txn};
// The hub imports' check before they admit the publisher (2k8d).
pub(crate) use effect::require_spendable_check_in;
pub use effect::{
    legal_hold_erase_effect_digest, outbound_call_request_erase_effect_digest,
    text_history_erase_effect_digest,
};
// The key-recovery doors' effects (2k3; P25-SHAPE Q1 = A).
pub(crate) use effect::owner_act_decision_in_own_writer;
pub use effect::{
    custody_drain_effect_digest, custody_reenrol_effect_digest, root_request_effect_digest,
    step_up_reset_effect_digest,
};
// The security-control doors' effects (2k4; P25-SHAPE Q1 = A).
pub use effect::{
    CHECK_IN_OPEN_ROUTE_REASON, mail_compliance_set_effect_digest, policy_row_change_effect_digest,
};
// The delete doors' effects (2k5; P25-SHAPE Q1 = A).
pub use effect::{embedding_space_probe_delete_effect_digest, record_delete_effect_digest};
// The archive attempt delete door's effect (2k5e).
pub use effect::attempt_archive_delete_effect_digest;
// The legal send door's effect (2k6a).
pub use effect::legal_send_effect_digest;
// The sign act's effect (2k6b).
pub use effect::sign_effect_digest;
// The slip conversion and grant back doors' effects (2k7b). The mints'
// are over their requests: `verbs::agent_grant_mint_effect_digest` (2k7a),
// `verbs::engine_controls_grant_effect_digest` and
// `verbs::git_push_grant_mint_effect_digest` (2k7c).
pub use effect::{agent_grant_from_slip_effect_digest, agent_grant_restore_effect_digest};
// The standing consent grant mints' effect (2k8a).
pub use effect::standing_grant_effect_digest;
// The Delegate mint's and the shared policy proposal's judge and effects
// (2k8e3).
pub(crate) use effect::person_door_go_decision_in_txn;
pub use effect::{members_delegate_effect_digest, shared_policy_propose_effect_digest};
// The widen doors' judge and effects (2k8f; MEMBER-SHARE-OWN = B).
pub use effect::room_pins_open_effect_digest;
pub(crate) use widen::{WidenAct, WidenCheckIn, person_widen_check_in_in_txn};
