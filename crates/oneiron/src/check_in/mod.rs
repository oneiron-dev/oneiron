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
//!
//! Fan-out admission is the first caller, through [`check_in_with_mode`],
//! because its mode comes from its own manifest rows. The agent verbs (2f,
//! 2l), the change path and the key and quorum proofs are later builds.

mod act_class;
mod chain;
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

pub use act_class::{ACT_CLASS, ActClass, ActClassRow, ModelCheck, ProofKind, UndoClass};
// The chain 2e's host builds; until then only `test_doors::check_in` does.
#[cfg_attr(not(oneiron_test_support), allow(unused_imports))]
pub(crate) use chain::{AgentHolderVerdict, NoAgentVerdict, VerifiedChain};
pub use mode::CheckInMode;
pub use pending::{
    CapturedWait, DelayWindow, DelayWindowOpen, Extension, HolderAnswer, HolderKind, HolderReply,
    Objection, OpenPendingCheckIn, PendingCheckIn, PendingState, Rung, RungEntry, RungHolder,
    RungMembers,
};
pub(crate) use pending::{erase_pending_check_in_actor_in_txn, pending_check_in_in_txn};
// The doors 2c and 2e-2l call; until then only `test_doors::check_in` does.
#[cfg_attr(not(oneiron_test_support), allow(unused_imports))]
pub(crate) use pending::{
    RungResolver, answer_pending_check_in_in_txn, extend_pending_check_in_in_txn,
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
pub(crate) use wake::next_check_in_due_at;
#[cfg_attr(not(oneiron_test_support), allow(unused_imports))]
pub(crate) use waits::advance_pending_check_in_in_txn;
