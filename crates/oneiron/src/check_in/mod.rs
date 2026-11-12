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
//!
//! Fan-out admission is the first caller, through [`check_in_with_mode`],
//! because its mode comes from its own manifest rows. The ladder above rung 1,
//! a proposal handle on `Wait`, the change path and the key, quorum and
//! delay-window proofs are later builds.

mod act_class;
mod mode;
mod resolve;
mod role_preset;

pub use act_class::{ACT_CLASS, ActClass, ActClassRow, ModelCheck, ProofKind, UndoClass};
pub use mode::CheckInMode;
pub use resolve::{
    CheckInAnswer, CheckInRequest, GoReason, ModeSource, ResolvedMode, UnsureTest, WaitReason,
    check_in, check_in_with_mode, resolve_mode,
};
pub use role_preset::{ROLE_PRESET, RoleDefault, RolePreset, RolePresetRow};
