//! CAL-06 prep pack: the render-time context pack a meeting earns at T-45.
//!
//! Five laws hold this layer together, and every function below is one of them
//! made mechanical:
//!
//! * **Nothing is precomputed.** [`build_prep_pack`] assembles from live vault
//!   state at the moment the host says the wake fired. No prep artifact is
//!   stored, indexed, or reused: this module opens no write door at all, so a
//!   pack built yesterday cannot be surfaced today. Evidence that landed after
//!   the wake was planned but before it fired is in; evidence that lands after
//!   the fire instant is out, because the assembly is scoped by learned time.
//! * **Precedence is fixed, recency is not.** Prior commitments outrank recent
//!   threads, which outrank dossier delta — [`PrepSectionKind`] declares that
//!   order and derives `Ord` from it. Newer lower-ranked material never
//!   overtakes older higher-ranked material, and the word ceiling is applied
//!   after ordering so the budget spends itself top-down.
//! * **External by default.** [`prep_is_eligible`] arms on an external
//!   attendee, a campaign linkage, or a commitment linkage. Internal-only and
//!   solo events need an explicit opt-in — per event, or crate-wide by clearing
//!   [`PrepPolicy::external_only`]. An imported `VALARM` is not one of those
//!   signals and has no representation here at all, so a feed reminder can
//!   neither arm this feature nor mint one.
//! * **Silence is an answer.** `Ok(None)` from [`build_prep_pack`] means the
//!   scoped, ranked evidence came out empty. The caller renders nothing —
//!   there is no empty card and no padded card. The 250-word default is a
//!   ceiling, never a target.
//! * **The engine owns no clock.** [`plan_prep_wake`] describes an exact host
//!   wake and returns; nothing here spawns, waits, repeats, or reads a system
//!   clock, and every timestamp is a caller argument. Closed-vault delivery is
//!   a host-owned home-node job: the host proves it holds the election, then
//!   calls [`run_due_home_node_prep`]. Election and lease storage stay in the
//!   host's hands — this module neither reads nor extends them.
//!
//! ## Two bridges this layer stands on, deliberately
//!
//! * **Wake shape.** [`PrepWake`] is the engine-side image of
//!   `oneiron_vault_contract::WakeEntry` carrying `Schedule::Exact`.
//!   `crates/oneiron` does not depend on the contract crate at this commit (the
//!   path dep is ONE-1783's reserved `Cargo.toml` append), so the three fields
//!   ride this struct and map one-to-one when that dep lands — exactly as
//!   CAL-07's [`super::outcome::OutcomeCheckInWake`] already does. CAL never
//!   plans a window, so [`PREP_WAKE_SCHEDULE_KIND`] pins the `exact` arm as a
//!   value a caller can assert without the dep.
//! * **Commitment trigger.** Until CMT-3 lands there is no commitment entity to
//!   key on, so `prep_section_kind_for` maps stored entity types onto the
//!   three ranked sections. That mapping is the swap point: when CMT-3 arrives,
//!   the commitment section keys on commitment rows instead of CLAIM rows and
//!   nothing else in this module moves.

mod home_node;
mod lens;
mod pack;
mod wake;

pub use self::home_node::{PrepHomeNodeJob, run_due_home_node_prep};
pub use self::lens::{PrepLensCopy, render_prep_lens};
pub use self::pack::{
    DEFAULT_PREP_MAX_WORDS, PrepBuildRequest, PrepItem, PrepPack, PrepSection, PrepSectionKind,
    build_prep_pack,
};
pub use self::wake::{
    DEFAULT_PREP_LEAD_SECS, PREP_WAKE_REASON_TAG, PREP_WAKE_SCHEDULE_KIND, PrepEvent, PrepPolicy,
    PrepWake, plan_prep_wake, prep_is_eligible, prep_wake_id,
};
