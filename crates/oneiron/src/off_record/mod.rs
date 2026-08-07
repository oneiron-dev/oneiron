//! Off-record sessions — ARCH-0052 branch store, ONE-1725..ONE-1732.
//!
//! The seam has exactly FOUR public verbs, and every one of them is about
//! WHERE a write lands, never about hiding a row that already landed:
//!
//! * **enter** ([`crate::Vault::enter_off_record_session`]) — creates an
//!   in-process session record and the room's RAM `SessionOverlay`.
//!   Session-bound reads compose overlay ∪ base; off-record writes stage in
//!   the overlay only.
//! * **mode flip** ([`crate::Vault::set_off_record_session_mode`]) — changes
//!   where NEW writes go. It moves no rows: turns already staged in the
//!   overlay stay there, so flipping to on-record exposes nothing the room
//!   accumulated while off record.
//! * **promote** ([`OffRecordSession::promote_turn`]) — replays exactly ONE
//!   witnessed turn's typed-journal closure into base, in one transaction,
//!   through the ordinary base write gates, minting a durable
//!   [`OffRecordPromoteReceipt`].
//! * **close** ([`crate::Vault::close_off_record_session`]) — drains the
//!   overlay's leases and drops the remaining overlay. The transcript
//!   evaporates because those rows only ever existed in RAM; nothing is
//!   deleted from base, so promoted turns are kept by construction.
//!
//! Nothing off-record is durable. Off-record state is session-ephemeral: no
//! registry row, overlay row, or session marker is ever serialized into the
//! vault, which is why storage ABI v16 (ONE-1732) removed the durable
//! off-record contract v11 had introduced. `lifecycle` owns enter / mode flip
//! / close and the registry; `promote` owns the replay and its receipt.

mod lifecycle;
mod promote;

pub use lifecycle::{
    ExecutorUtterance, OffRecordBackendClass, OffRecordCloseOutcome, OffRecordMode,
    OffRecordSession, OffRecordSessionRecord, OffRecordSessionVault,
};
pub use promote::{OffRecordPromoteReceipt, PromoteOutcome};

pub(crate) use lifecycle::OffRecordSessionRegistry;
/// `FloorWrites` lives in `promote.rs` from ONE-1728 on; this re-export keeps
/// the `crate::off_record::FloorWrites` path stable, so the `gate.rs` and
/// `deletion.rs` call sites are diff-quiet across the move.
pub(crate) use promote::FloorWrites;
/// The promote-replay capability `batch.rs` matches on. Only `promote.rs` can
/// MINT one (private field, private constructor); this path just lets the two
/// membership doors ask a grant they were handed what it exempts.
pub(crate) use promote::PromoteReplayGrant;

/// ONE-1728 (K2) / ONE-1729: downstream cites resolve through `off_record`.
/// `OverlaySnapshot` is promote's input; `SessionWriteRoute` is captured by
/// ONE-1729's executor run entry.
#[allow(
    unused_imports,
    reason = "ONE-1729 is the first lib-target consumer of SessionWriteRoute through this path"
)]
pub(crate) use crate::session_overlay::{OverlaySnapshot, SessionWriteRoute};
