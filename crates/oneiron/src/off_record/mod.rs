//! Off-record sessions — ARCH-0052 branch store, ONE-1725..ONE-1732.
//!
//! The seam has exactly FOUR public verbs, and every one of them is about
//! WHERE a write lands, never about hiding a row that already landed:
//!
//! * **enter** ([`crate::Vault::enter_off_record_session`]) — creates an
//!   in-process session record and the room's RAM `SessionOverlay`.
//!   Session-bound reads compose overlay ∪ base; off-record writes stage in
//!   the overlay only.
//! * **mode flip** ([`OffRecordSession::flip_on_record_as`], on the owner's
//!   proof, and [`crate::Vault::set_off_record_session_mode`] back off
//!   record) — changes where NEW writes go. It moves no rows: turns already
//!   staged in the overlay stay there, so flipping to on-record exposes
//!   nothing the room accumulated while off record.
//! * **promote** ([`OffRecordSession::promote_turn_as`]) — replays exactly ONE
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

pub mod anonymous_chat;
mod lifecycle;
mod promote;
mod run_view;

pub use lifecycle::{
    ExecutorUtterance, OffRecordBackendClass, OffRecordCloseOutcome, OffRecordCreator,
    OffRecordMode, OffRecordNotice, OffRecordNoticeAct, OffRecordSaveSuggestion, OffRecordSession,
    OffRecordSessionRecord, OffRecordSessionVault, OffRecordTalk, OffRecordTalkMessage,
    OffRecordTalkTurn, RetainedCharge, RoomNoteHandle, SavedTurns, room_entry_bytes,
    room_session_key,
};
pub use promote::{
    OffRecordPromoteReceipt, PROMOTE_INITIATOR_OWNER, PROMOTE_INITIATOR_ROOM_HOLDER,
    PROMOTE_INITIATOR_ROOM_OWNER, PromoteOutcome,
};
pub use run_view::{
    SessionCodeRun, SessionRunCards, SessionRunRead, SessionRunWait, SessionWaitAnswer,
    answerable as session_wait_answerable,
};

pub(crate) use lifecycle::OffRecordSessionRegistry;
/// The room's one shell-staging claim, held by the witness program's overlay
/// landing across its write transaction.
pub(crate) use lifecycle::OverlayShellReservation;
/// An on-record stretch's saver check, which the witness program runs again
/// in the write that lands its turn.
pub(crate) use lifecycle::SaverCheck;
/// ONE-1570 Arm B: the retrieval-run registration door. `context_pack.rs` and
/// the recall host reach the room's telemetry handles through this path; the
/// type stays crate-private, so no public surface gains a session channel.
pub(crate) use lifecycle::SessionRetrievalTelemetry;
/// FIX 4280/4281: a room NOTE where its room holds it, and what a room
/// write stages beside its row.
pub(crate) use lifecycle::{RoomNote, RoomRowAttachments};
/// `FloorWrites` lives in `promote.rs` from ONE-1728 on; this re-export keeps
/// the `crate::off_record::FloorWrites` path stable, so the `gate.rs` and
/// `deletion.rs` call sites are diff-quiet across the move.
pub(crate) use promote::FloorWrites;
/// Tests that drive `FloorWrites::promote` directly name who consented.
#[cfg(test)]
pub(crate) use promote::PromoteInitiator;
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
