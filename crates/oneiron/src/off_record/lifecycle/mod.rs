//! OF-326 off-record / ephemeral session seam (ARCH-0052 P6, ONE-1731).
//!
//! An evaporating session mode built on ONE mechanism: session content is
//! written into the session's own [`SessionOverlay`] and never into base. The
//! seam is FOUR verbs:
//!
//! * **Enter** — [`Vault::enter_off_record_session`] creates an in-process
//!   session record and the room's overlay. The engine exposes mode and
//!   backend-class enums; the host owns all user-facing marker composition.
//! * **Mode flip** — [`Vault::set_off_record_session_mode`] seals or rearms
//!   the overlay write path. Off record, writes stage in the overlay; on
//!   record, they are ORDINARY base writes under the session's continuation
//!   shell. A flip moves only where NEW writes land; rows already in the room
//!   stay in the room.
//! * **Promote** — [`OffRecordSession::promote_turn`] replays exactly ONE
//!   witnessed turn's typed-journal closure into base on explicit user
//!   consent, in one transaction, minting a durable
//!   [`OffRecordPromoteReceipt`] that survives close (ARCH-0052 D4).
//! * **Close** — [`Vault::close_off_record_session`] drains the overlay's
//!   leases, drops the overlay, and consumes the session-local receipt log.
//!   The transcript evaporates because the rows only ever existed in the
//!   room; nothing is deleted from base, so promoted content is kept by
//!   construction rather than by an exception in a delete pass.
//!
//! Two properties follow from the one mechanism rather than from any guard:
//!
//! * **Base invisibility.** Base readers hold canonical base-only accessors,
//!   so an overlay row is not something they filter out — it is something
//!   they cannot address. Session handles read overlay ∪ base through
//!   [`crate::store::SessionStoreView`]. The reverse direction is the only
//!   one needing a door: a BASE write naming a live overlay id is refused by
//!   the K4 taint guard in `batch.rs`.
//! * **Pipeline inertness.** Dreamer, extraction and every other derived-row
//!   producer read base, so a room's turns produce no derived rows. There is
//!   no per-entity taint state to carry.
//!
//! Two EGRESS doors remain, because both enumerate ids rather than reading
//! through a session handle: sync window packing and whole-vault export. Each
//! asks [`OffRecordSessionRegistry::contains_entity`] exactly once and SKIPS
//! overlay members. Export never refuses while a session is live.
//!
//! * **Talk-only** — an outbound intent whose originating session is
//!   currently in off-record mode is rejected by the dispatch spine with
//!   the typed [`crate::Error::OffRecordTalkOnly`] (exit-prompt semantics).
//!   The OF-333 floor still classifies real egress; its gate-decision
//!   receipts are floor receipts and survive close untouched.
//! * **RECEIPTS-FOLLOW-TRANSCRIPT** — session-local receipts ride two
//!   substrates and close covers both. Retrieval-run context receipts (whose
//!   `result_ids` would betray what the room was about) are written into the
//!   session's own overlay `VaultMeta` keyspace by the retrieval-run
//!   registration site, so they evaporate with the transcript; close counts
//!   them in the pre-close census. In-memory emit-adjacent receipts (dispatch
//!   emit receipts carrying the OF-369/RS9 context field-set) ride the
//!   session's [`SessionLocalReceiptLog`] — minted via
//!   [`Vault::off_record_receipt_log`] — which close CONSUMES, so there is
//!   one close path and no emit receipt can be orphaned. Only floor
//!   receipts (gate decisions, redaction audits) persist.
//!
//! Voice: the engine has no audio intermediate layer; ASR/TTS intermediates
//! persisted by a caller during a session are overlay rows like any other, so
//! they evaporate with the room without the seam knowing their type.

mod executor;
mod registry;
mod session;
mod telemetry;
mod types;
mod vault_api;

pub(crate) use self::registry::OffRecordSessionRegistry;
pub use self::session::{OffRecordSession, OffRecordSessionVault};
pub(crate) use self::telemetry::SessionRetrievalTelemetry;
pub use self::types::{
    ExecutorUtterance, OffRecordBackendClass, OffRecordCloseOutcome, OffRecordMode,
    OffRecordSessionRecord,
};

#[cfg(test)]
#[path = "../tests.rs"]
mod tests;

#[cfg(test)]
use self::registry::*;
#[cfg(test)]
use super::promote::FloorWrites;
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use crate::receipt::SessionLocalReceiptLog;
