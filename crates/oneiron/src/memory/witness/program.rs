//! The one witness program: request checks, one plan, the ONE-1686 ceiling door and the
//! ONE-1767 mint contract in one transaction, landing in base or in a session overlay.

use super::super::support::*;
use super::super::*;
use super::base::{BaseGuards, BaseSink, HeldTags};
use super::codec::{
    ImportStamp, encode_imported_turn_body, encode_witness_turn_body, import_stamp,
    incoming_turn_speaker, session_short_ref_string,
};
use super::session::{Admit, OverlaySink};
use super::validation::{
    validate_existing_witness_message, validate_existing_witness_message_orders,
    validate_existing_witness_quote, validate_existing_witness_turn, validate_witness_occurrence,
};
use super::{distinct_message_orders, witness_message_envelope};

use std::cell::Cell;
use std::collections::HashSet;

use rmpv::Value;

use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::gate::{
    WitnessMessageAuthorization, WitnessMessageEnvelope, check_witness_message_ceiling_with_permit,
    coach_offer_question_permit_in_txn, resolve_policy_manifest,
};
use crate::off_record::OffRecordSession;
use crate::ports::{EntityRecord, EntityStoreRead};
use crate::session_overlay::{RouteTarget, SessionWriteRoute, TxnSegmentGuard};
use crate::store::ManifestDbs;
use crate::temporal::TimeRange;
use crate::workspace_roster::RoomRegenerationPermit;
use crate::write_envelope::WriteActor;

mod execute;
mod planning;
mod validation;

use self::validation::*;

/// Where a witness is asked to land. The session is the one parameter the two
/// landings differ by.
pub(super) enum WitnessTarget<'a, 'v> {
    /// Durable base. `route` is `Some` only when a session's on-record
    /// continuation carries the turn (K10): it is the sole evidence the room
    /// was ON RECORD when the turn was admitted, so the program revalidates it
    /// as the last statement of the write transaction.
    Base {
        route: Option<&'a SessionWriteRoute>,
    },
    /// A session (ARCH-0052 §7, ONE-1728): the room's overlay while it is off
    /// record, the base continuation shell after a flip to on record. The
    /// summary is overlay-only (see [`Memory::witness_into_session`]).
    Session {
        session: &'a OffRecordSession<'v>,
        summary: Option<&'a str>,
        admit: Option<Admit<'a>>,
        /// The room whose roster admits speech into its overlay.
        rostered: Option<EntityId>,
    },
    /// Durable base, for a turn of an imported transcript (ARCH-0027).
    Imported { stamp: &'a ImportedTurnStamp },
    /// Durable base, for a turn whose tags its importer already holds.
    Held { held: HeldTags<'a> },
}

/// What an imported transcript turn carries that a witnessed one does not: the
/// source it came from, when it was imported, when each message occurred, and
/// the body its conversation is minted with. The source's speaker wrote these
/// words, so the landing stamps no `AuthoredBy` edge and no PERSON byline. Its
/// rows are learned at the import time and occurred when the source says, so
/// the Dreamer sees them as new evidence about the past.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImportedTurnStamp {
    pub(crate) source: &'static str,
    pub(crate) imported_at: u64,
    pub(crate) conversation_body: Vec<u8>,
    /// Unix seconds per message, in the turn's message order.
    pub(crate) message_occurred: Vec<u64>,
}

/// Who holds the door, and which turn-id capability they carry.
#[derive(Clone, Copy)]
pub(super) enum WitnessDoor {
    /// A guest caller: its `turn_ref`, if any, is create-or-get at base.
    Guest,
    /// The host executor at base; only it may write report-blocked receipts.
    HostExecutor,
    /// The host executor in a session, with a TURN id derived from its run
    /// identity. A separate capability from the guest `turn_ref`, so keeping a
    /// deterministic retry target cannot weaken the guest refusal.
    HostTurn(EntityId),
}

impl WitnessDoor {
    const fn is_host(self) -> bool {
        !matches!(self, Self::Guest)
    }
}

/// A target resolved against the session's current mode.
enum Landing<'a, 'v> {
    Base {
        route: Option<&'a SessionWriteRoute>,
        continuation: Option<EntityId>,
        imported: Option<&'a ImportedTurnStamp>,
        held: Option<HeldTags<'a>>,
    },
    Overlay {
        session: &'a OffRecordSession<'v>,
        route: &'a SessionWriteRoute,
        summary: Option<&'a str>,
    },
}

/// One MESSAGE as the plan holds it. The envelope the door authorizes and the
/// canonical body it proves come from ONE value ([`witness_message_envelope`]).
pub(super) struct PlannedMessage<'t> {
    pub(super) message: &'t WitnessMessage,
    pub(super) id: EntityId,
    /// When this message occurred: the turn's time, or for an imported
    /// message the time its source recorded for it.
    pub(super) occurred: TimeRange,
    envelope: WitnessMessageEnvelope<'t>,
    body: Vec<u8>,
}

/// Everything the program decides before its write transaction.
pub(super) struct WitnessPlan<'t> {
    pub(super) turn: &'t WitnessTurn,
    /// Every row carries the witness's own stamps, never the wall clock:
    /// promote replays them, and a restamped row would land in the wrong
    /// month window (ARCH-0052 D4).
    pub(super) occurred: TimeRange,
    pub(super) learned_at: u64,
    pub(super) conversation_id: EntityId,
    /// Base only: the conversation did not resolve before the transaction.
    pub(super) conversation_is_new: bool,
    pub(super) conversation_body: Vec<u8>,
    pub(super) turn_id: EntityId,
    /// The pre-transaction "this TURN does not exist yet" answer. ADVISORY:
    /// the transaction re-reads the row, so a concurrent mint takes the append
    /// path; only a turn expected present and gone is refused.
    pub(super) turn_is_new: bool,
    /// The call's one non-system speaker; `None` is system interleave only.
    speaker: Option<&'static str>,
    pub(super) messages: Vec<PlannedMessage<'t>>,
    /// Set for a turn of an imported transcript.
    pub(super) imported: Option<ImportedTurnStamp>,
}

impl WitnessPlan<'_> {
    pub(super) fn message_ids(&self) -> Vec<EntityId> {
        self.messages.iter().map(|planned| planned.id).collect()
    }
}

/// The TURN as the transaction found it.
pub(super) enum AdmittedTurn {
    /// Absent: this witness mints it (ONE-1767), with the one additive
    /// `speaker` entry and a `ChildOf` edge to its conversation.
    Mint { body: Vec<u8> },
    /// Stored and verified: same conversation, same speaker.
    Existing(EntityRecord),
}

/// What the transaction proved, in one pass for both landings.
pub(super) struct WitnessAdmission<'p> {
    pub(super) turn: AdmittedTurn,
    /// The door's own value per message, in plan order. A sink stages a
    /// MESSAGE from this value only, never from a body handed alongside it.
    pub(super) authorized: Vec<WitnessMessageAuthorization<'p>>,
    /// Per message, in plan order: an exact retry of a stored row, which
    /// stages nothing.
    pub(super) message_exists: Vec<bool>,
}

/// The writer's lane a reply's typed assertions are read through in the
/// write transaction (OF-063), and the slot the first pointer it cannot read
/// leaves the aborted writer in.
#[derive(Clone, Copy)]
struct AssertionRead<'a, 'l> {
    lane: &'a ScopedRead<'l>,
    refused: &'a Cell<Option<String>>,
}

impl WitnessAdmission<'_> {
    pub(super) fn has_new_messages(&self) -> bool {
        self.message_exists.iter().any(|exists| !exists)
    }
}

/// The landing's own staging state, prepared before the transaction.
enum WitnessSink<'a, 'v> {
    Base(BaseSink<'a>),
    Overlay(OverlaySink<'a, 'v>),
}

enum Landed {
    Base(WitnessReceipt),
    HardDeleted(EntityId),
    Overlay {
        segment: TxnSegmentGuard,
        aliases: Vec<(String, u8)>,
    },
}
