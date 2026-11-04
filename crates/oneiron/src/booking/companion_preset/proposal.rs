//! Companion proposal state, creation, and the curated shortlist.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::EntityId;
use crate::booking::constraint::validate_visitor_tz;
use crate::booking::lifecycle::{booking_writer, digest_with, mint_raw_token};
use crate::booking::{
    BookingError, ConstraintObject, EventTypeKey, RankedSlot, SlotOracle, SolveRequest,
};
use crate::calendar::tz::utc_to_wall;
use crate::temporal::TimeRange;

use super::CompanionPresetRow;
use super::storage::{PROPOSAL, companion_token_hash, participant_token_hash, refused, surface};
// -------------------------------------------------------------------------
// Ratified constants
// -------------------------------------------------------------------------
/// `vault_meta` prefix for the ephemeral proposal row.
pub const COMPANION_PROPOSAL_META_PREFIX: &[u8] = b"booking:companion_proposal:v1:";
/// How many curated choices one proposal offers. A shortlist, not a grid: the
/// companion asks friends to tap, and a wall of buttons is a poll.
const MAX_PROPOSAL_CHOICES: u16 = 5;
/// The participant count past which a proposal's creation is logged: an
/// advisory measurement, never a refusal. Every participant gets a token,
/// up to what the ordinal's own width counts.
const PROPOSAL_PARTICIPANTS_ADVISORY: u16 = 16;
/// Width of a raw participant token, in lower-hex characters. Pinned to what
/// the shared minter emits.
pub(super) const PARTICIPANT_TOKEN_HEX_LEN: usize = 64;
// Domain separators, in the discipline `lifecycle.rs` established: a companion
// digest can never be replayed as a hold token digest or a session key.
const PROPOSAL_ID_DOMAIN: &[u8] = b"oneiron.booking.companion_proposal_id.v1\0";
pub(super) const PARTICIPANT_TOKEN_DOMAIN: &[u8] =
    b"oneiron.booking.companion_participant_token.v1\0";
pub(super) const COMPANION_TOKEN_DOMAIN: &[u8] = b"oneiron.booking.companion_confirm_token.v1\0";
// -------------------------------------------------------------------------
// Proposal state
// -------------------------------------------------------------------------
/// Opaque proposal identity: 32 unguessable bytes, minted from the CSPRNG and
/// domain-tagged so it cannot collide with any other digest booking persists.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ProposalId(pub [u8; 32]);
/// Index of a choice within one proposal's shortlist.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ChoiceId(pub u16);
/// One tappable choice. The slot is the oracle's, verbatim — nothing here
/// rounds, widens, or invents a time.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProposalChoice {
    pub id: ChoiceId,
    pub slot: RankedSlot,
    pub label: String,
}
/// The ephemeral proposal. It stores participant token HASHES, never the raw
/// tokens: the raw values exist once, in the creation return value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompanionProposal {
    pub id: ProposalId,
    #[serde(with = "entity_ref_serde")]
    pub owner_ref: EntityId,
    pub preset_id: String,
    /// The configuration key the shortlist was solved under. Stored so confirm
    /// rebuilds its re-solve from the ROW and not from a caller argument.
    pub event_type: EventTypeKey,
    /// The visitor zone the shortlist was solved in, stored for the same
    /// reason.
    pub visitor_tz: String,
    pub choices: Vec<ProposalChoice>,
    pub participant_token_hashes: BTreeSet<[u8; 32]>,
    pub expires_at: u64,
}
/// One participant's raw credential. Deliberately not `Serialize` and not
/// `Debug`: a raw token has no wire form and no log form.
pub struct OneTimeParticipantToken {
    pub participant_ordinal: u16,
    pub raw_token: String,
}
/// What proposal creation returns. The raw tokens are handed over exactly once,
/// here; every later read of the proposal sees hashes only.
pub struct CompanionProposalCreation {
    pub proposal: CompanionProposal,
    pub participant_tokens: Vec<OneTimeParticipantToken>,
    /// The creating companion's credential for the soft confirmation. Only
    /// its hash is stored, and no participant link carries it.
    pub companion_token: String,
}
/// One recorded tap. This is the stored form: `(participant, choice)` is unique
/// within a proposal, so the tap log is bounded by participants x choices and
/// a re-tap is idempotent rather than growth.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProposalTap {
    pub proposal_id: ProposalId,
    pub participant_token_hash: [u8; 32],
    pub choice_id: ChoiceId,
    pub tapped_at: u64,
}
/// The folded view of a proposal's taps, keyed by participant.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct TapAggregate {
    pub choices_by_participant: BTreeMap<[u8; 32], BTreeSet<ChoiceId>>,
}
impl TapAggregate {
    /// Folds a tap log. Taps from a hash the proposal never issued are dropped
    /// here as well as refused on the write path, so a row that somehow carried
    /// one could still not influence an intersection.
    pub(super) fn fold(proposal: &CompanionProposal, taps: &[ProposalTap]) -> Self {
        let mut choices_by_participant: BTreeMap<[u8; 32], BTreeSet<ChoiceId>> = BTreeMap::new();
        for tap in taps {
            if !proposal
                .participant_token_hashes
                .contains(&tap.participant_token_hash)
            {
                continue;
            }
            choices_by_participant
                .entry(tap.participant_token_hash)
                .or_default()
                .insert(tap.choice_id);
        }
        Self {
            choices_by_participant,
        }
    }
}
/// The terminal artifact: the companion committed to one choice, softly.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompanionSoftConfirmation {
    pub proposal_id: ProposalId,
    pub selected: ProposalChoice,
    #[serde(with = "entity_ref_serde")]
    pub confirmed_by_companion: EntityId,
    pub confirmed_at: u64,
}
/// The persisted row. Proposal, tap log, and confirmation share ONE row so a
/// tap and a confirm read exactly the same bytes under the same writer lease.
#[derive(Serialize, Deserialize)]
pub(super) struct CompanionProposalRow {
    pub(super) proposal: CompanionProposal,
    pub(super) taps: Vec<ProposalTap>,
    pub(super) confirmation: Option<CompanionSoftConfirmation>,
    /// Who may confirm. A row written before this field existed has none,
    /// and nobody can confirm it.
    #[serde(default)]
    pub(super) companion: Option<CompanionBinding>,
}
/// The companion that created a proposal, and the hash of its confirm token.
#[derive(Serialize, Deserialize)]
pub(super) struct CompanionBinding {
    #[serde(with = "entity_ref_serde")]
    pub(super) companion_ref: EntityId,
    pub(super) token_hash: [u8; 32],
}
/// Hex spelling for the one `EntityId` field each stored shape carries. The
/// booking module keeps this adapter per file rather than sharing one, matching
/// `config.rs`, `disclosure_rung.rs`, and `lifecycle.rs`.
mod entity_ref_serde {
    use super::{Deserialize, Deserializer, EntityId, Serializer};

    pub(super) fn serialize<S: Serializer>(
        value: &EntityId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_hex())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EntityId, D::Error> {
        let hex = String::deserialize(deserializer)?;
        EntityId::from_hex(&hex).map_err(serde::de::Error::custom)
    }
}
// -------------------------------------------------------------------------
// Solve
// -------------------------------------------------------------------------
/// Builds the request from the preset's own configuration key.
///
/// Free text may have helped a companion assemble `constraint`, but only the
/// typed [`ConstraintObject`] reaches the oracle: [`SolveRequest`] has no text
/// field to carry a sentence in.
#[must_use]
pub fn companion_solve_request(
    preset: &CompanionPresetRow,
    window: TimeRange,
    constraint: Option<ConstraintObject>,
    visitor_tz: String,
) -> SolveRequest {
    SolveRequest {
        event_type: preset.synthetic_event_type_config.key.clone(),
        window,
        constraint,
        visitor_tz,
    }
}
/// Asks the shared oracle and freezes a curated shortlist, one opaque token per
/// participant and one for the creating companion.
///
/// The creating companion is `companion`'s actor, rechecked in the write
/// transaction (a live actor and, once the vault is rooted, a live authority
/// binding), never an id the caller names: the confirmation it later stamps
/// is attributed to whoever created the proposal.
///
/// No booking page is read: the configuration travelled in on `preset`, which
/// is what ONE-1823's synthetic-configuration arm exists for.
// The nine parameters are the ratified seam signature with the creating
// companion's facade in place of the vault. `oracle` is an injected host
// capability and the rest are independent inputs; bundling them would hide
// which of them the proposal actually stores.
#[allow(clippy::too_many_arguments)]
pub fn create_companion_proposal(
    companion: &crate::memory::Memory<'_>,
    oracle: &dyn SlotOracle,
    owner_ref: EntityId,
    preset: &CompanionPresetRow,
    window: TimeRange,
    constraint: Option<ConstraintObject>,
    visitor_tz: String,
    participant_count: usize,
    expires_at: u64,
) -> Result<CompanionProposalCreation, BookingError> {
    // Narrowing to the ordinal's own width IS the shape check, so a count
    // that survives it cannot need a fallback further down.
    let participants = u16::try_from(participant_count)
        .ok()
        .filter(|count| *count >= 1)
        .ok_or_else(|| {
            refused(format!(
                "a proposal must issue 1..={} participant tokens",
                u16::MAX
            ))
        })?;
    if participants > PROPOSAL_PARTICIPANTS_ADVISORY {
        tracing::info!(
            participants,
            advisory = PROPOSAL_PARTICIPANTS_ADVISORY,
            "companion proposal issues tokens past the advisory participant count"
        );
    }
    validate_visitor_tz(&visitor_tz)?;
    let vault = companion.vault();
    let companion_ref = companion.actor();

    let request = companion_solve_request(preset, window, constraint, visitor_tz);
    let solved = oracle.solve(&request)?;
    let choices = curated_shortlist(&solved.slots, &request.visitor_tz);
    if choices.is_empty() {
        return Err(BookingError::SlotOracle(
            "the oracle offered no slot to propose in this window".to_owned(),
        ));
    }

    // The id is minted before the tokens because every participant hash binds
    // it: that binding is what stops a token from being replayed elsewhere.
    let id = ProposalId(digest_with(PROPOSAL_ID_DOMAIN, mint_raw_token().as_bytes()));
    let mut participant_tokens = Vec::with_capacity(participant_count);
    let mut participant_token_hashes = BTreeSet::new();
    for participant_ordinal in 0..participants {
        let raw_token = mint_raw_token();
        participant_token_hashes.insert(participant_token_hash(id, &raw_token));
        participant_tokens.push(OneTimeParticipantToken {
            participant_ordinal,
            raw_token,
        });
    }

    let proposal = CompanionProposal {
        id,
        owner_ref,
        preset_id: preset.id.clone(),
        event_type: request.event_type,
        visitor_tz: request.visitor_tz,
        choices,
        participant_token_hashes,
        expires_at,
    };
    let companion_token = mint_raw_token();
    let row = CompanionProposalRow {
        proposal: proposal.clone(),
        taps: Vec::new(),
        confirmation: None,
        companion: Some(CompanionBinding {
            companion_ref,
            token_hash: companion_token_hash(id, &companion_token),
        }),
    };
    booking_writer(vault, |wtxn| {
        // A live row of an actor-capable type, and in a rooted vault a live
        // authority binding: a deleted shell or a revoked companion mints no
        // fresh confirmation token.
        let live_type = surface(crate::vault::live_entity_row_in_txn(
            &vault.store,
            wtxn,
            &companion_ref,
        ))?
        .live_type();
        if !live_type.is_some_and(|entity_type| {
            crate::provenance::validate_actor_class(entity_type, companion.actor_class()).is_ok()
        }) {
            return Err(refused(
                "the creating companion is not a live actor of this vault",
            ));
        }
        // A fresh local write, so the companion's own observed frontier: one
        // regranted after a revocation still creates.
        vault
            .observed_write_actor_in_txn(
                wtxn,
                crate::WriteActor::new(companion_ref, companion.actor_class()),
            )
            .map_err(|_| refused("the creating companion holds no live authority in this vault"))?;
        surface(PROPOSAL.put(&vault.store, wtxn, &id.0, &row))
    })?;

    Ok(CompanionProposalCreation {
        proposal,
        participant_tokens,
        companion_token,
    })
}
/// The shortlist: highest-ranked first, ties broken by the earlier start so two
/// equally-ranked slots order deterministically. The oracle's ranks and times
/// are read, never rewritten; each label shows the slot in the stored visitor
/// zone, named (FIX 9632).
fn curated_shortlist(slots: &[RankedSlot], visitor_tz: &str) -> Vec<ProposalChoice> {
    let mut ordered = slots.to_vec();
    ordered.sort_by(|left, right| {
        right
            .rank
            .total_cmp(&left.rank)
            .then(left.start_utc.cmp(&right.start_utc))
    });
    ordered.truncate(usize::from(MAX_PROPOSAL_CHOICES));
    // Counting in the id's own width: the truncation above is what makes that
    // safe, so no conversion is needed and none can fail.
    ordered
        .into_iter()
        .zip(0_u16..)
        .map(|(slot, index)| ProposalChoice {
            id: ChoiceId(index),
            label: choice_label(&slot, visitor_tz),
            slot,
        })
        .collect()
}

/// `2026-10-30 14:00-14:30 Asia/Tokyo`: the slot's wall times in the visitor
/// zone and the zone's name. The slot keeps its exact UTC identity; only the
/// label is local. A zone the calendar cannot resolve labels the slot in UTC,
/// so no proposal is refused for its label.
fn choice_label(slot: &RankedSlot, visitor_tz: &str) -> String {
    let (zone, start, end) = match (
        utc_to_wall(slot.start_utc, visitor_tz),
        utc_to_wall(slot.end_utc, visitor_tz),
    ) {
        (Ok(start), Ok(end)) => (visitor_tz, start, end),
        _ => match (
            utc_to_wall(slot.start_utc, "UTC"),
            utc_to_wall(slot.end_utc, "UTC"),
        ) {
            (Ok(start), Ok(end)) => ("UTC", start, end),
            _ => return format!("{}-{} UTC", slot.start_utc, slot.end_utc),
        },
    };
    let day = format!("{:04}-{:02}-{:02}", start.y, start.mo, start.d);
    let end_day = format!("{:04}-{:02}-{:02}", end.y, end.mo, end.d);
    if day == end_day {
        format!(
            "{day} {:02}:{:02}-{:02}:{:02} {zone}",
            start.h, start.mi, end.h, end.mi
        )
    } else {
        format!(
            "{day} {:02}:{:02}-{end_day} {:02}:{:02} {zone}",
            start.h, start.mi, end.h, end.mi
        )
    }
}
