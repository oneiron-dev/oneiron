//! Proposal taps, the authorized common intersection, and soft confirmation.

use crate::booking::lifecycle::{booking_writer, put_meta};
use crate::booking::{BookingError, RankedSlot, SlotOracle, SolveRequest};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

use super::render::validate_participant_token;
use super::storage::{
    encode_row, load_live_row, participant_token_hash, proposal_meta_key, refused,
};
use super::{
    ChoiceId, CompanionProposal, CompanionSoftConfirmation, ProposalChoice, ProposalId,
    ProposalTap, TapAggregate,
};
// -------------------------------------------------------------------------
// Taps
// -------------------------------------------------------------------------
/// How far either side of a chosen slot the confirm re-solve looks.
///
/// The pad widens the ASK so a slot with buffers is certain to fit inside the
/// window; it never widens the ANSWER, because acceptance is exact equality on
/// the oracle's own UTC bounds.
const CONFIRM_REVALIDATE_PAD_SECS: u64 = 24 * 60 * 60;
/// Records one participant's tap and returns the folded aggregate.
///
/// Three things are refused: a proposal past `expires_at` (the lazy check), a
/// token the proposal never issued, and a choice the shortlist does not offer.
pub fn record_proposal_tap(
    vault: &Vault,
    opaque_participant_token: &str,
    proposal_id: ProposalId,
    choice_id: ChoiceId,
    now_utc: u64,
) -> Result<TapAggregate, BookingError> {
    validate_participant_token(opaque_participant_token)?;
    let hash = participant_token_hash(proposal_id, opaque_participant_token);
    let key = proposal_meta_key(proposal_id);

    booking_writer(vault, |wtxn| {
        let mut row = load_live_row(vault, &*wtxn, &key, now_utc)?;
        if !row.proposal.participant_token_hashes.contains(&hash) {
            return Err(refused("this token was not issued for this proposal"));
        }
        if !row
            .proposal
            .choices
            .iter()
            .any(|choice| choice.id == choice_id)
        {
            return Err(refused("this proposal offers no such choice"));
        }
        // `(participant, choice)` is unique, so a re-tap is a no-op rather than
        // another row: the log cannot outgrow participants x choices.
        let already = row
            .taps
            .iter()
            .any(|tap| tap.participant_token_hash == hash && tap.choice_id == choice_id);
        if !already {
            row.taps.push(ProposalTap {
                proposal_id,
                participant_token_hash: hash,
                choice_id,
                tapped_at: now_utc,
            });
            let encoded = encode_row(&row)?;
            put_meta(vault, wtxn, &key, &encoded)?;
        }
        Ok(TapAggregate::fold(&row.proposal, &row.taps))
    })
}
/// The choices every participant who tapped has in common, highest-ranked
/// first.
///
/// Only participants the proposal issued a token to are counted, and only
/// participants who actually tapped: an invitee who never answered contributes
/// no constraint. Requiring silence to count as the empty set would make a
/// group answer impossible the moment one friend does not reply, which is the
/// ordinary case this preset exists for. The companion decides WHEN there is
/// enough to act on; this function decides WHAT they agreed to.
#[must_use]
pub fn ranked_authorized_common_intersection(
    proposal: &CompanionProposal,
    aggregate: &TapAggregate,
) -> Vec<ProposalChoice> {
    let mut authorized = aggregate
        .choices_by_participant
        .iter()
        .filter(|(participant, _)| proposal.participant_token_hashes.contains(*participant))
        .map(|(_, choices)| choices);

    let Some(first) = authorized.next() else {
        return Vec::new();
    };
    let common = authorized.fold(first.clone(), |common, choices| {
        common.intersection(choices).copied().collect()
    });

    let mut chosen: Vec<ProposalChoice> = proposal
        .choices
        .iter()
        .filter(|choice| common.contains(&choice.id))
        .cloned()
        .collect();
    chosen.sort_by(|left, right| {
        right
            .slot
            .rank
            .total_cmp(&left.slot.rank)
            .then(left.id.cmp(&right.id))
    });
    chosen
}
// -------------------------------------------------------------------------
// Soft confirm
// -------------------------------------------------------------------------
/// Picks the group's answer and records it, inside the home-node booking
/// writer.
///
/// The caller supplies no choice — it supplies identity and a clock. The
/// function reloads the proposal and its taps, refuses an expired proposal,
/// recomputes the authorized intersection from stored state, and walks it from
/// the highest rank down, taking the first slot the oracle still offers under
/// the same writer lease that records the answer. That last part is the whole
/// point: a slot that went busy while the message sat unread is re-proposed,
/// never double-booked.
///
/// `Ok(None)` means "nothing to confirm yet" — no agreement, or no agreed slot
/// survived revalidation. The proposal stays open for companion follow-up and
/// nothing is committed anywhere.
///
/// Nothing outbound happens here at any point: no event, no passport, no
/// calendar dispatch. A soft confirmation is a companion's answer, not a
/// business booking.
pub fn soft_confirm_highest_common_on_home_node(
    vault: &Vault,
    oracle: &dyn SlotOracle,
    proposal_id: ProposalId,
    companion_ref: EntityId,
    now_utc: u64,
) -> Result<Option<CompanionSoftConfirmation>, BookingError> {
    let key = proposal_meta_key(proposal_id);
    booking_writer(vault, |wtxn| {
        let mut row = load_live_row(vault, &*wtxn, &key, now_utc)?;
        // A retry is answered with the answer it was answered with the first
        // time; a second confirmation would be a second authority.
        if let Some(recorded) = &row.confirmation {
            return Ok(Some(recorded.clone()));
        }

        let aggregate = TapAggregate::fold(&row.proposal, &row.taps);
        let agreed = ranked_authorized_common_intersection(&row.proposal, &aggregate);
        let Some(selected) = first_still_offered(oracle, &row.proposal, &agreed)? else {
            return Ok(None);
        };

        let confirmation = CompanionSoftConfirmation {
            proposal_id,
            selected,
            confirmed_by_companion: companion_ref,
            confirmed_at: now_utc,
        };
        row.confirmation = Some(confirmation.clone());
        let encoded = encode_row(&row)?;
        put_meta(vault, wtxn, &key, &encoded)?;
        Ok(Some(confirmation))
    })
}
/// The first agreed choice the oracle still offers, asked in rank order.
fn first_still_offered(
    oracle: &dyn SlotOracle,
    proposal: &CompanionProposal,
    agreed: &[ProposalChoice],
) -> Result<Option<ProposalChoice>, BookingError> {
    for choice in agreed {
        let solved = oracle.solve(&SolveRequest {
            event_type: proposal.event_type.clone(),
            window: revalidate_window(&choice.slot),
            constraint: None,
            visitor_tz: proposal.visitor_tz.clone(),
        })?;
        // Equality, not containment: the oracle's UTC bounds are authoritative.
        if solved.slots.iter().any(|slot| {
            slot.start_utc == choice.slot.start_utc && slot.end_utc == choice.slot.end_utc
        }) {
            return Ok(Some(choice.clone()));
        }
    }
    Ok(None)
}
/// The inclusive engine window confirm re-solves over: the chosen slot, padded
/// far enough that its buffers cannot push it outside its own ask.
fn revalidate_window(slot: &RankedSlot) -> TimeRange {
    TimeRange {
        start: slot.start_utc.saturating_sub(CONFIRM_REVALIDATE_PAD_SECS),
        end: slot
            .end_utc
            .saturating_sub(1)
            .saturating_add(CONFIRM_REVALIDATE_PAD_SECS),
    }
}
