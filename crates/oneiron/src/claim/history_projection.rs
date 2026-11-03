//! Verified MACHINE history residence: exact birth + transition closure at a trusted pin.
//!
//! The mutable claim row is a projection, never evidence of its own current
//! authority. Missing bytes or a pin with unproved ancestry withhold reads.
//! A pin is the tip of a handoff chain whose packets each carry one delta;
//! the claim's whole history is the union of the chain's deltas.

use std::collections::{BTreeMap, BTreeSet};

use crate::authority::{AuthorityFold, AuthorityKey, ROLE_OWNER};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::transition::{
    ClaimTransitionProjection, SignedClaimTransitionEvent, TransitionFoldError,
    decode_machine_claim_transition_event, fold_machine_claim_transitions,
    machine_claim_transition_event_hash, machine_claim_transition_event_id,
};
use crate::error::{ClaimError, Error, Result};
use crate::scan_check::{EngineScan, ScanCount};
use crate::side_table::{Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};
use rand_core::RngCore;
use rmpv::Value;

use super::history_handoff::{DeltaClosure, handoff_delta_closure};
use super::history_store::{
    MachineHistoryKind, machine_history_ids_for_target, machine_history_kind,
    machine_history_shape_matches,
};
use super::{
    ClaimBody, ClaimHistoryHandoff, ClaimHistoryHandoffPin, HandoffKind, HandoffStanding,
    HandoffVerification, SignedClaimBirth, VerifiedClaimHistoryHandoff,
    verify_claim_history_handoff,
};

mod adopt;
mod carry;
mod chain;
mod pin;
mod resolve;

pub(crate) use self::chain::{
    ControlRows, StoreRows, chain_transitions, machine_history_for_restriction,
    machine_history_rows, machine_history_rows_at, machine_history_rows_from, read_handoff_chain,
    resolved_machine_history, resolved_machine_history_from, restricts_held_machine_history,
    trusted_machine_handoff, verified_handoff_chain, verified_handoff_chain_from,
    verify_handoff_signature,
};
pub(crate) use self::pin::{PIN_PREFIX, pin_key};
pub(crate) use self::resolve::project_machine_claim;

fn missing() -> Error {
    Error::Claim(ClaimError::MachineClaimHistoryIncomplete)
}
fn bad() -> Error {
    Error::Claim(ClaimError::InvalidMachineClaimProof)
}

/// Retired: a host re-root once recorded its carry here, local to the vault
/// that moved. The carry is now a `ReRootCarry` packet in the history's own
/// chain. Nothing writes or reads this table; a delete still clears a row an
/// earlier build left, so restore keeps classifying the family.
pub(crate) const CARRY: SideTable<EntityId, Vec<u8>, Raw> =
    SideTable::new(&crate::side_table::CLAIM_MACHINE_HISTORY_CARRY);

pub(crate) struct MachineHistoryRows {
    pub(crate) birth: SignedClaimBirth,
    pub(crate) events: Vec<SignedClaimTransitionEvent>,
    /// The tip's handoff chain, oldest first, ending at the tip.
    pub(crate) chain: Vec<ClaimHistoryHandoff>,
    /// The whole history: every transition of every delta in the chain, by
    /// hash, with its predecessors ([`chain_transitions`]).
    pub(crate) transitions: BTreeMap<[u8; 32], Vec<[u8; 32]>>,
}

impl MachineHistoryRows {
    /// Heads of the packet before the tip, read from that verified packet:
    /// the tip's pinned previous heads. Empty at genesis.
    pub(crate) fn previous_heads(&self) -> &[[u8; 32]] {
        self.chain
            .iter()
            .rev()
            .nth(1)
            .map_or(&[][..], |packet| packet.heads.as_slice())
    }
}

const TIP_HEAD_MISSING: &str = "handoff-chain tip authority head missing";
const PRIOR_HEAD_MISSING: &str = "handoff-chain prior authority head missing";

/// Whether a [`verified_handoff_chain`] error waits on what this vault does
/// not hold yet, an ancestor packet or an authority head, rather than on a
/// wrong chain (FIX 3823).
fn chain_awaits(error: &Error) -> bool {
    matches!(
        error,
        Error::Claim(ClaimError::MachineClaimHistoryIncomplete)
    ) || matches!(
        error,
        Error::InvalidClaimBody(reason) if [TIP_HEAD_MISSING, PRIOR_HEAD_MISSING].contains(reason)
    )
}

/// Whether the resident events are exactly the chain's union: one event per
/// listed transition, each with the predecessor set the chain lists for its
/// hash (a root event lists the birth digest).
fn events_match_chain(rows: &MachineHistoryRows) -> bool {
    rows.transitions.len() == rows.events.len()
        && rows.events.iter().all(|event| {
            let Ok(hash) = machine_claim_transition_event_hash(event) else {
                return false;
            };
            let expected_parents = if event.predecessors.is_empty() {
                vec![rows.birth.digest]
            } else {
                event.predecessors.clone()
            };
            rows.transitions.get(&hash) == Some(&expected_parents)
        })
}

/// The verified, folded history of `target`, read through `source`, and the
/// ids of every carrier it was folded from: the birth, the present pin, each
/// handoff in its chain and each transition of the chain's union.
fn machine_history(
    source: &dyn ControlRows,
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    target: EntityId,
) -> Result<(ClaimTransitionProjection, Vec<EntityId>)> {
    let rows = machine_history_rows_from(source, store, txn, target)?;
    let packet = trusted_machine_handoff(store, txn, target)?;
    if fold.vault_id != Some(rows.birth.vault_id)
        || packet.vault_id != rows.birth.vault_id
        || packet.births.len() != 1
        || packet.births[0].id != target
        || packet.births[0].digest != rows.birth.digest
        || !events_match_chain(&rows)
    {
        return Err(missing());
    }
    let mut hashes = rows
        .events
        .iter()
        .map(machine_claim_transition_event_hash)
        .collect::<Result<Vec<_>>>()?;
    hashes.sort_unstable();
    if !hashes
        .iter()
        .zip(rows.transitions.keys())
        .all(|(hash, listed)| hash == listed)
    {
        return Err(missing());
    }
    let handoff_chain = verified_handoff_chain_from(source, store, txn, &packet, fold)?;
    let mut hashes = vec![rows.birth.digest, packet.content_hash().map_err(|_| bad())?];
    hashes.extend(rows.transitions.keys().copied());
    for handoff in &handoff_chain {
        hashes.push(handoff.content_hash().map_err(|_| bad())?);
    }
    let carriers = hashes
        .iter()
        .map(|hash| {
            EntityId::from_bytes(hash[..16].try_into().map_err(|_| bad())?).map_err(|_| bad())
        })
        .collect::<Result<Vec<_>>>()?;
    let event_tips: Vec<_> = packet
        .heads
        .iter()
        .filter(|head| **head != rows.birth.digest)
        .copied()
        .collect();
    let original = super::decode_claim_body(&rows.birth.initial_body, true)?;
    // The signed birth's own ClaimOf weight, the one the materializer gave
    // the edge.
    let initial_weight = super::claim_initial_claim_of_weight(&original).map_err(|_| bad())?;
    fold_machine_claim_transitions(
        &original,
        &rows.birth.vault_id,
        target,
        &rows.birth.digest,
        initial_weight,
        &rows.events,
        &event_tips,
        |event| {
            let key = AuthorityKey::Ed25519(event.host_public_key);
            let event_hash = machine_claim_transition_event_hash(event).ok();
            let Some(index) = handoff_chain.iter().position(|packet| {
                packet.signer == key
                    && packet
                        .transitions
                        .iter()
                        .any(|row| Some(row.hash) == event_hash)
                    && (packet.authority_head == event.authority_head
                        || packet.previous_handoff_hash.is_none())
            }) else {
                return false;
            };
            if fold
                .roster
                .get(&key)
                .is_some_and(|root| !root.revoked && root.roles & ROLE_OWNER != 0)
                && fold.valid_entries.contains(&event.authority_head)
            {
                return true;
            }
            // The successor's in-chain ReRoot is the causal witness, not a
            // timestamp. Every later packet carries the event in its
            // ancestry, since its delta extends the introducing packet's
            // heads; its own delta never repeats the event. An old event
            // absent from the exact introducing packet cannot be inserted
            // after the root has been retired.
            handoff_chain.iter().skip(index + 1).any(|successor| {
                fold.roster
                    .get(&successor.signer)
                    .is_some_and(|root| !root.revoked && root.roles & ROLE_OWNER != 0)
                    && crate::authority::machine_history_authority_descends(
                        store,
                        txn,
                        &event.authority_head,
                        &successor.authority_head,
                    )
                    .unwrap_or(false)
            })
        },
    )
    .map_err(|error| match error {
        TransitionFoldError::MissingHistory | TransitionFoldError::FrontierMismatch => missing(),
        TransitionFoldError::InvalidBirth => {
            Error::InvalidClaimBody("machine history birth invalid")
        }
        TransitionFoldError::InvalidEvent => {
            Error::InvalidClaimBody("machine history event invalid")
        }
        TransitionFoldError::Unauthorized => {
            Error::InvalidClaimBody("machine history signer unauthorized")
        }
        TransitionFoldError::IncompatibleFork => {
            Error::InvalidClaimBody("machine history fork incompatible")
        }
        TransitionFoldError::Rollback => Error::InvalidClaimBody("machine history event rollback"),
    })
    .map(|projection| (projection, carriers))
}

/// How an adopted candidate must stand to the stored pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Succession {
    /// The out-of-band door: a stored pin is required, and the candidate is
    /// that pin or its immediate successor on the pin's own heads.
    Strict,
    /// A device receiving its own vault's history
    /// (`history_pin_exchange`): the stored pin, if any, must lie on the
    /// candidate's verified chain, so the trusted prefix is kept; with none,
    /// the chain from genesis is the first pin.
    OwnReceive,
}

/// An authenticated origin and derived current state are distinct facts.
/// A caller cannot treat the current projection as the body MACHINE signed.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedMachineClaim {
    pub claim_id: EntityId,
    pub signed_origin: ClaimBody,
    pub current: ClaimBody,
    pub birth_digest: [u8; 32],
    pub transition_heads: Vec<[u8; 32]>,
    pub handoff_digest: [u8; 32],
}
