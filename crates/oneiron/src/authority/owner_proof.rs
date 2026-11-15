//! An owner act's proof (row CARRIER-OWNER-PROOF; the lead's rulings 15 Nov
//! 12:1x and 13:2x, FIX [CARRIER-SELF-ANSWER-MINE]).
//!
//! The one carrier rule ([`super::owner_act_signer_admits`]) admits the
//! install key of any live profiled machine, in any role, so a carrier says
//! nothing about the owner. A carried act is PROVEN when exactly one cosign
//! beside the carrier's install key signs the same transcript, by a key the
//! vault already trusts as the owner's: a live roster key with `ROLE_OWNER`
//! that, on a hosted fold, is not in the host's custody (the class an
//! owner-held roster mark already rests on). The carrier still signs as the
//! carrier; the proof key never carries an act (FIX 2222).
//!
//! - Item 1, every vault: a carried answer that makes a machine the owner's
//!   (`Owned(Yours)`) stands only when proven, whoever carries it. Unproven,
//!   it is HELD: kept so the owner's device can ask, standing for nothing.
//! - Item 2: an act a carrier that is not the owner's machine delivers waits
//!   for the proof on every self-host vault, and on a hosted vault once an
//!   owner device key is enrolled there (CARRIER-HOSTED-WEB-ACTS = C).
//!
//! The judge reads the act's parent state only, so every replica judges the
//! same rows the same way.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

use super::machine_profile::in_host_custody;
use super::*;

/// The owner key that proves `entry`, judged at its parent state `state`:
/// None when it carries no cosign. A proof is exactly one cosign, by an
/// Ed25519 key that `state` trusts as the owner's ([`proves_for_the_owner`]);
/// any other cosign is a forged proof, an invalid entry, never a held one.
pub(super) fn owner_proof_key(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
) -> std::result::Result<Option<[u8; 32]>, AuthorityFoldIssue> {
    let [cosign] = entry.cosigns.as_slice() else {
        return if entry.cosigns.is_empty() {
            Ok(None)
        } else {
            Err(AuthorityFoldIssue::InvalidEntry(hash))
        };
    };
    let key = &cosign.public_key;
    match key {
        AuthorityKey::Ed25519(bytes) if proves_for_the_owner(state, key) => Ok(Some(*bytes)),
        _ => Err(AuthorityFoldIssue::InvalidEntry(hash)),
    }
}

/// Whether `key` is a key `state` trusts as the owner's: live on the roster
/// with `ROLE_OWNER`, and not in the host's custody on a hosted fold. A
/// revoked or retired key, an admin-only key and a managed host's custodial
/// root prove nothing.
fn proves_for_the_owner(state: &FoldState, key: &AuthorityKey) -> bool {
    roster_has_live_owner(&state.roster, key) && !(state.hosted && in_host_custody(state, key))
}

/// Whether an act a not-mine carrier delivers needs the proof in `state`
/// (item 2): on every self-host vault, and on a hosted vault as soon as its
/// roster holds an owner key outside the host's custody. A hosted vault with
/// none keeps today's acts (CARRIER-HOSTED-WEB-ACTS = C).
pub(super) fn not_mine_carriers_need_proof(state: &FoldState) -> bool {
    !state.hosted
        || state
            .roster
            .keys()
            .any(|key| proves_for_the_owner(state, key))
}

/// Whether a carried machine answer needs the proof (items 1 and 2), judged
/// at its parent state. `carrier_is_mine`: the carrier's install key that
/// signed is its trusted mine key there; `target_key`: the target machine's
/// trusted mine key there, if it is mine.
///
/// An answer `Owned(Yours)` needs it unless a mine carrier keeps an already
/// mine machine under the same key (a class revision makes nothing mine). A
/// new key, a new encryption key from a carrier that is not the owner's, or a
/// machine not yet mine all make something mine. Any answer a not-mine
/// carrier delivers needs it where item 2 applies.
pub(super) fn machine_answer_needs_proof(
    state: &FoldState,
    profile: &MachineProfile,
    carrier_is_mine: bool,
    target_key: Option<[u8; 32]>,
) -> bool {
    let makes_mine = profile.role == MachineRole::Owned(MachineOwnership::Yours)
        && !(carrier_is_mine && target_key == Some(profile.machine_key));
    makes_mine || (!carrier_is_mine && not_mine_carriers_need_proof(state))
}

/// Each machine's held answers that still ask the owner: the answers above
/// the machine's folded roster head (every held answer of a machine with no
/// roster head, as a held pairing), none of a removed machine's.
pub(super) fn listed_held_answers(
    state: &FoldState,
    machines: &BTreeMap<EntityId, FoldedMachine>,
) -> BTreeMap<EntityId, BTreeMap<AuthorityEntryHash, MachineRevision>> {
    state
        .held_machine_answers
        .iter()
        .filter_map(|(machine, held)| {
            let head = machines
                .get(machine)
                .and_then(|folded| folded.roster.as_ref());
            if head.is_some_and(|head| head.removed) {
                return None;
            }
            let above: BTreeMap<_, _> = held
                .iter()
                .filter(|(_, answer)| {
                    head.is_none_or(|head| answer.profile.revision > head.profile.revision)
                })
                .map(|(hash, answer)| (*hash, answer.clone()))
                .collect();
            (!above.is_empty()).then_some((*machine, above))
        })
        .collect()
}

/// Every waiting owner choice that still asks the owner, of every kind the
/// shared landing gate serves.
pub(super) fn asking_owner_choices(state: &FoldState) -> BTreeSet<AuthorityEntryHash> {
    state
        .checkpoint_policy
        .asking()
        .chain(state.home_pick.asking())
        .chain(state.origin_cut.asking())
        .chain(state.device_succession.asking())
        .chain(state.conversation_training.asking())
        .chain(state.conversation_training_vault.asking())
        .chain(state.policy_settings.asking())
        .collect()
}

impl AuthorityFold {
    /// The owner choices that wait for the owner's proof and still ask (row
    /// CARRIER-OWNER-PROOF), by entry, of every kind the shared landing gate
    /// serves: each is a stored, valid entry in no frontier. The owner
    /// confirms one by carrying the choice again from an owner device.
    #[must_use]
    pub fn waiting_owner_choices(&self) -> &BTreeSet<AuthorityEntryHash> {
        &self.waiting_owner_choices
    }

    /// Each machine's held answers that still ask the owner (row
    /// CARRIER-OWNER-PROOF): carried answers that needed an owner key's
    /// proof and carried none, by entry. Each names its carrier
    /// ([`MachineRevision::carrier`]). The owner confirms one on an owner
    /// device by answering again, with the proof, above it.
    #[must_use]
    pub fn held_machine_answers(
        &self,
    ) -> &BTreeMap<EntityId, BTreeMap<AuthorityEntryHash, MachineRevision>> {
        &self.held_machine_answers
    }
}
