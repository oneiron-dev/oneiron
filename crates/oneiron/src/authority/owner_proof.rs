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
//!   for the proof wherever the vault holds a key that can give it: a
//!   self-host vault's live owner root, and on a hosted vault an enrolled
//!   owner device key (CARRIER-HOSTED-WEB-ACTS = C). A vault with no such
//!   key keeps today's acts: nothing there could ever answer the wait.
//!
//! The judge reads the act's parent state only, so every replica judges the
//! same rows the same way. Mine is read in the roster view of that state
//! (the removal race and custody applied, no pin and no install's counting),
//! never off a raw chain head: a head whose carrier lost its removal race
//! names a machine that is not mine.
//!
//! A held answer asks until the owner answers: a later answer about the same
//! machine that an owner key proved, or that one of the owner's machines
//! carried, and that saw it. The revision numbers never decide it, so a held
//! answer at the last revision blocks nothing, and a new unproven answer
//! after the owner's is a new ask. A waiting choice asks the same way, until
//! the owner's own choice for its target that saw it.

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
/// (item 2): as soon as its roster holds a key that proves for the owner
/// ([`proves_for_the_owner`]). A self-host vault's live owner root is one; a
/// hosted vault has one once an owner device key is enrolled there. A vault
/// with none keeps today's acts (CARRIER-HOSTED-WEB-ACTS = C, and the
/// amendment to CARRIER-CHOICE-DOOR-WAIT-OR-REFUSE = B): no key there could
/// ever prove the act, so a wait would have no end.
pub(super) fn not_mine_carriers_need_proof(state: &FoldState) -> bool {
    state
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

/// One held answer in a fold state: the answer as it folded, and whether the
/// owner has answered since.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct HeldAnswer {
    pub(super) answer: MachineRevision,
    /// A later answer about the machine saw this one and was the owner's: an
    /// owner key proved it, or one of the owner's machines carried it.
    pub(super) answered: bool,
}

/// Holds `answer`, an answer that needed the proof and carried none.
pub(super) fn hold_answer(
    state: &mut FoldState,
    hash: AuthorityEntryHash,
    answer: MachineRevision,
) {
    state
        .held_machine_answers
        .entry(answer.profile.machine)
        .or_default()
        .insert(
            hash,
            HeldAnswer {
                answer,
                answered: false,
            },
        );
}

/// The owner answered about `machine` on `state`, the answer's parent state:
/// every held answer about it there asks no more.
pub(super) fn answer_held(state: &mut FoldState, machine: EntityId) {
    if let Some(held) = state.held_machine_answers.get_mut(&machine) {
        for answer in held.values_mut() {
            answer.answered = true;
        }
    }
}

/// Each machine's held answers that still ask the owner: the ones the owner
/// has not answered since, none of a removed machine's.
pub(super) fn listed_held_answers(
    state: &FoldState,
    machines: &BTreeMap<EntityId, FoldedMachine>,
) -> BTreeMap<EntityId, BTreeMap<AuthorityEntryHash, MachineRevision>> {
    state
        .held_machine_answers
        .iter()
        .filter_map(|(machine, held)| {
            let removed = machines
                .get(machine)
                .and_then(|folded| folded.roster.as_ref())
                .is_some_and(|head| head.removed);
            if removed {
                return None;
            }
            let asking: BTreeMap<_, _> = held
                .iter()
                .filter(|(_, held)| !held.answered)
                .map(|(hash, held)| (*hash, held.answer.clone()))
                .collect();
            (!asking.is_empty()).then_some((*machine, asking))
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
    /// Whether `key` proves an owner act on this fold, as the fold judges a
    /// proof cosign ([`owner_proof_key`]): live on the roster with
    /// `ROLE_OWNER`, and outside the host's custody when the vault is
    /// `hosted`. The writer's side of the one predicate.
    #[must_use]
    pub(crate) fn proves_owner_acts(&self, key: &AuthorityKey, hosted: bool) -> bool {
        roster_has_live_owner(&self.roster, key) && !(hosted && self.in_host_custody(key))
    }

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
    /// device by answering again, with the proof; any answer of the owner's
    /// about the machine that saw a held one ends its ask.
    #[must_use]
    pub fn held_machine_answers(
        &self,
    ) -> &BTreeMap<EntityId, BTreeMap<AuthorityEntryHash, MachineRevision>> {
        &self.held_machine_answers
    }
}

impl crate::Vault {
    /// The owner key this install can prove an owner act with on `fold`: the
    /// first root signer this handle holds whose key the fold trusts as the
    /// owner's ([`AuthorityFold::proves_owner_acts`]) under this vault's
    /// posture. A self-host server holds its host root, a device its enrolled
    /// owner signing key ([`crate::Vault::hold_checkpoint_root_signer`]); a
    /// managed host's custodial root proves nothing, and an install that
    /// holds neither carries its acts unproven.
    pub(crate) fn owner_proof_signer(
        &self,
        fold: &AuthorityFold,
    ) -> Option<std::sync::Arc<dyn CheckpointRootSigner>> {
        let hosted = self.privacy_posture() == crate::HostingPrivacyPosture::Hosted;
        self.checkpoint_root_signers()
            .into_iter()
            .find(|signer| fold.proves_owner_acts(&signer.root(), hosted))
    }
}
