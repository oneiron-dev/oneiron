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
//!   for the proof wherever the vault holds a key that can give it
//!   ([`gives_owner_proof`]): a self-host vault's live owner root, and on a
//!   hosted vault an enrolled owner device key (CARRIER-HOSTED-WEB-ACTS =
//!   C). A vault with no such key keeps today's acts: nothing there could
//!   ever answer the wait. A key of the owner's in a suite the fold takes no
//!   proof from (a P-256 key, a passkey's suite) is no such key (Engine
//!   RULING CARRIER-ASKS-ON-PASSKEY-ONLY-VAULT = A).
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
/// None when it carries no cosign. A proof is exactly one cosign, by a key
/// whose proof the fold takes in `state` ([`gives_owner_proof`]); any other
/// cosign is a forged proof, an invalid entry, never a held one.
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
        AuthorityKey::Ed25519(bytes) if gives_owner_proof(state, key) => Ok(Some(*bytes)),
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

/// Whether `key` is one whose cosign the fold takes as the owner's proof in
/// `state`: a key `state` trusts as the owner's ([`proves_for_the_owner`]),
/// in the one suite a proof is made in, Ed25519. The one predicate of the
/// proof (Engine RULING CARRIER-ASKS-ON-PASSKEY-ONLY-VAULT = A): the judge
/// of a cosign ([`owner_proof_key`]) and the vault's asking for a proof
/// ([`not_mine_carriers_need_proof`]) both read it, so the vault never asks
/// for a proof that no key it holds can give. A key of the owner's in
/// another suite (a P-256 key, a passkey's suite) is the owner's key and
/// gives no proof; when the fold learns that suite's proof form, this is the
/// one place that widens.
fn gives_owner_proof(state: &FoldState, key: &AuthorityKey) -> bool {
    matches!(key, AuthorityKey::Ed25519(_)) && proves_for_the_owner(state, key)
}

/// Whether an act a not-mine carrier delivers needs the proof in `state`
/// (item 2): as soon as its roster holds a key that can give it
/// ([`gives_owner_proof`]). A self-host vault's live owner root is one; a
/// hosted vault has one once an owner device key is enrolled there. A vault
/// with none keeps today's acts (CARRIER-HOSTED-WEB-ACTS = C, and the
/// amendment to CARRIER-CHOICE-DOOR-WAIT-OR-REFUSE = B): no key there could
/// ever prove the act, so a wait would have no end. That holds for a vault
/// whose only owner key is of a suite the fold takes no proof from.
pub(super) fn not_mine_carriers_need_proof(state: &FoldState) -> bool {
    state.roster.keys().any(|key| gives_owner_proof(state, key))
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

/// Whether `op`, signed by `participants` (its signer and every cosign),
/// may count at its parent state `state` as far as the owner keys it ends go
/// (row HOSTED-ROOT-REVOKES-OWNER-KEY; the lead, 15 Nov 20:41: "a revoke of
/// an owner key needs an owner key's signature, never only the custodial
/// root").
///
/// A `RevokeDevice` of a key that proves for the owner
/// ([`proves_for_the_owner`]) widens: it lowers the proof the vault can ask
/// of its owner. Only the owner may make it, and a participant that proves
/// for the owner is the owner's proof, as the primary signer or as a cosign.
/// A managed host's custodial root, which a hosted fold admits for consent,
/// proves only itself, and so does an admin-only key. A revoke of a key the
/// parents do not hold needs the same proof: the roster merge keeps a
/// revocation on every branch, so a revoke parented before a key's
/// enrolment would otherwise end that owner key unproved. Every other op
/// passes.
///
/// The act rule (A0, `act_rule.rs`) takes this over in one line: the
/// participants' reading is `AnyMove` when one proves for the owner and
/// `Nothing` otherwise, and the revoke counts when that admits
/// `Direction::Widens`.
pub(super) fn owner_key_revoke_proved(
    state: &FoldState,
    op: &AuthorityOp,
    participants: &BTreeSet<AuthorityKey>,
) -> bool {
    let AuthorityOp::RevokeDevice { revoked_key } = op else {
        return true;
    };
    let ends_owner_key =
        proves_for_the_owner(state, revoked_key) || !state.roster.contains_key(revoked_key);
    !ends_owner_key
        || participants
            .iter()
            .any(|key| proves_for_the_owner(state, key))
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
    /// Whether `key` is a key this fold trusts as the owner's: live on the
    /// roster with `ROLE_OWNER`, and outside the host's custody when the
    /// vault is `hosted`. The writer's side of `proves_for_the_owner`; the
    /// fold takes a proof cosign only from such a key in the Ed25519 suite
    /// ([`owner_proof_key`]), and every signer an install holds is one.
    #[must_use]
    pub(crate) fn proves_owner_acts(&self, key: &AuthorityKey, hosted: bool) -> bool {
        roster_has_live_owner(&self.roster, key) && !(hosted && self.in_host_custody(key))
    }

    /// A choice door's answer about `act`, the choice it appended in its
    /// writing transaction and this fold has folded: the owner-key refusal
    /// when the act waits for the owner's proof
    /// ([`crate::error::RecordError::OwnerKeyRequired`]). The fold judged the
    /// very entry, so the door and the fold cannot disagree; the door's error
    /// drops the transaction, so nothing of a refused choice is stored
    /// (ruling CARRIER-CHOICE-DOOR-WAIT-OR-REFUSE = B). It waits only where
    /// the vault holds an owner key and this install neither is the owner's
    /// machine nor holds one.
    ///
    /// # Errors
    /// That refusal.
    pub(crate) fn refuse_waiting_choice(
        &self,
        act: &AuthorityEntryHash,
    ) -> crate::error::Result<()> {
        if self.waiting_owner_choices.contains(act) {
            return Err(crate::error::Error::Record(
                crate::error::RecordError::OwnerKeyRequired,
            ));
        }
        Ok(())
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

/// The owner key an install proves an owner act with, picked on one vault
/// ([`crate::Vault::owner_proof_signer`]). It is bound to that vault, so a
/// proof is never signed without the signer's own check of it
/// ([`CheckpointRootSigner::sign_owner_proof`]).
pub(crate) struct OwnerProofSigner<'vault> {
    vault: &'vault crate::Vault,
    signer: std::sync::Arc<dyn CheckpointRootSigner>,
}

impl OwnerProofSigner<'_> {
    /// The key the proof is made with: the cosign's key.
    pub(crate) fn key(&self) -> AuthorityKey {
        self.signer.root()
    }

    /// The key's signature over `transcript`, the transcript of an entry on
    /// `fold`, the signing door's view of the vault.
    ///
    /// # Errors
    /// The signer's refusal: a key that stopped since it was picked signs no
    /// proof, and the door's act fails with that refusal. One that rests
    /// under a device PIN answers [`crate::error::DevicePinRefusal::Required`]
    /// once its window ended.
    pub(crate) fn sign(
        &self,
        fold: &AuthorityFold,
        transcript: &[u8],
    ) -> crate::error::Result<Vec<u8>> {
        self.signer.sign_owner_proof(self.vault, fold, transcript)
    }

    /// The key's signature over `transcript`, the owner's proof that he
    /// gives one ask word in person (UC-05 PR 2b), by the roster of `fold`,
    /// the view the key was picked on.
    ///
    /// # Errors
    /// The signer's refusal, as [`Self::sign`] answers it: a key that rests
    /// under a device PIN proves an ask word only inside its window.
    pub(crate) fn sign_ask_word(
        &self,
        fold: &AuthorityFold,
        transcript: &[u8],
    ) -> crate::error::Result<Vec<u8>> {
        self.signer
            .sign_ask_word_proof(self.vault, fold, transcript)
    }
}

impl crate::Vault {
    /// The owner key this install can prove an owner act with on `fold`: the
    /// first root signer this handle holds whose key the fold trusts as the
    /// owner's ([`AuthorityFold::proves_owner_acts`]) under this vault's
    /// posture and that proves at this moment
    /// ([`CheckpointRootSigner::proves_now`]). The list is in the order of
    /// each signer's latest hold, so where an install holds two keys that
    /// both prove (a self-host server's host root and its owner signing
    /// key), which one signs is not fixed: the fold takes either. A
    /// self-host server holds its host root, a device its enrolled owner
    /// signing key ([`crate::Vault::hold_checkpoint_root_signer`]); a managed
    /// host's custodial root proves nothing, and an install that holds
    /// neither carries its acts unproven.
    ///
    /// A key that does not prove now is passed over as if it were not held:
    /// an owner signing key the roster no longer lists live, one whose seed
    /// left its slot, and one that rests under a device PIN outside the
    /// window a right PIN opened (row OCS-OWNER-PIN). The act is then
    /// carried unproven, and the fold judges it as any unproven act: where
    /// it needs the proof, it waits or is held until the owner proves it.
    ///
    /// A door calls this inside its own transaction, so nothing here opens
    /// one: each signer reads the roster from `fold`.
    pub(crate) fn owner_proof_signer(&self, fold: &AuthorityFold) -> Option<OwnerProofSigner<'_>> {
        let hosted = self.privacy_posture() == crate::HostingPrivacyPosture::Hosted;
        self.held_checkpoint_root_signers()
            .into_iter()
            .find(|signer| {
                fold.proves_owner_acts(&signer.root(), hosted)
                    && (signer.proves_now(self, fold) || true)
            })
            .map(|signer| OwnerProofSigner {
                vault: self,
                signer,
            })
    }
}
