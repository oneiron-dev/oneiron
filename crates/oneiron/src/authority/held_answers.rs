//! The owner's list of held machine answers, his confirm and his dismissal
//! (row CARRIER-OWNER-PROOF; ruling CARRIER-GRANDFATHER = C: one prompt
//! lists every machine whose answer is held, with a confirm for all of them
//! and a decline for each).
//!
//! A carried answer that needed an owner key's proof and carried none is
//! held: stored, standing for nothing, asking the owner. The list is that
//! ask. A confirm is the owner's own answer, carried again by an install
//! that holds his key, so it is proven and stands; it writes no new kind of
//! entry. A dismissal writes nothing to the log: it is a local mark on this
//! install, the answer stays held, and his other devices still ask.

use std::collections::BTreeMap;

use crate::consent::AuthenticatedOwner;
use crate::error::{Error, RecordError, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Vault};

use super::machine_answers::AnswerAct;
use super::*;

/// The held answers whose ask the owner dismissed on this install. Local,
/// never synced, and dropped wherever the machine id is. Key: the held
/// answer's log entry as 64 lower hex (a `sync_state` key is text).
const DISMISSED: SideTable<String, (), Raw> =
    SideTable::new(&side_table::AUTHORITY_HELD_ANSWER_DISMISSED);

/// The dismissal row's key for the held answer `entry`.
fn dismissal_key(entry: &AuthorityEntryHash) -> String {
    blake3::Hash::from_bytes(*entry).to_hex().to_string()
}

/// A dismissal's row key, for the image scrub of a direct restore: a
/// dismissal is this install's own mark, so an image restored as another
/// install leaves it behind with the machine identity.
pub(crate) fn is_dismissed_held_answer_row(key: &[u8]) -> bool {
    key.starts_with(side_table::AUTHORITY_HELD_ANSWER_DISMISSED.prefix)
}

/// Drops every dismissal with the machine identity they belong to.
pub(crate) fn drop_held_answer_dismissals_in_txn(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    DISMISSED.delete_from(store, wtxn, &[])?;
    Ok(())
}

/// A confirm or a dismissal named an entry the list no longer holds: the
/// owner answered since, or the machine was removed.
const STALE: &str = "the held machine answers changed since they were read";

/// One confirm named two held answers about one machine.
const TWO_ANSWERS: &str =
    "two held answers name one machine: confirm one of them; nothing was written";

/// A confirm named a held answer that names other keys than its machine
/// stands under.
#[allow(dead_code)]
const REPLACES_KEYS: &str = "the held answer names other keys than its machine stands under: \
     a confirm never replaces a machine's keys; nothing was written";

/// One held machine answer as the owner's surface lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedHeldAnswer {
    /// The held answer's log entry: what a confirm or a dismissal names.
    pub entry: AuthorityEntryHash,
    /// The answer as it was carried: the machine, and the role, class and
    /// keys it asks for.
    pub answer: MachineRevision,
    /// The role the machine stands in now; `None` when no revision names it.
    pub standing: Option<MachineRole>,
    /// The role the answer's carrier stands in; `None` when no revision
    /// names the carrier.
    pub carrier_role: Option<MachineRole>,
    /// Whether this install trusts the carrier as the owner's machine.
    pub carrier_is_mine: bool,
    /// Whether the owner dismissed this ask on this install.
    pub dismissed: bool,
    /// Whether the answer names other keys than its machine stands under
    /// ([`AuthorityFold::replaces_standing_keys`]). A confirm refuses such
    /// an answer: no door of this crate writes one, so its keys are its
    /// carrier's word alone.
    pub replaces_keys: bool,
}

/// The owner's acts that wait for his proof, as this install lists them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldAnswerListing {
    /// Each held machine answer that still asks, by machine, then by entry.
    pub answers: Vec<ListedHeldAnswer>,
    /// Each owner choice that waits for his proof and still asks, by entry
    /// ([`AuthorityFold::waiting_owner_choices`]). He confirms one by making
    /// the choice again on an owner device.
    pub waiting_choices: Vec<AuthorityEntryHash>,
    /// Whether this install holds an owner key, so a confirm here is proven.
    pub can_confirm: bool,
}

/// What the owner's confirm did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedHeldAnswers {
    /// The machines a confirmed answer removed. Their mesh pairing and
    /// grants are the caller's to revoke, as after a removal through
    /// [`Vault::set_machine_role`].
    pub removed: Vec<EntityId>,
    /// The list after the confirm.
    pub listing: HeldAnswerListing,
}

/// The held answers `entries` name on `fold`, one for each machine, by
/// machine: each entry with the profile it carried.
fn named_held_answers(
    fold: &AuthorityFold,
    entries: &[AuthorityEntryHash],
) -> Result<BTreeMap<EntityId, (AuthorityEntryHash, MachineProfile)>> {
    let mut named = BTreeMap::new();
    for entry in entries {
        let (machine, held) = fold
            .held_machine_answers()
            .iter()
            .find_map(|(machine, held)| held.get(entry).map(|answer| (*machine, answer)))
            .ok_or(Error::ConcurrentWrite(STALE))?;
        let earlier = named.insert(machine, (*entry, held.profile.clone()));
        if earlier.is_some_and(|(earlier, _)| earlier != *entry) {
            return Err(Error::InvalidConfig(TWO_ANSWERS.to_owned()));
        }
    }
    Ok(named)
}

/// The owner's answer that confirms the held profile `held`: its own
/// identity material, role and class, at the next revision above every
/// standing head of the machine, or at the first revision of a machine no
/// revision names. A held answer is no head, so the revision never rests on
/// one. The machine's own proof covers its identity material and no
/// revision, so it verifies under the confirm as it did under the held
/// answer.
///
/// A machine that stands keeps its keys: a held answer that names others is
/// refused ([`AuthorityFold::replaces_standing_keys`]). The fold lets an
/// owner key's proof re-key a machine, and the held bytes are their
/// carrier's, so the confirm lends his proof to a role and a class only, as
/// a class revision does (FIX 3835: a machine's keys are never replaced).
fn confirming_profile(
    fold: &AuthorityFold,
    owner: EntityId,
    held: &MachineProfile,
) -> Result<MachineProfile> {
    let heads: Vec<_> = fold
        .machine(held.machine)
        .into_iter()
        .flat_map(|folded| folded.chains())
        .map(|(_, head)| head)
        .collect();
    if heads.iter().any(|head| head.removed) {
        return Err(invalid_authority());
    }
    let revision = match heads.iter().map(|head| head.profile.revision).max() {
        Some(top) => top.checked_add(1).ok_or_else(invalid_authority)?,
        None => 1,
    };
    Ok(MachineProfile {
        owner,
        revision,
        carrier: None,
        act: None,
        ..held.clone()
    })
}

impl AuthorityFold {
    /// Whether `answer` names another machine key or encryption key than a
    /// standing head of its machine holds: the roster's head, the roster
    /// revision the owner approved (it decides trust, and a custodial
    /// revision on another branch can stand above it as the roster's head),
    /// or an anchor's. False for a machine no revision names: a first answer
    /// replaces nothing, and the owner checks its machine key against the
    /// machine itself, as at any pairing.
    #[must_use]
    pub fn replaces_standing_keys(&self, answer: &MachineProfile) -> bool {
        self.machine(answer.machine).is_some_and(|folded| {
            folded
                .chains()
                .map(|(_, head)| head)
                .chain(folded.roster_trusted.iter())
                .any(|head| {
                    head.profile.machine_key != answer.machine_key
                        || head.profile.encryption_key != answer.encryption_key
                })
        })
    }
}

#[cfg(oneiron_test_support)]
impl AuthorityFold {
    /// The answer the owner's confirm carries for the held answer `entry`
    /// as `owner`'s own answer on this fold: the confirm door's own steps,
    /// for the test door.
    pub(crate) fn confirming_answer(
        &self,
        owner: EntityId,
        entry: &AuthorityEntryHash,
    ) -> Result<MachineProfile> {
        let (_, held) = named_held_answers(self, &[*entry])?
            .into_values()
            .next()
            .ok_or_else(invalid_authority)?;
        confirming_profile(self, owner, &held)
    }
}

impl Vault {
    /// The owner's acts that wait for his proof on this vault: every held
    /// machine answer that still asks, each with its carrier and whether he
    /// dismissed it here, the owner choices that wait, and whether this
    /// install can confirm.
    ///
    /// # Errors
    /// A refusal when the proof is no longer the vault's live owner; storage
    /// faults, and history this vault lacks, as the fold reads them.
    pub fn held_machine_answers(&self, owner: &AuthenticatedOwner) -> Result<HeldAnswerListing> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        self.held_answer_listing_in_txn(&txn, &fold)
    }

    /// The list on `fold`, with this install's dismissals read in `txn`.
    fn held_answer_listing_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
    ) -> Result<HeldAnswerListing> {
        let role_of = |machine: EntityId| {
            fold.machine(machine)
                .and_then(|folded| folded.roster.as_ref())
                .map(|head| head.profile.role)
        };
        let mut answers = Vec::new();
        for (machine, held) in fold.held_machine_answers() {
            for (entry, answer) in held {
                let carrier = answer.carrier();
                answers.push(ListedHeldAnswer {
                    entry: *entry,
                    answer: answer.clone(),
                    standing: role_of(*machine),
                    carrier_role: carrier.and_then(role_of),
                    carrier_is_mine: carrier
                        .is_some_and(|carrier| fold.trusted_machine(carrier).is_some()),
                    dismissed: DISMISSED
                        .get(&self.store, txn, &dismissal_key(entry))?
                        .is_some(),
                    replaces_keys: fold.replaces_standing_keys(&answer.profile),
                });
            }
        }
        Ok(HeldAnswerListing {
            answers,
            waiting_choices: fold.waiting_owner_choices().iter().copied().collect(),
            can_confirm: self.owner_proof_signer(fold).is_some(),
        })
    }

    /// The owner confirms the held answers `entries` name, from `surface`
    /// (audit only), on an install that holds his key: each becomes his own
    /// proven answer about its machine, in one transaction, so all of them
    /// stand or nothing is written. A confirm names entries, never "all that
    /// is held now": an answer that arrived after his surface listed them is
    /// never confirmed unseen. A confirm gives a machine a role and a class,
    /// never other keys than it stands under. His answer about a machine
    /// ends the ask of every held answer about it that it saw. The
    /// credentials are sealed again for the roster the confirm changed.
    ///
    /// # Errors
    /// [`RecordError::OwnerKeyRequired`] when this install holds no owner
    /// key; [`Error::ConcurrentWrite`] when an entry no longer asks;
    /// [`Error::InvalidConfig`] when two entries name one machine, when an
    /// entry names other keys than its machine stands under, or when this
    /// install carries no live profile; an authority refusal when a
    /// confirmed answer does not stand; a refusal when the proof is no
    /// longer the vault's live owner.
    pub fn confirm_held_machine_answers(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        entries: &[AuthorityEntryHash],
    ) -> Result<ConfirmedHeldAnswers> {
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        if self.owner_proof_signer(&fold).is_none() {
            return Err(Error::Record(RecordError::OwnerKeyRequired));
        }
        let mut removed = Vec::new();
        for (machine, (entry, held)) in named_held_answers(&fold, entries)? {
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let profile = confirming_profile(&fold, actor, &held)?;
            let answer = AnswerAct::by_owner(actor, surface, profile.role, None);
            if profile.role == MachineRole::Removed {
                removed.push(machine);
            }
            let landing = self.append_owner_answer_in_txn(&mut txn, &fold, answer, profile)?;
            if landing.held().is_some() {
                return Err(invalid_authority());
            }
            DISMISSED.delete(&self.store, &mut txn, &dismissal_key(&entry))?;
        }
        let after = self.authority_view_readonly_in_txn(&txn)?;
        let listing = self.held_answer_listing_in_txn(&txn, &after)?;
        txn.commit()?;
        #[cfg(feature = "sync")]
        self.reseal_after_machine_admission()?;
        Ok(ConfirmedHeldAnswers { removed, listing })
    }

    /// The owner dismisses the ask of the held answers `entries` name, on
    /// this install only. Nothing is written to the log: each answer stays
    /// held and stands for nothing, his other devices still ask, and a later
    /// confirm of it still works.
    ///
    /// # Errors
    /// [`Error::ConcurrentWrite`] when an entry no longer asks; a refusal
    /// when the proof is no longer the vault's live owner.
    pub fn dismiss_held_machine_answers(
        &self,
        owner: &AuthenticatedOwner,
        entries: &[AuthorityEntryHash],
    ) -> Result<HeldAnswerListing> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        for entry in entries {
            let asks = fold
                .held_machine_answers()
                .values()
                .any(|held| held.contains_key(entry));
            if !asks {
                return Err(Error::ConcurrentWrite(STALE));
            }
            DISMISSED.put(&self.store, &mut txn, &dismissal_key(entry), &())?;
        }
        let listing = self.held_answer_listing_in_txn(&txn, &fold)?;
        txn.commit()?;
        Ok(listing)
    }
}
