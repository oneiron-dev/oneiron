//! Who may bring a room's talk into this vault (ARCH-0052 #d5-save-grant,
//! owner ruling 2026-10-16): a holder of this vault's write grant, person or
//! agent. A person holds it who owns this vault, or whose shared-vault
//! membership writes its content; an agent holds it that is one of this
//! vault's own. Either acts on their own slip, as this vault minted it, able
//! to write over the whole vault. A slip that writes is not the grant by
//! itself: a guest speaks in the room on one, and this vault is not theirs.
//!
//! An agent without the grant may ask. Its suggestion waits in the room until
//! a holder answers it: a confirm is that holder's own save, a decline keeps
//! nothing. No new grant kind is involved.

use crate::authority::VerifiedSlip;
use crate::entity_id::EntityId;
use crate::error::{Error, OffRecordError, Result};
use crate::federation::{Scope, SharedVaultWrite};
use crate::off_record::promote::PromoteInitiator;
use crate::{EdgeActorClass, Vault, WriteActor};

use super::on_record::SaverProof;
use super::room::{Hearing, SavedTurns, post_notice};
use super::session::OffRecordSession;
use super::types::OffRecordNoticeAct;

/// A participant's claim to this vault's write grant, on their own slip.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct SaveGrant {
    holder: EntityId,
    class: EdgeActorClass,
    credential: VerifiedSlip,
}

impl SaveGrant {
    /// `credential` as `holder`'s claim, when it can carry the grant: their
    /// own slip, naming them a person or an agent, able to write, as minted
    /// (not narrowed or handed on), with no record bound. A save keeps the
    /// whole talk, so a slip bounded to some records keeps none of it; it
    /// consumes no slip, so a one-shot slip would save again.
    pub(super) fn claimed(holder: EntityId, credential: &VerifiedSlip) -> Option<Self> {
        let claims = credential.claims();
        let class = match claims.actor_class.as_deref() {
            Some("human") => EdgeActorClass::Human,
            Some("agent") => EdgeActorClass::Agent,
            _ => return None,
        };
        let mut whole = Scope::top();
        whole.verbs = credential.scope().verbs.clone();
        (EntityId::from_hex(&claims.holder_ref).ok() == Some(holder)
            && (credential.allows_verb("write") || credential.allows_verb("core:write"))
            && !claims.single_use
            && credential.is_unattenuated()
            && claims.records.is_empty()
            && claims.channels.is_empty()
            && whole.is_narrowing_of(credential.scope()))
        .then(|| Self {
            holder,
            class,
            credential: credential.clone(),
        })
    }

    pub(super) const fn holder(&self) -> EntityId {
        self.holder
    }

    /// Whether, in `txn`, the slip is live and the one this vault's authority
    /// log minted, and this vault grants its holder write.
    pub(super) fn holds_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
        if !vault.capability_slip_is_live_in_txn(txn, &self.credential)?
            || !minted_as_shown(vault, txn, &self.credential)?
        {
            return Ok(false);
        }
        match self.class {
            EdgeActorClass::Human => {
                Ok(
                    crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &self.holder)?
                        || writes_shared_content_in_txn(vault, txn, self.holder)?,
                )
            }
            EdgeActorClass::Agent => {
                let fold = vault.authority_fold_readonly_in_txn(txn)?;
                crate::disclosure::is_vault_agent_in(vault, txn, &fold, &self.holder)
            }
            EdgeActorClass::System => Ok(false),
        }
    }

    /// Refuses unless, in `txn`, the holder still holds.
    pub(super) fn require_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        session_ref: &str,
    ) -> Result<()> {
        if self.holds_in_txn(vault, txn)? {
            Ok(())
        } else {
            Err(not_a_holder(session_ref, self.holder))
        }
    }

    /// Who consented, as each saved turn's receipt names them: an owner of
    /// this vault as one, anyone else as a holder of its grant.
    pub(super) fn initiator_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<PromoteInitiator> {
        Ok(
            if crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &self.holder)? {
                PromoteInitiator::room_owner(self.holder)
            } else {
                PromoteInitiator::room_holder(self.holder)
            },
        )
    }
}

/// The refusal of someone who does not hold this vault's write grant.
pub(super) fn not_a_holder(session_ref: &str, actor: EntityId) -> Error {
    Error::OffRecord(OffRecordError::OffRecordPromoteUnauthenticated {
        session_ref: session_ref.to_owned(),
        actor_ref: actor.to_hex(),
    })
}

/// Whether this vault is shared and, in `txn`, `person`'s membership there
/// writes its content over the whole vault. Any refusal holds no grant.
fn writes_shared_content_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
) -> Result<bool> {
    let Some(creation) = vault.shared_vault_creation_in_txn(txn)? else {
        return Ok(false);
    };
    Ok(vault
        .authorize_shared_vault_write_in_txn(
            txn,
            creation.vault_id,
            &WriteActor::new(person, EdgeActorClass::Human),
            &SharedVaultWrite::Content(Scope::top()),
        )
        .is_ok())
}

/// Whether this vault's authority log minted `credential` as it shows
/// itself, holder key and bounds alike. A slip narrowed or handed on to
/// another key since shows other claims than its mint; and a proof verified
/// against a snapshot other than this vault's may name a live slip id, but
/// not the claims this vault minted under it.
fn minted_as_shown(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    credential: &VerifiedSlip,
) -> Result<bool> {
    let shown = credential.claims();
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    Ok(fold.slips.mints.get(&shown.slip_id).is_some_and(|mint| {
        // Verification trims the lifetime left to the moment it ran.
        let minted = &mint.action.claims;
        *minted
            == crate::authority::SlipClaims {
                ttl_secs: minted.ttl_secs,
                ..shown.clone()
            }
    }))
}

impl OffRecordSession<'_> {
    /// A holder's confirm of the save suggestions waiting in the room: their
    /// own save of the whole talk, as [`Self::save_talk_by`], which answers
    /// every suggestion waiting when it ran. `None`, saving nothing, when no
    /// suggestion waits; someone without the grant is refused either way.
    ///
    /// # Errors
    ///
    /// As [`Self::save_talk_by`].
    pub fn confirm_save_by(
        &self,
        holder: EntityId,
        credential: &VerifiedSlip,
    ) -> Result<Option<SavedTurns>> {
        self.save_talk_for_holder(holder, credential, true)
    }

    /// The owner's confirm, on their proof, as [`Self::confirm_save_by`].
    pub fn confirm_save_as(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
    ) -> Result<Option<SavedTurns>> {
        self.save_talk_for_owner(owner, true)
    }

    /// A holder declines the save suggestions waiting in the room: nothing is
    /// saved, the suggestions stop waiting, and the room hears a
    /// `save_declined` notice. `false`, changing nothing, when no suggestion
    /// waits; someone without the grant is refused either way.
    ///
    /// # Errors
    ///
    /// [`OffRecordError::OffRecordPromoteUnauthenticated`] when `credential`
    /// does not carry this vault's write grant for `holder`,
    /// [`OffRecordError::OffRecordNotInRoom`] when they are not in the room.
    pub fn decline_save_by(&self, holder: EntityId, credential: &VerifiedSlip) -> Result<bool> {
        self.require_in_room(holder)?;
        let grant = SaveGrant::claimed(holder, credential)
            .ok_or_else(|| not_a_holder(&self.session_ref, holder))?;
        self.decline_save(holder, |txn| {
            grant.require_in_txn(self.vault, txn, &self.session_ref)
        })
    }

    /// The owner's decline, on their proof, as [`Self::decline_save_by`].
    pub fn decline_save_as(&self, owner: &crate::consent::AuthenticatedOwner) -> Result<bool> {
        let actor = owner
            .revalidate_as_vault_owner_in_txn(self.vault, &self.vault.store.env.read_txn()?)?;
        self.require_in_room(actor)?;
        self.decline_save(actor, |txn| {
            owner
                .revalidate_as_vault_owner_in_txn(self.vault, txn)
                .map(drop)
        })
    }

    /// Puts the stretch on record for a holder of this vault's write grant,
    /// as [`Self::flip_on_record_as`] does for the owner: later turns are
    /// saved as they land, and every landing checks again that the holder
    /// still holds the grant on a live slip and is still in the room, in the
    /// membership they flipped in.
    ///
    /// # Errors
    ///
    /// [`OffRecordError::OffRecordPromoteUnauthenticated`] when `credential`
    /// does not carry this vault's write grant for `holder`,
    /// [`OffRecordError::OffRecordNotInRoom`] when they are not in the room.
    pub fn flip_on_record_by(&self, holder: EntityId, credential: &VerifiedSlip) -> Result<()> {
        self.require_in_room(holder)?;
        let grant = SaveGrant::claimed(holder, credential)
            .ok_or_else(|| not_a_holder(&self.session_ref, holder))?;
        let recheck = || {
            grant.require_in_txn(
                self.vault,
                &self.vault.store.env.read_txn()?,
                &self.session_ref,
            )
        };
        recheck()?;
        self.put_on_record(holder, SaverProof::Grant(grant.clone()), recheck)
    }

    /// Whether a save suggestion waits in the room.
    fn suggestion_waits(&self) -> Result<bool> {
        Ok(!super::registry::session_entry_state(&self.entry)?
            .record
            .suggestions
            .is_empty())
    }

    /// The whole-talk save of a holder on their slip; with `answering`, only
    /// while a suggestion waits.
    pub(super) fn save_talk_for_holder(
        &self,
        holder: EntityId,
        credential: &VerifiedSlip,
        answering: bool,
    ) -> Result<Option<SavedTurns>> {
        let room = self.require_in_room(holder)?;
        let grant = SaveGrant::claimed(holder, credential)
            .ok_or_else(|| not_a_holder(&self.session_ref, holder))?;
        let authority = |vault: &Vault, txn: &heed::RoTxn<'_>| {
            grant.require_in_txn(vault, txn, &self.session_ref)
        };
        // Refused the same way whether or not there is anything to save yet.
        let initiator = {
            let txn = self.vault.store.env.read_txn()?;
            authority(self.vault, &txn)?;
            grant.initiator_in_txn(self.vault, &txn)?
        };
        if answering && !self.suggestion_waits()? {
            return Ok(None);
        }
        self.save_talk(initiator, Some(room), authority).map(Some)
    }

    /// The owner's whole-talk save on their proof; with `answering`, only
    /// while a suggestion waits. In a room the owner must be on the roster,
    /// and only the turns their membership shows them are saved.
    pub(super) fn save_talk_for_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        answering: bool,
    ) -> Result<Option<SavedTurns>> {
        let room = match self.room()? {
            Some(_) => {
                let actor = owner.revalidate_as_vault_owner_in_txn(
                    self.vault,
                    &self.vault.store.env.read_txn()?,
                )?;
                Some(self.require_in_room(actor)?)
            }
            None => None,
        };
        let authority = |vault: &Vault, txn: &heed::RoTxn<'_>| {
            owner.revalidate_as_vault_owner_in_txn(vault, txn).map(drop)
        };
        // Refused the same way whether or not there is anything to save yet.
        authority(self.vault, &self.vault.store.env.read_txn()?)?;
        if answering && !self.suggestion_waits()? {
            return Ok(None);
        }
        self.save_talk(PromoteInitiator::owner(self.vault, owner)?, room, authority)
            .map(Some)
    }

    fn decline_save(
        &self,
        by: EntityId,
        authority: impl Fn(&heed::RoTxn<'_>) -> Result<()>,
    ) -> Result<bool> {
        // Refused the same way whether or not a suggestion waits.
        authority(&self.vault.store.env.read_txn()?)?;
        let mut state = self.recording_state()?;
        if state.record.suggestions.is_empty() {
            return Ok(false);
        }
        state.record.suggestions.clear();
        let hearing = Hearing::now(self.vault, state.record.room);
        post_notice(&mut state, OffRecordNoticeAct::SaveDeclined, by, hearing);
        self.entry.publish_state(&state);
        Ok(true)
    }
}
