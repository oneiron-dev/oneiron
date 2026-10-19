//! Who manages a stretch entered alone (WILL-PLAN L13 row 03, Engine ruling
//! 2026-10-19): the person or agent who entered it, on their own live
//! Grant, and the vault's live owner on their proof.
//!
//! A door that authenticated its caller enters through
//! [`OffRecordSessionVault::enter_as_creator`] or
//! [`OffRecordSessionVault::enter_anonymous_as_creator`], and the registry
//! keeps that creator on this one instance's entry, in RAM only, beside the
//! overlay: never in a side table, never in the record a caller reads. Every
//! later act binds through [`OffRecordSessionVault::bind_as_creator`], which
//! asks the entry it finds, so neither the session's name nor a broad read
//! Grant stands in for the creator, and a name taken again after close
//! carries none of the closed instance's authority. A stretch the owner
//! entered names no creator and stays the owner's alone.
//!
//! Each creator names their stretches in a space of their own (FIX 4597):
//! the registry keys a created stretch by an opaque handle minted at entry,
//! which the entering door answers as its `session_ref`, and keeps the
//! creator's name beside it. A later call or session header names it by
//! that handle, or by the name within its creator's own stretches. A name
//! another creator or the owner holds is no answer of "taken", and a handle
//! binds only for its creator, or for the owner on their proof.

use std::sync::Arc;

use crate::authority::VerifiedSlip;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, OffRecordError, Result};
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult, WitnessReceipt, WitnessTurn,
};

use super::registry::{OffRecordSessionEntry, session_entry_state, vet_off_record_session_ref};
use super::session::{OffRecordSession, OffRecordSessionVault};
use super::types::{OffRecordBackendClass, OffRecordMode, OffRecordSessionRecord};

/// The person or agent who entered a stretch alone through a door that
/// authenticated them: the actor and the class their credential binds.
/// It manages that stretch, as the vault's owner does, while it acts on a
/// live Grant that admits each act.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OffRecordCreator {
    pub actor: EntityId,
    pub class: EdgeActorClass,
}

impl<'vault> OffRecordSessionVault<'vault> {
    /// Enters a stretch alone, off record, for `creator`, whom the entering
    /// door authenticated, under `session_ref`, their own name for it. The
    /// handle's [`OffRecordSession::session_ref`] is the instance's opaque
    /// handle. Otherwise as [`Self::enter`].
    pub fn enter_as_creator(
        &self,
        session_ref: &str,
        backend: OffRecordBackendClass,
        creator: OffRecordCreator,
    ) -> Result<OffRecordSession<'vault>> {
        let entry = self.vault.enter_created_session_entry(
            session_ref,
            backend,
            OffRecordMode::OffRecord,
            creator,
        )?;
        self.created_handle(entry)
    }

    /// Enters an anonymous stretch alone for `creator`: it keeps nothing,
    /// and `creator` is the one caller its no-record exception serves
    /// (`Vault::off_record_session_is_anonymous_for`), as for
    /// [`Self::enter_anonymous_for`].
    pub fn enter_anonymous_as_creator(
        &self,
        session_ref: &str,
        backend: OffRecordBackendClass,
        creator: OffRecordCreator,
    ) -> Result<OffRecordSession<'vault>> {
        let entry = self.vault.enter_created_session_entry(
            session_ref,
            backend,
            OffRecordMode::Anonymous,
            creator,
        )?;
        self.created_handle(entry)
    }

    /// The handle of a created `entry`, under the key the registry minted.
    fn created_handle(
        &self,
        entry: Arc<OffRecordSessionEntry>,
    ) -> Result<OffRecordSession<'vault>> {
        let key = session_entry_state(&entry)?.record.session_ref.clone();
        Ok(self.handle(key, entry))
    }

    /// Binds the live stretch `session_ref` for `creator`, when this
    /// instance is one `creator` entered: `session_ref` is its handle, or
    /// the name `creator` gave it (FIX 4597).
    ///
    /// # Errors
    ///
    /// [`OffRecordError::OffRecordSessionNotFound`] for no stretch, the
    /// owner's, a room's and one someone else entered alike, asked before
    /// whether it closes, so a caller learns nothing of a stretch that is not
    /// theirs; [`OffRecordError::OffRecordSessionClosing`] for their own once
    /// its close began.
    pub fn bind_as_creator(
        &self,
        session_ref: &str,
        creator: OffRecordCreator,
    ) -> Result<OffRecordSession<'vault>> {
        vet_off_record_session_ref(session_ref)?;
        let not_found = || {
            Error::OffRecord(OffRecordError::OffRecordSessionNotFound {
                session_ref: session_ref.to_owned(),
            })
        };
        let key = self
            .vault
            .store
            .off_record_sessions
            .created_key(session_ref, creator.actor)
            .ok_or_else(not_found)?;
        let entry = self
            .vault
            .store
            .off_record_sessions
            .entry(&key)?
            .ok_or_else(not_found)?;
        if entry.creator != Some(creator) {
            return Err(not_found());
        }
        let state = session_entry_state(&entry)?;
        if state.record.closing || state.gone {
            return Err(Error::OffRecord(OffRecordError::OffRecordSessionClosing {
                session_ref: session_ref.to_owned(),
            }));
        }
        drop(state);
        Ok(self.handle(key, entry))
    }
}

impl OffRecordSession<'_> {
    /// Who entered this stretch through a creator's door; `None` for the
    /// owner's own, a room's, and one entered with no actor.
    #[must_use]
    pub fn creator(&self) -> Option<OffRecordCreator> {
        self.entry.creator
    }

    /// This instance's record now. A room's member reads it through
    /// [`Self::record_for`], which keeps to what their membership shows.
    ///
    /// # Errors
    ///
    /// [`OffRecordError::OffRecordSessionNotFound`] once it closed.
    pub fn record(&self) -> Result<OffRecordSessionRecord> {
        let state = session_entry_state(&self.entry)?;
        if state.gone {
            return Err(Error::OffRecord(OffRecordError::OffRecordSessionNotFound {
                session_ref: self.session_ref.clone(),
            }));
        }
        Ok(state.record.clone())
    }

    /// [`Memory::witness_into_session`] for this stretch's creator:
    /// `memory` acts as the creator this instance keeps, and `credential`,
    /// the Grant they presented, is checked live again first in each
    /// transaction the witness opens, so a witness queued behind its
    /// revocation writes nothing and reads nothing of the stretch.
    ///
    /// # Errors
    ///
    /// `FORBIDDEN` when `memory` acts as anyone else or `credential` is no
    /// longer live; otherwise as [`Memory::witness_into_session`].
    pub fn witness_as_creator(
        &self,
        memory: &Memory<'_>,
        turn: &WitnessTurn,
        summary: Option<&str>,
        credential: &VerifiedSlip,
    ) -> MemoryResult<WitnessReceipt> {
        let refused = || {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "only the live creator of this stretch speaks in it here".to_owned(),
                &["Call with the live credential of the person or agent who started it."],
            )
        };
        let speaker = OffRecordCreator {
            actor: memory.actor(),
            class: memory.actor_class(),
        };
        if self.creator() != Some(speaker) {
            return Err(refused());
        }
        let vault = self.vault;
        let admit = |txn: &heed::RoTxn<'_>| -> MemoryResult<()> {
            // A read that fails is that failure, not a refusal.
            if vault.capability_slip_is_live_in_txn(txn, credential)? {
                Ok(())
            } else {
                Err(refused())
            }
        };
        // The session witness that takes its door's own admission: the same
        // guest witness the owner's and a member's doors run, with no room
        // roster to read.
        memory.witness_into_session_for_run(self, turn, summary, None, admit, |_| Ok(()))
    }
}
