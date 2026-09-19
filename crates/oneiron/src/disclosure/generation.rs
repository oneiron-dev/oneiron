//! Live generation barrier. Hosts keep one session per generation audience.
//!
//! A roster update invalidates every snapshot, including already assembled
//! transcript turns. Output must cross `publish`; stale output is refused,
//! not released with a prompt asking the model to keep it private.

use super::DisclosureContext;
use crate::error::{Error, GateError, Result};
use crate::interlocutor::InterlocutorSet;
use crate::{EntityId, Vault};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct State {
    id: EntityId,
    revision: u64,
    context: DisclosureContext,
}

/// Session-owned state, never a process-global registry.
#[derive(Debug, Clone)]
pub struct DisclosureSession {
    state: Arc<Mutex<State>>,
}

#[derive(Debug, Clone)]
pub(super) struct GenerationStamp {
    state: Arc<Mutex<State>>,
    revision: u64,
    observed: Arc<Mutex<BTreeSet<EntityId>>>,
}

/// An in-flight generation's non-forgeable audience snapshot.
#[derive(Debug, Clone)]
pub struct DisclosureGeneration {
    context: DisclosureContext,
    stamp: GenerationStamp,
}

fn invalidated() -> Error {
    Error::Gate(GateError::DisclosureClampViolation(
        "generation audience changed; abort and reassemble",
    ))
}

impl DisclosureSession {
    pub fn new(vault: &Vault, roster: InterlocutorSet) -> Result<Self> {
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                id: EntityId::now(),
                revision: 0,
                context: DisclosureContext::resolve(vault, roster)?,
            })),
        })
    }

    /// Call on every observed arrival, attribution change, clearance change,
    /// or tentative departure. Unknown arrivals belong in the roster now;
    /// omitted parties stay until `confirm_roster` verifies owner intent.
    /// Errors invalidate old work too.
    pub fn update_roster(&self, vault: &Vault, roster: InterlocutorSet) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| invalidated())?;
        // Unconfirmed absences do not widen. Keep prior parties until an
        // exact owner-confirmed roster change removes them.
        let mut parties: Vec<_> = roster.non_owner().cloned().collect();
        for prior in state.context.interlocutors().non_owner() {
            if !parties.contains(prior) {
                parties.push(prior.clone());
            }
        }
        let roster = if roster.supervised() {
            InterlocutorSet::with_session_owner(parties)
        } else {
            InterlocutorSet::without_owner(parties)
        };
        state.revision = state.revision.checked_add(1).ok_or_else(invalidated)?;
        // A failed resolution must never leave an old private context reusable.
        state.context = DisclosureContext::resolve(
            vault,
            InterlocutorSet::without_owner(vec![crate::interlocutor::Interlocutor::unknown(
                "unresolved roster",
                false,
            )]),
        )?;
        state.context = DisclosureContext::resolve(vault, roster)?;
        Ok(())
    }

    /// Bytes for an owner-confirmed roster replacement, including this
    /// session and revision. A stale confirmation cannot remove a new arrival.
    pub fn roster_change_transcript(
        &self,
        roster: &InterlocutorSet,
        authorization: &super::DisclosureScopeAuthorization,
    ) -> Result<Vec<u8>> {
        let state = self.state.lock().map_err(|_| invalidated())?;
        authorization.roster_transcript(state.id, state.revision, roster)
    }

    /// A signature over this exact session/revision/roster is a deterministic
    /// owner confirmation. Silence, voice-only matches and inferred identity
    /// cannot take this widening door.
    pub fn confirm_roster(
        &self,
        vault: &Vault,
        roster: InterlocutorSet,
        authorization: &super::DisclosureScopeAuthorization,
    ) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| invalidated())?;
        let transcript = authorization.roster_transcript(state.id, state.revision, &roster)?;
        let mut txn = vault.store.env.write_txn()?;
        authorization.consume_transcript(vault, &mut txn, transcript)?;
        let context = DisclosureContext::resolve(vault, roster)?;
        let revision = state.revision.checked_add(1).ok_or_else(invalidated)?;
        txn.commit()?;
        state.revision = revision;
        state.context = context;
        Ok(())
    }

    pub fn begin_generation(&self) -> Result<DisclosureGeneration> {
        let state = self.state.lock().map_err(|_| invalidated())?;
        let stamp = GenerationStamp {
            state: Arc::clone(&self.state),
            revision: state.revision,
            observed: Arc::new(Mutex::new(BTreeSet::new())),
        };
        let mut context = state.context.clone();
        context.generation = Some(stamp.clone());
        Ok(DisclosureGeneration { context, stamp })
    }
}

impl GenerationStamp {
    pub(super) fn observe(&self, id: EntityId) -> Result<()> {
        self.observed.lock().map_err(|_| invalidated())?.insert(id);
        Ok(())
    }

    pub(super) fn ensure_current(&self) -> Result<()> {
        let state = self.state.lock().map_err(|_| invalidated())?;
        if state.revision != self.revision {
            return Err(invalidated());
        }
        Ok(())
    }
}

impl DisclosureGeneration {
    /// Use this exact snapshot for both memory and transcript assembly.
    pub fn context(&self) -> &DisclosureContext {
        &self.context
    }

    /// Redacts a transcript to visible record ids before the host loads text.
    /// Ranking, recency and being a prior turn grant no exception.
    pub fn transcript_records(&self, vault: &Vault, records: &[EntityId]) -> Result<Vec<EntityId>> {
        self.stamp.ensure_current()?;
        let txn = vault.store.env.read_txn()?;
        let mut admitted = Vec::new();
        for id in records {
            let Some(raw) = vault.store.entities.get(&txn, id.as_bytes())? else {
                continue;
            };
            let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
                return Err(Error::CorruptedIndex("transcript entity header"));
            };
            if self
                .context
                .admits(&vault.store, &txn, id, header.entity_type, None)?
            {
                admitted.push(*id);
            }
        }
        self.stamp.ensure_current()?;
        Ok(admitted)
    }

    /// Release one output chunk while holding the audience barrier. An update
    /// either happens before this check (refusal) or after the release. Never
    /// call back into the vault or session from the callback. A stale generation must be
    /// aborted; the host must discard its buffered output and reassemble.
    pub fn publish<T>(&self, vault: &Vault, release: impl FnOnce() -> T) -> Result<T> {
        let state = self.stamp.state.lock().map_err(|_| invalidated())?;
        if state.revision != self.stamp.revision {
            return Err(invalidated());
        }
        // Serialize the short release with clearance revocations and record
        // restamps as well as roster changes. This read-only write txn aborts
        // on drop. The callback must not reenter the vault or session.
        let txn = vault.store.env.write_txn()?;
        if self.context.live_ceiling(&vault.store, &txn)? != self.context.scope {
            return Err(invalidated());
        }
        let mut context = self.context.clone();
        context.generation = None;
        let observed = self.stamp.observed.lock().map_err(|_| invalidated())?;
        for id in observed.iter() {
            let Some(raw) = vault.store.entities.get(&txn, id.as_bytes())? else {
                return Err(invalidated());
            };
            let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
                return Err(invalidated());
            };
            if !context.admits(&vault.store, &txn, id, header.entity_type, None)? {
                return Err(invalidated());
            }
        }
        Ok(release())
    }
}
