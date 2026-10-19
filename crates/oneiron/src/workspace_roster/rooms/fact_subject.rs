//! Who a participation fact's key names (FIX 4228): a live subject, or no
//! one once that subject was erased.
//!
//! A fact's subject sits in its key, not its value, so an erase cannot take
//! it out of the value alone. The erased subject's fact moves to a key of
//! its own: its place and cause stay, and in the subject's slot sits the
//! opaque digest of the whole live key. Each erased fact keeps its own row,
//! its time, its receipt and its cause, and names no one; no live subject or
//! Ready lookup ever reads it.

use super::participation::{FACTS, FactKey};
use crate::error::Result;
use crate::workspace_roster::JoinSubject;
use crate::workspace_roster::join_receipt::names_no_actor;
use crate::{EntityId, Vault};

/// What an actor's erase does with the participation facts whose key names
/// it as their subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParticipationKeyErase {
    /// The fact moves to its opaque historical key and keeps its value.
    OpaqueHistoricalKey,
    /// The fact goes.
    Delete,
}

/// A fact records an event that happened, so it stays under a key that
/// names no one rather than going (FIX 4228; a call).
pub const ACTOR_ERASE_PARTICIPATION_KEY: ParticipationKeyErase =
    ParticipationKeyErase::OpaqueHistoricalKey;

/// The domain of an erased fact's opaque subject digest (FIX 4228).
const ACTOR_ERASE_PARTICIPATION_KEY_DOMAIN: &str = "oneiron.rooms.participation.actor-erased.v1";

/// The subject-kind byte of an erased fact's key: below a person's and an
/// agent's, so a place's erased facts sort first.
const ERASED_KIND: u8 = 0;

/// Who a fact's key names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FactSubject {
    /// The subject that took part.
    Live(JoinSubject),
    /// No one: the opaque digest of the fact's live key.
    Erased([u8; 16]),
}

impl FactSubject {
    /// The kind byte the key spells.
    pub(super) const fn kind(&self) -> u8 {
        match self {
            Self::Live(JoinSubject::Person(_)) => 1,
            Self::Live(JoinSubject::Agent(_)) => 2,
            Self::Erased(_) => ERASED_KIND,
        }
    }

    /// The sixteen bytes the key spells after the kind.
    pub(super) fn key_id(&self) -> [u8; 16] {
        match self {
            Self::Live(subject) => *subject.id().as_bytes(),
            Self::Erased(digest) => *digest,
        }
    }

    /// The subject a key spells as `kind` and `id`; `None` for a kind no key
    /// spells, or a live id that does not parse.
    pub(super) fn decode(kind: u8, id: [u8; 16]) -> Option<Self> {
        Some(match kind {
            1 => Self::Live(JoinSubject::Person(EntityId::from_bytes(id).ok()?)),
            2 => Self::Live(JoinSubject::Agent(EntityId::from_bytes(id).ok()?)),
            ERASED_KIND => Self::Erased(id),
            _ => return None,
        })
    }
}

impl FactKey {
    /// This live fact's key once its subject is erased (FIX 4228): its place
    /// and cause, and the opaque digest of the whole live key. An erased key
    /// stays as it is.
    pub(super) fn erased(&self) -> Self {
        if matches!(self.subject, FactSubject::Erased(_)) {
            return *self;
        }
        let mut live = Vec::new();
        crate::side_table::SideKey::encode_into(self, &mut live);
        let mut hasher = blake3::Hasher::new();
        hasher.update(ACTOR_ERASE_PARTICIPATION_KEY_DOMAIN.as_bytes());
        hasher.update(&live);
        let mut digest = [0; 16];
        digest.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        Self {
            subject: FactSubject::Erased(digest),
            ..*self
        }
    }

    /// Whether this key names `actor` as its live subject.
    pub(super) fn names(&self, actor: EntityId) -> bool {
        matches!(self.subject, FactSubject::Live(subject) if subject.id() == actor)
    }
}

/// Moves every fact whose key names `actor` as its subject to the key that
/// names no one, or deletes it, as [`ACTOR_ERASE_PARTICIPATION_KEY`] says.
pub(super) fn move_subject_facts_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    facts: Vec<(FactKey, super::participation::Fact)>,
) -> Result<()> {
    for (key, fact) in facts {
        if !key.names(actor) {
            continue;
        }
        FACTS.delete(&vault.store, wtxn, &key)?;
        if ACTOR_ERASE_PARTICIPATION_KEY == ParticipationKeyErase::OpaqueHistoricalKey {
            let erased = key.erased();
            if !FACTS.contains(&vault.store, wtxn, &erased)? {
                FACTS.put(&vault.store, wtxn, &erased, &fact)?;
            }
        }
    }
    Ok(())
}

impl Vault {
    /// Erasing `actor` from the participation facts (FIX 4228): each fact
    /// whose key names it as its subject keeps its place, its cause, its
    /// time and its receipt under the key that names no one, when
    /// [`ACTOR_ERASE_PARTICIPATION_KEY`] says so. One-way, in the erase's own
    /// transaction. An id whose entity is no actor scans nothing.
    ///
    /// # Errors
    ///
    /// Storage errors, or a fact row that cannot be read.
    pub(crate) fn erase_participation_actor_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        if names_no_actor(self, wtxn, actor)? {
            return Ok(());
        }
        let facts = FACTS.scan(&self.store, wtxn)?;
        move_subject_facts_in_txn(self, wtxn, *actor, facts)
    }
}
