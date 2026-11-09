//! Engine substrate reads behind a grant (untangle 6.6c; owner 9 Nov 22:47,
//! "every substrate read and control is a public verb behind a grant").
//!
//! The agent health, learning, failure-evidence and retrieval-run reads
//! answer the vault's human owner, or a holder of a live Steward grant that
//! names `read`; the learning dials read answers the owner, or a holder of
//! `engine.controls`. Each is checked at each read, so a narrowed or revoked
//! grant reads nothing from its next call on. The Coach holds both by
//! default (6.6a); the owner can give them to any agent.

use super::grant_scope;
use super::system_agent_grant::SystemAgent;
use crate::error::Result;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::{EdgeActorClass, Vault, WriteActor};

/// Which grant a substrate read needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubstrateRead {
    /// Rows the engine keeps about agents and their work: the Steward
    /// `read` verb.
    Evidence,
    /// The learning dials, the read side of `engine.controls`.
    Dials,
    /// A project's intake goal (untangle 6.6d, F4): the Steward `read` verb.
    Goal,
}

impl SubstrateRead {
    const fn grant(self) -> &'static str {
        match self {
            Self::Evidence | Self::Goal => grant_scope::STEWARD_READ_VERB,
            Self::Dials => grant_scope::ENGINE_CONTROLS_VERB,
        }
    }
}

impl Vault {
    /// Whether `reader` may make the substrate read `read` now: the vault's
    /// human owner, or the holder of a live Steward grant naming the verb
    /// the read needs ([`Self::steward_grant_with_verb_in`]).
    pub(crate) fn substrate_read_allowed_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        reader: WriteActor,
        read: SubstrateRead,
    ) -> Result<bool> {
        if reader.actor_class() == EdgeActorClass::Human
            && self.verify_owner_write_actor_in_txn(txn, &reader).is_ok()
        {
            return Ok(true);
        }
        Ok(self
            .steward_grant_with_verb_in(txn, reader.entity_ref(), read.grant())?
            .is_some())
    }

    /// Whether the Coach's own review and trend jobs read now (untangle
    /// 6.6c): through its grant, as its read key does (6.6a, the X04 guard).
    /// Before the first mint the manifest rows decide, as before; after it,
    /// only while its grant names `read` and its MACHINE binding is live. A
    /// Coach narrowed off `read` reviews nothing.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub(crate) fn coach_reads_through_grant(&self) -> Result<bool> {
        let coach = SystemAgent::Coach.actor_id()?;
        let txn = self.store.env.read_txn()?;
        self.system_agent_reads_live_in(&txn, coach)
    }

    /// [`Self::substrate_read_allowed_in_txn`] in a snapshot of its own.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub(crate) fn substrate_read_allowed(
        &self,
        reader: WriteActor,
        read: SubstrateRead,
    ) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        self.substrate_read_allowed_in_txn(&txn, reader, read)
    }
}

/// Admits `memory`'s caller to the substrate read `read` of verb `verb`, or
/// refuses it without saying what the rows hold.
pub(crate) fn admit_substrate_read(
    memory: &Memory<'_>,
    verb: &str,
    read: SubstrateRead,
) -> MemoryResult<()> {
    let reader = WriteActor::new(memory.actor(), memory.actor_class());
    admit_substrate_read_by(memory.vault(), reader, verb, read)
}

/// Admits `reader` to the substrate read `read` of verb `verb` in `vault`,
/// or refuses it without saying what the rows hold.
pub(crate) fn admit_substrate_read_by(
    vault: &Vault,
    reader: WriteActor,
    verb: &str,
    read: SubstrateRead,
) -> MemoryResult<()> {
    if vault
        .substrate_read_allowed(reader, read)
        .map_err(MemoryError::from)?
    {
        return Ok(());
    }
    Err(MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        &format!(
            "{verb} reads for the vault owner, or for a holder of a Steward grant naming `{}`",
            read.grant()
        ),
        &["Ask the owner for the grant; the Coach holds it by default."],
    ))
}
