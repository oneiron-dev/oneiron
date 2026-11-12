//! Engine substrate reads behind a grant (untangle 6.6c; owner 9 Nov 22:47,
//! "every substrate read and control is a public verb behind a grant").
//!
//! The agent health, learning, failure-evidence and retrieval-run reads
//! answer the vault's human owner, or a holder of a live Steward grant that
//! names `read`; the learning dials read answers the owner, or a holder of
//! any `engine.controls` class. Each is checked at each read, so a narrowed or revoked
//! grant reads nothing from its next call on. The Coach holds both by
//! default (6.6a); the owner can give them to any agent.
//!
//! The owner reads under its proof: a server takes it from the request and
//! calls the read's owner door, and an embedded handle carries its own
//! ([`Memory::embedded_owner`]). A caller's actor id is never that proof
//! (review of #6999). The holder and reader doors admit by the grant alone,
//! so an owner credential the owner doors refuse, attenuated or handed to
//! another key, reads none of these rows through them.
//!
//! These rows are the engine's own, kept for the whole vault, and no reader
//! here filters them by project, world, band or sensitivity. So the grant
//! must reach the whole vault: one narrowed to part of it (a vault or holder
//! override row) reads none of them (review of #6996).

use super::grant_scope;
use super::system_agent_grant::SystemAgent;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::{EdgeActorClass, Vault, WriteActor};

/// Which grant a substrate read needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubstrateRead {
    /// Rows the engine keeps about agents and their work: the Steward
    /// `read` verb.
    Evidence,
    /// The learning dials and the snapshot bounds (6.6f), the read side of
    /// `engine.controls`: any of its four classes reads them, since a read
    /// changes nothing.
    Dials,
    /// A project's intake goal (untangle 6.6d, F4): the Steward `read` verb.
    Goal,
}

impl SubstrateRead {
    /// The Steward verbs that admit the read: any one of them does.
    const fn grants(self) -> &'static [&'static str] {
        match self {
            Self::Evidence | Self::Goal => &[grant_scope::STEWARD_READ_VERB],
            Self::Dials => &grant_scope::ENGINE_CONTROLS_VERBS,
        }
    }
}

impl Vault {
    /// Whether `holder` holds a live Steward grant that names a verb the
    /// substrate read `read` needs and reaches the whole vault
    /// ([`Self::whole_vault_steward_grant_with_verb_in`]). The one rule of
    /// every holder and reader door: who the holder is plays no part, the
    /// vault's owner included.
    pub(crate) fn substrate_read_granted_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        holder: EntityId,
        read: SubstrateRead,
    ) -> Result<bool> {
        for verb in read.grants() {
            if self
                .whole_vault_steward_grant_with_verb_in(txn, holder, verb)?
                .is_some()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether the engine makes the substrate read `read` for `reader`, a
    /// reader the engine names itself (its own goal reads,
    /// [`Self::project_intake_goal_as_in_txn`]): the vault's human owner, or
    /// a holder of the grant ([`Self::substrate_read_granted_in_txn`]). Never
    /// the admission of a request's caller, whose actor id proves no owner:
    /// those go through [`admit_substrate_read`] and
    /// [`admit_substrate_read_by`].
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
        self.substrate_read_granted_in_txn(txn, reader.entity_ref(), read)
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

    /// [`Self::substrate_read_granted_in_txn`] in a snapshot of its own.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub(crate) fn substrate_read_granted(
        &self,
        holder: EntityId,
        read: SubstrateRead,
    ) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        self.substrate_read_granted_in_txn(&txn, holder, read)
    }
}

/// Admits the caller of a read that has no owner door of its own (the agent
/// health rows) to the substrate read `read` of verb `verb`: the embedded
/// owner under the proof its own handle carries
/// ([`Memory::embedded_owner`]), else as a holder
/// ([`admit_substrate_read_by`]). It refuses without saying what the rows
/// hold.
pub(crate) fn admit_substrate_read(
    memory: &Memory<'_>,
    verb: &str,
    read: SubstrateRead,
) -> MemoryResult<()> {
    if memory.embedded_owner(verb).is_ok() {
        return Ok(());
    }
    let holder = WriteActor::new(memory.actor(), memory.actor_class());
    admit_substrate_read_by(memory.vault(), holder, verb, read)
}

/// Admits `holder` to the substrate read `read` of verb `verb` in `vault` by
/// its grant alone ([`Vault::substrate_read_granted_in_txn`]), or refuses it
/// without saying what the rows hold. The reader side of every read with an
/// owner door: the vault's owner, named here by its actor id, holds no such
/// grant and is refused as anyone is (review of #6999).
pub(crate) fn admit_substrate_read_by(
    vault: &Vault,
    holder: WriteActor,
    verb: &str,
    read: SubstrateRead,
) -> MemoryResult<()> {
    if vault
        .substrate_read_granted(holder.entity_ref(), read)
        .map_err(MemoryError::from)?
    {
        return Ok(());
    }
    Err(MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        &format!(
            "{verb} reads for the vault owner under its proof, or for a holder of a Steward grant naming `{}` that reaches the whole vault",
            read.grants().join("` or `")
        ),
        &[
            "Ask the owner for the grant; the Coach holds it by default.",
            "A grant narrowed to some projects, worlds, bands or a sensitivity ceiling does not read these vault-wide rows.",
            "The owner reads with its own verified, unattenuated credential.",
        ],
    ))
}

#[cfg(oneiron_test_support)]
mod fixture {
    use std::collections::BTreeSet;

    use super::super::{
        FederationGrant, FederationGrantPreset, FederationGrantRole, ScopeAxis, ScopeId,
        encode_federation_grant_body,
    };
    use crate::batch::{BatchOp, apply_ops};
    use crate::entity_id::EntityId;
    use crate::error::Result;
    use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
    use crate::{TimeRange, Vault};

    impl Vault {
        /// TEST-ONLY: stands a Steward grant on this vault's root for
        /// `holder` with `verbs`, its audience narrowed to the one project
        /// `project`, as a holder override row leaves a member's grant.
        pub(crate) fn stand_project_steward_grant_for_test(
            &self,
            holder: EntityId,
            verbs: &[&str],
            project: EntityId,
        ) -> Result<EntityId> {
            self.with_write_txn_grouped(|txn| {
                let mut grant = FederationGrant::new(
                    self.steward_root_scope_in_txn(txn)?,
                    holder,
                    FederationGrantRole::Steward,
                    FederationGrantPreset::Steward,
                );
                grant.authority_scope.verbs =
                    ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
                grant.authority_scope.audience =
                    ScopeAxis::Some(BTreeSet::from([ScopeId(project)]));
                let id = EntityId::now();
                let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
                apply_ops(
                    &self.store,
                    &self.config,
                    &self.analyzer,
                    txn,
                    vec![BatchOp::Put {
                        id,
                        entity_type: ENTITY_TYPE_FEDERATION_GRANT,
                        occurred: TimeRange {
                            start: now,
                            end: now,
                        },
                        learned_at: now,
                        row_version: None,
                        data: encode_federation_grant_body(&grant)?,
                        allow_maintenance: true,
                        allow_reserved_predicate: false,
                        hub_sync_imported: false,
                    }],
                    self.text_index_trusted
                        .load(std::sync::atomic::Ordering::Acquire),
                    false,
                    true,
                )?;
                Ok(id)
            })
        }
    }
}
