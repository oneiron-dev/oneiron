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
//! These rows are the engine's own, kept for the whole vault. The six reads
//! of them answer a grant narrowed to some projects with the rows its ceiling
//! holds ([`SubstrateReach`]; DEC-0005 #scope: "the answer is the ceiling";
//! FIX [SUBSTRATE-READS-NO-SCOPE-FILTER]). A row lies inside a narrowed
//! ceiling only by the projects it records: the learning cell and the
//! learning dials record their own, and the agent health cards and calls,
//! the failure evidence and the retrieval runs lie where the attempts they
//! name ran ([`SubstrateReach::holds_attempts_in_txn`]). A row that records
//! no project stays whole-vault-only, and so does every row for a ceiling
//! narrowed on an axis these rows record nothing for. The other reads (a
//! project's intake goal, a hosted import, the snapshot and world settings)
//! still ask a grant that reaches the whole vault: one narrowed to part of it
//! reads none of them (review of #6996).

use super::engine_controls::reaches_whole_vault;
use super::system_agent_grant::SystemAgent;
use super::{Scope, ScopeId, grant_scope};
use crate::attempt_queue::{AttemptId, AttemptQueue};
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
    /// A hosted import's progress (ARCH-0027 #hosted-import,
    /// `vault.imports.get`): the Steward `read` verb.
    Import,
}

impl SubstrateRead {
    /// The Steward verbs that admit the read: any one of them does.
    const fn grants(self) -> &'static [&'static str] {
        match self {
            Self::Evidence | Self::Goal | Self::Import => &[grant_scope::STEWARD_READ_VERB],
            Self::Dials => &grant_scope::ENGINE_CONTROLS_VERBS,
        }
    }
}

/// How far an admitted substrate read reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SubstrateReach {
    /// The vault's owner under its proof, or a grant that reaches the whole
    /// vault: every row.
    WholeVault,
    /// Grants narrowed to part of the vault, each by its own ceiling: a row
    /// lies inside when every project it records lies inside one of them.
    Within(Vec<Scope>),
}

impl SubstrateReach {
    /// Whether a row that records the projects `projects` lies inside this
    /// reach: always for the whole vault; inside narrowed ceilings only when
    /// it records at least one project and each lies inside a ceiling
    /// ([`project_inside`]). A row that records no project stays
    /// whole-vault-only.
    ///
    /// This is the reader's one judgement. The act rule (pass 26, A0 #8320)
    /// takes it over in one line: `true` and `false` here are its
    /// `Permitted::AnyMove` and `Permitted::Nothing` for one row.
    pub(crate) fn holds_row_of(&self, projects: &[EntityId]) -> bool {
        match self {
            Self::WholeVault => true,
            Self::Within(ceilings) => {
                !projects.is_empty()
                    && projects.iter().all(|project| {
                        ceilings
                            .iter()
                            .any(|ceiling| project_inside(ceiling, *project))
                    })
            }
        }
    }

    /// [`Self::holds_row_of`] for a row that records at most one project.
    pub(crate) fn holds_row_in(&self, project: Option<EntityId>) -> bool {
        self.holds_row_of(project.as_slice())
    }

    /// [`Self::holds_row_of`] for a row that lies where the attempts
    /// `attempts` ran: the projects their stored agent dispatches name
    /// ([`Vault::attempt_dispatch_project_in_txn`]). An attempt that names
    /// none, or a row that names no attempt, leaves the row
    /// whole-vault-only. The whole vault holds every row, unread.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub(crate) fn holds_attempts_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        attempts: &[AttemptId],
    ) -> Result<bool> {
        if *self == Self::WholeVault {
            return Ok(true);
        }
        let mut projects = Vec::with_capacity(attempts.len());
        for attempt in attempts {
            let Some(project) = vault.attempt_dispatch_project_in_txn(txn, *attempt)? else {
                return Ok(false);
            };
            projects.push(project);
        }
        Ok(self.holds_row_of(&projects))
    }
}

/// Whether `project` lies inside the narrowed ceiling `ceiling`: its
/// audience (project) axis names `project`, and no other axis but `verbs` is
/// narrowed, since these rows record no world, facet, band or sensitivity.
fn project_inside(ceiling: &Scope, project: EntityId) -> bool {
    *ceiling
        == Scope {
            audience: ceiling.audience.clone(),
            verbs: ceiling.verbs.clone(),
            ..Scope::top()
        }
        && ceiling.audience.contains(&ScopeId(project))
}

impl Vault {
    /// The project `attempt`'s stored agent dispatch names (every dispatch
    /// records the project it runs in); None for an attempt that is not
    /// stored, is no agent dispatch, or names none.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub(crate) fn attempt_dispatch_project_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt: AttemptId,
    ) -> Result<Option<EntityId>> {
        Ok(AttemptQueue::new(self)
            .get_in_txn(txn, attempt)?
            .as_ref()
            .and_then(crate::agent_dispatch::record_dispatch_input)
            .and_then(|input| input.project_ref))
    }

    /// How far `holder` reads the substrate read `read` through its grants:
    /// the whole vault when a live Steward grant naming one of the read's
    /// verbs reaches it ([`reaches_whole_vault`]), else the ceilings of the
    /// narrowed ones ([`Self::steward_grant_ceilings_with_verb_in`]); None
    /// when no such grant names `holder`. Who the holder is plays no part,
    /// the vault's owner included.
    pub(crate) fn substrate_read_reach_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        holder: EntityId,
        read: SubstrateRead,
    ) -> Result<Option<SubstrateReach>> {
        let mut ceilings = Vec::new();
        for verb in read.grants() {
            for ceiling in self.steward_grant_ceilings_with_verb_in(txn, holder, verb)? {
                if reaches_whole_vault(&ceiling) {
                    return Ok(Some(SubstrateReach::WholeVault));
                }
                ceilings.push(ceiling);
            }
        }
        Ok((!ceilings.is_empty()).then_some(SubstrateReach::Within(ceilings)))
    }

    /// Whether `holder` holds a live Steward grant that names a verb the
    /// substrate read `read` needs and reaches the whole vault
    /// ([`Self::substrate_read_reach_in_txn`]). The one rule of every holder
    /// and reader door of a read that does not filter by project: who the
    /// holder is plays no part, the vault's owner included.
    pub(crate) fn substrate_read_granted_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        holder: EntityId,
        read: SubstrateRead,
    ) -> Result<bool> {
        Ok(matches!(
            self.substrate_read_reach_in_txn(txn, holder, read)?,
            Some(SubstrateReach::WholeVault)
        ))
    }

    /// Whether the engine makes the substrate read `read` for `reader`, a
    /// reader the engine names itself (its own goal reads,
    /// [`Self::project_intake_goal_as_in_txn`]): the vault's human owner, or
    /// a holder of the grant ([`Self::substrate_read_granted_in_txn`]). Never
    /// the admission of a request's caller, whose actor id proves no owner:
    /// those go through [`admit_scoped_substrate_read`],
    /// [`admit_scoped_substrate_read_by`] and [`admit_substrate_read_by`].
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

    /// [`Self::substrate_read_reach_in_txn`] in a snapshot of its own.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub(crate) fn substrate_read_reach(
        &self,
        holder: EntityId,
        read: SubstrateRead,
    ) -> Result<Option<SubstrateReach>> {
        let txn = self.store.env.read_txn()?;
        self.substrate_read_reach_in_txn(&txn, holder, read)
    }
}

/// Admits `holder` to the substrate read `read` of verb `verb` as far as its
/// grants reach ([`Vault::substrate_read_reach_in_txn`]), or refuses a
/// holder no such grant names without saying what the rows hold. The vault's
/// owner, named here by its actor id, holds no such grant and is refused as
/// anyone is (review of #6999). The reader side of every scoped read with an
/// owner door.
pub(crate) fn admit_scoped_substrate_read_by(
    vault: &Vault,
    holder: WriteActor,
    verb: &str,
    read: SubstrateRead,
) -> MemoryResult<SubstrateReach> {
    vault
        .substrate_read_reach(holder.entity_ref(), read)
        .map_err(MemoryError::from)?
        .ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                &format!(
                    "{verb} reads for the vault owner under its proof, or for a holder of a Steward grant naming `{}`, as far as that grant reaches",
                    read.grants().join("` or `")
                ),
                &[
                    "Ask the owner for the grant; the Coach holds it by default.",
                    "The owner reads with its own verified, unattenuated credential.",
                ],
            )
        })
}

/// The refusal of a scoped substrate read's one row that lies outside the
/// reader's reach ([`SubstrateReach::holds_row_of`]): it says nothing of
/// what the row holds, or whether it exists.
pub(crate) fn outside_reach(verb: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        &format!("{verb}: this row lies outside the projects the reader's grant reaches"),
        &[
            "A grant narrowed to some projects reads the rows each of them records; a row that records no project reads only for a grant across the whole vault.",
        ],
    )
}

/// Admits the caller of a read that has no owner door of its own (the agent
/// health rows) to the substrate read `read` of verb `verb`: the embedded
/// owner under the proof its own handle carries ([`Memory::embedded_owner`])
/// across the whole vault, else as far as its grants reach
/// ([`admit_scoped_substrate_read_by`]). It refuses without saying what the
/// rows hold.
pub(crate) fn admit_scoped_substrate_read(
    memory: &Memory<'_>,
    verb: &str,
    read: SubstrateRead,
) -> MemoryResult<SubstrateReach> {
    if memory.embedded_owner(verb).is_ok() {
        return Ok(SubstrateReach::WholeVault);
    }
    let holder = WriteActor::new(memory.actor(), memory.actor_class());
    admit_scoped_substrate_read_by(memory.vault(), holder, verb, read)
}

/// Admits `holder` to the substrate read `read` of verb `verb` in `vault` by
/// its grant alone ([`Vault::substrate_read_granted_in_txn`]), or refuses it
/// without saying what the rows hold. The reader side of every read with an
/// owner door that does not filter by project: the vault's owner, named here
/// by its actor id, holds no such grant and is refused as anyone is (review
/// of #6999).
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
