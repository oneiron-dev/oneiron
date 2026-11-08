//! One actor-bound batch effect set, derived from normalized local operations.
//! Trusted replay keeps using the ordinary batch path and is never re-gated.

use super::*;
use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::batch::shared_vault_write::SharedVaultWrite;
use crate::claim::ClaimRecordScope;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::write_envelope::WriteActor;
use oneiron_authority::federation::Scope;
use std::collections::{BTreeMap, BTreeSet};

/// The semantic change to one content owner; indexes and receipts follow its
/// transaction, rather than needing their own independent membership grants.
#[derive(Debug)]
enum RecordTransition {
    Create {
        id: EntityId,
        to: Scope,
    },
    Replace {
        id: EntityId,
        from: Scope,
        to: Scope,
    },
    Remove {
        id: EntityId,
        from: Scope,
    },
    Derived {
        id: EntityId,
        from: Scope,
        to: Scope,
    },
}

struct EffectEntry {
    old: Option<Scope>,
    local_put: bool,
    derived_parent: bool,
}

/// No facade supplies a list of changed parents: the batch's own ChildOf
/// overlay and candidate computation determine them before any operation runs.
pub(super) struct ContentWriteSet {
    vault_id: u64,
    entries: BTreeMap<EntityId, EffectEntry>,
}

impl ContentWriteSet {
    pub(super) fn before(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        actor: &WriteActor,
        ops: &[BatchOp],
    ) -> Result<Option<Self>> {
        let Some(creation) = vault.shared_vault_creation_in_txn(txn)? else {
            return Ok(None);
        };
        let mut ids = BTreeSet::new();
        let mut local_puts = BTreeSet::new();
        for op in ops {
            match op {
                BatchOp::Put {
                    id,
                    allow_maintenance,
                    allow_reserved_predicate,
                    ..
                } => {
                    if *allow_maintenance && *allow_reserved_predicate {
                        return Err(Error::InvalidClaimBody(
                            "replicated Put is not an actor content write",
                        ));
                    }
                    ids.insert(*id);
                    local_puts.insert(*id);
                }
                BatchOp::ClaimCandidate { id, .. }
                | BatchOp::Delete { id }
                | BatchOp::Text { id, .. }
                | BatchOp::Phonetic { id, .. }
                | BatchOp::Vector { id, .. }
                | BatchOp::MediaVector { id, .. } => {
                    ids.insert(*id);
                }
                BatchOp::Edge { src, .. }
                | BatchOp::PublicEdgeWithCreatedAt { src, .. }
                | BatchOp::EdgeWithCreatedAt { src, .. }
                | BatchOp::SetEdgeWeight { src, .. }
                | BatchOp::SetEdgeVad { src, .. }
                | BatchOp::DeleteEdge { src, .. } => {
                    ids.insert(*src);
                }
                BatchOp::CommitmentGapDecay { ids: affected, .. } => {
                    ids.extend(affected.iter().copied());
                }
                BatchOp::ReconcileLexicalQueryHints { source, .. } => {
                    ids.insert(*source);
                }
            }
        }
        let overlay = ChildOfBatchOverlay::from_ops(ops);
        let parents = habit_streak_recompute_candidates(&vault.store, txn, ops, &overlay)?;
        let mut derived_parents = BTreeSet::new();
        for parent in parents {
            if stored_task_role(&vault.store, txn, &parent)?
                == Some(crate::write_envelope::task_body::TaskRole::Habit)
            {
                derived_parents.insert(parent);
                ids.insert(parent);
            }
        }
        Self::capture(
            vault,
            txn,
            actor,
            creation.vault_id,
            ids,
            local_puts,
            derived_parents,
        )
    }

    /// A routed input still meets the original local CLAIM's create-position
    /// check. For these validated comm claims, the normal blob scope resolver
    /// uses this same ClaimBody scope; no temporary raw CLAIM is stored.
    pub(super) fn admit_routed_inputs(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        actor: &WriteActor,
        bodies: &[(EntityId, crate::claim::ClaimBody)],
    ) -> Result<()> {
        for (_, body) in bodies {
            vault.authorize_shared_vault_write_in_txn(
                txn,
                self.vault_id,
                actor,
                &SharedVaultWrite::Content(body.record_scope("read")),
            )?;
        }
        Ok(())
    }

    /// Exact head effects, captured before the projector changes any of them.
    pub(super) fn before_heads(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        actor: &WriteActor,
        ids: &[EntityId],
        local_puts: &[EntityId],
    ) -> Result<Option<Self>> {
        let Some(creation) = vault.shared_vault_creation_in_txn(txn)? else {
            return Ok(None);
        };
        Self::capture(
            vault,
            txn,
            actor,
            creation.vault_id,
            ids.iter().copied().collect(),
            local_puts.iter().copied().collect(),
            BTreeSet::new(),
        )
    }

    fn capture(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        actor: &WriteActor,
        vault_id: u64,
        ids: BTreeSet<EntityId>,
        local_puts: BTreeSet<EntityId>,
        derived_parents: BTreeSet<EntityId>,
    ) -> Result<Option<Self>> {
        let mut entries = BTreeMap::new();
        for id in ids {
            let old = if vault.get_raw_in(txn, &id)?.is_some() {
                let old = vault.content_scope_in_txn(txn, id)?;
                vault.authorize_shared_vault_write_in_txn(
                    txn,
                    vault_id,
                    actor,
                    &SharedVaultWrite::Content(old.clone()),
                )?;
                Some(old)
            } else {
                None
            };
            entries.insert(
                id,
                EffectEntry {
                    old,
                    local_put: local_puts.contains(&id),
                    derived_parent: derived_parents.contains(&id),
                },
            );
        }
        Ok(Some(Self {
            vault_id: vault_id,
            entries,
        }))
    }

    pub(super) fn after(
        self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        actor: &WriteActor,
    ) -> Result<()> {
        for (id, effect) in self.entries {
            if effect.local_put
                && let Some(raw) = vault.get_raw_in(txn, &id)?
            {
                let header = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("actor content header"))?;
                // Only an actor's local Put gets a final-body stamp. Opaque
                // replay never enters this adapter and stays unstamped, and
                // so does a replicated row an actor re-puts (FIX 11925).
                let put = if effect.old.is_some() {
                    crate::batch::row_put::RowPut::LocalReput
                } else {
                    crate::batch::row_put::RowPut::Birth
                };
                vault.store.scope_stamps.stamp_put(
                    &vault.store,
                    txn,
                    id,
                    header.entity_type,
                    &raw[ENTITY_METADATA_HEADER_LEN..],
                    put,
                )?;
            }
            let new = vault
                .get_raw_in(txn, &id)?
                .map(|_| vault.content_scope_in_txn(txn, id))
                .transpose()?;
            let transition = match (effect.old, new) {
                (None, Some(to)) => RecordTransition::Create { id, to },
                (Some(from), Some(to)) if effect.derived_parent => {
                    RecordTransition::Derived { id, from, to }
                }
                (Some(from), Some(to)) => RecordTransition::Replace { id, from, to },
                (Some(from), None) => RecordTransition::Remove { id, from },
                (None, None) => continue,
            };
            match transition {
                RecordTransition::Create { id, to } => {
                    let _ = id;
                    vault.authorize_shared_vault_write_in_txn(
                        txn,
                        self.vault_id,
                        actor,
                        &SharedVaultWrite::Content(to),
                    )?;
                }
                RecordTransition::Replace { id, from, to }
                | RecordTransition::Derived { id, from, to } => {
                    let _ = (id, from); // The old position was checked before applying.
                    vault.authorize_shared_vault_write_in_txn(
                        txn,
                        self.vault_id,
                        actor,
                        &SharedVaultWrite::Content(to),
                    )?;
                }
                RecordTransition::Remove { id, from } => {
                    let _ = (id, from); // The old position was checked before applying.
                }
            }
        }
        Ok(())
    }
}

/// Only local actor-bound programs use this adapter. Parent effects come from
/// the same batch overlay the reducer consumes; all positions are checked in
/// the caller's committing writer, and a denied effect rolls back the batch.
pub(crate) fn apply_actor_ops(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &WriteActor,
    lane: crate::core_write::CoreWriteLaneRef<'_>,
    ops: Vec<BatchOp>,
    text_index_trusted: bool,
    gate_mode: ApplyOpsGateMode,
    origin: BaseWriteOrigin<'_>,
) -> Result<()> {
    let gated = super::builder::reference_read::admit_lane_before_staging(vault, lane, txn, &ops)?;
    apply_actor_ops_admitted(
        vault,
        txn,
        actor,
        ops,
        text_index_trusted,
        gate_mode,
        origin,
    )?;
    if let crate::core_write::CoreWriteLaneRef::Read(reader) = lane {
        super::builder::reference_read::check_staged_references(vault, txn, reader, &gated)?;
    }
    Ok(())
}

pub(super) fn apply_actor_ops_admitted(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &WriteActor,
    ops: Vec<BatchOp>,
    text_index_trusted: bool,
    gate_mode: ApplyOpsGateMode,
    origin: BaseWriteOrigin<'_>,
) -> Result<()> {
    let admitted = match origin {
        BaseWriteOrigin::Ordinary => true,
        BaseWriteOrigin::PromoteReplay(grant) => grant.selected_saver() == Some(*actor),
    };
    if !admitted {
        return Err(Error::InvariantViolation(
            "actor content cannot be replay origin",
        ));
    }
    let effects = ContentWriteSet::before(vault, txn, actor, &ops)?;
    apply_ops_with_origin(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        txn,
        ops,
        text_index_trusted,
        gate_mode,
        origin,
    )?;
    if let Some(effects) = effects {
        effects.after(vault, txn, actor)?;
    }
    Ok(())
}
