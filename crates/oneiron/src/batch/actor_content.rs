//! One actor-bound batch effect set, derived from normalized local operations.
//! Trusted replay keeps using the ordinary batch path and is never re-gated.

use super::*;
use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::batch::shared_vault_write::SharedVaultWrite;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::write_envelope::WriteActor;
use oneiron_authority::federation::Scope;
use std::collections::{BTreeMap, BTreeSet};

mod inputs;
pub(crate) use inputs::ContentWriteInputs;
use inputs::authorize_content_write;

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
    before_inputs: Option<crate::federation::OwnedSharedVaultWriteInputs>,
    after_inputs: Option<crate::federation::OwnedSharedVaultWriteInputs>,
}

/// No facade supplies a list of changed parents: the batch's own ChildOf
/// overlay and candidate computation determine them before any operation runs.
pub(super) struct ContentWriteSet {
    // None comes only from the original personal-vault creation lookup.
    shared: Option<SharedContentWriteSet>,
    native_target: Option<EntityId>,
}

struct SharedContentWriteSet {
    vault_id: u64,
    entries: BTreeMap<EntityId, EffectEntry>,
}

impl ContentWriteSet {
    fn before(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        actor: &WriteActor,
        ops: &[BatchOp],
        native_target: Option<EntityId>,
    ) -> Result<Self> {
        let Some(creation) = vault.shared_vault_creation_in_txn(txn)? else {
            return Ok(Self {
                shared: None,
                native_target,
            });
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
        let mut entries = BTreeMap::new();
        for id in ids {
            let mut before_inputs = None;
            let old = if vault.get_raw_in(txn, &id)?.is_some() {
                let old = vault.content_scope_in_txn(txn, id)?;
                authorize_content_write(
                    vault,
                    txn,
                    creation.vault_id,
                    actor,
                    &SharedVaultWrite::Content(old.clone()),
                    (native_target == Some(id)).then_some(&mut before_inputs),
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
                    before_inputs,
                    after_inputs: None,
                },
            );
        }
        Ok(Self {
            shared: Some(SharedContentWriteSet {
                vault_id: creation.vault_id,
                entries,
            }),
            native_target,
        })
    }

    fn after(
        &mut self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        actor: &WriteActor,
    ) -> Result<()> {
        let Some(shared) = &mut self.shared else {
            return Ok(());
        };
        for (&id, effect) in &mut shared.entries {
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
            let transition = match (effect.old.clone(), new) {
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
                    authorize_content_write(
                        vault,
                        txn,
                        shared.vault_id,
                        actor,
                        &SharedVaultWrite::Content(to),
                        (self.native_target == Some(id)).then_some(&mut effect.after_inputs),
                    )?;
                }
                RecordTransition::Replace { id, from, to }
                | RecordTransition::Derived { id, from, to } => {
                    let _ = (id, from); // The old position was checked before applying.
                    authorize_content_write(
                        vault,
                        txn,
                        shared.vault_id,
                        actor,
                        &SharedVaultWrite::Content(to),
                        (self.native_target == Some(id)).then_some(&mut effect.after_inputs),
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
    ops: Vec<BatchOp>,
    text_index_trusted: bool,
    gate_mode: ApplyOpsGateMode,
    origin: BaseWriteOrigin<'_>,
) -> Result<()> {
    apply_actor_ops_collecting(
        vault,
        txn,
        actor,
        ops,
        text_index_trusted,
        gate_mode,
        origin,
    )
    .map(|_| ())
}

pub(super) fn apply_actor_ops_collecting(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &WriteActor,
    ops: Vec<BatchOp>,
    text_index_trusted: bool,
    gate_mode: ApplyOpsGateMode,
    origin: BaseWriteOrigin<'_>,
) -> Result<(super::base_apply::PendingNativeSkillBatch, ContentWriteSet)> {
    if !matches!(origin, BaseWriteOrigin::Ordinary) {
        return Err(Error::InvariantViolation(
            "actor content cannot be replay origin",
        ));
    }
    #[cfg(feature = "sync")]
    let native_target = gate_mode
        .skill_state_write
        .as_ref()
        .map(|write| write.entity());
    #[cfg(not(feature = "sync"))]
    let native_target = None;
    let mut effects = ContentWriteSet::before(vault, txn, actor, &ops, native_target)?;
    let pending = super::base_apply::apply_ops_with_authority_beside_collecting(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        txn,
        ops,
        text_index_trusted,
        gate_mode,
        origin,
        None,
        None,
        Some(NativePublicationContext {
            vault,
            actor: Some(*actor),
            content_writes: Some(&effects),
        }),
    )?;
    effects.after(vault, txn, actor)?;
    Ok((pending, effects))
}
