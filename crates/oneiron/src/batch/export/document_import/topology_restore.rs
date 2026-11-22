//! The merges and splits the owner's restore into a fresh vault decides
//! again (fix list row RESTORE-KEEPS-MERGES-AND-SPLITS; Engine ANSWER 08:00
//! 17 Nov = B; NOTE PLAN-RESTORE-KEEPS-MERGES 11:27 17 Nov).
//!
//! The archive's manifest names the decisions its source held current
//! (`current_identity_topology_events`). Each is read whole from the
//! archive's type-76 rows and applied again, in its archived `(seq, id)`
//! order, through this vault's topology door under the restoring owner's
//! decision seal and this install's key, each in a savepoint of the
//! import's writer. A refusal by the door rolls back only that savepoint and
//! goes into the receipt; any other error aborts the import. One shell
//! reconcile then runs over the restored ledger. Every other import, and
//! the owner's restore into a vault already holding rows, restores none.

use std::collections::BTreeSet;
use std::io::{Read, Seek};

use super::super::archive_index::IndexedArchive;
use super::super::{
    IdentityTopologyNotRestored, IdentityTopologyRestoreKind, RestoredIdentityTopologyEvent,
    UnrestoredIdentityTopologyEvent,
};
use super::parse_id;
use crate::Vault;
use crate::authority::{ActAuthority, ActSurface};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::identity_topology::{
    IdentityOpOutcome, IdentityTopologyOp, TopologySeal, archived_topology_decision,
    is_topology_refusal, restored_merge_or_split,
};
use crate::serialize::{ExportBody, ExportSecrets};

/// What the owner's restore did with the archive's current merges and
/// splits.
#[derive(Default)]
pub(super) struct TopologyRestore {
    pub(super) restored: Vec<RestoredIdentityTopologyEvent>,
    pub(super) unrestored: Vec<UnrestoredIdentityTopologyEvent>,
    /// The merged sources and split originals a restored decision shelled
    /// again: no longer back here as separate rows.
    pub(super) shelled: BTreeSet<EntityId>,
}

impl TopologyRestore {
    fn unrestored(&mut self, archived: &EntityId, reason: IdentityTopologyNotRestored) {
        self.unrestored.push(UnrestoredIdentityTopologyEvent {
            archived: archived.to_hex(),
            reason,
        });
    }
}

/// Decides each current merge and split `archive` names again in `wtxn`,
/// as the restoring `owner`'s act. `signing` says whether this install's
/// keys loaded before the writer opened; with none, every named decision
/// stays archive data, as the restore did before this row.
pub(super) fn restore_identity_topology_in_txn<R: Read + Seek>(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    archive: &IndexedArchive<'_, R>,
    secrets: ExportSecrets,
    owner: &AuthenticatedOwner,
    signing: bool,
) -> Result<TopologyRestore> {
    let mut restore = TopologyRestore::default();
    let mut decisions = Vec::new();
    for hex in &archive.manifest.current_identity_topology_events {
        let archived = parse_id(hex)?;
        let decision = archived_topology_decision(&archived, |id| {
            let Some((_, row)) = archive.entity(id)? else {
                return Ok(None);
            };
            if matches!(row.body, ExportBody::Nulled) {
                return Ok(None);
            }
            let body = row.body.to_bytes_in_with(&archive.files, secrets)?;
            Ok(Some((row.entity_type, body)))
        })?;
        match decision
            .as_ref()
            .and_then(|decision| Some((decision.seq, restored_merge_or_split(decision)?)))
        {
            Some((seq, (op, write))) => decisions.push((seq, archived, op, write)),
            None => restore.unrestored(
                &archived,
                IdentityTopologyNotRestored::ArchivedDecisionIncomplete,
            ),
        }
    }
    decisions.sort_by_key(|(seq, archived, ..)| (*seq, *archived));
    let seal = TopologySeal::decision(ActAuthority::Owner(owner.clone(), ActSurface::ThisInstall));
    let now = vault.store.clock.now_recorded_at();
    for (_, archived, op, write) in decisions {
        let (kind, shelled) = match &op {
            IdentityTopologyOp::Merge(merge) => {
                (IdentityTopologyRestoreKind::Merge, merge.sources.clone())
            }
            IdentityTopologyOp::Split(split) => {
                (IdentityTopologyRestoreKind::Split, vec![split.entity])
            }
            IdentityTopologyOp::Facet(_) | IdentityTopologyOp::AssertDistinct(_) => {
                restore.unrestored(
                    &archived,
                    IdentityTopologyNotRestored::ArchivedDecisionIncomplete,
                );
                continue;
            }
        };
        if !signing {
            restore.unrestored(&archived, IdentityTopologyNotRestored::SigningUnavailable);
            continue;
        }
        let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
        match vault.apply_identity_topology_op_as_in_txn(&mut savepoint, &op, &write, &seal, now) {
            Ok(IdentityOpOutcome::Applied { event, .. }) => {
                savepoint.commit()?;
                restore.shelled.extend(shelled);
                restore.restored.push(RestoredIdentityTopologyEvent {
                    archived: archived.to_hex(),
                    restored: event.to_hex(),
                    kind,
                });
            }
            // An Auto or Approved write never parks, and is never the
            // consent no-op; read either as a refusal, never as restored.
            Ok(outcome) => {
                drop(savepoint);
                restore.unrestored(
                    &archived,
                    IdentityTopologyNotRestored::Refused(format!("{outcome:?}")),
                );
            }
            Err(error) if is_topology_refusal(&error) => {
                drop(savepoint);
                restore.unrestored(
                    &archived,
                    IdentityTopologyNotRestored::Refused(error.to_string()),
                );
            }
            Err(error) => return Err(error),
        }
    }
    if !restore.restored.is_empty() {
        vault.reconcile_identity_topology_edges_in_txn(wtxn)?;
    }
    Ok(restore)
}
