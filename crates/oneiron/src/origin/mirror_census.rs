//! Core half of `origin::mirror_census`: its store-layer items live in `oneiron_store::origin::mirror_census` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::origin::mirror_census::*;

use super::lfs::{LFS_POINTER_SIZE_CUTOFF, LfsOid, LfsPushedPointer};
use super::mirror::{
    ORIGIN_MIRROR_NAMED_LFS_OBJECTS, OriginMirrorLfsObject, OriginMirrorNotReadyReason,
    OriginMirrorReadiness, OriginMirrorTarget,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::git_wire::{
    GitOid, GitPeeledTip, GitRefName, GitWire, GitWireFailureClass, GitWireRepo,
};
use crate::side_table::{self, Named, SideTable};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// The last finished census of one repository's pushed refs. Key: repo id.
const CENSUS: SideTable<EntityId, MirrorLfsCensus, Named> =
    SideTable::new(&side_table::ORIGIN_MIRROR_LFS_CENSUS);

impl Vault {
    /// The readiness of the mirror `target` that took exactly `refs`, once
    /// each Git-LFS object the census met went to it (FIX 919). A census
    /// that cannot finish is never ready, and neither it nor a transfer
    /// that fails ever fails the push.
    pub(super) fn mirror_lfs_readiness(
        &self,
        wire: &GitWire<'_>,
        handle: &GitWireRepo,
        target: &OriginMirrorTarget,
        repo_id: EntityId,
        refs: &[(GitRefName, GitOid)],
    ) -> OriginMirrorReadiness {
        let tips: Vec<GitOid> = refs.iter().map(|(_, oid)| oid.clone()).collect();
        let kept = self.kept_mirror_lfs_census(repo_id);
        let mut census = LfsCensus::default();
        let walk = match census_walk(wire, handle, &tips, kept.as_ref(), &mut census) {
            Ok(walk) => walk,
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "mirror LFS census did not finish");
                return census.readiness(false);
            }
        };
        if walk.complete {
            match walk
                .peeled
                .map_or_else(|| wire.peel_tips(handle, &tips), Ok)
            {
                Ok(peeled) => {
                    self.keep_mirror_lfs_census(repo_id, &peeled, walk.paged, &census, kept);
                }
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "mirror LFS census was not kept");
                }
            }
            if !census.met.is_empty() {
                match self.push_mirror_lfs_objects(target, &census.met) {
                    Ok(missing) => census.met.retain(|(oid, _)| missing.contains(oid)),
                    Err(error) => {
                        tracing::warn!(kind = ?error.kind(), "mirror LFS objects were not sent");
                    }
                }
            }
        }
        census.readiness(walk.complete)
    }

    /// Drops the kept census of a repository whose mirror target goes.
    pub(super) fn clear_mirror_lfs_census_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        repo_id: &EntityId,
    ) -> Result<()> {
        CENSUS.delete(&self.store, txn, repo_id)?;
        Ok(())
    }

    /// The kept census, or `None` when there is none or it cannot be read.
    fn kept_mirror_lfs_census(&self, repo_id: EntityId) -> Option<MirrorLfsCensus> {
        let read = || -> Result<Option<MirrorLfsCensus>> {
            let txn = self.store.env.read_txn()?;
            CENSUS.get(&self.store, &txn, &repo_id)
        };
        read().unwrap_or_else(|error| {
            tracing::warn!(kind = ?error.kind(), "kept mirror LFS census is unreadable");
            None
        })
    }

    /// Keeps a finished census for the next push. A census that cannot be
    /// kept only costs the next push a whole walk.
    fn keep_mirror_lfs_census(
        &self,
        repo_id: EntityId,
        peeled: &[GitPeeledTip],
        paged: bool,
        census: &LfsCensus,
        kept: Option<MirrorLfsCensus>,
    ) {
        let row = MirrorLfsCensus {
            tips: peeled
                .iter()
                .map(|tip| MirrorCensusTip {
                    tip: tip.tip.as_str().to_owned(),
                    commit: tip.commit().map(|commit| commit.as_str().to_owned()),
                })
                .collect(),
            objects: census.objects(),
            paged,
        };
        if kept.as_ref() == Some(&row) {
            return;
        }
        let write = || -> Result<()> {
            let mut txn = self.store.env.write_txn()?;
            CENSUS.put(&self.store, &mut txn, &repo_id, &row)?;
            txn.commit()?;
            Ok(())
        };
        if let Err(error) = write() {
            tracing::warn!(kind = ?error.kind(), "mirror LFS census was not kept");
        }
    }
}

/// Every Git-LFS object the whole history `tips` reach in `handle` names,
/// each once in the order met, and whether every object was read: an
/// outside import's census, walked from nothing (FIX 7596).
///
/// # Errors
/// An object store failure.
pub(crate) fn history_lfs_objects(
    wire: &GitWire<'_>,
    handle: &GitWireRepo,
    tips: &[GitOid],
) -> Result<(bool, Vec<(LfsOid, u64)>)> {
    let mut census = LfsCensus::default();
    let walk = census_walk(wire, handle, tips, None, &mut census)?;
    Ok((walk.complete, census.met))
}

/// Walks the census of `tips`. One call when the history fits it, unless a
/// kept census that needed pages still holds; otherwise in pages, from the
/// kept census when it holds, else from nothing.
fn census_walk(
    wire: &GitWire<'_>,
    handle: &GitWireRepo,
    tips: &[GitOid],
    kept: Option<&MirrorLfsCensus>,
    census: &mut LfsCensus,
) -> Result<CensusWalk> {
    let mut peeled = None;
    let mut reuse = None;
    let mut paged = true;
    if let Some(row) = kept.filter(|row| row.paged) {
        match wire.peel_tips(handle, tips) {
            Ok(pushed) => {
                reuse = reusable(wire, handle, row, &pushed);
                peeled = Some(pushed);
            }
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "kept mirror LFS census was not checked");
            }
        }
    }
    if reuse.is_none() {
        let single = wire.for_each_reachable_blob_below(
            handle,
            tips,
            LFS_POINTER_SIZE_CUTOFF,
            |_, bytes| census.meet_pointer(bytes),
        )?;
        match single {
            Ok(complete) => {
                return Ok(CensusWalk {
                    complete,
                    paged: false,
                    peeled,
                });
            }
            // A timeout may pass; the next push tries one call again.
            Err(class) => paged = class == GitWireFailureClass::OutputOverflow,
        }
    }
    let pushed = match peeled {
        Some(pushed) => pushed,
        None => wire.peel_tips(handle, tips)?,
    };
    if reuse.is_none()
        && let Some(row) = kept.filter(|row| !row.paged)
    {
        reuse = reusable(wire, handle, row, &pushed);
    }
    let walked = match reuse {
        Some(reuse) => {
            for (oid, size) in reuse.objects {
                census.meet(oid, size);
            }
            reuse.walked
        }
        None => Vec::new(),
    };
    let complete = wire.for_each_reachable_blob_below_paged(
        handle,
        &pushed,
        &walked,
        LFS_POINTER_SIZE_CUTOFF,
        |_, bytes| census.meet_pointer(bytes),
    )?;
    Ok(CensusWalk {
        complete,
        paged,
        peeled: Some(pushed),
    })
}

/// The kept census, when it still holds under the pushed tips: each tip it
/// walked is pushed again, or peels to a commit the pushed tips still reach,
/// so everything it read is still reached; and every row of it reads.
fn reusable(
    wire: &GitWire<'_>,
    handle: &GitWireRepo,
    row: &MirrorLfsCensus,
    pushed: &[GitPeeledTip],
) -> Option<Reuse> {
    let current: HashSet<&str> = pushed.iter().map(|tip| tip.tip.as_str()).collect();
    let mut walked = Vec::with_capacity(row.tips.len());
    let mut moved = Vec::new();
    for kept in &row.tips {
        if !current.contains(kept.tip.as_str()) {
            moved.push(GitOid::parse_hex(kept.commit.as_deref()?).ok()?);
        }
        walked.push(GitOid::parse_hex(kept.tip.as_str()).ok()?);
    }
    let objects = row
        .objects
        .iter()
        .map(|object| {
            LfsOid::parse_hex(&object.oid)
                .ok()
                .map(|oid| (oid, object.size))
        })
        .collect::<Option<Vec<_>>>()?;
    let tips: Vec<GitOid> = pushed.iter().map(|tip| tip.tip.clone()).collect();
    match wire.commits_reachable_from(handle, &moved, &tips) {
        Ok(true) => Some(Reuse { walked, objects }),
        Ok(false) => None,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "kept mirror LFS census was not checked");
            None
        }
    }
}
