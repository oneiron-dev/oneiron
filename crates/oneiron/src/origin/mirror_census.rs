//! The Git-LFS census behind a mirror run's readiness (FIX 6052, FIX 6331).
//!
//! A census reads every Git-LFS pointer the pushed refs' whole history
//! reaches, each object once. A history that fits one reachable-objects call
//! is read in that call, in git's order, so it answers as a single walk does.
//! A larger history is read in pages, each call inside GitWire's own bounds,
//! and no bound stops the census.
//!
//! A finished census is kept per repository: the tips it walked, the commit
//! each peels to, and every object it met, in order. Once a history has
//! needed pages, the next push walks only the commits the kept tips do not
//! reach, and starts from the kept objects. A kept census that no longer
//! holds under the pushed tips, or that cannot be read, is a miss: the push
//! walks the whole history again, and a miss never makes a run ready.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::lfs::{LFS_POINTER_SIZE_CUTOFF, LfsOid, LfsPushedPointer};
use super::mirror::{
    ORIGIN_MIRROR_NAMED_LFS_OBJECTS, OriginMirrorLfsObject, OriginMirrorNotReadyReason,
    OriginMirrorReadiness,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::git_wire::{
    GitOid, GitPeeledTip, GitRefName, GitWire, GitWireFailureClass, GitWireRepo,
};
use crate::side_table::{self, Named, SideTable};

/// The last finished census of one repository's pushed refs. Key: repo id.
const CENSUS: SideTable<EntityId, MirrorLfsCensus, Named> =
    SideTable::new(&side_table::ORIGIN_MIRROR_LFS_CENSUS);

/// A finished census, kept for the next push.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MirrorLfsCensus {
    /// Each pushed tip it walked, with the commit it peels to.
    tips: Vec<MirrorCensusTip>,
    /// Every Git-LFS object under them, in the order the census met them.
    objects: Vec<OriginMirrorLfsObject>,
    /// Whether the history's whole listing passed one call's output bound,
    /// so the next push pages on from this census. A listing only grows
    /// while the kept tips stay reached.
    paged: bool,
}

/// One tip a kept census walked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MirrorCensusTip {
    /// The tip as pushed, lower hex.
    tip: String,
    /// The commit it peels to, lower hex; `None` for any other object.
    commit: Option<String>,
}

/// How one census walk went.
struct CensusWalk {
    /// Every object the pushed refs reach was read.
    complete: bool,
    /// The whole listing passed one call's output bound.
    paged: bool,
    /// The pushed tips, peeled, when the walk peeled them.
    peeled: Option<Vec<GitPeeledTip>>,
}

/// A kept census that still holds under the tips being pushed.
struct Reuse {
    /// The tips it walked: the walk leaves out what they reach.
    walked: Vec<GitOid>,
    /// The objects it met, in order.
    objects: Vec<(LfsOid, u64)>,
}

impl Vault {
    /// The readiness of a mirror that took exactly `refs`. A census that
    /// cannot finish is never ready, and never fails the push.
    pub(super) fn mirror_lfs_readiness(
        &self,
        wire: &GitWire<'_>,
        handle: &GitWireRepo,
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

/// The Git-LFS objects a census met, each once, in the order it met them.
#[derive(Default)]
pub(super) struct LfsCensus {
    seen: HashSet<LfsOid>,
    met: Vec<(LfsOid, u64)>,
}

impl LfsCensus {
    /// Meets the object a blob names, when the blob is a Git-LFS pointer.
    fn meet_pointer(&mut self, bytes: &[u8]) {
        if let Some(pointer) = LfsPushedPointer::from_pointer_content("", bytes) {
            self.meet(pointer.oid, pointer.size_bytes);
        }
    }

    fn meet(&mut self, oid: LfsOid, size: u64) {
        if self.seen.insert(oid) {
            self.met.push((oid, size));
        }
    }

    fn objects(&self) -> Vec<OriginMirrorLfsObject> {
        self.met
            .iter()
            .map(|(oid, size)| OriginMirrorLfsObject {
                oid: oid.to_hex(),
                size: *size,
            })
            .collect()
    }

    /// Ready only over a finished census that met no object: nothing proves
    /// an object at the mirror yet, so each one met leaves it not ready. The
    /// first [`ORIGIN_MIRROR_NAMED_LFS_OBJECTS`] are named; the rest are
    /// counted.
    pub(super) fn readiness(self, complete: bool) -> OriginMirrorReadiness {
        let reason = if !complete {
            OriginMirrorNotReadyReason::LfsInventoryIncomplete
        } else if self.met.is_empty() {
            return OriginMirrorReadiness::Ready;
        } else {
            OriginMirrorNotReadyReason::LfsObjectsNotVerified
        };
        let omitted = self
            .met
            .len()
            .saturating_sub(ORIGIN_MIRROR_NAMED_LFS_OBJECTS);
        OriginMirrorReadiness::NotReady {
            reason,
            objects: self
                .met
                .iter()
                .take(ORIGIN_MIRROR_NAMED_LFS_OBJECTS)
                .map(|(oid, size)| OriginMirrorLfsObject {
                    oid: oid.to_hex(),
                    size: *size,
                })
                .collect(),
            omitted_objects: u64::try_from(omitted).unwrap_or(u64::MAX),
        }
    }
}
