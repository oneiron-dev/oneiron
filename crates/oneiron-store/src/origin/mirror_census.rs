//! The Git-LFS census behind a mirror run's readiness (FIX 6052, FIX 6331),
//! and the objects it met sent to the mirror (FIX 919).
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

use crate::git_wire::failure::GitWireFailureClass;
use crate::git_wire::ids::GitOid;
use crate::git_wire::ids::GitRefName;
use crate::git_wire::reachable_blobs::GitPeeledTip;
use crate::git_wire::repo::GitWireRepo;
use crate::origin::lfs::oid::LfsOid;
use crate::origin::lfs::pointer::LFS_POINTER_SIZE_CUTOFF;
use crate::origin::lfs::pointer::LfsPushedPointer;
use crate::origin::mirror::ORIGIN_MIRROR_NAMED_LFS_OBJECTS;
use crate::origin::mirror::OriginMirrorLfsObject;
use crate::origin::mirror::OriginMirrorNotReadyReason;
use crate::origin::mirror::OriginMirrorReadiness;
use crate::origin::mirror::OriginMirrorTarget;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// A finished census, kept for the next push.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorLfsCensus {
    /// Each pushed tip it walked, with the commit it peels to.
    pub tips: Vec<MirrorCensusTip>,
    /// Every Git-LFS object under them, in the order the census met them.
    pub objects: Vec<OriginMirrorLfsObject>,
    /// Whether the history's whole listing passed one call's output bound,
    /// so the next push pages on from this census. A listing only grows
    /// while the kept tips stay reached.
    pub paged: bool,
}

/// One tip a kept census walked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorCensusTip {
    /// The tip as pushed, lower hex.
    pub tip: String,
    /// The commit it peels to, lower hex; `None` for any other object.
    pub commit: Option<String>,
}

/// How one census walk went.
pub struct CensusWalk {
    /// Every object the pushed refs reach was read.
    pub complete: bool,
    /// The whole listing passed one call's output bound.
    pub paged: bool,
    /// The pushed tips, peeled, when the walk peeled them.
    pub peeled: Option<Vec<GitPeeledTip>>,
}

/// A kept census that still holds under the tips being pushed.
pub struct Reuse {
    /// The tips it walked: the walk leaves out what they reach.
    pub walked: Vec<GitOid>,
    /// The objects it met, in order.
    pub objects: Vec<(LfsOid, u64)>,
}

/// The Git-LFS objects a census met, each once, in the order it met them.
#[derive(Default)]
pub struct LfsCensus {
    pub seen: HashSet<LfsOid>,
    pub met: Vec<(LfsOid, u64)>,
}

impl LfsCensus {
    /// Meets the object a blob names, when the blob is a Git-LFS pointer.
    pub fn meet_pointer(&mut self, bytes: &[u8]) {
        if let Some(pointer) = LfsPushedPointer::from_pointer_content("", bytes) {
            self.meet(pointer.oid, pointer.size_bytes);
        }
    }

    pub fn meet(&mut self, oid: LfsOid, size: u64) {
        if self.seen.insert(oid) {
            self.met.push((oid, size));
        }
    }

    pub fn objects(&self) -> Vec<OriginMirrorLfsObject> {
        self.met
            .iter()
            .map(|(oid, size)| OriginMirrorLfsObject {
                oid: oid.to_hex(),
                size: *size,
            })
            .collect()
    }

    /// Ready only over a finished census with no object left: each one the
    /// mirror is not known to hold, met and not sent or not verified there,
    /// leaves it not ready (FIX 919). The first
    /// [`ORIGIN_MIRROR_NAMED_LFS_OBJECTS`] are named; the rest are counted.
    pub fn readiness(self, complete: bool) -> OriginMirrorReadiness {
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
