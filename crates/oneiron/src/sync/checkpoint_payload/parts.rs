//! Which holders each part of a parted window value has (KS7-3a). Every
//! manifest the capture's history holds counts, in a window's shallow root,
//! its latest state, its retained operations and its pending and queued
//! updates, never only today's head: a part an older manifest named is
//! still that holder's. A part's digest only associates it with the
//! manifests naming it; it is never an owner, and nothing is minted from
//! it. Identical parts of several holders are each holder's own copy. A
//! part no manifest names stays unclassified, and so does one a manifest
//! names whose joined value still owes its own split.

use std::collections::{BTreeMap, BTreeSet};

use super::{Holder, Placement, SyncUnclassified};
use crate::store::checkpoint_payload::rows::OwnerRef;

/// What the manifests naming one part say of it.
#[derive(Default)]
struct PartClaim {
    holders: BTreeSet<Holder>,
    /// Why a manifest naming it keeps it unclassified, with that manifest's
    /// first holder.
    withheld: Option<(Option<OwnerRef>, SyncUnclassified)>,
}

/// Every part's holders, by its window root map and part key.
#[derive(Default)]
pub(crate) struct PartHolders {
    parts: BTreeMap<(String, String), PartClaim>,
}

impl PartHolders {
    /// Notes `entry`, a value of the root map `root` in any version the
    /// capture holds: a manifest's holders hold each part it names. Any
    /// other placement names no part.
    pub(crate) fn note(&mut self, root: &str, entry: &Placement) {
        let Placement::Manifest {
            holders,
            parts,
            joined,
        } = entry
        else {
            return;
        };
        for key in parts.keys() {
            let claim = self.parts.entry((root.to_owned(), key)).or_default();
            claim.holders.extend(holders.iter().cloned());
            if let Some(reason) = joined
                && claim.withheld.is_none()
            {
                claim.withheld = Some((holders.first().map(|holder| holder.owner), *reason));
            }
        }
    }

    /// Where the part under `key` in `root` goes: one copy under each
    /// holder a manifest named it for, or unclassified.
    pub(crate) fn place(&self, root: &str, key: &str) -> Placement {
        let Some(claim) = self.parts.get(&(root.to_owned(), key.to_owned())) else {
            return Placement::unclassified(None, SyncUnclassified::OrphanPart);
        };
        match claim.withheld {
            Some((owner, reason)) => Placement::unclassified(owner, reason),
            None => Placement::Owned(claim.holders.iter().cloned().collect()),
        }
    }
}
