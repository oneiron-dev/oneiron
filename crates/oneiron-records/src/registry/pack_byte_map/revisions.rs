//! Moved from `crates/oneiron/src/registry/pack_byte_map/revisions.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::registry::pack_byte_map::types::PackKindIdentity;
use crate::registry::pack_byte_map::types::PackKindRegistration;
use crate::registry::pack_byte_map::types::invalid;
use heed::RoTxn;
use oneiron_base::error::Result;
use std::collections::BTreeSet;

impl PackKindIdentity {
    /// Whether `other` is a same-pack revision of this identity: the same
    /// global name, pack and kind schema under another exact source.
    pub fn same_pack_revision(&self, other: &Self) -> bool {
        self.name == other.name
            && self.pack == other.pack
            && self.schema_hash == other.schema_hash
            && self.source_hash != other.source_hash
    }
}

impl PackKindRegistration {
    /// Takes `next` as the active identity and retains the one it replaces;
    /// a retained identity admitted again is active, not kept twice.
    pub fn revise(&mut self, next: &PackKindIdentity) {
        let replaced = std::mem::replace(&mut self.identity, next.clone());
        self.retained.retain(|kept| kept != next);
        if !self.retained.contains(&replaced) {
            self.retained.push(replaced);
        }
    }

    /// Whether an instance pinned to `kind` is this registration's: its
    /// active identity, or one an admitted revision retained.
    pub fn admits(&self, kind: &PackKindIdentity) -> bool {
        self.identity == *kind || self.retained.contains(kind)
    }

    /// Every retained identity is a distinct same-pack revision of the
    /// active one.
    pub fn validate_retained(&self) -> Result<()> {
        let mut sources = BTreeSet::new();
        for kept in &self.retained {
            kept.validate()?;
            if !self.identity.same_pack_revision(kept) || !sources.insert(kept.source_hash) {
                return Err(invalid("pack map retained revision conflict"));
            }
        }
        Ok(())
    }
}
