//! Admitted same-pack revisions (FIX 10062).
//!
//! A kind's global name stays owned by its pack. An update of that pack the
//! catalog admitted, under a new exact source with the kind's schema
//! unchanged, becomes the kind's active identity; the identity it replaced
//! is retained on the registration, so an instance pinned to it still
//! validates, remaps and keeps its pin when rewritten. Another pack's
//! identity, or a changed schema, still collides, and import and remap never
//! add a revision: only the local install door does.

use super::types::{
    PackByteMapSnapshot, PackInstanceEnvelope, PackKindIdentity, PackKindRegistration, invalid,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{TypeByteZone, zone_of};
use crate::store::Store;
use heed::RoTxn;
use std::collections::BTreeSet;

impl PackKindIdentity {
    /// Whether `other` is a same-pack revision of this identity: the same
    /// global name, pack and kind schema under another exact source.
    pub(super) fn same_pack_revision(&self, other: &Self) -> bool {
        self.name == other.name
            && self.pack == other.pack
            && self.schema_hash == other.schema_hash
            && self.source_hash != other.source_hash
    }
}

impl PackKindRegistration {
    /// Takes `next` as the active identity and retains the one it replaces;
    /// a retained identity admitted again is active, not kept twice.
    pub(super) fn revise(&mut self, next: &PackKindIdentity) {
        let replaced = std::mem::replace(&mut self.identity, next.clone());
        self.retained.retain(|kept| kept != next);
        if !self.retained.contains(&replaced) {
            self.retained.push(replaced);
        }
    }

    /// Whether an instance pinned to `kind` is this registration's: its
    /// active identity, or one an admitted revision retained.
    pub(super) fn admits(&self, kind: &PackKindIdentity) -> bool {
        self.identity == *kind || self.retained.contains(kind)
    }

    /// Every retained identity is a distinct same-pack revision of the
    /// active one.
    pub(super) fn validate_retained(&self) -> Result<()> {
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

impl PackByteMapSnapshot {
    /// The envelope a write to `id` stores: an instance already written under
    /// an identity of the same kind this map still admits keeps that exact
    /// pin; a new instance takes the active identity. A prior row that is no
    /// pack instance is left to the write's own identity guard.
    pub(super) fn keep_instance_pin(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: &EntityId,
        mut envelope: PackInstanceEnvelope,
    ) -> Result<PackInstanceEnvelope> {
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw_wiped(store, txn, id)?
        else {
            return Ok(envelope);
        };
        let pack_row = EntityMetadataHeader::parse(&raw)
            .is_some_and(|header| zone_of(header.entity_type) == TypeByteZone::PackHandle);
        if !pack_row {
            return Ok(envelope);
        }
        let Ok(prior) = PackInstanceEnvelope::from_bytes(&raw[ENTITY_METADATA_HEADER_LEN..]) else {
            return Ok(envelope);
        };
        if prior.kind.name == envelope.kind.name
            && self
                .registrations
                .get(&prior.kind.name)
                .is_some_and(|row| row.admits(&prior.kind))
        {
            envelope.kind = prior.kind;
        }
        Ok(envelope)
    }
}
