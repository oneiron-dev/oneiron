//! Composed room reads: the session-scoped siblings of
//! [`crate::Vault::entities_by_type`], [`crate::Vault::targets`] and [`crate::Vault::get_raw`].
//!
//! Without them every caller re-derives the same `read_view()` snapshot plus
//! `read_txn` plus `prefix_iter` plus `parse_strict_edge_record_key` dance
//! against the view's raw handles, with a load-bearing manual drop order at
//! the end of it. They live here, gated, because no production caller composes
//! them yet — the reads themselves are the base vault's, taken over the
//! session's own snapshot so a multi-step read cannot see a torn
//! overlay-base union.

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::session::OffRecordSession;

impl OffRecordSession<'_> {
    /// Every entity id of `entity_type` this room can see — the composed
    /// sibling of [`crate::Vault::entities_by_type`], read through ONE
    /// [`Self::read_view`] snapshot so a census cannot see a torn
    /// overlay-base union half-way down the type index.
    ///
    /// Bounded exactly like the base read: a type index wider than
    /// `MAX_TYPE_QUERY_RESULTS` is `Err(IndexOverflow)`, never an unbounded
    /// allocation.
    ///
    pub(crate) fn entities_by_type(&self, entity_type: u8) -> Result<Vec<EntityId>> {
        let view = self.read_view()?;
        let rtxn = self.vault.store.env.read_txn()?;
        let mut ids = Vec::new();
        for row in view.type_index.prefix_iter(&rtxn, &[entity_type])? {
            if ids.len() >= crate::vault::MAX_TYPE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("entities_by_type"));
            }
            let (key, _) = row?;
            ids.push(crate::vault::entity_id_from_type_index_key(&key)?);
        }
        Ok(ids)
    }

    /// The outbound targets of `src` on `kind`, as this room sees them — the
    /// composed sibling of [`crate::Vault::targets`], over one snapshot.
    ///
    /// No target-type filter: a room's edges are the ones it staged, so the
    /// kind prefix is the whole question its callers ask.
    pub(crate) fn targets(
        &self,
        src: &EntityId,
        kind: crate::edge::EdgeKind,
    ) -> Result<Vec<EntityId>> {
        let view = self.read_view()?;
        let rtxn = self.vault.store.env.read_txn()?;
        let prefix = crate::vault::edge_kind_prefix(src, kind);
        let mut targets = Vec::new();
        for row in view.edges_out.prefix_iter(&rtxn, &prefix)? {
            let (key, _) = row?;
            let (_, _, target) = crate::edge::parse_strict_edge_record_key(&key)?;
            targets.push(target);
        }
        Ok(targets)
    }

    /// The raw entity row for `id` as this room sees it — the composed
    /// sibling of [`crate::Vault::get_raw`], sealed against custody rows for the same
    /// reason the base reader is.
    pub(crate) fn get_raw(&self, id: &EntityId) -> Result<Option<Vec<u8>>> {
        let view = self.read_view()?;
        let rtxn = self.vault.store.env.read_txn()?;
        let Some(bytes) = view.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        if crate::batch::EntityMetadataHeader::parse(&bytes)
            .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY)
        {
            return Err(crate::secret_custody::reject_secret_custody_byte());
        }
        Ok(Some(bytes.into_owned()))
    }
}
