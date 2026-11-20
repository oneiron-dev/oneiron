//! A canonical restore's succession proof (FIX 3553, FIX 3464; Engine
//! 11-06 20:16, option A).
//!
//! A restore rebuilds an entity document from its canonical value: fresh
//! history under a fresh incarnation. A peer that still holds the document
//! the value was captured from cannot join that history, so without a proof
//! both sides keep their own copy for good. The rebuilt document names the
//! history it replaces: the incarnation and version its snapshot was
//! captured at. The proof sits in the document's own meta map, beside its
//! birth, so it travels with every snapshot, state and update a window
//! carries of the document. A peer that holds exactly that incarnation
//! adopts the successor; its operations past that version stay as a fork
//! for the owner to land or drop, never lost; and a pin twin with the same
//! quote, span and version text is held (the window's side, in `sync`).

use super::document::{META, map_get_bytes, map_insert_bytes};
use super::invalid;
use crate::EntityId;
use crate::error::Result;
use crate::store::canonical_document::CanonicalDocumentOrigin;
use loro::{LoroDoc, VersionVector};
use serde::{Deserialize, Serialize};

#[doc(hidden)]
use oneiron_records::entity_doc::succession::SUCCEEDS;

/// The history a rebuilt document replaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Succession {
    /// The incarnation its snapshot was captured at.
    pub(crate) incarnation: String,
    /// That incarnation's version vector there, encoded.
    pub(crate) version: Vec<u8>,
}

impl Succession {
    /// The history `origin` names: an incarnation that is an id, and a
    /// version with each peer once, in peer order.
    pub(super) fn of(origin: &CanonicalDocumentOrigin) -> Result<Self> {
        if !origin.version.windows(2).all(|pair| pair[0].0 < pair[1].0) {
            return Err(invalid("entity document origin version"));
        }
        let version: VersionVector = origin.version.iter().copied().collect();
        Ok(Self {
            incarnation: EntityId::from_bytes(origin.incarnation)?.to_hex(),
            version: version.encode(),
        })
    }

    /// The proof `doc` holds in its meta map: `None` for a document no
    /// restore rebuilt, or one whose proof is not whole.
    #[cfg(feature = "sync")]
    pub(super) fn read(doc: &LoroDoc) -> Option<Self> {
        let bytes = map_get_bytes(&doc.get_map(META), SUCCEEDS)?;
        let proof: Self = super::storage::decode(&bytes).ok()?;
        EntityId::from_hex(&proof.incarnation)
            .ok()
            .filter(|id| id.to_hex() == proof.incarnation)?;
        VersionVector::decode(&proof.version).ok()?;
        Some(proof)
    }

    /// Writes the proof into `doc`'s meta map; the caller commits it.
    pub(super) fn write(&self, doc: &LoroDoc) -> Result<()> {
        let bytes = rmp_serde::to_vec_named(self)
            .map_err(|_| invalid("entity document succession encoding"))?;
        map_insert_bytes(&doc.get_map(META), SUCCEEDS, &bytes)
    }
}

/// The version `entity`'s document here replaces, when a canonical restore
/// rebuilt it or it came here as a restore's successor (FIX 3553).
#[cfg(feature = "sync")]
pub(super) fn replaced_version_in(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
) -> Result<Option<VersionVector>> {
    if !super::storage::has_record_head(store, txn, entity)? {
        return Ok(None);
    }
    Ok(super::storage::head(store, txn, entity)?
        .succeeds
        .and_then(|succeeds| VersionVector::decode(&succeeds.version).ok()))
}

/// `version` as a canonical snapshot carries it: (peer, counter) pairs in
/// peer order, the same on every capture.
pub(super) fn origin_version(version: &VersionVector) -> Vec<(u64, i32)> {
    let mut pairs: Vec<(u64, i32)> = version
        .iter()
        .map(|(peer, counter)| (*peer, *counter))
        .collect();
    pairs.sort_unstable();
    pairs
}
