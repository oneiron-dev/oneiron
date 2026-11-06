//! Canonical source facts for same-vault ASSET and ASSET_TEXT positions.
//!
//! These values describe the stored position and the exact logical rows in
//! one snapshot. They grant nothing: a receiver still needs a live own-device
//! import proof and its dedicated writer before it can install a position.

use serde::{Deserialize, Serialize};

use super::{SCOPE_RECORD, Scope, ScopeId, birth_facet, singleton, stored_scope};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead, TombstoneStoreRead};
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT};
use crate::sync::asset_body::references::AssetBodyRef;
use crate::{EntityId, Vault};

/// A position's row and every native source are bound to their whole logical
/// bytes, metadata header included, and their actual birth facet. File rows
/// also carry the native descriptor-bound reference, never a guessed manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginRow {
    pub(crate) id: EntityId,
    pub(crate) kind: u8,
    pub(crate) facet: EntityId,
    pub(crate) logical_digest: [u8; 32],
    /// The actual stored native birth, when known. None remains unknown;
    /// the metadata header alone is not a universal incarnation proof.
    pub(crate) birth_digest: Option<[u8; 32]>,
    pub(crate) file_reference: Option<Vec<u8>>,
}

/// A source's actual stored BASE position, not a position inferred from a
/// replicated FacetOf edge. Sources are the complete sorted, distinct native
/// DerivedFrom set of an ASSET_TEXT, and empty for an ASSET.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginPosition {
    pub(crate) row: OriginRow,
    pub(crate) scope: Scope,
    pub(crate) sources: Vec<OriginRow>,
}

impl OriginPosition {
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self)
            .map_err(|_| Error::InvalidConfig("an origin position does not encode".into()))
    }

    /// Whether this value describes the exact owner carrier. A file row
    /// uses its native reference; its logical digest is checked separately
    /// against the local checked body in the canonical facts transaction.
    pub(crate) fn binds_carrier(&self, id: &EntityId, carrier: &[u8]) -> bool {
        self.row.id == *id
            && EntityMetadataHeader::parse(carrier)
                .is_some_and(|header| header.entity_type == self.row.kind)
            && match self.row.file_reference.as_deref() {
                Some(bytes) => {
                    self.row.kind == ENTITY_TYPE_ASSET
                        && AssetBodyRef::decode(&id.to_hex(), bytes)
                            .is_some_and(|reference| reference.binds(carrier))
                }
                None => *blake3::hash(carrier).as_bytes() == self.row.logical_digest,
            }
    }

    /// Only the canonical encoding is a carrier. Decoding is data parsing,
    /// not authentication or permission to install the carried position.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let position: Self = rmp_serde::from_slice(bytes).ok()?;
        (position.encode().ok()? == bytes).then_some(position)
    }
}

/// Captures only the canonical row the source window actually carries. A
/// stale or projected carrier cannot borrow the current row's position.
pub(crate) fn capture_for_carrier(
    vault: &Vault,
    id: &EntityId,
    carrier: &[u8],
) -> Result<Option<OriginPosition>> {
    let _bodies = vault.pin_all_result_bodies();
    let txn = vault.store.env.read_txn()?;
    if vault.store.port_entity_raw(&txn, id)?.as_deref() != Some(carrier) {
        return Ok(None);
    }
    capture_in_txn(vault, &txn, id)
}

/// The transaction-composable source capture. The caller pins result bodies
/// before opening `txn` and holds that pin until this read finishes.
pub(crate) fn capture_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<OriginPosition>> {
    let Some(row) = row_in_txn(vault, txn, id)? else {
        return Ok(None);
    };
    let Some(stamp) = SCOPE_RECORD.get(&vault.store, txn, id)? else {
        return Ok(None);
    };
    // scope_for_blob recomputes a NOTE/ASSET position from FacetOf. It is
    // deliberately not this source: only the actual immutable stamp travels.
    if stamp.version != 2
        || stamp.kind != row.kind
        || stamp.birth_facet != *row.facet.as_bytes()
        || stamp.scope.worlds != singleton(ScopeId(crate::claim::base_world_id()))
        || stored_scope(&vault.store, txn, *id, row.kind)?.as_ref() != Some(&stamp.scope)
    {
        return Ok(None);
    }
    let Some(sources) = sources_in_txn(vault, txn, &row)? else {
        return Ok(None);
    };
    Ok(Some(OriginPosition {
        row,
        scope: stamp.scope,
        sources,
    }))
}

/// Whether the current canonical row, native full source set, facets and
/// checked file facts equal the captured facts in this same transaction.
/// This does not authenticate a carrier or install a scope stamp.
pub(crate) fn matches_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    position: &OriginPosition,
) -> Result<bool> {
    let Some(row) = row_in_txn(vault, txn, &position.row.id)? else {
        return Ok(false);
    };
    if row != position.row {
        return Ok(false);
    }
    Ok(sources_in_txn(vault, txn, &row)?.as_ref() == Some(&position.sources))
}

fn sources_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &OriginRow,
) -> Result<Option<Vec<OriginRow>>> {
    if row.kind != ENTITY_TYPE_ASSET_TEXT {
        return Ok(Some(Vec::new()));
    }
    let mut ids = std::collections::BTreeSet::new();
    for edge in vault.store.port_edges(
        txn,
        &row.id,
        EdgeDirection::Out,
        Some(EdgeKind::DerivedFrom),
        None,
    )? {
        ids.insert(edge?.target);
    }
    let mut sources = Vec::with_capacity(ids.len());
    for id in ids {
        let Some(source) = row_in_txn(vault, txn, &id)? else {
            return Ok(None);
        };
        if source.kind != ENTITY_TYPE_ASSET || source.facet != row.facet {
            return Ok(None);
        }
        sources.push(source);
    }
    // A text born under a source facet cannot lose its final source and
    // become an unbound caption. This is the native asset_text read rule.
    if sources.is_empty() && birth_facet(&vault.store, txn, row.id)?.is_some() {
        return Ok(None);
    }
    Ok(Some(sources))
}

fn row_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<Option<OriginRow>> {
    let state = vault.store.port_deletion_state(txn, id)?;
    if state.deleted || state.stale {
        return Ok(None);
    }
    let Some(raw) = vault.store.port_entity_raw(txn, id)? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if !matches!(
        header.entity_type,
        ENTITY_TYPE_ASSET | ENTITY_TYPE_ASSET_TEXT
    ) || !crate::ports::raw_readable_in_txn(&vault.store, txn, id, &raw)?
    {
        return Ok(None);
    }
    let facet = if header.entity_type == ENTITY_TYPE_ASSET {
        let Some(facet) = birth_facet(&vault.store, txn, *id)? else {
            return Ok(None);
        };
        facet
    } else {
        super::asset_text::text_facet(&vault.store, txn, *id)?
    };
    let (logical_digest, file_reference) = if header.entity_type == ENTITY_TYPE_ASSET {
        let manifest = crate::store::asset_file_in_txn(
            &vault.store,
            txn,
            id,
            &raw[ENTITY_METADATA_HEADER_LEN..],
        )?;
        let reference = manifest
            .as_ref()
            .map(|manifest| AssetBodyRef::of_carrier(*id, &raw, manifest).encode())
            .transpose()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&raw[..ENTITY_METADATA_HEADER_LEN]);
        let Some(()) = vault.with_asset_body_reader_in_txn(txn, id, |reader| {
            std::io::copy(reader, &mut hasher)?;
            Ok(())
        })?
        else {
            return Ok(None);
        };
        (*hasher.finalize().as_bytes(), reference)
    } else {
        (*blake3::hash(&raw).as_bytes(), None)
    };
    let birth_digest = crate::provenance::birth::row_birth_in_txn(&vault.store, txn, id)?
        .map(|birth| {
            rmp_serde::to_vec_named(&birth)
                .map(|bytes| *blake3::hash(&bytes).as_bytes())
                .map_err(|_| Error::InvalidConfig("a row birth does not encode".into()))
        })
        .transpose()?;
    Ok(Some(OriginRow {
        id: *id,
        kind: header.entity_type,
        facet,
        logical_digest,
        birth_digest,
        file_reference,
    }))
}
