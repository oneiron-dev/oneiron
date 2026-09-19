//! Monotone record exposure. Generic writes and replay cannot declassify an
//! existing private record by removing its stamps or its source links.
//! Owner-signed restamping is the sole widening door.

use super::position::{accumulate_exposure, payload_position, record_scope_position};
use super::{
    DisclosureScopeAuthorization, ScopeKindAxis, ScopePosition, decode_scope_position_body,
    encode_scope_position_body,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::store::Store;
use crate::{EntityId, Vault};
use heed::{RoTxn, RwTxn};
use sha2::{Digest, Sha256};

fn key(id: &EntityId) -> Vec<u8> {
    let mut key = b"disclosure.position-floor.v2:".to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}
fn digest(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}
fn encoded(position: &ScopePosition, override_digest: Option<[u8; 32]>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.push(u8::from(override_digest.is_some()));
    bytes.extend_from_slice(&override_digest.unwrap_or([0; 32]));
    bytes.extend_from_slice(&encode_scope_position_body(position)?);
    Ok(bytes)
}
fn decoded(bytes: &[u8]) -> Result<(ScopePosition, Option<[u8; 32]>)> {
    if bytes.len() < 33 || bytes[0] > 1 {
        return Err(Error::CorruptedIndex("disclosure position floor"));
    }
    let hash = bytes[1..33]
        .try_into()
        .map_err(|_| Error::CorruptedIndex("disclosure position hash"))?;
    Ok((
        decode_scope_position_body(&bytes[33..])?,
        (bytes[0] == 1).then_some(hash),
    ))
}

pub(super) fn apply_floor(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    payload: &[u8],
    mut position: ScopePosition,
) -> Result<ScopePosition> {
    if let Some(bytes) = store.vault_meta.get(txn, &key(id))? {
        let (floor, authorized) = decoded(&bytes)?;
        if authorized == Some(digest(payload)) {
            return Ok(floor);
        }
        accumulate_exposure(&mut position, floor);
    }
    Ok(position)
}

/// Shared by first-party puts, transactional puts and replicated replay.
/// It can only narrow disclosure, so it does not import peer authority.
pub(crate) fn stage_record_exposure(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    data: &[u8],
) -> Result<()> {
    if !matches!(
        entity_type,
        ENTITY_TYPE_CLAIM | ENTITY_TYPE_TURN | ENTITY_TYPE_MESSAGE
    ) {
        return Ok(());
    }
    let mut incoming = payload_position(entity_type, data);
    let mut unchanged_authorized = None;
    if let Some(bytes) = store.vault_meta.get(txn, &key(id))? {
        let (floor, authorized) = decoded(&bytes)?;
        if authorized == Some(digest(data)) {
            unchanged_authorized = authorized;
            incoming = floor;
        } else {
            accumulate_exposure(&mut incoming, floor);
        }
    }
    if let Some(raw) = store.entities.get(txn, id.as_bytes())? {
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if &raw[ENTITY_METADATA_HEADER_LEN..] != data || header.entity_type != entity_type {
            // Capture the OLD effective provenance before a rewrite can drop it.
            let old = record_scope_position(store, txn, id, header.entity_type, None)?;
            accumulate_exposure(&mut incoming, old);
            unchanged_authorized = None;
        }
    }
    store
        .vault_meta
        .put(txn, &key(id), &encoded(&incoming, unchanged_authorized)?)?;
    Ok(())
}

impl Vault {
    /// Restamps an existing record under an exact owner-signed intent. The
    /// authorization binds its current bytes; a later content rewrite loses
    /// the override. Actual source exposure remains an admission conjunct.
    pub fn restamp_disclosure_position(
        &self,
        id: &EntityId,
        position: &ScopePosition,
        authorization: &DisclosureScopeAuthorization,
    ) -> Result<()> {
        position.validate()?;
        let mut txn = self.store.env.write_txn()?;
        let raw = self
            .store
            .entities
            .get(&txn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if !matches!(
            header.entity_type,
            ENTITY_TYPE_CLAIM | ENTITY_TYPE_TURN | ENTITY_TYPE_MESSAGE
        ) || position.kinds != ScopeKindAxis::Some(vec![header.entity_type])
        {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        let hash = digest(&raw[ENTITY_METADATA_HEADER_LEN..]);
        let transcript = authorization.restamp_transcript(id, position, hash)?;
        authorization.consume_transcript(self, &mut txn, transcript)?;
        self.store
            .vault_meta
            .put(&mut txn, &key(id), &encoded(position, Some(hash))?)?;
        txn.commit()?;
        Ok(())
    }
}
