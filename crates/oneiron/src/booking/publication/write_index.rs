//! Local owner write authorization and bounded public-address lookup.
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::memory::booking_publication::publication_write_key;
use crate::store::Store;

/// `incoming_claim` is the structurally validated write-door body, or `None`
/// for a non-CLAIM put. Admission stays read-only and precedes all write effects.
pub(crate) fn guard_publication_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    incoming_claim: Option<&ClaimBody>,
) -> Result<()> {
    let new_publication =
        incoming_claim.is_some_and(|body| body.predicate == BOOKING_PUBLIC_PAGE_PREDICATE);
    let old_publication = match store.entities.get(txn, id.as_bytes())? {
        Some(raw) => {
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            // A parsed header-only row is an erased shell, not malformed
            // MessagePack. Nonempty CLAIM bodies must still decode fail-closed.
            header.entity_type == crate::registry::ENTITY_TYPE_CLAIM
                && raw.len() > ENTITY_METADATA_HEADER_LEN
                && crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?
                    .predicate
                    == BOOKING_PUBLIC_PAGE_PREDICATE
        }
        None => false,
    };
    if (new_publication
        || old_publication
        || store
            .vault_meta
            .get(txn, &publication_slot_key(id))?
            .is_some())
        && store
            .vault_meta
            .get(txn, &publication_write_key(id))?
            .is_none()
    {
        return Err(Error::InvalidClaimBody(
            "booking publication requires the owner memory write door",
        ));
    }
    Ok(())
}

// Deny-only ownership of the claim id survives body erasure and head changes.
// It is not a write permit or publication authority; only the owner transaction
// creates it, and generic writes/replay cannot clear it or use it as consent.
fn publication_slot_key(claim: EntityId) -> Vec<u8> {
    let mut key = b"booking.public_page.protected_claim/".to_vec();
    key.extend_from_slice(claim.as_bytes());
    key
}

fn index_key(token: &str) -> Vec<u8> {
    let mut key = b"booking.public_page.token/".to_vec();
    key.extend_from_slice(token.as_bytes());
    key
}

pub(crate) fn index_publication_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    page: EntityId,
    claim: EntityId,
) -> Result<()> {
    let mut value = page.as_bytes().to_vec();
    value.extend_from_slice(claim.as_bytes());
    vault.store.vault_meta.put(
        txn,
        &index_key(&crate::booking::PublicBookingPageToken::for_page(page).0),
        &value,
    )?;
    vault
        .store
        .vault_meta
        .put(txn, &publication_slot_key(claim), &[])?;
    Ok(())
}

pub(super) fn indexed_publication(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    token: &str,
) -> Result<Option<(EntityId, EntityId)>> {
    if !token.strip_prefix("bkp_").is_some_and(|s| {
        s.len() == 32
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }) {
        return Ok(None);
    }
    let Some(raw) = vault.store.vault_meta.get(txn, &index_key(token))? else {
        return Ok(None);
    };
    if raw.len() != 32 {
        return Err(Error::CorruptedIndex("public booking token index"));
    }
    let page = EntityId::from_bytes(
        raw[..16]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("public booking page"))?,
    )?;
    let claim = EntityId::from_bytes(
        raw[16..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("public booking claim"))?,
    )?;
    Ok(Some((page, claim)))
}

/// A fixed-key durable lookup. A miss never scans claims. This only locates a
/// page; callers must still check its live owner-authored publication.
pub fn resolve_public_booking_token(vault: &Vault, token: &str) -> Result<Option<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    Ok(indexed_publication(vault, &txn, token)?.map(|(page, _)| page))
}

/// Digest of the exact typed scheduling content, not just its duration.
pub fn booking_config_hash(config: &crate::booking::EventTypeConfig) -> Result<String> {
    let bytes = rmp_serde::to_vec_named(config)
        .map_err(|_| Error::InvalidClaimBody("booking configuration does not encode"))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}
