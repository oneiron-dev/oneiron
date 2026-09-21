//! Exact citation dependency indexes shared by sync and featureless erasure.

use crate::store::Store;
use crate::{EntityId, Error, Result};
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Deserialize)]
struct PinRefs {
    #[serde(with = "super::id_codec")]
    document: EntityId,
    #[serde(with = "super::id_codec")]
    claim: EntityId,
}

pub(super) fn remove_citing(store: &Store, txn: &mut heed::RwTxn<'_>, id: EntityId) -> Result<()> {
    let prefix = format!("note.pin/citing/{}:", id.to_hex());
    let rows = store
        .vault_meta
        .prefix_iter(txn, prefix.as_bytes())?
        .map(|row| row.map(|(key, value)| (key.to_vec(), value.to_vec())))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (key, source_key) in rows {
        let bytes = store
            .vault_meta
            .get(txn, &source_key)?
            .ok_or(Error::CorruptedIndex("NOTE reverse pin source missing"))?;
        let refs: PinRefs = serde_json::from_slice(&bytes)
            .map_err(|_| Error::CorruptedIndex("NOTE reverse pin value"))?;
        let source_key_str = std::str::from_utf8(&source_key)
            .map_err(|_| Error::CorruptedIndex("NOTE reverse pin key"))?;
        let source_prefix = format!(
            "note.pin/source/{}:{}:",
            refs.document.to_hex(),
            id.to_hex()
        );
        let hash = source_key_str
            .strip_prefix(&source_prefix)
            .ok_or(Error::CorruptedIndex("NOTE reverse pin identity"))?;
        let claim_key = format!(
            "note.pin/claim/{}:{}:{}",
            refs.claim.to_hex(),
            id.to_hex(),
            hash
        );
        store.vault_meta.delete(txn, claim_key.as_bytes())?;
        store.vault_meta.delete(txn, &source_key)?;
        store.vault_meta.delete(txn, &key)?;
    }
    Ok(())
}

pub(super) fn dependents(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<BTreeSet<EntityId>> {
    let mut out = BTreeSet::new();
    for family in ["source", "claim", "request/source", "request/claim"] {
        let prefix = format!("note.pin/{family}/{}:", id.to_hex());
        for row in store.vault_meta.prefix_iter(txn, prefix.as_bytes())? {
            let (key, _) = row?;
            let suffix = std::str::from_utf8(&key[prefix.len()..])
                .map_err(|_| Error::CorruptedIndex("NOTE dependency key"))?;
            let (citing, hash) = suffix
                .split_once(':')
                .ok_or(Error::CorruptedIndex("NOTE dependency key"))?;
            let citing = EntityId::from_hex(citing)?;
            let expected_len = if family.starts_with("request/") {
                32
            } else {
                64
            };
            if hash.len() != expected_len
                || !hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(Error::CorruptedIndex("NOTE dependency hash"));
            }
            out.insert(citing);
        }
    }
    Ok(out)
}

pub(crate) fn citation_delete_scope_exists(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(!dependents(store, txn, *id)?.is_empty())
}

#[cfg(feature = "sync")]
pub(crate) fn track_citation_request(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    citing: EntityId,
    request: EntityId,
    pin: &super::NotePin,
) -> Result<()> {
    pin.validate()?;
    let refs = serde_json::to_vec(
        &serde_json::json!({ "document": pin.document.to_hex(), "claim": pin.claim.to_hex() }),
    )
    .map_err(|_| Error::InvariantViolation("NOTE request dependency encode"))?;
    store.vault_meta.put(
        txn,
        format!(
            "note.pin/request/citing/{}:{}",
            citing.to_hex(),
            request.to_hex()
        )
        .as_bytes(),
        &refs,
    )?;
    for (family, source) in [("source", pin.document), ("claim", pin.claim)] {
        store.vault_meta.put(
            txn,
            format!(
                "note.pin/request/{family}/{}:{}:{}",
                source.to_hex(),
                citing.to_hex(),
                request.to_hex()
            )
            .as_bytes(),
            &[],
        )?;
    }
    Ok(())
}

pub(crate) fn remove_citation_request(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    citing: EntityId,
    request: EntityId,
) -> Result<()> {
    let key = format!(
        "note.pin/request/citing/{}:{}",
        citing.to_hex(),
        request.to_hex()
    );
    if let Some(bytes) = store.vault_meta.get(txn, key.as_bytes())? {
        let refs: PinRefs = serde_json::from_slice(&bytes)
            .map_err(|_| Error::CorruptedIndex("NOTE request dependency"))?;
        for (family, source) in [("source", refs.document), ("claim", refs.claim)] {
            store.vault_meta.delete(
                txn,
                format!(
                    "note.pin/request/{family}/{}:{}:{}",
                    source.to_hex(),
                    citing.to_hex(),
                    request.to_hex()
                )
                .as_bytes(),
            )?;
        }
        store.vault_meta.delete(txn, key.as_bytes())?;
    }
    Ok(())
}

pub(super) fn remove_citing_requests(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    citing: EntityId,
) -> Result<()> {
    let prefix = format!("note.pin/request/citing/{}:", citing.to_hex());
    let keys = store
        .vault_meta
        .prefix_iter(txn, prefix.as_bytes())?
        .map(|row| row.map(|(key, _)| key.to_vec()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for key in keys {
        let request = std::str::from_utf8(&key[prefix.len()..])
            .map_err(|_| Error::CorruptedIndex("NOTE request dependency key"))?;
        remove_citation_request(store, txn, citing, EntityId::from_hex(request)?)?;
    }
    Ok(())
}
