//! Source and actor erasure for the server's original admitted usage snapshot.
//! Money, owner, rates and pending allocation custody are not rewritten here.
use rmpv::Value;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::side_table::{self, Named, SideTable};

const ADMITTED: SideTable<String, Value, Named> = SideTable::new(&side_table::USAGE_ADMITTED_CALL);

fn corrupt() -> Error {
    Error::CorruptedIndex("admitted usage attribution")
}

fn map(raw: &[u8]) -> Result<Vec<(Value, Value)>> {
    match rmpv::decode::read_value(&mut &raw[..]) {
        Ok(Value::Map(entries)) => Ok(entries),
        _ => Err(corrupt()),
    }
}

fn field_mut<'a>(entries: &'a mut [(Value, Value)], name: &str) -> Option<&'a mut Value> {
    entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value)
}

fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T> {
    let mut raw = Vec::new();
    rmpv::encode::write_value(&mut raw, value).map_err(|_| corrupt())?;
    rmp_serde::from_slice(&raw).map_err(|_| corrupt())
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Value> {
    let raw = rmp_serde::to_vec_named(value).map_err(|_| corrupt())?;
    rmpv::decode::read_value(&mut raw.as_slice()).map_err(|_| corrupt())
}

fn sources(
    entries: &mut [(Value, Value)],
    field: &str,
    live: &mut impl FnMut(&EntityId) -> Result<bool>,
) -> Result<bool> {
    let Some(value) = field_mut(entries, field).filter(|value| !value.is_nil()) else {
        return Ok(false);
    };
    let original: Vec<EntityId> = decode(value)?;
    let mut kept = Vec::with_capacity(original.len());
    for id in &original {
        if live(id)? {
            kept.push(*id);
        }
    }
    if kept.len() == original.len() {
        return Ok(false);
    }
    *value = encode(&kept)?;
    Ok(true)
}

fn association(
    entries: &mut [(Value, Value)],
    field: &str,
    members: &[&str],
    live: &mut impl FnMut(&EntityId) -> Result<bool>,
) -> Result<bool> {
    let Some(value) = field_mut(entries, field).filter(|value| !value.is_nil()) else {
        return Ok(false);
    };
    let ids: Vec<EntityId> = if members.is_empty() {
        vec![decode(value)?]
    } else {
        let Value::Map(fields) = value else {
            return Err(corrupt());
        };
        let mut ids = Vec::new();
        for name in members {
            let Some((_, id)) = fields.iter().find(|(key, _)| key.as_str() == Some(name)) else {
                return Err(corrupt());
            };
            ids.push(decode(id)?);
        }
        ids
    };
    for id in ids {
        if !live(&id)? {
            *value = Value::Nil;
            return Ok(true);
        }
    }
    Ok(false)
}

fn scrub(
    entries: &mut [(Value, Value)],
    mut live: impl FnMut(&EntityId) -> Result<bool>,
) -> Result<bool> {
    let mut changed = sources(entries, "price_sources", &mut live)?;
    let Some(Value::Map(facts)) = field_mut(entries, "facts") else {
        return Err(corrupt());
    };
    changed |= sources(facts, "source_rows", &mut live)?;
    changed |= association(facts, "initiator", &[], &mut live)?;
    changed |= association(facts, "payer_person", &["person"], &mut live)?;
    changed |= association(facts, "attribution", &["agent", "cycle", "item"], &mut live)?;
    Ok(changed)
}

/// The native erase rewrites attribution only, never releases a hold or changes
/// the original billing owner or rates. A terminal consumes these stored facts.
pub(crate) fn erase_admitted_usage_source_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    erased: &EntityId,
) -> Result<()> {
    let mut updates = Vec::new();
    for row in ADMITTED.iter_raw_from(&vault.store, &*txn, &[])? {
        let (key, raw) = row?;
        let update = map(&raw).and_then(|mut entries| {
            let changed = scrub(&mut entries, |id| Ok(id != erased))?;
            Ok(changed.then_some(entries))
        });
        match update {
            Ok(Some(entries)) => {
                updates.push((String::from_utf8(key).map_err(|_| corrupt())?, entries))
            }
            Ok(None) => {}
            Err(_) => tracing::warn!(
                "an admitted usage snapshot needs attribution repair; its bytes remain"
            ),
        }
    }
    for (key, entries) in updates {
        ADMITTED.put(&vault.store, txn, &key, &Value::Map(entries))?;
    }
    Ok(())
}

impl Vault {
    /// Filters the original usage admission's nullable source/actor associations
    /// against hard erasure in this same writer. This is attribution sanitation,
    /// not an admission decision or permission to reconstruct an erased actor.
    pub fn usage_admission_with_live_attribution_in_write_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        encoded: &[u8],
    ) -> Result<Vec<u8>> {
        let mut entries = map(encoded)?;
        if !scrub(&mut entries, |id| {
            Ok(!self
                .store
                .port_deletion_marked(txn, DeletionMarker::HardDelete, id)?)
        })? {
            return Ok(encoded.to_vec());
        }
        ADMITTED.encode_value(&Value::Map(entries))
    }
}
