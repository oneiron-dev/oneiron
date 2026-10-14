//! A policy manifest without the Dreamer's actor-keyed rows, as a release
//! before warm-by-default seeded it.

use rmpv::Value;

use crate::{Result, Vault};

/// The Dreamer's actor-keyed rows removed: the shipped manifest as a release
/// before warm-by-default seeded it, or an owner pack written without them.
pub(crate) fn without_dreamer_rows(manifest: &[u8]) -> Result<Vec<u8>> {
    let dreamer = crate::dreamer_runner::authority::dreamer_actor_id()?.to_hex();
    let names_dreamer = |row: &Value| {
        row.as_map().is_some_and(|fields| {
            fields.iter().any(|(key, value)| {
                key.as_str() == Some("actor_ref") && value.as_str() == Some(&dreamer)
            })
        })
    };
    let strip = |rows: &mut Value| {
        if let Value::Array(list) = rows {
            list.retain(|row| !names_dreamer(row));
            if list.len() == 1 {
                *rows = list.remove(0);
            }
        }
    };
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut &manifest[..]).expect("map") else {
        panic!("policy manifest is a map");
    };
    entries.retain(|(key, value)| {
        !(key.as_str() == Some("scoped_grants")
            && value
                .as_array()
                .is_some_and(|rows| rows.iter().all(names_dreamer)))
    });
    for (key, value) in &mut entries {
        match key.as_str() {
            Some("actor_ceilings") => {
                if let Value::Array(rows) = value {
                    rows.retain(|row| !names_dreamer(row));
                }
            }
            Some("source_trust") => {
                if let Value::Map(sources) = value {
                    for (source, rows) in sources.iter_mut() {
                        if source.as_str() == Some("generated") {
                            strip(rows);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &Value::Map(entries)).expect("encode");
    Ok(data)
}

/// A vault seeded by a release before the Dreamer's rows shipped: its seeded
/// default has none, and it is still the untouched seed.
pub(crate) fn seeded_without_dreamer_rows(vault: &Vault) -> Result<()> {
    let id = crate::gate::default_policy_manifest_id()?;
    let old = without_dreamer_rows(&crate::gate::default_policy_manifest()?)?;
    crate::test_util::put_policy_manifest_bytes(vault, id, &old)?;
    vault.with_write_txn(|txn| {
        vault.store.sync_state.put(
            txn,
            &crate::gate::seeded_manifest_key(&id),
            blake3::hash(&old).as_bytes(),
        )?;
        Ok(())
    })
}
