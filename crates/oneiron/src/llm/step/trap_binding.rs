//! Device-local trap-anchor binding rows (attempt/step-hash/park-owner ground truth for consume).

use super::codec::{
    decode_attempt_id_value, expect_key, expect_map, expect_string, expect_u64, invalid_trap,
    pinned_key_index,
};
use super::types::{
    DREAMER_PRIVATE_TRAP_BINDING_PREFIX, DREAMER_TRAP_BINDING_KEYS,
    DREAMER_TRAP_BINDING_SCHEMA_VERSION, KEY_ATTEMPT_ID, KEY_PARK_OWNER, KEY_SCHEMA_VERSION,
    KEY_STEP_HASH,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Result;
use rmpv::Value;

// ---------------------------------------------------------------------------
// Private trap-binding rows (device-local consume ground truth, ruling L8)
// ---------------------------------------------------------------------------
/// Device-local binding of one trap anchor to the suspended step: written by
/// [`open_trap`] in the anchor's wtxn, read back at consume as the ONLY
/// authority for the attempt id, step hash, and park owner.
pub(super) struct TrapBindingRow {
    pub(super) attempt_id: AttemptId,
    pub(super) step_hash: [u8; 32],
    pub(super) park_owner: String,
}

fn trap_binding_key(anchor: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(DREAMER_PRIVATE_TRAP_BINDING_PREFIX.len() + 16);
    key.extend_from_slice(DREAMER_PRIVATE_TRAP_BINDING_PREFIX);
    key.extend_from_slice(anchor.as_bytes());
    key
}

pub(super) fn trap_binding_put_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    anchor: &EntityId,
    row: &TrapBindingRow,
) -> Result<()> {
    let entries = vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_TRAP_BINDING_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_ATTEMPT_ID),
            Value::Binary(row.attempt_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_STEP_HASH),
            Value::Binary(row.step_hash.to_vec()),
        ),
        (
            Value::from(KEY_PARK_OWNER),
            Value::from(row.park_owner.as_str()),
        ),
    ];
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &Value::Map(entries))
        .map_err(|_| invalid_trap("dreamer trap binding row MessagePack encode failed"))?;
    vault
        .store
        .vault_meta
        .put(wtxn, &trap_binding_key(anchor), &encoded)?;
    Ok(())
}

pub(super) fn trap_binding_read(
    vault: &Vault,
    anchor: &EntityId,
) -> Result<Option<TrapBindingRow>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, &trap_binding_key(anchor))?
    else {
        return Ok(None);
    };
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(raw))
        .map_err(|_| invalid_trap("dreamer trap binding row MessagePack decode failed"))?;
    let entries = expect_map(&value, "dreamer trap binding row must be a MessagePack map")?;

    let mut schema_version = None;
    let mut attempt_id = None;
    let mut step_hash = None;
    let mut park_owner = None;
    let mut seen = [false; DREAMER_TRAP_BINDING_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer trap binding row keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_TRAP_BINDING_KEYS)
            .ok_or(invalid_trap("dreamer trap binding row key is not pinned"))?;
        if seen[index] {
            return Err(invalid_trap("duplicate dreamer trap binding row key"));
        }
        seen[index] = true;

        match DREAMER_TRAP_BINDING_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer trap binding schema_version must be an integer",
                )?);
            }
            KEY_ATTEMPT_ID => attempt_id = Some(decode_attempt_id_value(value)?),
            KEY_STEP_HASH => {
                let Value::Binary(bytes) = value else {
                    return Err(invalid_trap(
                        "dreamer trap binding step_hash must be binary",
                    ));
                };
                let raw: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| invalid_trap("dreamer trap binding step_hash must be 32 bytes"))?;
                step_hash = Some(raw);
            }
            KEY_PARK_OWNER => {
                park_owner = Some(expect_string(
                    value,
                    "dreamer trap binding park_owner must be a string",
                )?);
            }
            _ => unreachable!("index resolved from DREAMER_TRAP_BINDING_KEYS"),
        }
    }

    let schema_version =
        schema_version.ok_or(invalid_trap("missing dreamer trap binding schema_version"))?;
    if schema_version != DREAMER_TRAP_BINDING_SCHEMA_VERSION {
        return Err(invalid_trap(
            "unsupported dreamer trap binding schema_version",
        ));
    }

    Ok(Some(TrapBindingRow {
        attempt_id: attempt_id.ok_or(invalid_trap("missing dreamer trap binding job_id"))?,
        step_hash: step_hash.ok_or(invalid_trap("missing dreamer trap binding step_hash"))?,
        park_owner: park_owner.ok_or(invalid_trap("missing dreamer trap binding park_owner"))?,
    }))
}

pub(super) fn trap_binding_delete_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    anchor: &EntityId,
) -> Result<()> {
    vault
        .store
        .vault_meta
        .delete(wtxn, &trap_binding_key(anchor))?;
    Ok(())
}
