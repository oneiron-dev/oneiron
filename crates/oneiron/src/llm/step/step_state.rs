//! Device-local step progression rows (Started/ResponseReceived/Logged) in vault_meta.

use super::codec::{expect_key, expect_map, expect_u64, invalid_step, pinned_key_index};
use super::types::{
    DREAMER_PRIVATE_STEP_STATE_PREFIX, DREAMER_STEP_STATE_KEYS, DREAMER_STEP_STATE_SCHEMA_VERSION,
    KEY_PROGRESSION, KEY_RESPONSE, KEY_SCHEMA_VERSION, KEY_STARTED_AT, KEY_UPDATED_AT,
    StepProgression,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::error::Result;
use rmpv::Value;

// ---------------------------------------------------------------------------
// Private step-state rows (device-local live progression)
// ---------------------------------------------------------------------------
pub(super) struct StepStateRow {
    pub(super) progression: StepProgression,
    pub(super) started_at: u64,
    pub(super) updated_at: u64,
    pub(super) response_payload: Option<Vec<u8>>,
}

fn step_state_key(attempt_id: AttemptId, step_hash: &[u8; 32]) -> Vec<u8> {
    let mut key =
        Vec::with_capacity(DREAMER_PRIVATE_STEP_STATE_PREFIX.len() + 16 + step_hash.len());
    key.extend_from_slice(DREAMER_PRIVATE_STEP_STATE_PREFIX);
    key.extend_from_slice(attempt_id.as_bytes());
    key.extend_from_slice(step_hash);
    key
}

pub(super) fn step_state_write(
    vault: &Vault,
    attempt_id: AttemptId,
    step_hash: &[u8; 32],
    progression: StepProgression,
    response_payload: Option<&[u8]>,
    now_ms: u64,
) -> Result<()> {
    let started_at =
        step_state_read(vault, attempt_id, step_hash)?.map_or(now_ms, |row| row.started_at);
    let mut wtxn = vault.store.env.write_txn()?;
    step_state_put_in_txn(
        vault,
        &mut wtxn,
        attempt_id,
        step_hash,
        &StepStateRow {
            progression,
            started_at,
            updated_at: now_ms,
            response_payload: response_payload.map(<[u8]>::to_vec),
        },
    )?;
    wtxn.commit()?;
    Ok(())
}

pub(super) fn step_state_put_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt_id: AttemptId,
    step_hash: &[u8; 32],
    row: &StepStateRow,
) -> Result<()> {
    let mut entries = vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_STEP_STATE_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_PROGRESSION),
            Value::from(u64::from(row.progression.as_u8())),
        ),
        (Value::from(KEY_STARTED_AT), Value::from(row.started_at)),
        (Value::from(KEY_UPDATED_AT), Value::from(row.updated_at)),
    ];
    if let Some(payload) = &row.response_payload {
        entries.push((Value::from(KEY_RESPONSE), Value::Binary(payload.clone())));
    }
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &Value::Map(entries))
        .map_err(|_| invalid_step("dreamer step state row MessagePack encode failed"))?;
    vault
        .store
        .vault_meta
        .put(wtxn, &step_state_key(attempt_id, step_hash), &encoded)?;
    Ok(())
}

pub(super) fn step_state_read(
    vault: &Vault,
    attempt_id: AttemptId,
    step_hash: &[u8; 32],
) -> Result<Option<StepStateRow>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, &step_state_key(attempt_id, step_hash))?
    else {
        return Ok(None);
    };
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(raw))
        .map_err(|_| invalid_step("dreamer step state row MessagePack decode failed"))?;
    let entries = expect_map(&value, "dreamer step state row must be a MessagePack map")?;

    let mut schema_version = None;
    let mut progression = None;
    let mut started_at = None;
    let mut updated_at = None;
    let mut response_payload = None;
    let mut seen = [false; DREAMER_STEP_STATE_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer step state row keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_STEP_STATE_KEYS)
            .ok_or(invalid_step("dreamer step state row key is not pinned"))?;
        if seen[index] {
            return Err(invalid_step("duplicate dreamer step state row key"));
        }
        seen[index] = true;

        match DREAMER_STEP_STATE_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer step state schema_version must be an integer",
                )?);
            }
            KEY_PROGRESSION => {
                let raw = expect_u64(value, "dreamer step state progression must be an integer")?;
                let raw = u8::try_from(raw)
                    .map_err(|_| invalid_step("dreamer step state progression out of range"))?;
                progression = Some(
                    StepProgression::from_u8(raw)
                        .ok_or(invalid_step("unknown dreamer step state progression"))?,
                );
            }
            KEY_STARTED_AT => {
                started_at = Some(expect_u64(
                    value,
                    "dreamer step state started_at must be an integer",
                )?);
            }
            KEY_UPDATED_AT => {
                updated_at = Some(expect_u64(
                    value,
                    "dreamer step state updated_at must be an integer",
                )?);
            }
            KEY_RESPONSE => {
                let Value::Binary(bytes) = value else {
                    return Err(invalid_step("dreamer step state response must be binary"));
                };
                response_payload = Some(bytes.clone());
            }
            _ => unreachable!("index resolved from DREAMER_STEP_STATE_KEYS"),
        }
    }

    let schema_version =
        schema_version.ok_or(invalid_step("missing dreamer step state schema_version"))?;
    if schema_version != DREAMER_STEP_STATE_SCHEMA_VERSION {
        return Err(invalid_step(
            "unsupported dreamer step state schema_version",
        ));
    }

    Ok(Some(StepStateRow {
        progression: progression.ok_or(invalid_step("missing dreamer step state progression"))?,
        started_at: started_at.ok_or(invalid_step("missing dreamer step state started_at"))?,
        updated_at: updated_at.ok_or(invalid_step("missing dreamer step state updated_at"))?,
        response_payload,
    }))
}

pub(super) fn step_state_delete(
    vault: &Vault,
    attempt_id: AttemptId,
    step_hash: &[u8; 32],
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .vault_meta
        .delete(&mut wtxn, &step_state_key(attempt_id, step_hash))?;
    wtxn.commit()?;
    Ok(())
}
