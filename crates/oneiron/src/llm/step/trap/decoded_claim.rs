//! Decoded trap claim values: the decoded struct and its fail-closed MessagePack decoder.

use super::*;

pub(in crate::llm::step) struct DecodedTrapClaim {
    pub(in crate::llm::step) at: u64,
    pub(crate) kind: DreamerTrapKind,
    pub(crate) attempt_id: AttemptId,
    pub(crate) step_hash: [u8; 32],
    pub(crate) state: DreamerTrapState,
    pub(crate) note: String,
}

/// Fail-closed `dreamer.trap` claim value decode: pinned keys only, no
/// duplicates, schema-version checked, every field mandatory.
pub(in crate::llm::step) fn decode_trap_claim_value(value: &Value) -> Result<DecodedTrapClaim> {
    let entries = expect_map(value, "dreamer trap value must be a MessagePack map")?;
    let mut schema_version = None;
    let mut trap_kind = None;
    let mut attempt_id = None;
    let mut step_hash = None;
    let mut state = None;
    let mut at = None;
    let mut note = None;
    let mut seen = [false; DREAMER_TRAP_VALUE_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer trap value keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_TRAP_VALUE_KEYS)
            .ok_or(invalid_trap("dreamer trap value key is not pinned"))?;
        if seen[index] {
            return Err(invalid_trap("duplicate dreamer trap value key"));
        }
        seen[index] = true;

        match DREAMER_TRAP_VALUE_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer trap value schema_version must be an integer",
                )?);
            }
            KEY_TRAP_KIND => {
                let parsed = expect_string(value, "dreamer trap value trap_kind must be a string")?;
                trap_kind = Some(
                    DreamerTrapKind::parse(&parsed)
                        .ok_or(invalid_trap("unknown dreamer trap value trap_kind"))?,
                );
            }
            KEY_ATTEMPT_ID => attempt_id = Some(decode_attempt_id_value(value)?),
            KEY_STEP_HASH => {
                let hex = expect_string(value, "dreamer trap value step_hash must be a string")?;
                step_hash = Some(decode_hash_hex(&hex)?);
            }
            KEY_STATE => {
                let parsed = expect_string(value, "dreamer trap value state must be a string")?;
                state = Some(
                    DreamerTrapState::parse(&parsed)
                        .ok_or(invalid_trap("unknown dreamer trap value state"))?,
                );
            }
            KEY_AT => {
                at = Some(expect_u64(
                    value,
                    "dreamer trap value at must be an integer",
                )?);
            }
            KEY_NOTE => {
                note = Some(expect_string(
                    value,
                    "dreamer trap value note must be a string",
                )?);
            }
            _ => unreachable!("index resolved from DREAMER_TRAP_VALUE_KEYS"),
        }
    }

    let schema_version =
        schema_version.ok_or(invalid_trap("missing dreamer trap value schema_version"))?;
    if schema_version != DREAMER_TRAP_VALUE_SCHEMA_VERSION {
        return Err(invalid_trap(
            "unsupported dreamer trap value schema_version",
        ));
    }

    let at = at.ok_or(invalid_trap("missing dreamer trap value at"))?;

    Ok(DecodedTrapClaim {
        at,
        kind: trap_kind.ok_or(invalid_trap("missing dreamer trap value trap_kind"))?,
        attempt_id: attempt_id.ok_or(invalid_trap("missing dreamer trap value job_id"))?,
        step_hash: step_hash.ok_or(invalid_trap("missing dreamer trap value step_hash"))?,
        state: state.ok_or(invalid_trap("missing dreamer trap value state"))?,
        note: note.ok_or(invalid_trap("missing dreamer trap value note"))?,
    })
}
