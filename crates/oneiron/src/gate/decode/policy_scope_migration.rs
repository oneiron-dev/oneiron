//! Explicit schema-1.1 selector migration and schema-1.2 stored Scope normalization.
//!
//! This runs only at storage materialization and the one-time open sweep. Live
//! decoding never derives authority from selectors. Invalid/unsupported manifests
//! retain their original bytes so resolution keeps its fail-closed diagnostics.

use std::io::Cursor;

use rmpv::Value;

use crate::federation::scope_codec::{
    decode_scope_value, effect_preset, encode_scope_value, legacy_read_scope,
};
use crate::gate::constants::{
    GRANT_EFFECTOR_KEY, GRANT_SCOPE_KEY, GRANT_SELECTORS_KEY, LEGACY_POLICY_SCOPE_SCHEMA_VERSION,
    POLICY_SCHEMA_VERSION, POLICY_SCHEMA_VERSION_KEY, POLICY_SCOPED_GRANTS_KEY,
    SCOPED_READ_EFFECTOR_CORE_READ, SCOPED_READ_EFFECTOR_ONEIRON_READ,
};

use super::decode_manifest::decode_policy_manifest;
use super::decode_map_util::{MapValue, optional_value, required_string, single_map_value};

/// Returns replacement bytes only for a fully decoded, explicitly versioned
/// manifest. `None` means preserve the input, not replace it with default policy.
pub(crate) fn normalize_policy_manifest_scope(data: &[u8]) -> Option<Vec<u8>> {
    let mut cursor = Cursor::new(data);
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor).ok()? else {
        return None;
    };
    if cursor.position() != data.len() as u64 {
        return None;
    }
    let version = required_string(&entries, POLICY_SCHEMA_VERSION_KEY)?;
    if version != POLICY_SCHEMA_VERSION && version != LEGACY_POLICY_SCOPE_SCHEMA_VERSION {
        return None;
    }
    // Check duplicates before taking mutable references. The full decoder below
    // validates the remaining envelope and grant fields without dropping data.
    if matches!(
        single_map_value(&entries, POLICY_SCOPED_GRANTS_KEY),
        MapValue::Duplicate
    ) {
        return None;
    }
    for (key, value) in &mut entries {
        match key.as_str()? {
            POLICY_SCHEMA_VERSION_KEY => *value = POLICY_SCHEMA_VERSION.into(),
            POLICY_SCOPED_GRANTS_KEY => {
                let Value::Array(rows) = value else {
                    return None;
                };
                for row in rows {
                    let Value::Map(grant) = row else {
                        return None;
                    };
                    if version == LEGACY_POLICY_SCOPE_SCHEMA_VERSION {
                        upgrade_legacy_grant(grant)?;
                    } else {
                        let scope = match single_map_value(grant, GRANT_SCOPE_KEY) {
                            MapValue::Present(value) => decode_scope_value(value).ok()?,
                            MapValue::Missing | MapValue::Duplicate => return None,
                        };
                        let canonical = encode_scope_value(&scope).ok()?;
                        for (key, value) in grant {
                            if key.as_str() == Some(GRANT_SCOPE_KEY) {
                                *value = canonical.clone();
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).ok()?;
    decode_policy_manifest(&out)?;
    (out != data).then_some(out)
}

fn upgrade_legacy_grant(entries: &mut Vec<(Value, Value)>) -> Option<()> {
    // A caller cannot mix the new selectors field or six-axis keys into an old
    // envelope and acquire a preset. Only the explicit old vocabulary migrates.
    if !matches!(
        single_map_value(entries, GRANT_SELECTORS_KEY),
        MapValue::Missing
    ) {
        return None;
    }
    let effector = required_string(entries, GRANT_EFFECTOR_KEY)?;
    let selectors = optional_value(entries, GRANT_SCOPE_KEY)?;
    let scope = if matches!(
        effector.trim(),
        SCOPED_READ_EFFECTOR_CORE_READ | SCOPED_READ_EFFECTOR_ONEIRON_READ
    ) {
        legacy_read_scope(selectors.as_ref())?
    } else {
        match selectors.as_ref() {
            None | Some(Value::Nil) => {}
            Some(Value::Map(rows)) => {
                for (key, _) in rows {
                    if !matches!(
                        key.as_str()?,
                        "verb"
                            | "channel"
                            | "channel_ref"
                            | "channelRef"
                            | "policy_risk"
                            | "policyRisk"
                    ) {
                        return None;
                    }
                }
            }
            _ => return None,
        }
        effect_preset()
    };
    for (key, _) in entries.iter_mut() {
        if key.as_str() == Some(GRANT_SCOPE_KEY) {
            *key = GRANT_SELECTORS_KEY.into();
        }
    }
    entries.push((GRANT_SCOPE_KEY.into(), encode_scope_value(&scope).ok()?));
    Some(())
}

#[cfg(test)]
mod tests;
