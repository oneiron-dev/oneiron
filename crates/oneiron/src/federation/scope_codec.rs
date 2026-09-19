//! Canonical MessagePack bridge for six-axis Scope positions and grant presets.
use super::{Scope, ScopeAxis, ScopeId};
use crate::error::{Error, Result};
use rmpv::Value;
use std::collections::BTreeSet;

pub(crate) fn encode_scope_value(scope: &Scope) -> Result<Value> {
    let bytes =
        rmp_serde::to_vec_named(scope).map_err(|_| Error::InvalidClaimBody("scope encoding"))?;
    rmpv::decode::read_value(&mut bytes.as_slice())
        .map_err(|_| Error::InvalidClaimBody("scope encoding"))
}
pub(crate) fn decode_scope_value(value: &Value) -> Result<Scope> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| Error::InvalidClaimBody("scope encoding"))?;
    rmp_serde::from_slice(&bytes).map_err(|_| Error::InvalidClaimBody("invalid six-axis scope"))
}
pub(crate) fn read_preset() -> Scope {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    scope
}
pub(crate) fn effect_preset() -> Scope {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["effect".to_owned()]));
    scope
}
/// Explicit upgrade for old manifest selectors. This is never the decoder for
/// a six-axis object: malformed new axes must remain bottom or an error.
pub(crate) fn legacy_read_scope(value: Option<&Value>) -> Option<Scope> {
    let mut out = read_preset();
    let entries = match value {
        None | Some(Value::Nil) => return Some(out),
        Some(Value::Map(entries)) => entries,
        _ => return None,
    };
    for (k, v) in entries {
        match k.as_str()? {
            "world" | "world_ref" | "worldRef" => {
                let id = if v.as_str() == Some("base") || matches!(v, Value::Nil) {
                    crate::claim::base_world_id()
                } else {
                    id(v)?
                };
                out.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(id)]));
            }
            "entity_types" => {
                let Value::Array(values) = v else {
                    return None;
                };
                out.bands = ScopeAxis::Some(
                    values
                        .iter()
                        .map(|v| u8::try_from(v.as_u64()?).ok())
                        .collect::<Option<_>>()?,
                );
            }
            "max_sensitivity_band" => {
                out.sensitivity = super::SensitivityCeiling::AtMost(match v.as_u64()? {
                    0 => super::Sensitivity::Public,
                    1 => super::Sensitivity::Private,
                    2 => super::Sensitivity::Sensitive,
                    3 => super::Sensitivity::Restricted,
                    _ => return None,
                });
            }
            "scopeProjectId" => out.audience = ScopeAxis::Some(BTreeSet::from([ScopeId(id(v)?)])),
            // Legacy constraints are still checked conjunctively by their owning door.
            "facet" | "facet_ref" | "facetRef" | "claim_scope" | "claimScope" | "scope"
            | "include_stale" | "min_confidence" | "min_salience" => {}
            _ => return None,
        }
    }
    Some(out)
}
fn id(v: &Value) -> Option<crate::EntityId> {
    match v {
        Value::Binary(bytes) => crate::EntityId::from_bytes(bytes.as_slice().try_into().ok()?).ok(),
        _ => crate::EntityId::from_hex(v.as_str()?).ok(),
    }
}
