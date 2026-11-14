//! Moved from `crates/oneiron/src/connector_key/slate.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::connector_key::slate::ELICITATION_ROW_KEY;
pub use oneiron_verb_wire::connector_key::slate::SlateCapability;
pub use oneiron_verb_wire::connector_key::slate::SlatePackSource;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// ARCH-0054's one aggregate, with the slate's two named inputs: the
/// manifest hash and the grant hash.
pub const SLATE_STAMP_DOMAIN: &[u8] = b"connector-grant-slate-stamp-v1";

pub const SLATE_GRANT_DOMAIN: &[u8] = b"connector-grant-slate-grant-v1";

pub fn invalid() -> Error {
    Error::InvalidConfig("invalid typed connector grant slate".to_owned())
}

/// The holder's own facet narrowing, kept beside the owner's limit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlateFacetNarrow {
    pub facets: BTreeSet<EntityId>,
    pub actor: String,
    pub at: u64,
}

/// A dropped facet limit, or a facet the old limit lacked, widens the Grant.
pub fn facets_widen(old: Option<&BTreeSet<EntityId>>, next: Option<&BTreeSet<EntityId>>) -> bool {
    match (old, next) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(old), Some(next)) => !next.is_subset(old),
    }
}

/// Only a provable restriction carries consent. Anything unknown re-asks.
/// Manifest drift reads the same judgment (FIX 2604).
pub fn schema_narrows(old: Option<&serde_json::Value>, next: Option<&serde_json::Value>) -> bool {
    let (Some(old), Some(next)) = (old, next) else {
        return old == next;
    };
    if old == next {
        return true;
    }
    let (Some(a), Some(b)) = (old.as_object(), next.as_object()) else {
        return false;
    };
    if a.get("type") != b.get("type") || a.get("default") != b.get("default") {
        return false;
    }
    if a.get("additionalProperties") != b.get("additionalProperties") {
        return false;
    }
    let (Some(ap), Some(bp)) = (
        a.get("properties").and_then(|v| v.as_object()),
        b.get("properties").and_then(|v| v.as_object()),
    ) else {
        return false;
    };
    if bp.keys().collect::<BTreeSet<_>>() != ap.keys().collect::<BTreeSet<_>>() {
        return false;
    }
    let required = |obj: &serde_json::Map<String, serde_json::Value>| -> Option<BTreeSet<String>> {
        obj.get("required")
            .map_or(Some(&[][..]), |v| v.as_array().map(Vec::as_slice))?
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<BTreeSet<_>>>()
    };
    let (Some(ar), Some(br)) = (required(a), required(b)) else {
        return false;
    };
    if !ar.is_subset(&br) {
        return false;
    }
    if a.keys().any(|k| {
        !matches!(
            k.as_str(),
            "type" | "default" | "properties" | "required" | "additionalProperties"
        )
    }) || b.keys().any(|k| {
        !matches!(
            k.as_str(),
            "type" | "default" | "properties" | "required" | "additionalProperties"
        )
    }) {
        return false;
    }
    ap.iter().all(|(name, prior)| {
        let Some(current) = bp.get(name) else {
            return false;
        };
        if current == prior {
            return true;
        }
        let (Some(x), Some(y)) = (prior.as_object(), current.as_object()) else {
            return false;
        };
        if x.get("type") != y.get("type") || x.get("default") != y.get("default") {
            return false;
        }
        let (Some(xe), Some(ye)) = (
            x.get("enum").and_then(|v| v.as_array()),
            y.get("enum").and_then(|v| v.as_array()),
        ) else {
            return false;
        };
        x.keys()
            .all(|k| matches!(k.as_str(), "type" | "default" | "enum"))
            && y.keys()
                .all(|k| matches!(k.as_str(), "type" | "default" | "enum"))
            && ye.iter().all(|value| xe.contains(value))
    })
}

pub fn is_resolved_schema(value: &serde_json::Value) -> bool {
    let Some(schema) = value.as_object() else {
        return false;
    };
    // Unions stay in a resolved schema, each variant resolved; the call
    // validator reads them (outbound_consent/tool_schema.rs).
    if schema
        .keys()
        .any(|key| matches!(key.as_str(), "$ref" | "allOf"))
    {
        return false;
    }
    for key in ["anyOf", "oneOf", "prefixItems"] {
        if let Some(value) = schema.get(key)
            && !value.as_array().is_some_and(|variants| {
                variants
                    .iter()
                    .all(|variant| variant.is_boolean() || is_resolved_schema(variant))
            })
        {
            return false;
        }
    }
    // Names under `properties` are caller-chosen parameter names, not schema
    // operators. Values in defaults/const/enums are instance data; never
    // interpret their object keys as `$ref` or composition keywords.
    for key in [
        "properties",
        "patternProperties",
        "$defs",
        "definitions",
        "dependentSchemas",
    ] {
        if let Some(value) = schema.get(key) {
            let Some(entries) = value.as_object() else {
                return false;
            };
            if !entries.values().all(is_resolved_schema) {
                return false;
            }
        }
    }
    for key in [
        "items",
        "additionalProperties",
        "unevaluatedProperties",
        "contains",
        "not",
        "if",
        "then",
        "else",
        "propertyNames",
    ] {
        if let Some(value) = schema.get(key) {
            if value.is_boolean() {
                continue;
            }
            if key == "items" && value.is_array() {
                if !value
                    .as_array()
                    .is_some_and(|items| items.iter().all(is_resolved_schema))
                {
                    return false;
                }
            } else if !is_resolved_schema(value) {
                return false;
            }
        }
    }
    true
}
