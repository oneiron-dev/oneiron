//! The AGENT_DEF memory profile's `optional_memory` sub-map codec
//! (ZERO-RETRIEVAL = A): the pinned-key encode and the strict decode.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use rmpv::Value;

use crate::error::{ArtifactError, Error, Result};
use crate::store::agent_manifest::validate_text_field;
use crate::store::agent_optional_memory::{OptionalMemory, OptionalMemoryProfile};
use crate::store::agent_record::AGENT_REF_KEY_MAX_BYTES;
use crate::store::context_field_profile::FieldProfile;

/// The pinned sub-map keys for an [`OptionalMemoryProfile`], in encode order.
pub const OPTIONAL_MEMORY_PROFILE_KEYS: [&str; 2] = ["default", "families"];

/// The pinned sub-map keys for an [`OptionalMemory::Budget`], in encode order.
pub const OPTIONAL_MEMORY_BUDGET_KEYS: [&str; 2] = ["tokens", "view"];

/// The encoded form of [`OptionalMemory::None`].
const NONE: &str = "none";

/// Encodes the sub-map, with `families` elided when empty.
pub(crate) fn encode_optional_memory_profile(profile: &OptionalMemoryProfile) -> Value {
    let mut entries = vec![(
        Value::from(OPTIONAL_MEMORY_PROFILE_KEYS[0]),
        encode_choice(profile.default),
    )];
    if !profile.families.is_empty() {
        entries.push((
            Value::from(OPTIONAL_MEMORY_PROFILE_KEYS[1]),
            Value::Map(
                profile
                    .families
                    .iter()
                    .map(|(family, choice)| (Value::from(family.as_str()), encode_choice(*choice)))
                    .collect(),
            ),
        ));
    }
    Value::Map(entries)
}

fn encode_choice(choice: OptionalMemory) -> Value {
    match choice {
        OptionalMemory::None => Value::from(NONE),
        OptionalMemory::Budget { tokens, view } => Value::Map(vec![
            (
                Value::from(OPTIONAL_MEMORY_BUDGET_KEYS[0]),
                Value::from(tokens.get()),
            ),
            (
                Value::from(OPTIONAL_MEMORY_BUDGET_KEYS[1]),
                Value::from(view_name(view)),
            ),
        ]),
    }
}

const fn view_name(view: FieldProfile) -> &'static str {
    match view {
        FieldProfile::Minimal => "summary",
        FieldProfile::Standard => "standard",
        FieldProfile::Full => "full",
    }
}

fn invalid(context: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidAgentDefBody(context))
}

/// Strict decode, in the same discipline as the parent map: unknown,
/// duplicate and out-of-order keys are refused, so a decoded profile always
/// re-encodes to the same bytes.
pub(crate) fn decode_optional_memory_profile(value: &Value) -> Result<OptionalMemoryProfile> {
    let entries = pinned_entries(
        value,
        &OPTIONAL_MEMORY_PROFILE_KEYS,
        "optional_memory must be a map of default and families, in that order",
    )?;
    let mut profile = None;
    let mut families = BTreeMap::new();
    for (key, value) in entries {
        if key == OPTIONAL_MEMORY_PROFILE_KEYS[0] {
            profile = Some(decode_choice(value)?);
            continue;
        }
        let Value::Map(rows) = value else {
            return Err(invalid("optional_memory families must be a map"));
        };
        if rows.is_empty() {
            return Err(invalid(
                "optional_memory families must hold at least one entry (elide it when empty)",
            ));
        }
        let mut previous: Option<&str> = None;
        for (family, choice) in rows {
            let family = family
                .as_str()
                .ok_or_else(|| invalid("optional_memory family names must be strings"))?;
            validate_text_field(
                family,
                AGENT_REF_KEY_MAX_BYTES,
                "optional_memory family names must be non-empty",
            )?;
            if previous.is_some_and(|previous| previous >= family) {
                return Err(invalid(
                    "optional_memory families must be unique and in ascending order",
                ));
            }
            previous = Some(family);
            families.insert(family.to_owned(), decode_choice(choice)?);
        }
    }
    let default = profile.ok_or_else(|| invalid("missing required optional_memory key default"))?;
    Ok(OptionalMemoryProfile { default, families })
}

fn decode_choice(value: &Value) -> Result<OptionalMemory> {
    if let Some(text) = value.as_str() {
        return if text == NONE {
            Ok(OptionalMemory::None)
        } else {
            Err(invalid(
                "an optional memory choice must be \"none\" or a budget map",
            ))
        };
    }
    let entries = pinned_entries(
        value,
        &OPTIONAL_MEMORY_BUDGET_KEYS,
        "an optional memory budget must be a map of tokens and view, in that order",
    )?;
    if entries.len() != OPTIONAL_MEMORY_BUDGET_KEYS.len() {
        return Err(invalid(
            "an optional memory budget needs both tokens and view",
        ));
    }
    let tokens = entries[0]
        .1
        .as_u64()
        .and_then(NonZeroU64::new)
        // A pack budget of 0 means no limit: "no optional memory" is `none`.
        .ok_or_else(|| invalid("optional memory tokens must be a positive integer"))?;
    let view = match entries[1].1.as_str() {
        Some("summary") => FieldProfile::Minimal,
        Some("standard") => FieldProfile::Standard,
        Some("full") => FieldProfile::Full,
        _ => {
            return Err(invalid(
                "optional memory view must be one of summary|standard|full",
            ));
        }
    };
    Ok(OptionalMemory::Budget { tokens, view })
}

/// The map's entries, each key one of `keys` and in `keys` order (so neither
/// unknown nor duplicate).
fn pinned_entries<'v>(
    value: &'v Value,
    keys: &[&'static str],
    context: &'static str,
) -> Result<Vec<(&'static str, &'v Value)>> {
    let Value::Map(entries) = value else {
        return Err(invalid(context));
    };
    let mut next = 0;
    let mut out = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let index = key
            .as_str()
            .and_then(|key| keys.iter().position(|known| *known == key))
            .filter(|index| *index >= next)
            .ok_or_else(|| invalid(context))?;
        next = index + 1;
        out.push((keys[index], value));
    }
    Ok(out)
}
