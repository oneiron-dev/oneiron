//! The AGENT_DEF memory profile's `optional_memory` sub-map codec
//! (ZERO-RETRIEVAL = A): the pinned-key encode and the strict decode.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use rmpv::Value;

use crate::agent_manifest::validate_text_field;
use crate::agent_record::AGENT_REF_KEY_MAX_BYTES;
use crate::context_field_profile::FieldProfile;
use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

/// The pinned sub-map keys for an [`OptionalMemoryProfile`], in encode order.
pub const OPTIONAL_MEMORY_PROFILE_KEYS: [&str; 2] = ["default", "families"];

/// The pinned sub-map keys for an [`OptionalMemory::Budget`], in encode order.
pub const OPTIONAL_MEMORY_BUDGET_KEYS: [&str; 2] = ["tokens", "view"];

/// The encoded form of [`OptionalMemory::None`].
pub const NONE: &str = "none";

pub const fn view_name(view: FieldProfile) -> &'static str {
    match view {
        FieldProfile::Minimal => "summary",
        FieldProfile::Standard => "standard",
        FieldProfile::Full => "full",
    }
}

pub fn invalid(context: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidAgentDefBody(context))
}

/// The map's entries, each key one of `keys` and in `keys` order (so neither
/// unknown nor duplicate).
pub fn pinned_entries<'v>(
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
