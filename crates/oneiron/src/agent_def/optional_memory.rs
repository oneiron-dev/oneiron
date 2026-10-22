//! How much optional recall a reader takes, per task family (ZERO-RETRIEVAL
//! = A, ARCH-0004 #reader-budget).
//!
//! Held-out outcomes for the actual reader and task pick the setting; zero
//! optional memory is always a candidate. The value carries no authority,
//! scope or disclosure field: it can only narrow what a caller asked for.
//! Pinned rows and mandatory instructions are not optional memory and never
//! read it.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use rmpv::Value;

use super::decode::validate_text_field;
use super::types::AGENT_REF_KEY_MAX_BYTES;
use crate::context_pack::FieldProfile;
use crate::error::{ArtifactError, Error, Result};

/// The pinned sub-map keys for an [`OptionalMemoryProfile`], in encode order.
pub const OPTIONAL_MEMORY_PROFILE_KEYS: [&str; 2] = ["default", "families"];

/// The pinned sub-map keys for an [`OptionalMemory::Budget`], in encode order.
pub const OPTIONAL_MEMORY_BUDGET_KEYS: [&str; 2] = ["tokens", "view"];

/// The encoded form of [`OptionalMemory::None`].
const NONE: &str = "none";

/// One reader's optional recall for one task family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionalMemory {
    /// No optional recall. Not a budget of 0, which means no limit.
    None,
    /// At most `tokens` of optional recall, at `view` detail or less.
    Budget {
        tokens: NonZeroU64,
        view: FieldProfile,
    },
}

impl OptionalMemory {
    /// Narrows a caller's pack budget (0 is no limit) and view. `None` means
    /// the pack takes no optional recall at all. The caller's smaller budget
    /// and narrower view always win: a profile never widens a request.
    #[must_use]
    pub fn narrow(
        self,
        caller_tokens: usize,
        caller_view: FieldProfile,
    ) -> Option<(usize, FieldProfile)> {
        let Self::Budget { tokens, view } = self else {
            return None;
        };
        let tokens = usize::try_from(tokens.get()).unwrap_or(usize::MAX);
        let tokens = if caller_tokens == 0 {
            tokens
        } else {
            caller_tokens.min(tokens)
        };
        Some((tokens, narrower_view(caller_view, view)))
    }
}

const fn view_rank(view: FieldProfile) -> u8 {
    match view {
        FieldProfile::Minimal => 0,
        FieldProfile::Standard => 1,
        FieldProfile::Full => 2,
    }
}

const fn narrower_view(a: FieldProfile, b: FieldProfile) -> FieldProfile {
    if view_rank(b) < view_rank(a) { b } else { a }
}

/// A reader's optional recall: a default, and the task families that differ.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OptionalMemoryProfile {
    pub default: OptionalMemory,
    pub families: BTreeMap<String, OptionalMemory>,
}

impl OptionalMemoryProfile {
    #[must_use]
    pub const fn new(default: OptionalMemory) -> Self {
        Self {
            default,
            families: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_family(mut self, family: impl Into<String>, choice: OptionalMemory) -> Self {
        self.families.insert(family.into(), choice);
        self
    }

    /// The setting for `family`; no family, or one not listed, is the default.
    #[must_use]
    pub fn for_family(&self, family: Option<&str>) -> OptionalMemory {
        family
            .and_then(|family| self.families.get(family))
            .copied()
            .unwrap_or(self.default)
    }
}

/// Encodes the sub-map, with `families` elided when empty.
pub(super) fn encode_optional_memory_profile(profile: &OptionalMemoryProfile) -> Value {
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
pub(super) fn decode_optional_memory_profile(value: &Value) -> Result<OptionalMemoryProfile> {
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
                "optional_memory family names must be non-empty and at most 256 bytes",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_def::{
        AgentCeiling, AgentDefinition, AgentScope, CompactionOwnership, MemoryProfile,
        decode_agent_definition, encode_agent_definition,
    };
    use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
    use crate::error::ErrorKind;
    use crate::llm::ModelTierRef;

    fn reader(profile: MemoryProfile) -> AgentDefinition {
        AgentDefinition::new(
            "oneiron.agent.reader",
            "Optional-memory reader fixture",
            "1.0.0",
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            AgentScope::All,
            AgentCeiling::Proposed,
            None,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
            ClaimSource::UserStated,
            1.0,
            false,
            true,
            Value::Map(vec![(Value::from("definedVia"), Value::from("test"))]),
            None,
            true,
            None,
        )
        .with_memory_profile(Some(profile))
    }

    fn window() -> MemoryProfile {
        MemoryProfile::new(
            8_000,
            ModelTierRef("cheap.slm".to_owned()),
            CompactionOwnership::Engine,
        )
    }

    fn encoded_profile(definition: &AgentDefinition) -> Vec<(Value, Value)> {
        let bytes = encode_agent_definition(definition).expect("encode");
        let Value::Map(entries) = rmpv::decode::read_value(&mut bytes.as_slice()).unwrap() else {
            panic!("body is not a map");
        };
        let Some((_, Value::Map(profile))) = entries
            .into_iter()
            .find(|(key, _)| key.as_str() == Some("memory_profile"))
        else {
            panic!("memory_profile is not a map");
        };
        profile
    }

    /// ZERO-RETRIEVAL = A (ARCH-0004 #reader-budget): "no optional memory" is
    /// its own stored value, because a pack budget of 0 means no limit, and a
    /// profile that never sets it keeps the bytes it had.
    #[test]
    fn no_optional_memory_is_stored_apart_from_a_zero_budget() {
        let plain = encoded_profile(&reader(window()));
        let keys: Vec<_> = plain.iter().filter_map(|(key, _)| key.as_str()).collect();
        assert_eq!(
            keys,
            ["window_token_budget", "compaction_backend", "compaction"]
        );

        let standard = OptionalMemory::Budget {
            tokens: NonZeroU64::new(4_096).unwrap(),
            view: FieldProfile::Standard,
        };
        let picked = OptionalMemoryProfile::new(standard)
            .with_family("event_ordering", OptionalMemory::None);
        let definition = reader(window().with_optional_memory(picked.clone()));
        let decoded =
            decode_agent_definition(&encode_agent_definition(&definition).unwrap()).unwrap();
        let carried = decoded.memory_profile.unwrap().optional_memory.unwrap();
        assert_eq!(carried, picked);
        assert_eq!(
            carried.for_family(Some("event_ordering")),
            OptionalMemory::None
        );
        assert_eq!(carried.for_family(Some("unlisted")), standard);
        assert_eq!(carried.for_family(None), standard);

        let mut zero = encoded_profile(&definition);
        let (_, Value::Map(stored)) = zero.last_mut().unwrap() else {
            panic!("optional_memory is not a map");
        };
        stored[0].1 = Value::Map(vec![
            (Value::from("tokens"), Value::from(0_u64)),
            (Value::from("view"), Value::from("standard")),
        ]);
        let with_profile = |profile: Vec<(Value, Value)>| {
            let mut body = rmpv::decode::read_value(
                &mut encode_agent_definition(&definition).unwrap().as_slice(),
            )
            .unwrap();
            let Value::Map(fields) = &mut body else {
                unreachable!()
            };
            fields
                .iter_mut()
                .find(|(key, _)| key.as_str() == Some("memory_profile"))
                .unwrap()
                .1 = Value::Map(profile);
            let mut bytes = Vec::new();
            rmpv::encode::write_value(&mut bytes, &body).unwrap();
            bytes
        };
        assert_eq!(
            decode_agent_definition(&with_profile(zero))
                .expect_err("a 0 budget is no limit")
                .kind(),
            ErrorKind::InvalidAgentDefBody
        );

        // Sol #1523 F2: the key out of its pinned place would decode and
        // re-encode to other bytes.
        let mut first = encoded_profile(&definition);
        first.rotate_right(1);
        assert_eq!(
            decode_agent_definition(&with_profile(first))
                .expect_err("optional_memory comes last")
                .kind(),
            ErrorKind::InvalidAgentDefBody
        );
    }
}
