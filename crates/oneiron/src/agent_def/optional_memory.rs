//! How much optional recall a reader takes, per task family (ZERO-RETRIEVAL
//! = A, ARCH-0004 #reader-budget).
//!
//! Held-out outcomes for the actual reader and task pick the setting; zero
//! optional memory is always a candidate. The value carries no authority,
//! scope or disclosure field: it can only narrow what a caller asked for.
//! Pinned rows and mandatory instructions are not optional memory and never
//! read it.

use std::collections::BTreeMap;

use crate::context_pack::FieldProfile;

pub use crate::store::agent_definition_codec::optional_memory::{
    OPTIONAL_MEMORY_BUDGET_KEYS, OPTIONAL_MEMORY_PROFILE_KEYS,
};
pub use crate::store::agent_optional_memory::{OptionalMemory, OptionalMemoryProfile};

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

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use rmpv::Value;

    use super::*;
    use crate::agent_def::{
        AgentCeiling, AgentDefinition, AgentScope, CompactionOwnership, MemoryProfile,
        decode_agent_definition, encode_agent_definition,
    };
    use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
    use crate::error::ErrorKind;
    use crate::llm::ModelTierRef;

    fn reader(optional_memory: Option<OptionalMemoryProfile>) -> AgentDefinition {
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
        .with_memory_profile(Some(window()))
        .with_optional_memory(optional_memory)
    }

    fn window() -> MemoryProfile {
        MemoryProfile::new(
            8_000,
            ModelTierRef("cheap.slm".to_owned()),
            CompactionOwnership::Engine,
        )
    }

    fn encoded_body(definition: &AgentDefinition) -> Vec<(Value, Value)> {
        let bytes = encode_agent_definition(definition).expect("encode");
        let Value::Map(entries) = rmpv::decode::read_value(&mut bytes.as_slice()).unwrap() else {
            panic!("body is not a map");
        };
        entries
    }

    fn profile_keys(definition: &AgentDefinition) -> Vec<String> {
        let Some((_, Value::Map(profile))) = encoded_body(definition)
            .into_iter()
            .find(|(key, _)| key.as_str() == Some("memory_profile"))
        else {
            panic!("memory_profile is not a map");
        };
        profile
            .iter()
            .filter_map(|(key, _)| key.as_str().map(str::to_owned))
            .collect()
    }

    fn body_bytes(entries: Vec<(Value, Value)>) -> Vec<u8> {
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &Value::Map(entries)).unwrap();
        bytes
    }

    /// ZERO-RETRIEVAL = A (ARCH-0004 #reader-budget): "no optional memory" is
    /// its own stored value, because a pack budget of 0 means no limit, and a
    /// definition that never sets it keeps the bytes it had. The setting is
    /// the body's own last key, apart from the window profile (Engine ruling
    /// L9-32-NO-PROFILE = A), so setting it leaves the window as authored.
    #[test]
    fn no_optional_memory_is_stored_apart_from_a_zero_budget() {
        let plain = reader(None);
        assert_eq!(
            profile_keys(&plain),
            ["window_token_budget", "compaction_backend", "compaction"]
        );
        assert!(
            encoded_body(&plain)
                .iter()
                .all(|(key, _)| key.as_str() != Some("optional_memory")),
            "an unset choice is elided"
        );

        let standard = OptionalMemory::Budget {
            tokens: NonZeroU64::new(4_096).unwrap(),
            view: FieldProfile::Standard,
        };
        let picked = OptionalMemoryProfile::new(standard)
            .with_family("event_ordering", OptionalMemory::None);
        let definition = reader(Some(picked.clone()));
        assert_eq!(
            profile_keys(&definition),
            profile_keys(&plain),
            "the window profile is untouched"
        );
        assert_eq!(
            encoded_body(&definition).last().unwrap().0.as_str(),
            Some("optional_memory")
        );
        let decoded =
            decode_agent_definition(&encode_agent_definition(&definition).unwrap()).unwrap();
        assert_eq!(decoded.memory_profile, Some(window()));
        let carried = decoded.optional_memory.unwrap();
        assert_eq!(carried, picked);
        assert_eq!(
            carried.for_family(Some("event_ordering")),
            OptionalMemory::None
        );
        assert_eq!(carried.for_family(Some("unlisted")), standard);
        assert_eq!(carried.for_family(None), standard);

        let mut zero = encoded_body(&definition);
        let (_, Value::Map(stored)) = zero.last_mut().unwrap() else {
            panic!("optional_memory is not a map");
        };
        stored[0].1 = Value::Map(vec![
            (Value::from("tokens"), Value::from(0_u64)),
            (Value::from("view"), Value::from("standard")),
        ]);
        assert_eq!(
            decode_agent_definition(&body_bytes(zero))
                .expect_err("a 0 budget is no limit")
                .kind(),
            ErrorKind::InvalidAgentDefBody
        );

        // Sol #1523 F2: the key out of its pinned place would decode and
        // re-encode to other bytes.
        let mut first = encoded_body(&definition);
        first.rotate_right(1);
        assert_eq!(
            decode_agent_definition(&body_bytes(first))
                .expect_err("optional_memory comes last")
                .kind(),
            ErrorKind::InvalidAgentDefBody
        );
    }

    /// The window profile no longer carries the key: a body that nests it
    /// under `memory_profile`, as before the lift, is refused.
    #[test]
    fn a_nested_optional_memory_key_is_refused() {
        let definition = reader(Some(OptionalMemoryProfile::new(OptionalMemory::None)));
        let mut entries = encoded_body(&definition);
        let (_, choice) = entries.pop().unwrap();
        let (_, Value::Map(profile)) = entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("memory_profile"))
            .unwrap()
        else {
            panic!("memory_profile is not a map");
        };
        profile.push((Value::from("optional_memory"), choice));
        assert_eq!(
            decode_agent_definition(&body_bytes(entries))
                .expect_err("not a memory_profile key")
                .kind(),
            ErrorKind::InvalidAgentDefBody
        );
    }
}
