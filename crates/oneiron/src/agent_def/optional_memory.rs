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
