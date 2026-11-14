//! Moved from `crates/oneiron/src/gate/pack_install_policy.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::write_envelope::skill_record::SkillContentHash;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackInstallPrecedence {
    NestedNarrowingHolderCappedAtVault,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackInstallRuleRow {
    pub hidden_instructions: Vec<String>,
    pub parameter_injection: Vec<String>,
    pub allowed_calls: Option<Vec<String>>,
    pub known_bad_patterns: Vec<String>,
    pub removed_hashes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HolderInstallRow {
    pub holder_ref: String,
    pub rules: PackInstallRuleRow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePackInstallPolicy {
    pub hidden_instructions: Vec<String>,
    pub parameter_injection: Vec<String>,
    pub allowed_calls: BTreeSet<String>,
    pub known_bad_patterns: Vec<String>,
    pub removed_hashes: Vec<String>,
}

/// Owner policy changes are narrowings: additions to the refusal classes and
/// an optional subset of already-allowed analyzed calls. `holder_ref` scopes
/// this narrowing to one publisher; None narrows the entire vault.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackInstallPolicyOverride {
    pub holder_ref: Option<String>,
    pub hidden_instruction_phrases: Vec<String>,
    pub parameter_description_phrases: Vec<String>,
    pub allowed_python_calls: Option<Vec<String>>,
    pub known_bad_patterns: Vec<String>,
    pub removed_hashes: Vec<String>,
}

impl From<PackInstallPolicyOverride> for PackInstallRuleRow {
    fn from(value: PackInstallPolicyOverride) -> Self {
        Self {
            hidden_instructions: value.hidden_instruction_phrases,
            parameter_injection: value.parameter_description_phrases,
            allowed_calls: value.allowed_python_calls,
            known_bad_patterns: value.known_bad_patterns,
            removed_hashes: value.removed_hashes,
        }
    }
}

impl PackInstallRuleRow {
    fn validate(&self) -> bool {
        for list in [
            &self.hidden_instructions,
            &self.parameter_injection,
            &self.known_bad_patterns,
            &self.removed_hashes,
        ] {
            if list.iter().any(|s| s.trim().is_empty() || s.len() > 256) {
                return false;
            }
        }
        if self
            .removed_hashes
            .iter()
            .any(|h| SkillContentHash::parse_hex(h).is_err())
        {
            return false;
        }
        self.allowed_calls.as_ref().is_none_or(|calls| {
            calls.iter().all(|s| {
                !s.is_empty()
                    && s.len() <= 128
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_'))
            })
        })
    }

    fn restrict(&mut self, other: Self) {
        self.hidden_instructions.extend(other.hidden_instructions);
        self.parameter_injection.extend(other.parameter_injection);
        self.known_bad_patterns.extend(other.known_bad_patterns);
        self.removed_hashes.extend(other.removed_hashes);
        if let Some(other) = other.allowed_calls {
            if let Some(existing) = &mut self.allowed_calls {
                existing.retain(|call| other.contains(call));
            } else {
                self.allowed_calls = Some(other);
            }
        }
    }

    fn apply(&self, effective: &mut EffectivePackInstallPolicy) {
        effective
            .hidden_instructions
            .extend(self.hidden_instructions.iter().cloned());
        effective
            .parameter_injection
            .extend(self.parameter_injection.iter().cloned());
        effective
            .known_bad_patterns
            .extend(self.known_bad_patterns.iter().cloned());
        effective
            .removed_hashes
            .extend(self.removed_hashes.iter().cloned());
        if let Some(calls) = &self.allowed_calls {
            effective.allowed_calls.retain(|call| calls.contains(call));
        }
    }
}
