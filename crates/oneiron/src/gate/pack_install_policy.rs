//! Vault-resident connector-pack install rows; default behavior is shipped data.
//! Grammar and resource-safety ceilings stay in code. Rows may only narrow
//! the analyzed operation set and add refusal patterns; holder rows are capped
//! by the vault row under the manifest's explicit precedence.
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::{Vault, skill::SkillContentHash};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Cursor;

pub(super) const KEY: &str = "pack_install_policy";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PackInstallPrecedence {
    NestedNarrowingHolderCappedAtVault,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackInstallRuleRow {
    pub hidden_instructions: Vec<String>,
    pub parameter_injection: Vec<String>,
    pub allowed_calls: Option<Vec<String>>,
    pub known_bad_patterns: Vec<String>,
    pub removed_hashes: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HolderInstallRow {
    pub holder_ref: String,
    pub rules: PackInstallRuleRow,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackInstallPolicy {
    pub precedence: PackInstallPrecedence,
    pub vault: PackInstallRuleRow,
    pub owner: PackInstallRuleRow,
    pub holders: Vec<HolderInstallRow>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectivePackInstallPolicy {
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
            if list.len() > 1024 || list.iter().any(|s| s.trim().is_empty() || s.len() > 256) {
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
            calls.len() <= 128
                && calls.iter().all(|s| {
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
impl PackInstallPolicy {
    pub(crate) fn shipped() -> Self {
        serde_json::from_str(include_str!("pack_install_defaults.json"))
            .expect("shipped install policy must decode")
    }
    pub(crate) fn decode(value: Value) -> Option<Self> {
        let policy: Self = rmpv::ext::from_value(value).ok()?;
        policy.validate().then_some(policy)
    }
    pub(crate) fn encode(&self) -> Value {
        rmpv::ext::to_value(self).expect("validated install policy must encode")
    }
    fn validate(&self) -> bool {
        self.vault.validate()
            && self
                .vault
                .allowed_calls
                .as_ref()
                .is_some_and(|calls| !calls.is_empty())
            && self.owner.validate()
            && self.holders.len() <= 128
            && self.holders.iter().all(|row| {
                !row.holder_ref.trim().is_empty()
                    && row.holder_ref.len() <= 256
                    && row.rules.validate()
            })
            && self
                .holders
                .iter()
                .map(|row| row.holder_ref.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                == self.holders.len()
    }
    pub(crate) fn restrict(&mut self, other: Self) {
        self.vault.restrict(other.vault);
        self.owner.restrict(other.owner);
        for holder in other.holders {
            if let Some(existing) = self
                .holders
                .iter_mut()
                .find(|row| row.holder_ref == holder.holder_ref)
            {
                existing.rules.restrict(holder.rules);
            } else {
                self.holders.push(holder);
            }
        }
    }
    pub(crate) fn effective(&self, holder: &str) -> EffectivePackInstallPolicy {
        let mut effective = EffectivePackInstallPolicy {
            hidden_instructions: Vec::new(),
            parameter_injection: Vec::new(),
            allowed_calls: self
                .vault
                .allowed_calls
                .as_ref()
                .expect("validated vault row")
                .iter()
                .cloned()
                .collect(),
            known_bad_patterns: Vec::new(),
            removed_hashes: Vec::new(),
        };
        self.vault.apply(&mut effective);
        self.owner.apply(&mut effective);
        if let Some(row) = self.holders.iter().find(|row| row.holder_ref == holder) {
            row.rules.apply(&mut effective);
        }
        effective
    }
}

impl Vault {
    /// Update one owner-authored row in the pinned, trusted policy manifest.
    /// The default vault row and unrelated policy axes are never replaced.
    pub(crate) fn update_pack_install_policy(
        &self,
        owner: &AuthenticatedOwner,
        f: impl FnOnce(&mut PackInstallPolicy) -> Result<()>,
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let id = super::default_manifest::default_policy_manifest_id()?;
            let raw = self
                .store
                .entities
                .get(txn, id.as_bytes())?
                .ok_or(Error::EntityNotFound)?;
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("policy manifest header"))?;
            if header.entity_type != ENTITY_TYPE_POLICY_MANIFEST {
                return Err(Error::CorruptedIndex("policy manifest type"));
            }
            let body = &raw[ENTITY_METADATA_HEADER_LEN..];
            let mut cursor = Cursor::new(body);
            let mut manifest = rmpv::decode::read_value(&mut cursor)
                .map_err(|_| Error::CorruptedIndex("pack install policy manifest"))?;
            if cursor.position() != body.len() as u64 {
                return Err(Error::CorruptedIndex("pack install policy trailing bytes"));
            }
            let Value::Map(entries) = &mut manifest else {
                return Err(Error::CorruptedIndex("policy manifest map"));
            };
            let mut index = None;
            for (i, (key, _)) in entries.iter().enumerate() {
                if key.as_str() == Some(KEY) {
                    if index.replace(i).is_some() {
                        return Err(Error::CorruptedIndex("duplicate pack install policy"));
                    }
                }
            }
            let index = index.ok_or(Error::CorruptedIndex("pack install policy missing"))?;
            let mut policy = PackInstallPolicy::decode(entries[index].1.clone())
                .ok_or(Error::CorruptedIndex("pack install policy invalid"))?;
            f(&mut policy)?;
            if !policy.validate() {
                return Err(Error::InvalidConfig("invalid pack install policy".into()));
            }
            entries[index].1 = policy.encode();
            let mut data = Vec::new();
            rmpv::encode::write_value(&mut data, &manifest)
                .map_err(|_| Error::InvariantViolation("pack policy manifest encoding"))?;
            self.write_owner_policy_manifest_in_txn(owner, txn, id, data, crate::unix_seconds_now())
        })
    }
}
