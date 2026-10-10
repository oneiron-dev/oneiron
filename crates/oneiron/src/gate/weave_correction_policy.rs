//! Vault-resident per-link correction quota and resolution precedence.
use std::collections::BTreeMap;

use rmpv::Value;

/// A bounded policy value, not a storage/reader capacity. The vault ceiling
/// caps holder overrides; the default narrows only callers without overrides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WeaveCorrectionPolicy {
    vault_max: u32,
    default: u32,
    holders: BTreeMap<String, u32>,
    precedence: CorrectionPrecedence,
}

/// These are authorable precedence strategies. The shipped strategy allows a
/// holder to override the nested default while the vault ceiling always wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CorrectionPrecedence {
    HolderThenDefault,
    DefaultThenHolder,
}

impl CorrectionPrecedence {
    fn parse(value: &Value) -> Option<Self> {
        match value.as_str()? {
            "holder_then_default" => Some(Self::HolderThenDefault),
            "default_then_holder" => Some(Self::DefaultThenHolder),
            _ => None,
        }
    }
    fn token(self) -> &'static str {
        match self {
            Self::HolderThenDefault => "holder_then_default",
            Self::DefaultThenHolder => "default_then_holder",
        }
    }
}

impl WeaveCorrectionPolicy {
    pub(crate) fn parse(value: &Value) -> Option<Self> {
        let Value::Map(entries) = value else {
            return None;
        };
        let mut vault_max = None;
        let mut default = None;
        let mut holders = None;
        let mut precedence = None;
        for (key, value) in entries {
            match key.as_str()? {
                "precedence" if precedence.is_none() => {
                    precedence = Some(CorrectionPrecedence::parse(value)?);
                }
                "vault_max" if vault_max.is_none() => vault_max = Some(nonzero_u32(value)?),
                "default" if default.is_none() => default = Some(nonzero_u32(value)?),
                "holders" if holders.is_none() => {
                    let Value::Map(rows) = value else { return None };
                    if rows.len() > 256 {
                        return None;
                    }
                    let mut parsed = BTreeMap::new();
                    for (holder, limit) in rows {
                        let holder = holder.as_str()?;
                        if crate::EntityId::from_hex(holder).ok()?.to_hex() != holder
                            || parsed
                                .insert(holder.to_owned(), nonzero_u32(limit)?)
                                .is_some()
                        {
                            return None;
                        }
                    }
                    holders = Some(parsed);
                }
                _ => return None,
            }
        }
        let vault_max = vault_max?;
        let default = default?;
        if default > vault_max {
            return None;
        }
        Some(Self {
            vault_max,
            default,
            holders: holders.unwrap_or_default(),
            precedence: precedence?,
        })
    }

    pub(crate) fn limit_for(&self, holder: &str) -> usize {
        let holder_limit = self.holders.get(holder).copied();
        let selected = match self.precedence {
            CorrectionPrecedence::HolderThenDefault => holder_limit.unwrap_or(self.default),
            CorrectionPrecedence::DefaultThenHolder => {
                holder_limit.map_or(self.default, |limit| self.default.min(limit))
            }
        };
        selected.min(self.vault_max) as usize
    }

    /// Restrictive composition across trusted manifests, without treating the
    /// shipped default as an immutable cap on later owner-edited policy.
    pub(crate) fn restrict(&mut self, other: Self) {
        let holders = self
            .holders
            .keys()
            .chain(other.holders.keys())
            .cloned()
            .collect::<Vec<_>>();
        let mut effective = BTreeMap::new();
        for holder in holders {
            let limit = self.limit_for(&holder).min(other.limit_for(&holder)) as u32;
            effective.insert(holder, limit);
        }
        self.vault_max = self.vault_max.min(other.vault_max);
        self.default = self.default.min(other.default).min(self.vault_max);
        self.holders = effective;
        // The merged per-holder effective table is already narrowed by both
        // policies, so either precedence spelling resolves to those entries.
        self.precedence = CorrectionPrecedence::HolderThenDefault;
    }

    pub(crate) fn hash_into(&self, hasher: &mut impl sha2::Digest) {
        hasher.update(self.vault_max.to_be_bytes());
        hasher.update(self.default.to_be_bytes());
        hasher.update(self.precedence.token().as_bytes());
        for (holder, limit) in &self.holders {
            hasher.update((holder.len() as u64).to_be_bytes());
            hasher.update(holder.as_bytes());
            hasher.update(limit.to_be_bytes());
        }
    }
}

fn nonzero_u32(value: &Value) -> Option<u32> {
    u32::try_from(value.as_u64()?).ok().filter(|v| *v > 0)
}
