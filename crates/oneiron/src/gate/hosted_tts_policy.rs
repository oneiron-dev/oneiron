//! DEC-0005 hosted TTS resource rows. Limits are policy data, never
//! adapter-wide constants. A holder may narrow, never raise, its vault cap.

use super::resolution::resolve_policy_manifest;
use crate::{
    EntityId, Vault,
    error::{Error, Result},
};
use rmpv::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostedTtsLimits {
    pub max_text_bytes: usize,
    pub max_pcm_fragment_bytes: usize,
}
impl HostedTtsLimits {
    fn restrict(self, other: Self) -> Self {
        Self {
            max_text_bytes: self.max_text_bytes.min(other.max_text_bytes),
            max_pcm_fragment_bytes: self
                .max_pcm_fragment_bytes
                .min(other.max_pcm_fragment_bytes),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::gate) enum HostedTtsScope {
    Vault,
    Holder(EntityId),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::gate) struct HostedTtsPolicyRow {
    pub provider: String,
    pub scope: HostedTtsScope,
    pub limits: HostedTtsLimits,
}

/// The only shipped precedence: more specific rows narrow the vault row;
/// multiple trusted manifests intersect rather than replacing one another.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::gate) enum HostedTtsPrecedence {
    #[default]
    NestedNarrowing,
}
impl HostedTtsPrecedence {
    pub(in crate::gate) fn as_str(self) -> &'static str {
        match self {
            Self::NestedNarrowing => "nested_narrowing",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::gate) struct HostedTtsPolicy {
    pub precedence: HostedTtsPrecedence,
    pub rows: Vec<HostedTtsPolicyRow>,
}
impl HostedTtsPolicy {
    pub(in crate::gate) fn parse(value: &Value) -> Option<Self> {
        let Value::Map(fields) = value else {
            return None;
        };
        if fields.len() != 2 {
            return None;
        }
        let mut precedence = None;
        let mut rows = None;
        for (key, value) in fields {
            match key.as_str()? {
                "precedence" => {
                    if precedence
                        .replace(match value.as_str()? {
                            "nested_narrowing" => HostedTtsPrecedence::NestedNarrowing,
                            _ => return None,
                        })
                        .is_some()
                    {
                        return None;
                    }
                }
                "rows" => {
                    if rows.replace(parse_rows(value)?).is_some() {
                        return None;
                    }
                }
                _ => return None,
            }
        }
        Some(Self {
            precedence: precedence?,
            rows: rows?,
        })
    }

    pub(in crate::gate) fn limits(
        &self,
        provider: &str,
        holder: EntityId,
    ) -> Option<HostedTtsLimits> {
        let mut vault = None;
        let mut holder_limit = None;
        for row in self.rows.iter().filter(|row| row.provider == provider) {
            let slot = match row.scope {
                HostedTtsScope::Vault => &mut vault,
                HostedTtsScope::Holder(id) if id == holder => &mut holder_limit,
                HostedTtsScope::Holder(_) => continue,
            };
            *slot = Some(slot.map_or(row.limits, |limit: HostedTtsLimits| {
                limit.restrict(row.limits)
            }));
        }
        let vault = vault?;
        Some(holder_limit.map_or(vault, |limit| vault.restrict(limit)))
    }
}

fn parse_rows(value: &Value) -> Option<Vec<HostedTtsPolicyRow>> {
    let Value::Array(values) = value else {
        return None;
    };
    if values.len() > 256 {
        return None;
    } // structural decoder bound, not a render limit
    let mut rows = Vec::with_capacity(values.len());
    for value in values {
        let Value::Map(fields) = value else {
            return None;
        };
        let mut provider = None;
        let mut scope = None;
        let mut holder_ref = None;
        let mut max_text_bytes = None;
        let mut max_pcm_fragment_bytes = None;
        for (key, value) in fields {
            match key.as_str()? {
                "provider" => {
                    if provider.replace(value.as_str()?.to_owned()).is_some() {
                        return None;
                    }
                }
                "scope" => {
                    if scope.replace(value.as_str()?.to_owned()).is_some() {
                        return None;
                    }
                }
                "holder_ref" => {
                    if holder_ref.replace(value.as_str()?.to_owned()).is_some() {
                        return None;
                    }
                }
                "max_text_bytes" => {
                    if max_text_bytes
                        .replace(usize::try_from(value.as_u64()?).ok()?)
                        .is_some()
                    {
                        return None;
                    }
                }
                "max_pcm_fragment_bytes" => {
                    if max_pcm_fragment_bytes
                        .replace(usize::try_from(value.as_u64()?).ok()?)
                        .is_some()
                    {
                        return None;
                    }
                }
                _ => return None,
            }
        }
        let provider = provider?;
        if !matches!(provider.as_str(), "cartesia" | "elevenlabs_flash") {
            return None;
        }
        let scope = match (scope?.as_str(), holder_ref) {
            ("vault", None) => HostedTtsScope::Vault,
            ("holder", Some(id)) => {
                let parsed = EntityId::from_hex(&id).ok()?;
                if parsed.to_hex() != id {
                    return None;
                }
                HostedTtsScope::Holder(parsed)
            }
            _ => return None,
        };
        let limits = HostedTtsLimits {
            max_text_bytes: max_text_bytes?,
            max_pcm_fragment_bytes: max_pcm_fragment_bytes?,
        };
        if limits.max_text_bytes == 0 || limits.max_pcm_fragment_bytes == 0 {
            return None;
        }
        if rows
            .iter()
            .any(|row: &HostedTtsPolicyRow| row.provider == provider && row.scope == scope)
        {
            return None;
        }
        rows.push(HostedTtsPolicyRow {
            provider,
            scope,
            limits,
        });
    }
    Some(rows)
}

pub(crate) fn resolve_hosted_tts_limits(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    provider: &str,
    holder: EntityId,
) -> Result<HostedTtsLimits> {
    resolve_policy_manifest(&vault.store, txn)?
        .hosted_tts_limits(provider, holder)
        .ok_or_else(|| Error::InvalidConfig("missing or invalid hosted TTS policy".into()))
}
impl Vault {
    pub(crate) fn hosted_tts_limits(
        &self,
        provider: &str,
        holder: EntityId,
    ) -> Result<HostedTtsLimits> {
        let txn = self.store.env.read_txn()?;
        resolve_hosted_tts_limits(self, &txn, provider, holder)
    }
}
