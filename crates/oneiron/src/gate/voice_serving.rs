//! Resolved, narrow-only limits for the generic voice serving seam.
//! The seeded manifest ships values. No budget is inferred from a model name.
use crate::{
    EntityId,
    error::{Error, Result},
};
use rmpv::Value;

pub(crate) const KEY: &str = "voice_serving";
const PRECEDENCE: &str = "nested_narrowing";
#[doc(hidden)]
use oneiron_records::gate::voice_serving::FIELDS;
#[doc(hidden)]
pub use oneiron_records::gate::voice_serving::VoiceServingLimits;

/// The voice serving limits a resolution answers, and where they came from
/// (FIX 8772). A resolution receipt, not proof that any audio rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoiceServingPolicyReceipt {
    pub limits: VoiceServingLimits,
    /// True only when the trusted manifests were read and none carries the
    /// optional `voice_serving` row, so the shipped defaults stood in. An
    /// authored row is never this, even one whose values equal the defaults.
    pub used_shipped_defaults: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VoiceServingRows {
    pub(crate) vault: VoiceServingLimits,
    pub(crate) holders: Vec<(EntityId, VoiceServingLimits)>,
}
impl VoiceServingRows {
    pub(crate) fn seeded() -> Value {
        Value::Map(vec![
            (Value::from("precedence"), Value::from(PRECEDENCE)),
            (Value::from("vault"), VoiceServingLimits::DEFAULT.encode()),
            (Value::from("holders"), Value::Array(vec![])),
        ])
    }
    pub(crate) fn decode(value: &Value) -> Option<Self> {
        let Value::Map(entries) = value else {
            return None;
        };
        if entries.len() != 3 {
            return None;
        }
        let mut precedence = None;
        let mut vault = None;
        let mut holders = None;
        for (key, value) in entries {
            match key.as_str()? {
                "precedence" if precedence.is_none() => {
                    precedence = Some(value.as_str()? == PRECEDENCE);
                }
                "vault" if vault.is_none() => vault = Some(VoiceServingLimits::decode(value)?),
                "holders" if holders.is_none() => {
                    // Every holder override is kept, however many (FIX
                    // 8773); each still meets its shape and duplicate checks.
                    let Value::Array(rows) = value else {
                        return None;
                    };
                    let mut parsed = Vec::with_capacity(rows.len());
                    for row in rows {
                        let Value::Map(fields) = row else {
                            return None;
                        };
                        if fields.len() != 2 {
                            return None;
                        }
                        let mut holder = None;
                        let mut limits = None;
                        for (k, v) in fields {
                            match k.as_str()? {
                                "holder" if holder.is_none() => {
                                    let id = v.as_str()?;
                                    if id.len() != 32
                                        || !id.bytes().all(|b| {
                                            b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
                                        })
                                    {
                                        return None;
                                    }
                                    holder = Some(EntityId::from_hex(id).ok()?);
                                }
                                "limits" if limits.is_none() => {
                                    limits = Some(VoiceServingLimits::decode(v)?);
                                }
                                _ => return None,
                            }
                        }
                        let holder = holder?;
                        if parsed.iter().any(|(id, _)| *id == holder) {
                            return None;
                        }
                        parsed.push((holder, limits?));
                    }
                    holders = Some(parsed);
                }
                _ => return None,
            }
        }
        if precedence != Some(true) {
            return None;
        }
        Some(Self {
            vault: vault?,
            holders: holders?,
        })
    }
}

/// The effective limits for `holder` under `rows`, every present row
/// composing restrictively. With no row at all, the shipped defaults stand in
/// only on `trusted_absence`, the resolution's positive proof that trusted
/// manifests were read and simply omit the optional row (FIX 8772); without
/// that proof the policy is unavailable.
pub(crate) fn resolve(
    rows: &[VoiceServingRows],
    holder: Option<EntityId>,
    trusted_absence: bool,
) -> Result<VoiceServingPolicyReceipt> {
    let Some(first) = rows.first() else {
        if trusted_absence {
            return Ok(VoiceServingPolicyReceipt {
                limits: VoiceServingLimits::DEFAULT,
                used_shipped_defaults: true,
            });
        }
        return Err(Error::InvalidConfig(
            "voice serving manifest row missing".into(),
        ));
    };
    let vault = rows
        .iter()
        .skip(1)
        .fold(first.vault, |acc, row| acc.narrow(row.vault));
    if !vault.valid() {
        return Err(Error::InvalidConfig(
            "voice serving vault limits invalid".into(),
        ));
    }
    let mut effective = vault;
    for row in rows {
        for (id, limits) in &row.holders {
            if !limits.within(vault) {
                return Err(Error::InvalidConfig(
                    "voice serving holder override widens vault".into(),
                ));
            }
            if Some(*id) == holder {
                effective = effective.narrow(*limits);
            }
        }
    }
    if !effective.valid() {
        return Err(Error::InvalidConfig(
            "voice serving effective limits invalid".into(),
        ));
    }
    Ok(VoiceServingPolicyReceipt {
        limits: effective,
        used_shipped_defaults: false,
    })
}
