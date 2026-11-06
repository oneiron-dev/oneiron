//! The AGENT_DEF `refusal` dial codec (OF-533): the pinned-key encode, the
//! strict decode and the dial rule every encode and decode holds.

use rmpv::Value;

use crate::error::{ArtifactError, Error, Result};
use crate::store::agent_refusal::{REFUSAL_DIAL_KEYS, RefusalDial, RefusalDomain, RefusalLevel};

/// Encodes a [`RefusalDial`] sub-map: the [`REFUSAL_DIAL_KEYS`] in pinned
/// order, each unset domain elided.
pub(crate) fn encode_refusal_dial(dial: RefusalDial) -> Value {
    let entries = [
        (RefusalDomain::Bond, dial.bond),
        (RefusalDomain::Logistics, dial.logistics),
    ]
    .into_iter()
    .filter_map(|(domain, level)| {
        level.map(|level| (Value::from(domain.as_str()), Value::from(level.as_str())))
    })
    .collect();
    Value::Map(entries)
}

/// Strict [`RefusalDial`] decode: a map over [`REFUSAL_DIAL_KEYS`] with no
/// unknown or duplicate key and at least one domain set.
pub(crate) fn decode_refusal_dial(value: &Value) -> Result<RefusalDial> {
    let Value::Map(entries) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "refusal must be a MessagePack map",
        )));
    };
    let mut dial = RefusalDial::new();
    for (key, level) in entries {
        let domain = key
            .as_str()
            .and_then(RefusalDomain::parse)
            .ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "refusal keys must be one of bond|logistics",
            )))?;
        if dial.get(domain).is_some() {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "duplicate refusal key",
            )));
        }
        let level = level
            .as_str()
            .and_then(RefusalLevel::parse)
            .ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "refusal levels must be one of none|voice|veto|full",
            )))?;
        dial = dial.with(domain, level);
    }
    validate_refusal_dial(dial)?;
    Ok(dial)
}

pub(crate) fn validate_refusal_dial(dial: RefusalDial) -> Result<()> {
    if dial.bond.is_none() && dial.logistics.is_none() {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "refusal must set at least one domain; omit it for the vault defaults",
        )));
    }
    Ok(())
}
