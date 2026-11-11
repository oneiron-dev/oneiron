//! Moved from `crates/oneiron/src/consent/bypass.rs` (core split slice 2: consent state below core).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;

pub const BYPASS_GRANT_REF_DOMAIN: &[u8] = b"oneiron.consent.bypass_grant.v1\0";

/// Where a bypass grant applies.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BypassScope {
    /// One project. The vault's root project is the whole vault, so it is
    /// never a bypass scope.
    Project(EntityId),
    /// One conversation thread.
    Thread(EntityId),
}

impl BypassScope {
    pub const fn kind(self) -> &'static str {
        match self {
            Self::Project(_) => "project",
            Self::Thread(_) => "thread",
        }
    }

    pub const fn id(self) -> EntityId {
        match self {
            Self::Project(id) | Self::Thread(id) => id,
        }
    }
}

/// The bypass half of a persisted grant row.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
pub struct BypassExtent {
    /// Where the grant applies.
    pub scope: BypassScope,
    /// The catastrophe-floor row version the grant was created under.
    pub floor_version: u16,
}

impl BypassExtent {
    pub fn encode_value(&self) -> Value {
        Value::Map(vec![
            (Value::from("scope"), Value::from(self.scope.kind())),
            (Value::from("id"), Value::from(self.scope.id().to_hex())),
            (
                Value::from("floor_version"),
                Value::from(self.floor_version),
            ),
        ])
    }

    pub fn decode_value(value: &Value) -> Option<Self> {
        let Value::Map(fields) = value else {
            return None;
        };
        if fields.len() != 3 {
            return None;
        }
        let field = |name: &str| {
            fields
                .iter()
                .find(|(key, _)| key.as_str() == Some(name))
                .map(|(_, value)| value)
        };
        let id = EntityId::from_hex(field("id")?.as_str()?).ok()?;
        let scope = match field("scope")?.as_str()? {
            "project" => BypassScope::Project(id),
            "thread" => BypassScope::Thread(id),
            _ => return None,
        };
        Some(Self {
            scope,
            floor_version: u16::try_from(field("floor_version")?.as_u64()?).ok()?,
        })
    }
}
