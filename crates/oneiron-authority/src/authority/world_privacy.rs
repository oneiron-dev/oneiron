//! A world's privacy settings and their wire codec: where the world may be
//! read, where its sealed copies may rest, and the model routes it prefers.
//!
//! The settings never live in the WORLD body. One machine the owner marked
//! "yours" signs each edit with its install key, and the authority fold merges
//! concurrent edits stricter. Edits ride the authority log as a side branch:
//! no other entry takes one as a parent, so a later PR can send a world's edits
//! only where the world may live without stalling any replica's log.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_WORLD_PRIVACY: &str = "world_privacy";
/// At most this many model routes in one order.
pub const WORLD_MODEL_ROUTES_MAX: usize = 16;
/// The longest model route id, in bytes.
pub const WORLD_MODEL_ROUTE_MAX_BYTES: usize = 128;
const WORLD_PRIVACY_KEYS: [&str; 8] = [
    OP_KEY_KIND,
    "world",
    "owner",
    "machine",
    "read",
    "read_machine",
    "sealed",
    "models",
];

/// Where a world's rows may be read.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum ReadLocation {
    /// Only on this machine, which must be one the owner marked "yours".
    OneMachine(EntityId),
    /// On every machine the owner marked "yours".
    MyMachines,
    Everywhere,
}

/// Where sealed copies of a world may rest. Declared strictest first, so the
/// derived order is the stricter-wins order.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SealedCopies {
    Off,
    MyMachines,
    CloudAndMyMachines,
}

/// The model routes a world prefers. Route ids are opaque here.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum ModelOrder {
    /// The vault's own order.
    #[default]
    Inherit,
    Ordered(Vec<String>),
}

/// One world's settings, as one edit states them in full.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct WorldPrivacy {
    pub read: ReadLocation,
    pub sealed: SealedCopies,
    pub models: ModelOrder,
}

impl Default for WorldPrivacy {
    /// A new world is readable everywhere, with sealed copies on the cloud
    /// and the owner's machines.
    fn default() -> Self {
        Self {
            read: ReadLocation::Everywhere,
            sealed: SealedCopies::CloudAndMyMachines,
            models: ModelOrder::Inherit,
        }
    }
}

impl WorldPrivacy {
    pub fn validate(&self) -> Result<()> {
        let ModelOrder::Ordered(routes) = &self.models else {
            return Ok(());
        };
        let distinct: std::collections::BTreeSet<_> = routes.iter().collect();
        if routes.is_empty()
            || routes.len() > WORLD_MODEL_ROUTES_MAX
            || distinct.len() != routes.len()
            || routes.iter().any(|route| {
                route.is_empty()
                    || route.len() > WORLD_MODEL_ROUTE_MAX_BYTES
                    || route.contains(char::is_control)
            })
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

/// One owner edit of one world's settings, signed by the install key of
/// `machine`, a machine the owner marked "yours" that holds the world.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorldPrivacyEdit {
    pub world: EntityId,
    /// The owner the door authenticated.
    pub owner: EntityId,
    pub machine: EntityId,
    pub settings: WorldPrivacy,
}

pub(super) fn world_privacy_value(edit: &WorldPrivacyEdit) -> Value {
    let (read, read_machine) = match edit.settings.read {
        ReadLocation::OneMachine(machine) => ("one_machine", Value::from(machine.to_hex())),
        ReadLocation::MyMachines => ("my_machines", Value::Nil),
        ReadLocation::Everywhere => ("everywhere", Value::Nil),
    };
    let sealed = match edit.settings.sealed {
        SealedCopies::Off => "off",
        SealedCopies::MyMachines => "my_machines",
        SealedCopies::CloudAndMyMachines => "cloud_and_my_machines",
    };
    let models = match &edit.settings.models {
        ModelOrder::Inherit => Value::Nil,
        ModelOrder::Ordered(routes) => Value::Array(
            routes
                .iter()
                .map(|route| Value::from(route.as_str()))
                .collect(),
        ),
    };
    Value::Map(vec![
        (Value::from(OP_KEY_KIND), Value::from(OP_KIND_WORLD_PRIVACY)),
        (Value::from("world"), Value::from(edit.world.to_hex())),
        (Value::from("owner"), Value::from(edit.owner.to_hex())),
        (Value::from("machine"), Value::from(edit.machine.to_hex())),
        (Value::from("read"), Value::from(read)),
        (Value::from("read_machine"), read_machine),
        (Value::from("sealed"), Value::from(sealed)),
        (Value::from("models"), models),
    ])
}

pub(super) fn decode_world_privacy(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &WORLD_PRIVACY_KEYS)?;
    let read_machine = required(entries, "read_machine")?;
    let read = match (required(entries, "read")?.as_str(), read_machine) {
        (Some("one_machine"), machine) => ReadLocation::OneMachine(decode_canonical_id(machine)?),
        (Some("my_machines"), Value::Nil) => ReadLocation::MyMachines,
        (Some("everywhere"), Value::Nil) => ReadLocation::Everywhere,
        _ => return Err(invalid_authority()),
    };
    let sealed = match required(entries, "sealed")?.as_str() {
        Some("off") => SealedCopies::Off,
        Some("my_machines") => SealedCopies::MyMachines,
        Some("cloud_and_my_machines") => SealedCopies::CloudAndMyMachines,
        _ => return Err(invalid_authority()),
    };
    let models = match required(entries, "models")? {
        Value::Nil => ModelOrder::Inherit,
        Value::Array(routes) => ModelOrder::Ordered(
            routes
                .iter()
                .map(|route| route.as_str().map(str::to_owned))
                .collect::<Option<_>>()
                .ok_or_else(invalid_authority)?,
        ),
        _ => return Err(invalid_authority()),
    };
    Ok(AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
        world: decode_canonical_id(required(entries, "world")?)?,
        owner: decode_canonical_id(required(entries, "owner")?)?,
        machine: decode_canonical_id(required(entries, "machine")?)?,
        settings: WorldPrivacy {
            read,
            sealed,
            models,
        },
    }))
}
