//! A world's privacy settings and their wire codec: where the world may be
//! read, where its sealed copies may rest, and the model routes it prefers.
//!
//! The settings never live in the WORLD body. The owner decides them from
//! any surface where he is authenticated, and the install that served him, a
//! live machine of the vault in any role, signs the edit with its install key
//! as the carrier of his act ([`OwnerAct`], mesh contract §2). The authority
//! fold merges concurrent edits stricter. Edits are main-log metadata, so
//! they reach every linked machine; a world's keys and content stay
//! recipient-filtered (the Engine call "OwnerAct world metadata to every
//! linked machine").

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
    OP_KEY_ACT,
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
    /// Only on one machine, which must be one the owner marked "yours": his
    /// recipient choice, never a limit on who edits the world.
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
/// `machine`, the carrier: any live machine of the vault, in any role, that
/// served the owner's authenticated say-so. It need not hold the world.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorldPrivacyEdit {
    pub world: EntityId,
    /// The owner's act: who decided, from which surface, on which settings
    /// revision. Its kind is `world_privacy` and its target is `world`.
    pub act: OwnerAct,
    pub machine: EntityId,
    pub settings: WorldPrivacy,
}

impl WorldPrivacyEdit {
    /// The edit's shape. An agent's act (`by: Agent`) is well formed here:
    /// whether it stands is the fold's to judge against the settings at its
    /// `seen` (FIX 4480: only a tighten or an equal change is ever an
    /// agent's), since a lone edit cannot see the settings it changes.
    pub fn validate(&self) -> Result<()> {
        self.settings.validate()?;
        self.act
            .validate_carried(OwnerActKind::WorldPrivacy, self.world)
    }
}

/// Which way a settings change moves a world (FIX 4480), judged against every
/// live head of its current settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyDirection {
    /// The change equals every live head: a no-op, receipted as any change.
    Equal,
    /// Every field is equal to or narrower than every live head, and some
    /// field of some head moves: the world goes to no new place.
    Tighten,
    /// Anything else: a wider read or sealed-copy choice, any model-order
    /// change, an incomparable one-machine pick, or a mixed change.
    Widen,
}

/// Which way `next` moves a world whose current settings are the live
/// `heads` (a world nobody edited has none, and stands at
/// [`WorldPrivacy::default`]). Read narrows OneMachine < MyMachines <
/// Everywhere, and one machine to another is incomparable: a machine id is
/// compared for equality only, never by its derived order. Sealed copies
/// narrow Off < MyMachines < CloudAndMyMachines. Any model-order change
/// (Inherit to Ordered or back, or a reordering) counts as a widen: a route
/// the world never used could read it (CALLS "FIX 4480 direction", open).
#[must_use]
pub fn privacy_direction<H: core::borrow::Borrow<WorldPrivacy>>(
    heads: impl IntoIterator<Item = H>,
    next: &WorldPrivacy,
) -> PrivacyDirection {
    let default = WorldPrivacy::default();
    let held: Vec<H> = heads.into_iter().collect();
    let heads: Vec<&WorldPrivacy> = if held.is_empty() {
        vec![&default]
    } else {
        held.iter()
            .map(<H as core::borrow::Borrow<WorldPrivacy>>::borrow)
            .collect()
    };
    if heads.iter().all(|head| *head == next) {
        return PrivacyDirection::Equal;
    }
    let narrower = heads.iter().all(|head| {
        read_rank_le(next.read, head.read)
            && sealed_rank(next.sealed) <= sealed_rank(head.sealed)
            && next.models == head.models
    });
    if narrower {
        PrivacyDirection::Tighten
    } else {
        PrivacyDirection::Widen
    }
}

/// Whether read `next` is equal to or narrower than read `head`.
fn read_rank_le(next: ReadLocation, head: ReadLocation) -> bool {
    match (next, head) {
        (ReadLocation::OneMachine(next), ReadLocation::OneMachine(head)) => next == head,
        (ReadLocation::OneMachine(_), _)
        | (ReadLocation::MyMachines, ReadLocation::MyMachines | ReadLocation::Everywhere)
        | (ReadLocation::Everywhere, ReadLocation::Everywhere) => true,
        (ReadLocation::MyMachines | ReadLocation::Everywhere, _) => false,
    }
}

/// Sealed copies' place in the narrowing order, written out rather than read
/// from the derived order.
const fn sealed_rank(sealed: SealedCopies) -> u8 {
    match sealed {
        SealedCopies::Off => 0,
        SealedCopies::MyMachines => 1,
        SealedCopies::CloudAndMyMachines => 2,
    }
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
        (
            Value::from(OP_KEY_ACT),
            super::owner_act::owner_act_value(&edit.act),
        ),
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
        act: super::owner_act::decode_owner_act(required(entries, OP_KEY_ACT)?)?,
        machine: decode_canonical_id(required(entries, "machine")?)?,
        settings: WorldPrivacy {
            read,
            sealed,
            models,
        },
    }))
}
