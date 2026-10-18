//! The owner's act as a signed op carries it (mesh contract §2): one
//! provenance record, [`OwnerAct`], inside the value of each op that carries
//! the owner's say-so, under the key [`OP_KEY_ACT`].
//!
//! The install that authenticated the will (the carrier: his own machine, a
//! linked work, school or rented machine, an execution node, or the hosted
//! home) signs the op with its install key, and that Ed25519 signature over
//! the authority transcript covers the record. There is no second signature
//! and no owner seed, and the supervisor's request MAC never enters a record.
//! A world settings edit's `machine` field names the carrier; an op whose
//! `machine` already names its target (a machine-profile revision) names the
//! carrier in a `carrier` field of its own, with `target == machine` (mesh
//! PR1b). Who may carry an act is `oneiron::authority::owner_act_signer_admits`.
//!
//! The owner's ruling (10-19): "Linking together machines is like a
//! computronium mesh. It doesn't matter where you said yes, if you said so."
//! So [`OwnerAct::surface`] is audit and receipts only: no admission rule
//! reads it.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

/// The key an op's value carries its [`OwnerAct`] under.
pub const OP_KEY_ACT: &str = "act";
const OWNER_ACT_KEYS: [&str; 10] = [
    "owner",
    "by",
    "agent",
    "grant",
    "surface",
    "surface_machine",
    "act",
    "target",
    "seen",
    "answer",
];

/// Who decided the act.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ActBy {
    /// The owner himself, authenticated at the writer.
    Owner,
    /// An agent whose live Grant names this act. An agent is never
    /// relabelled as the owner.
    Agent { agent: EntityId, grant: EntityId },
}

/// Where the owner's say-so reached the carrier. Audit and receipts only: no
/// admission rule anywhere may read it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ActSurface {
    /// An in-process call on the carrier install: its CLI or its own app.
    ThisInstall,
    /// A linked machine of the vault, proven on its connection, relayed it.
    LinkedDevice { machine: EntityId },
    /// The hosted console under the owner's login, behind the supervisor's
    /// `ManagedOwnerAction` at managed ingress.
    HostedConsole,
}

/// What an owner act changes. Closed: every kind the mesh contract names,
/// so no lane adds a variant.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum OwnerActKind {
    WorldPrivacy,
    MachineAnswer,
    MachineRemoval,
    Pairing,
    CustodyTransition,
    WorldKeyRequest,
    RootRequest,
    TopologySeal,
    CheckpointPolicy,
    /// A federation grant's travel choice (`GrantTravelSet`; Engine 10-19
    /// 02:0x). Its `seen` is over the grant's live choices.
    GrantTravel,
    /// A vault-wide policy setting the owner changed: the dreamer's wake
    /// policy or the inference defaults (Engine 10-19 02:4x). Its `target`
    /// names the setting, its `seen` the setting as it stood.
    PolicySetting,
    /// A whole-vault export the owner made (Engine 10-19 02:4x). It changes
    /// nothing, so its `seen` is zero.
    Export,
}

impl OwnerActKind {
    /// The wire tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WorldPrivacy => "world_privacy",
            Self::MachineAnswer => "machine_answer",
            Self::MachineRemoval => "machine_removal",
            Self::Pairing => "pairing",
            Self::CustodyTransition => "custody_transition",
            Self::WorldKeyRequest => "world_key_request",
            Self::RootRequest => "root_request",
            Self::TopologySeal => "topology_seal",
            Self::CheckpointPolicy => "checkpoint_policy",
            Self::GrantTravel => "grant_travel",
            Self::PolicySetting => "policy_setting",
            Self::Export => "export",
        }
    }

    /// The kind a wire tag names; `None` for any other text.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "world_privacy" => Self::WorldPrivacy,
            "machine_answer" => Self::MachineAnswer,
            "machine_removal" => Self::MachineRemoval,
            "pairing" => Self::Pairing,
            "custody_transition" => Self::CustodyTransition,
            "world_key_request" => Self::WorldKeyRequest,
            "root_request" => Self::RootRequest,
            "topology_seal" => Self::TopologySeal,
            "checkpoint_policy" => Self::CheckpointPolicy,
            "grant_travel" => Self::GrantTravel,
            "policy_setting" => Self::PolicySetting,
            "export" => Self::Export,
            _ => return None,
        })
    }
}

/// One owner act, as the op that carries it records it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct OwnerAct {
    /// The PERSON whose will this is: a live vault owner, by the existing
    /// resolver (the embedded PERSON, or a live Owner-role member of a shared
    /// vault). A per-world owner rule replaces the resolver behind this
    /// field later; the record's shape does not change.
    pub owner: EntityId,
    pub by: ActBy,
    /// Audit and receipts only.
    pub surface: ActSurface,
    pub act: OwnerActKind,
    /// The world, machine, secret, root, seal or grant the act changes.
    pub target: EntityId,
    /// The target revision the deciding surface showed the owner: BLAKE3
    /// over the target's sorted live head entry hashes, zero for a target
    /// nobody acted on. World privacy uses its `PolicyRevision`. A
    /// vault-local receipt counter is never `seen`.
    pub seen: [u8; 32],
    /// The in-moment ask receipt, when the owner said yes to an agent's
    /// proposal (FIX 4480).
    pub answer: Option<EntityId>,
}

impl OwnerAct {
    /// The owner's own act of kind `act` on `target`, decided from `surface`
    /// on revision `seen`.
    #[must_use]
    pub fn by_owner(
        owner: EntityId,
        act: OwnerActKind,
        target: EntityId,
        surface: ActSurface,
        seen: [u8; 32],
    ) -> Self {
        Self {
            owner,
            by: ActBy::Owner,
            surface,
            act,
            target,
            seen,
            answer: None,
        }
    }

    /// The check every carrying op runs: the record names the op's own kind
    /// and target, and only the owner's own say-so answers an ask.
    pub fn validate_carried(&self, act: OwnerActKind, target: EntityId) -> Result<()> {
        if self.act != act
            || self.target != target
            || (self.answer.is_some() && self.by != ActBy::Owner)
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

/// The revision an act's `seen` names, in the [`PolicyRevision`] shape:
/// BLAKE3 over `context` and the target's sorted distinct live head entry
/// hashes, or zero for a target with no head. Each act kind names its own
/// `context`, so one kind's revision never stands for another's.
#[must_use]
pub fn act_revision(
    context: &[u8],
    heads: impl IntoIterator<Item = AuthorityEntryHash>,
) -> [u8; 32] {
    let heads: std::collections::BTreeSet<_> = heads.into_iter().collect();
    if heads.is_empty() {
        return [0; 32];
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(context);
    for head in heads {
        hasher.update(&head);
    }
    *hasher.finalize().as_bytes()
}

/// The record's canonical value, for a signed record family outside the
/// authority log that carries an owner act under its own install signature:
/// the identity-topology admission seal (mesh PR2a). The same map an op
/// carries under [`OP_KEY_ACT`]; one codec, no second dialect.
#[must_use]
pub fn owner_act_to_value(act: &OwnerAct) -> Value {
    owner_act_value(act)
}

/// The [`owner_act_to_value`] inverse, fail-closed on any malformed field. The
/// carrying record's canonical re-encode pins the key order.
pub fn owner_act_from_value(value: &Value) -> Result<OwnerAct> {
    decode_owner_act(value)
}

/// The record's value, the map an op carries under [`OP_KEY_ACT`].
pub(super) fn owner_act_value(act: &OwnerAct) -> Value {
    let id = |id: &EntityId| Value::from(id.to_hex());
    let (by, agent, grant) = match &act.by {
        ActBy::Owner => ("owner", Value::Nil, Value::Nil),
        ActBy::Agent { agent, grant } => ("agent", id(agent), id(grant)),
    };
    let (surface, surface_machine) = match &act.surface {
        ActSurface::ThisInstall => ("this_install", Value::Nil),
        ActSurface::LinkedDevice { machine } => ("linked_device", id(machine)),
        ActSurface::HostedConsole => ("hosted_console", Value::Nil),
    };
    Value::Map(vec![
        (Value::from("owner"), id(&act.owner)),
        (Value::from("by"), Value::from(by)),
        (Value::from("agent"), agent),
        (Value::from("grant"), grant),
        (Value::from("surface"), Value::from(surface)),
        (Value::from("surface_machine"), surface_machine),
        (Value::from("act"), Value::from(act.act.as_str())),
        (Value::from("target"), id(&act.target)),
        (Value::from("seen"), binary_value(act.seen)),
        (
            Value::from("answer"),
            act.answer.as_ref().map_or(Value::Nil, id),
        ),
    ])
}

/// The record an op carries under [`OP_KEY_ACT`]; the envelope's canonical
/// re-encode pins its key order.
pub(super) fn decode_owner_act(value: &Value) -> Result<OwnerAct> {
    let entries = map_entries(value)?;
    validate_keys(entries, &OWNER_ACT_KEYS)?;
    let optional_id = |name: &str| -> Result<Option<EntityId>> {
        match required(entries, name)? {
            Value::Nil => Ok(None),
            value => decode_canonical_id(value).map(Some),
        }
    };
    let by = match (
        required(entries, "by")?.as_str(),
        optional_id("agent")?,
        optional_id("grant")?,
    ) {
        (Some("owner"), None, None) => ActBy::Owner,
        (Some("agent"), Some(agent), Some(grant)) => ActBy::Agent { agent, grant },
        _ => return Err(invalid_authority()),
    };
    let surface = match (
        required(entries, "surface")?.as_str(),
        optional_id("surface_machine")?,
    ) {
        (Some("this_install"), None) => ActSurface::ThisInstall,
        (Some("linked_device"), Some(machine)) => ActSurface::LinkedDevice { machine },
        (Some("hosted_console"), None) => ActSurface::HostedConsole,
        _ => return Err(invalid_authority()),
    };
    let act = required(entries, "act")?
        .as_str()
        .and_then(OwnerActKind::from_name)
        .ok_or_else(invalid_authority)?;
    Ok(OwnerAct {
        owner: decode_canonical_id(required(entries, "owner")?)?,
        by,
        surface,
        act,
        target: decode_canonical_id(required(entries, "target")?)?,
        seen: decode_hash(required(entries, "seen")?)?,
        answer: optional_id("answer")?,
    })
}
