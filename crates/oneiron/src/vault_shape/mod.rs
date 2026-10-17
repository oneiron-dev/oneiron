//! Vault shape as code (ARCH-0070): the setup plane held in one hand.
//!
//! Four words, and only these four. **The shape** is the arrangement itself,
//! held as one document. **The seed** is its durable in-vault declaration,
//! the source the live arrangement projects. **Plan** is a pure read at a
//! pinned frontier that renders the difference between the seed and the
//! vault. **Apply** lands that difference one item at a time through the
//! named doors the vault already has, each under its own gate.
//!
//! The memory plane is out of scope by construction: no [`ShapeRow`] can name
//! a claim, an episode or a piece of evidence. It is a grammar the seed lacks,
//! not a policy it obeys. Apply is additive over declared names: structure
//! the seed does not name is invisible to it, and removal is only an explicit
//! [`ShapeRow::Retire`] line, which always waits for the owner's word. A
//! deleted line is never a deleted world. The shape holds no authority of its
//! own; it says what should be true, never a new way of making it true.

mod apply;
mod card;
mod channel;
mod grant;
mod live;
mod manifest;
mod member;
mod plan;
mod reach;
mod seed;
mod skill;

pub use apply::{
    ShapeApplier, ShapeApplyItem, ShapeApplyReceipt, ShapeApplyRequest, ShapeItemState,
};
pub use card::ShapeCard;
pub use channel::{
    ShapeChannelBinding, ShapeChannelCustody, ShapeChannelFulfillment, ShapeChannelProvision,
    ShapeMailScope, ShapeSelfHeld,
};
pub use grant::ShapeGrantBound;
pub use member::{ShapeMemberRole, ShapePreset, ShapePresetMember, ShapePresetPick};
pub use plan::{ShapeChange, ShapeItemClass, ShapePlan, ShapePlanItem, ShapePlanSummary};
pub use reach::{
    REACH_LINE_MAX_CHANGES, REACH_LINE_NO_CHANGE, REACH_LINE_NONE, ShapePlanReach, ShapeReach,
    ShapeReachFact, ShapeReachVerdict,
};
pub use seed::StoredShapeSeed;
pub use skill::ShapeSkillSource;

use crate::EntityId;
use crate::error::{Error, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Most rows one seed may carry.
pub const SHAPE_SEED_MAX_ROWS: usize = 4096;
/// Longest name, id or reference a row may carry, in bytes.
pub const SHAPE_NAME_MAX_BYTES: usize = 256;

/// An actor's approval ceiling as a seed states it: `auto` lands its writes,
/// `proposed` holds them for review.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ShapeCeiling {
    Auto,
    Proposed,
}

impl From<crate::agent_def::AgentCeiling> for ShapeCeiling {
    fn from(ceiling: crate::agent_def::AgentCeiling) -> Self {
        match ceiling {
            crate::agent_def::AgentCeiling::Auto => Self::Auto,
            crate::agent_def::AgentCeiling::Proposed => Self::Proposed,
        }
    }
}

impl From<ShapeCeiling> for crate::agent_def::AgentCeiling {
    fn from(ceiling: ShapeCeiling) -> Self {
        match ceiling {
            ShapeCeiling::Auto => Self::Auto,
            ShapeCeiling::Proposed => Self::Proposed,
        }
    }
}

const fn enabled_by_default() -> bool {
    true
}

/// One declared row of the setup plane. Every variant names setup structure
/// by a stable name; none names memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ShapeRow {
    /// The vault shared (ARCH-0043), under its shared-vault id and the
    /// preset its defaults came from. A vault is shared once; no seed
    /// reshares it.
    Shared {
        vault_id: u64,
        #[serde(default)]
        preset: Option<ShapePreset>,
    },
    /// A member of the shared vault, by person (entity id hex), at a role.
    /// A new member is invited and joins on acceptance; an Owner's role
    /// moves only through the ownership ceremony.
    Member {
        member: String,
        role: ShapeMemberRole,
    },
    /// A world (ARCH-0022), by name. A missing world is created.
    World { name: String },
    /// A facet (ARCH-0022): a named mask a person (entity id hex) wears.
    /// A mask grants nothing; a missing one is created.
    Facet { person: String, name: String },
    /// An installed pack, by name, optionally pinned to a version.
    Pack {
        name: String,
        #[serde(default)]
        version: Option<String>,
    },
    /// An actor on the roster (an agent definition), by agent id, with its
    /// approval ceiling and whether it may be dispatched.
    Actor {
        agent_id: String,
        ceiling: ShapeCeiling,
        #[serde(default = "enabled_by_default")]
        enabled: bool,
    },
    /// A registered skill, by skill id, optionally pinned to a version.
    /// Only a row naming its hub source can import a missing one.
    Skill {
        skill_id: String,
        #[serde(default)]
        version: Option<String>,
        #[serde(default)]
        source: Option<ShapeSkillSource>,
    },
    /// A channel identity (ARCH-0063), by channel and address or handle.
    /// Only a row stating its custody, binding and fulfillment can
    /// provision a missing one.
    Channel {
        channel: String,
        address: String,
        #[serde(default)]
        provision: Option<ShapeChannelProvision>,
    },
    /// A standing grant (DEC-0006), declared as its bound. Its registry
    /// reference is the bound's digest; a row may name the grant by that
    /// reference alone, but only a row carrying the bound can mint it. Every
    /// new grant is a widening.
    Grant {
        #[serde(default)]
        grant_ref: String,
        #[serde(default)]
        bound: Option<ShapeGrantBound>,
    },
    /// A policy manifest (DEC-0005), by entity id hex, with its exact
    /// MessagePack body as hex. Every change waits for the owner's word.
    Manifest { manifest_ref: String, body: String },
    /// A sync declaration: whether one entity kind is on the wire. A shape
    /// can propose a federation; it never effects one.
    Sync { entity_kind: String, on_wire: bool },
    /// Removal, stated: the named structure leaves. Always a widening,
    /// receipted and stamped, never automatic.
    Retire { target: ShapeTarget },
}

/// The name a row speaks about: its kind and key, without its values.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ShapeTarget {
    Shared,
    Member { member: String },
    World { name: String },
    Facet { person: String, name: String },
    Pack { name: String },
    Actor { agent_id: String },
    Skill { skill_id: String },
    Channel { channel: String, address: String },
    Grant { grant_ref: String },
    Manifest { manifest_ref: String },
    Sync { entity_kind: String },
}

impl ShapeTarget {
    /// Landing order: structure before what lives in it, grants after the
    /// actors they bound.
    const fn rank(&self) -> u8 {
        match self {
            Self::Shared => 0,
            Self::Member { .. } => 1,
            Self::World { .. } => 2,
            Self::Facet { .. } => 3,
            Self::Pack { .. } => 4,
            Self::Actor { .. } => 5,
            Self::Skill { .. } => 6,
            Self::Channel { .. } => 7,
            Self::Grant { .. } => 8,
            Self::Manifest { .. } => 9,
            Self::Sync { .. } => 10,
        }
    }

    /// The kind a row of this target is tagged with on the wire.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::Member { .. } => "member",
            Self::World { .. } => "world",
            Self::Facet { .. } => "facet",
            Self::Pack { .. } => "pack",
            Self::Actor { .. } => "actor",
            Self::Skill { .. } => "skill",
            Self::Channel { .. } => "channel",
            Self::Grant { .. } => "grant",
            Self::Manifest { .. } => "manifest",
            Self::Sync { .. } => "sync",
        }
    }

    fn keys(&self) -> Vec<&str> {
        match self {
            Self::Shared => Vec::new(),
            Self::Member { member } => vec![member.as_str()],
            Self::World { name } | Self::Pack { name } => vec![name.as_str()],
            Self::Facet { person, name } => vec![person.as_str(), name.as_str()],
            Self::Actor { agent_id } => vec![agent_id.as_str()],
            Self::Skill { skill_id } => vec![skill_id.as_str()],
            Self::Channel { channel, address } => vec![channel.as_str(), address.as_str()],
            Self::Grant { grant_ref } => vec![grant_ref.as_str()],
            Self::Manifest { manifest_ref } => vec![manifest_ref.as_str()],
            Self::Sync { entity_kind } => vec![entity_kind.as_str()],
        }
    }
}

impl ShapeRow {
    /// The structure this row speaks about. A retire line speaks about the
    /// structure it retires.
    #[must_use]
    pub fn target(&self) -> ShapeTarget {
        match self {
            Self::Shared { .. } => ShapeTarget::Shared,
            Self::Member { member, .. } => ShapeTarget::Member {
                member: member.clone(),
            },
            Self::World { name } => ShapeTarget::World { name: name.clone() },
            Self::Facet { person, name } => ShapeTarget::Facet {
                person: person.clone(),
                name: name.clone(),
            },
            Self::Pack { name, .. } => ShapeTarget::Pack { name: name.clone() },
            Self::Actor { agent_id, .. } => ShapeTarget::Actor {
                agent_id: agent_id.clone(),
            },
            Self::Skill { skill_id, .. } => ShapeTarget::Skill {
                skill_id: skill_id.clone(),
            },
            Self::Channel {
                channel, address, ..
            } => ShapeTarget::Channel {
                channel: channel.clone(),
                address: address.clone(),
            },
            Self::Grant { grant_ref, bound } => ShapeTarget::Grant {
                grant_ref: if grant_ref.is_empty() {
                    bound
                        .as_ref()
                        .and_then(|bound| bound.bound().ok())
                        .map(|bound| bound.digest().to_hex())
                        .unwrap_or_default()
                } else {
                    grant_ref.clone()
                },
            },
            Self::Manifest { manifest_ref, .. } => ShapeTarget::Manifest {
                manifest_ref: manifest_ref.clone(),
            },
            Self::Sync { entity_kind, .. } => ShapeTarget::Sync {
                entity_kind: entity_kind.clone(),
            },
            Self::Retire { target } => target.clone(),
        }
    }

    /// Whether `live` already is what this declaration says. An unpinned
    /// version accepts any installed one.
    fn satisfied_by(&self, live: &Self) -> bool {
        match (self, live) {
            (
                Self::Pack {
                    version: Some(want),
                    ..
                },
                Self::Pack { version: have, .. },
            )
            | (
                Self::Skill {
                    version: Some(want),
                    ..
                },
                Self::Skill { version: have, .. },
            ) => have.as_ref() == Some(want),
            // A source or provision says how to make a missing one; the
            // live row is what it made.
            (Self::Pack { version: None, .. }, Self::Pack { .. })
            | (Self::Skill { version: None, .. }, Self::Skill { .. })
            | (Self::Channel { .. }, Self::Channel { .. }) => true,
            // One reference is one bound: a grant read by it is the grant.
            (Self::Grant { .. }, Self::Grant { .. }) => self.target() == live.target(),
            // The vault stores a manifest as its install door completes it.
            (Self::Manifest { body: want, .. }, Self::Manifest { body: have, .. }) => {
                manifest::manifest_as_stored(want).as_ref() == Some(have)
            }
            _ => self == live,
        }
    }
}

/// A seed: the setup plane as it should be, one row per declared name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShapeSeed {
    pub rows: Vec<ShapeRow>,
}

impl ShapeSeed {
    /// Refuses a seed a plan cannot read as one statement: too many rows, an
    /// empty or oversized name, or two rows about the same structure.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] naming the first fault.
    pub fn validate(&self) -> Result<()> {
        if self.rows.len() > SHAPE_SEED_MAX_ROWS {
            return Err(invalid(format!(
                "a seed carries at most {SHAPE_SEED_MAX_ROWS} rows"
            )));
        }
        let mut seen = BTreeSet::new();
        for row in &self.rows {
            if let ShapeRow::Member { member: person, .. } | ShapeRow::Facet { person, .. } = row
                && EntityId::from_hex(person).is_err()
            {
                return Err(invalid(
                    "a member or facet row names a person by entity id hex",
                ));
            }
            if let ShapeRow::Manifest { manifest_ref, .. } = row
                && EntityId::from_hex(manifest_ref).is_err()
            {
                return Err(invalid(
                    "a manifest row names its manifest by entity id hex",
                ));
            }
            if let ShapeRow::Grant {
                grant_ref,
                bound: Some(bound),
            } = row
            {
                let digest = bound.bound()?.digest().to_hex();
                if !grant_ref.is_empty() && *grant_ref != digest {
                    return Err(invalid(
                        "a grant row's grant_ref is its bound's digest; they disagree",
                    ));
                }
            }
            let target = row.target();
            for key in target.keys() {
                if key.trim().is_empty() || key.len() > SHAPE_NAME_MAX_BYTES {
                    return Err(invalid(format!(
                        "a seed name is 1 to {SHAPE_NAME_MAX_BYTES} bytes and not blank"
                    )));
                }
            }
            if !seen.insert(target) {
                return Err(invalid(
                    "a seed names each structure once; two rows speak about the same one",
                ));
            }
        }
        Ok(())
    }
}

/// `vault.shape.read`'s answer: the stored seed, the editable source, and
/// the live arrangement held as one document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapeRead {
    /// The newest seed revision; none until a seed is first stored.
    pub seed: Option<StoredShapeSeed>,
    /// The setup plane as it stands, as rows a seed could declare. Adopting
    /// it folds the live arrangement into the seed.
    pub live: ShapeSeed,
    /// Applies with an item still waiting for the owner's word, or torn.
    pub applies: Vec<ShapeApplyReceipt>,
}

/// `vault.shape.plan`'s input.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShapePlanRequest {
    /// The seed to plan; the stored seed when absent.
    #[serde(default)]
    pub seed: Option<ShapeSeed>,
    /// A preset picked at creation, planned as the seed it compiles to with
    /// the caller as the vault's Owner. Exclusive with `seed`.
    #[serde(default)]
    pub preset: Option<ShapePresetPick>,
}

impl ShapePlanRequest {
    /// The seed this request plans, as `creator` would hold the vault.
    ///
    /// # Errors
    ///
    /// Both a seed and a preset, or a preset that does not compile.
    pub fn seed_for(&self, creator: EntityId) -> Result<Option<ShapeSeed>> {
        match (&self.seed, &self.preset) {
            (Some(_), Some(_)) => Err(invalid("plan a seed or a preset, not both")),
            (_, Some(pick)) => ShapeSeed::for_preset(pick, creator).map(Some),
            (seed, None) => Ok(seed.clone()),
        }
    }
}

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidConfig(message.into())
}
