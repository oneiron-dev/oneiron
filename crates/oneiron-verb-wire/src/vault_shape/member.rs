//! Moved from `crates/oneiron/src/vault_shape/member.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::federation::grant::FederationGrantRole;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

/// A member's role, as a seed states it. A delegate's expiring grant and
/// an ask guest are not membership, so no row names them.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ShapeMemberRole {
    Owner,
    /// Admin's powers plus a Grant for delegated Owner powers; never the
    /// org root (ARCH-0082 #roles).
    Deputy,
    Admin,
    /// A Steward looks after the vault's memory for its owners: it can read
    /// and organise everything in this vault, but it can only suggest who
    /// joins or what role they get, and it can never give itself more access.
    Steward,
    Member,
    Viewer,
}

impl ShapeMemberRole {
    /// The row a live role reads as; a delegate or guest is no member row at
    /// all.
    #[must_use]
    pub const fn of(role: FederationGrantRole) -> Option<Self> {
        match role {
            FederationGrantRole::Owner => Some(Self::Owner),
            FederationGrantRole::Deputy => Some(Self::Deputy),
            FederationGrantRole::Admin => Some(Self::Admin),
            FederationGrantRole::Steward => Some(Self::Steward),
            FederationGrantRole::Member => Some(Self::Member),
            FederationGrantRole::Viewer => Some(Self::Viewer),
            _ => None,
        }
    }

    /// How much the role may do, for telling a raise from a lowering.
    pub const fn reach(self) -> u8 {
        match self {
            Self::Viewer => 0,
            Self::Member => 1,
            Self::Steward => 2,
            Self::Admin => 3,
            Self::Deputy => 4,
            Self::Owner => 5,
        }
    }

    /// Whether a member moved from `was` to `now` loses the capability slips
    /// they hold: a lowering, or a move into or out of Steward, whose verbs
    /// are neither a subset nor a superset of another role's (as
    /// `shared_act::membership` revokes them).
    pub fn move_lowers(was: Self, now: Self) -> bool {
        now.reach() < was.reach() || (now != was && (now == Self::Steward || was == Self::Steward))
    }
}

impl From<ShapeMemberRole> for FederationGrantRole {
    fn from(role: ShapeMemberRole) -> Self {
        match role {
            ShapeMemberRole::Owner => Self::Owner,
            ShapeMemberRole::Deputy => Self::Deputy,
            ShapeMemberRole::Admin => Self::Admin,
            ShapeMemberRole::Steward => Self::Steward,
            ShapeMemberRole::Member => Self::Member,
            ShapeMemberRole::Viewer => Self::Viewer,
        }
    }
}

/// The ARCH-0043 preset a shared vault's defaults came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ShapePreset {
    Personal,
    Family,
    Team,
    Org,
    Community,
}

/// One founding member of a preset pick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShapePresetMember {
    /// The person, by entity id hex.
    pub member: String,
    /// Their role; the preset's default member role when absent.
    #[serde(default)]
    pub role: Option<ShapeMemberRole>,
}

/// A preset picked at vault creation: which preset, the shared vault's id,
/// and the founding members besides the creator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShapePresetPick {
    pub preset: ShapePreset,
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    #[serde(default)]
    pub members: Vec<ShapePresetMember>,
}
