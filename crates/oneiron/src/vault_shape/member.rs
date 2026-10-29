//! Shared-vault membership as shape rows (ARCH-0043 presets as seeds). A
//! preset pick compiles to a seed: the vault shared under the preset, the
//! creator as its Owner, and each founding member at their role, the
//! preset's default when they name none. Picking a preset is picking a
//! seed; it stays editable afterwards. Membership lands through the
//! membership doors the vault already has.
use super::plan::{ShapeChange, ShapePlanItem};
use super::{ShapeRow, ShapeSeed, invalid};
use crate::authority::HostSlipIssuer;
use crate::error::Result;
use crate::federation::{FederationGrantRole, SharedVaultPreset};
use crate::{EntityId, Vault};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A member's role, as a seed states it. A delegate's expiring grant and
/// an ask guest are not membership, so no row names them.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ShapeMemberRole {
    Owner,
    Admin,
    Member,
    Viewer,
}

impl ShapeMemberRole {
    /// The row a live role reads as; the legacy auditor spelling is a
    /// viewer, and a delegate or guest is no member row at all.
    #[must_use]
    pub const fn of(role: FederationGrantRole) -> Option<Self> {
        match role {
            FederationGrantRole::Owner => Some(Self::Owner),
            FederationGrantRole::Admin => Some(Self::Admin),
            FederationGrantRole::Member => Some(Self::Member),
            FederationGrantRole::Viewer | FederationGrantRole::Auditor => Some(Self::Viewer),
            _ => None,
        }
    }

    /// How much the role may do, for telling a raise from a lowering.
    pub(super) const fn reach(self) -> u8 {
        match self {
            Self::Viewer => 0,
            Self::Member => 1,
            Self::Admin => 2,
            Self::Owner => 3,
        }
    }
}

impl From<ShapeMemberRole> for FederationGrantRole {
    fn from(role: ShapeMemberRole) -> Self {
        match role {
            ShapeMemberRole::Owner => Self::Owner,
            ShapeMemberRole::Admin => Self::Admin,
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

impl From<SharedVaultPreset> for ShapePreset {
    fn from(preset: SharedVaultPreset) -> Self {
        match preset {
            SharedVaultPreset::Personal => Self::Personal,
            SharedVaultPreset::Family => Self::Family,
            SharedVaultPreset::Team => Self::Team,
            SharedVaultPreset::Org => Self::Org,
            SharedVaultPreset::Community => Self::Community,
        }
    }
}

impl From<ShapePreset> for SharedVaultPreset {
    fn from(preset: ShapePreset) -> Self {
        match preset {
            ShapePreset::Personal => Self::Personal,
            ShapePreset::Family => Self::Family,
            ShapePreset::Team => Self::Team,
            ShapePreset::Org => Self::Org,
            ShapePreset::Community => Self::Community,
        }
    }
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

impl ShapeSeed {
    /// The seed `pick` compiles to, with `creator` as the vault's Owner.
    ///
    /// # Errors
    ///
    /// A zero vault id, or a founding member named twice or naming the
    /// creator.
    pub fn for_preset(pick: &ShapePresetPick, creator: EntityId) -> Result<Self> {
        if pick.vault_id == 0 {
            return Err(invalid("a shared vault's id is not zero"));
        }
        let preset = SharedVaultPreset::from(pick.preset);
        let default_role = ShapeMemberRole::of(preset.default_member_role())
            .ok_or_else(|| invalid("the preset's default role is not a member role"))?;
        let mut rows = vec![
            ShapeRow::Shared {
                vault_id: pick.vault_id,
                preset: Some(pick.preset),
            },
            ShapeRow::Member {
                member: creator.to_hex(),
                role: ShapeMemberRole::Owner,
                pending_invitation: None,
            },
        ];
        rows.extend(pick.members.iter().map(|member| ShapeRow::Member {
            member: member.member.clone(),
            role: member.role.unwrap_or(default_role),
            pending_invitation: None,
        }));
        let seed = Self { rows };
        seed.validate()?;
        Ok(seed)
    }
}

/// Whether `item` lowers or removes a member: the change that ends the
/// member's capability slips (FIX 2574). A person still invited holds none.
pub(super) fn lowers_member(item: &ShapePlanItem) -> bool {
    match (item.change, &item.before, &item.after) {
        (
            ShapeChange::Retire,
            Some(ShapeRow::Member {
                pending_invitation: None,
                ..
            }),
            _,
        ) => true,
        (
            ShapeChange::Update,
            Some(ShapeRow::Member {
                role: was,
                pending_invitation: None,
                ..
            }),
            Some(ShapeRow::Member { role: now, .. }),
        ) => now.reach() < was.reach(),
        _ => false,
    }
}

/// The invitation a live member row is still pending on, by id (FIX 2573).
pub(super) fn pending_invitation(live: Option<&(ShapeRow, Option<EntityId>)>) -> Option<&str> {
    match live {
        Some((
            ShapeRow::Member {
                pending_invitation: Some(invitation),
                ..
            },
            _,
        )) => Some(invitation),
        _ => None,
    }
}

impl Vault {
    /// The issuer that ends the slips of a member the shape lowers or
    /// removes when the host passed none (FIX 2574): this install's own host
    /// issuer for the vault, as `vault.members.*` revokes with one. Only
    /// while it is the live host on the vault's roster, so revoking with it
    /// refuses no membership change the door would have landed. None when
    /// the host passed one, or this install holds no live one.
    pub(super) fn shape_slip_issuer(
        &self,
        slips: Option<&HostSlipIssuer>,
    ) -> Option<HostSlipIssuer> {
        if slips.is_some() {
            return None;
        }
        let issuer = self.load_host_slip_issuer().ok()?;
        let txn = self.store.env.read_txn().ok()?;
        let view = self.authority_view_readonly_in_txn(&txn).ok()?;
        (view.vault_id.is_some()
            && !view.vault_root_is_conflicted()
            && crate::authority::roster_has_live_owner(&view.roster, &issuer.public_key()))
        .then_some(issuer)
    }
}
