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

#[doc(hidden)]
pub use oneiron_verb_wire::vault_shape::member::{
    ShapeMemberRole, ShapePreset, ShapePresetMember, ShapePresetPick,
};

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
        ) => ShapeMemberRole::move_lowers(*was, *now),
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
