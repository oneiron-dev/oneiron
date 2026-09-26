//! Creation-time membership defaults, materialized once as explicit grant/policy rows.
use super::{
    FederationGrant, FederationGrantPreset as GrantPreset, FederationGrantRole as Role,
    FederationGrantScope, encode_federation_grant_body,
};
use crate::batch::{BatchOp, apply_ops};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{EntityId, TimeRange, Vault};

/// One-time creation-time membership defaults. Key: `()` (singleton).
const SHARED_VAULT_CREATION: SideTable<(), SharedVaultCreation, LegacyJson> =
    SideTable::new(&side_table::SHARED_VAULT_CREATION);

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedVaultPreset {
    Personal,
    Family,
    Team,
    Org,
    Community,
}
impl SharedVaultPreset {
    pub const fn default_member_role(self) -> Role {
        match self {
            Self::Personal | Self::Community => Role::Viewer,
            Self::Family | Self::Team | Self::Org => Role::Member,
        }
    }
}
#[derive(Debug, Clone)]
pub struct InitialSharedMember {
    pub member_ref: EntityId,
    pub role: Option<Role>,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedVaultCreation {
    pub vault_id: u64,
    pub preset: Option<SharedVaultPreset>,
    pub owner_ref: String,
    pub grant_refs: Vec<String>,
    pub policy_ref: Option<String>,
}
fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}
fn role_preset(role: Role) -> Result<GrantPreset> {
    Ok(match role {
        Role::Owner => GrantPreset::Owner,
        Role::Admin => GrantPreset::Admin,
        Role::Member => GrantPreset::Member,
        Role::Viewer => GrantPreset::ReadOnly,
        Role::Auditor => GrantPreset::Audit,
        Role::Delegate => {
            return Err(invalid(
                "delegate needs a separately attenuated expiring grant",
            ));
        }
    })
}
impl Vault {
    /// Run once while creating shared membership. Reopening never reapplies defaults.
    /// No preset means exactly the explicitly supplied roles, without implicit grants.
    pub fn initialize_shared_vault(
        &self,
        owner: &AuthenticatedOwner,
        vault_id: u64,
        preset: Option<SharedVaultPreset>,
        members: &[InitialSharedMember],
        now: u64,
    ) -> Result<SharedVaultCreation> {
        if vault_id == 0 {
            return Err(invalid("shared vault id cannot be zero"));
        }
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        if SHARED_VAULT_CREATION.contains(&self.store, &txn, &())?
            || self
                .store
                .type_index
                .prefix_iter(&txn, &[crate::registry::ENTITY_TYPE_FEDERATION_GRANT])?
                .next()
                .transpose()?
                .is_some()
        {
            return Err(invalid("shared membership has already been initialized"));
        }
        let mut rows = std::collections::BTreeMap::new();
        if preset.is_some() {
            rows.insert(owner.actor(), Role::Owner);
        }
        for member in members {
            let role = member
                .role
                .or_else(|| preset.map(SharedVaultPreset::default_member_role))
                .ok_or_else(|| invalid("no preset requires an explicit role"))?;
            if rows.insert(member.member_ref, role).is_some() {
                return Err(invalid("duplicate initial member"));
            }
        }
        let mut creation = SharedVaultCreation {
            vault_id,
            preset,
            owner_ref: owner.actor().to_hex(),
            grant_refs: Vec::new(),
            policy_ref: None,
        };
        let mut ops = Vec::new();
        for (member, role) in rows {
            if self.store.entities.get(&txn, member.as_bytes())?.is_none() {
                return Err(Error::EntityNotFound);
            }
            let grant = FederationGrant::new(
                FederationGrantScope::vault(vault_id),
                member,
                role,
                role_preset(role)?,
            );
            let id = EntityId::now();
            creation.grant_refs.push(id.to_hex());
            ops.push(BatchOp::Put {
                id,
                entity_type: crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                data: encode_federation_grant_body(&grant)?,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            });
        }
        if preset.is_some() {
            let id = crate::gate::default_policy_manifest_id()?;
            // Creation cannot overwrite policy the owner has already customized.
            if self
                .store
                .entities
                .get(&txn, id.as_bytes())?
                .is_some_and(|raw| {
                    raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
                        != Some(crate::gate::default_policy_manifest().as_slice())
                })
            {
                return Err(invalid("shared preset must precede customized policy"));
            }
            // Defaults are ordinary editable stored policy, not a second runtime policy engine.
            ops.push(BatchOp::Put {
                id,
                entity_type: crate::registry::ENTITY_TYPE_POLICY_MANIFEST,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                data: crate::gate::default_policy_manifest(),
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            });
            creation.policy_ref = Some(id.to_hex());
        }
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut txn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        SHARED_VAULT_CREATION.put(&self.store, &mut txn, &(), &creation)?;
        txn.commit()?;
        Ok(creation)
    }
    pub fn shared_vault_creation(&self) -> Result<Option<SharedVaultCreation>> {
        let txn = self.store.env.read_txn()?;
        SHARED_VAULT_CREATION.get(&self.store, &txn, &())
    }
}
