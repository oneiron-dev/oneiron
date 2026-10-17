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
pub(super) fn role_preset(role: Role) -> Result<GrantPreset> {
    Ok(match role {
        Role::Owner => GrantPreset::Owner,
        Role::Admin => GrantPreset::Admin,
        Role::Member => GrantPreset::Member,
        Role::Viewer => GrantPreset::ReadOnly,
        Role::Auditor => GrantPreset::ReadOnly,
        Role::Delegate => {
            return Err(invalid(
                "delegate needs a separately attenuated expiring grant",
            ));
        }
        Role::Guest => return Err(invalid("ask guest is not shared-vault membership")),
    })
}
/// A guest grant is disjoint from member initialization even though both
/// records carry the FEDERATION_GRANT kind byte.
fn has_member_grant(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(
        &vault.store,
        txn,
        crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
        None,
    )? {
        let id = id?;
        let raw = vault.get_raw_in(txn, &id)?.ok_or(Error::EntityNotFound)?;
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("federation grant header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_FEDERATION_GRANT {
            return Err(Error::CorruptedIndex("federation grant type"));
        }
        let grant =
            super::decode_federation_grant_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])?;
        if matches!(grant.scope, FederationGrantScope::Vault { .. }) {
            return Ok(true);
        }
    }
    Ok(false)
}

impl Vault {
    /// Run once while creating shared membership. Reopening never reapplies defaults.
    /// No preset means exactly the explicitly supplied roles, without implicit grants.
    ///
    /// Only the creator's own row is granted at once: their Owner grant under a
    /// preset, or the role they name for themselves. Every other founding member
    /// is invited at their role and joins on acceptance (OF-531, Engine ruling
    /// 2026-10-17), so the creator needs a grant of their own to invite anyone.
    /// A founding co-Owner's invitation names the Owner role (OF-150); until
    /// it is accepted the creator is the vault's only Owner.
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
        // Only the vault's owner shares it: a native host's proof shows a
        // live person, not whose vault this is.
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        if SHARED_VAULT_CREATION.contains(&self.store, &txn, &())? || has_member_grant(self, &txn)?
        {
            return Err(invalid("shared membership has already been initialized"));
        }
        let mut rows = std::collections::BTreeMap::new();
        let mut invites = std::collections::BTreeMap::new();
        if preset.is_some() {
            rows.insert(actor, Role::Owner);
        }
        for member in members {
            let role = member
                .role
                .or_else(|| preset.map(SharedVaultPreset::default_member_role))
                .ok_or_else(|| invalid("no preset requires an explicit role"))?;
            let fresh = if member.member_ref == actor {
                rows.insert(actor, role).is_none()
            } else {
                invites.insert(member.member_ref, role).is_none()
            };
            if !fresh {
                return Err(invalid("duplicate initial member"));
            }
        }
        if !invites.is_empty() && !rows.contains_key(&actor) {
            return Err(invalid(
                "founding members are invited by the creator, who needs a grant of their own",
            ));
        }
        let mut creation = SharedVaultCreation {
            vault_id,
            preset,
            owner_ref: actor.to_hex(),
            grant_refs: Vec::new(),
            policy_ref: None,
        };
        let mut ops = Vec::new();
        for (member, role) in rows {
            if !crate::ports::EntityStoreRead::port_entity_present(&self.store, &txn, &member)? {
                return Err(Error::EntityNotFound);
            }
            let role = if role == Role::Auditor {
                Role::Viewer
            } else {
                role
            };
            let mut grant = FederationGrant::new(
                FederationGrantScope::vault(vault_id),
                member,
                role,
                role_preset(role)?,
            );
            grant.authority_scope =
                self.grant_default_scope_in_txn(&txn, role, vault_id, member)?;
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
        let mut seeded_manifest = None;
        if let Some(preset) = preset {
            let id = crate::gate::default_policy_manifest_id()?;
            let default = crate::gate::default_policy_manifest()?;
            match crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, &id)? {
                Some(raw)
                    if raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
                        != Some(default.as_slice()) =>
                {
                    let header = crate::batch::EntityMetadataHeader::parse(&raw)
                        .ok_or(Error::CorruptedIndex("shared policy manifest header"))?;
                    if header.entity_type != crate::registry::ENTITY_TYPE_POLICY_MANIFEST {
                        return Err(invalid("shared policy id is not a policy manifest"));
                    }
                    // A customized vault policy remains authoritative; do not
                    // overwrite its rows as a side effect of choosing a preset.
                    creation.policy_ref = Some(id.to_hex());
                }
                _ => {
                    // Defaults are ordinary editable stored policy, not a
                    // second runtime policy engine. The preset's act-policy
                    // rows ride the same manifest through the owner door.
                    let data = super::pending_act::with_preset_act_policies(default, preset)?;
                    seeded_manifest = Some((id, data));
                    creation.policy_ref = Some(id.to_hex());
                }
            }
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
        if let Some((id, data)) = seeded_manifest {
            self.write_owner_policy_manifest_in_txn(owner, &mut txn, id, data, now)?;
        }
        SHARED_VAULT_CREATION.put(&self.store, &mut txn, &(), &creation)?;
        if !invites.is_empty() {
            // Invitations run on the store clock, as acceptance does.
            let invited_at = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
            for (member, role) in invites {
                if !crate::ports::EntityStoreRead::port_entity_present(&self.store, &txn, &member)?
                {
                    return Err(Error::EntityNotFound);
                }
                let role = if role == Role::Auditor {
                    Role::Viewer
                } else {
                    role
                };
                self.invite_founding_member_in_txn(
                    &mut txn, vault_id, actor, member, role, invited_at,
                )?;
            }
        }
        txn.commit()?;
        Ok(creation)
    }
    pub(crate) fn shared_vault_creation_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<SharedVaultCreation>> {
        SHARED_VAULT_CREATION.get(&self.store, txn, &())
    }

    pub fn shared_vault_creation(&self) -> Result<Option<SharedVaultCreation>> {
        let txn = self.store.env.read_txn()?;
        self.shared_vault_creation_in_txn(&txn)
    }
}
