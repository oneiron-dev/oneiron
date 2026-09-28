//! Creation-time membership defaults, materialized once as explicit grant/policy rows.
use super::{
    FederationGrant, FederationGrantPreset as GrantPreset, FederationGrantRole as Role,
    FederationGrantScope, encode_federation_grant_body,
};
use crate::batch::{BatchOp, apply_ops};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::{EntityId, TimeRange, Vault};
const CREATION_KEY: &[u8] = b"shared-vault:creation:v1";

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
    for row in vault
        .store
        .type_index
        .prefix_iter(txn, &[crate::registry::ENTITY_TYPE_FEDERATION_GRANT])?
    {
        let (key, _) = row?;
        let id = crate::vault::entity_id_from_type_index_key(&key)?;
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
        if self.store.vault_meta.get(&txn, CREATION_KEY)?.is_some() || has_member_grant(self, &txn)?
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
            if crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, &member)?.is_none()
            {
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
        if preset.is_some() {
            let id = crate::gate::default_policy_manifest_id()?;
            let default = crate::gate::default_policy_manifest();
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
                    // second runtime policy engine.
                    ops.push(BatchOp::Put {
                        id,
                        entity_type: crate::registry::ENTITY_TYPE_POLICY_MANIFEST,
                        occurred: TimeRange {
                            start: now,
                            end: now,
                        },
                        learned_at: now,
                        data: default,
                        allow_maintenance: true,
                        allow_reserved_predicate: false,
                        hub_sync_imported: false,
                    });
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
        let bytes = serde_json::to_vec(&creation).map_err(|_| invalid("shared creation encode"))?;
        self.store.vault_meta.put(&mut txn, CREATION_KEY, &bytes)?;
        txn.commit()?;
        Ok(creation)
    }
    pub(crate) fn shared_vault_creation_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<SharedVaultCreation>> {
        self.store
            .vault_meta
            .get(txn, CREATION_KEY)?
            .map(|raw| serde_json::from_slice(&raw).map_err(|_| invalid("shared creation decode")))
            .transpose()
    }

    pub fn shared_vault_creation(&self) -> Result<Option<SharedVaultCreation>> {
        let txn = self.store.env.read_txn()?;
        self.shared_vault_creation_in_txn(&txn)
    }
}
