//! Closed organization-administration powers. No member key custody or root power.
use super::ScopeId;
use crate::batch::export::archive_side_install::{
    ArchivedSideRowOutcome, decode_archived_row, install_archived_row,
};
use crate::batch::export::{
    ArchiveRetainedSideRow, OwnerArchiveRestorePermit, RetainedSideHeldBackReason,
};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::side_table::{self, HexId, LegacyJson, SideTable};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Immutable per-organization setup, keyed by the org's hex32 entity id.
const ORG_ADMIN_POLICY: SideTable<HexId, OrgAdminPolicy, LegacyJson> =
    SideTable::new(&side_table::ORG_ADMIN_POLICY);

pub use crate::batch::shared_vault_write::OrgAdminPower;

/// Immutable setup policy. Contains actor references, never member key material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrgAdminPolicy {
    org_ref: ScopeId,
    admin_refs: BTreeSet<ScopeId>,
    powers: BTreeSet<OrgAdminPower>,
}

#[doc(hidden)]
pub use oneiron_verb_wire::federation::org_admin::OrgAdminError;

impl OrgAdminPolicy {
    /// Defines the fixed power set at organization setup.
    pub fn new(
        org_ref: EntityId,
        admin_refs: BTreeSet<EntityId>,
        powers: BTreeSet<OrgAdminPower>,
    ) -> Result<Self, OrgAdminError> {
        if org_ref.as_bytes() == &[0; 16]
            || admin_refs.is_empty()
            || admin_refs.iter().any(|id| id.as_bytes() == &[0; 16])
        {
            return Err(OrgAdminError::Denied);
        }
        Ok(Self {
            org_ref: ScopeId(org_ref),
            admin_refs: admin_refs.into_iter().map(ScopeId).collect(),
            powers,
        })
    }
    /// Organization whose setup this policy fixes.
    pub fn org_ref(&self) -> EntityId {
        self.org_ref.0
    }

    /// Only granted actions are rendered. Excluded powers cannot be represented.
    pub fn visible_powers(&self, admin: EntityId) -> Vec<OrgAdminPower> {
        if !self.admin_refs.contains(&ScopeId(admin)) {
            return Vec::new();
        }
        self.powers.iter().copied().collect()
    }
    /// Checks a requested named power against the frozen policy.
    pub fn authorize(&self, admin: EntityId, power: OrgAdminPower) -> Result<(), OrgAdminError> {
        if self.admin_refs.contains(&ScopeId(admin)) && self.powers.contains(&power) {
            Ok(())
        } else {
            Err(OrgAdminError::Denied)
        }
    }
}

impl Vault {
    /// Stores an immutable organization setup. Host callers must hold the owner credential.
    /// No member private key or decryption authority is accepted by this door.
    pub fn configure_org_admin(&self, policy: &OrgAdminPolicy) -> Result<(), OrgAdminError> {
        let mut txn = self.store.env.write_txn()?;
        self.configure_org_admin_in_txn(&mut txn, policy)?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(())
    }

    /// The public setup door revalidates the owner's own credential in the writer.
    pub fn configure_org_admin_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        policy: &OrgAdminPolicy,
    ) -> Result<(), OrgAdminError> {
        let mut txn = self.store.env.write_txn()?;
        owner.owner_authored_write_in_txn(self, &txn)?;
        self.configure_org_admin_in_txn(&mut txn, policy)?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(())
    }

    fn configure_org_admin_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        policy: &OrgAdminPolicy,
    ) -> Result<(), OrgAdminError> {
        OrgAdminPolicy::new(
            policy.org_ref.0,
            policy.admin_refs.iter().map(|id| id.0).collect(),
            policy.powers.clone(),
        )?;
        let key = HexId(policy.org_ref.0);
        if ORG_ADMIN_POLICY.contains(&self.store, txn, &key)? {
            return Err(OrgAdminError::AlreadyConfigured);
        }
        ORG_ADMIN_POLICY.put(&self.store, txn, &key, policy)?;
        Ok(())
    }
    /// Reads the fixed power set; absence refuses, rather than granting a default.
    pub fn org_admin_policy(&self, org_ref: EntityId) -> Result<OrgAdminPolicy, OrgAdminError> {
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let policy = ORG_ADMIN_POLICY
            .get(&self.store, &txn, &HexId(org_ref))?
            .ok_or(OrgAdminError::Denied)?;
        if policy.org_ref.0 != org_ref {
            return Err(OrgAdminError::Denied);
        }
        OrgAdminPolicy::new(
            policy.org_ref.0,
            policy.admin_refs.iter().map(|id| id.0).collect(),
            policy.powers.clone(),
        )?;
        Ok(policy)
    }
}

/// Lands archived org-admin policies in input order, one outcome per row.
///
/// A row installs only when its org matches its key and every named admin is
/// a live PERSON. There is no foreign-org check: the vault holds one policy
/// per org with no own-org registry to judge against, and the setup door
/// never requires an ORG entity while no read dereferences one.
///
/// # Errors
/// Storage faults; validation stays in the returned outcomes.
pub(crate) fn land_archived_org_admin_rows_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    rows: &[ArchiveRetainedSideRow],
) -> crate::error::Result<Vec<ArchivedSideRowOutcome>> {
    use RetainedSideHeldBackReason::InvalidValue;

    let mut outcomes = Vec::with_capacity(rows.len());
    for row in rows {
        let outcome = match decode_archived_row(&ORG_ADMIN_POLICY, row) {
            Err(reason) => ArchivedSideRowOutcome::HeldBack(reason),
            Ok((key, value)) => {
                if value.org_ref.0 != key.0 {
                    ArchivedSideRowOutcome::HeldBack(InvalidValue)
                } else {
                    match live_admin_holdback_in_txn(vault, txn, &value)? {
                        Some(reason) => ArchivedSideRowOutcome::HeldBack(reason),
                        None => {
                            install_archived_row(&ORG_ADMIN_POLICY, vault, txn, permit, &key, row)?
                        }
                    }
                }
            }
        };
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

/// The holdback reason when a named admin is not a live PERSON, or `None` when all are.
fn live_admin_holdback_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    value: &OrgAdminPolicy,
) -> crate::error::Result<Option<RetainedSideHeldBackReason>> {
    use RetainedSideHeldBackReason::{MissingLiveEntity, WrongEntityKind};

    for admin in &value.admin_refs {
        match live_entity_row_in_txn(&vault.store, txn, &admin.0)? {
            LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_PERSON => {}
            LiveEntityRow::Live { .. } => return Ok(Some(WrongEntityKind)),
            LiveEntityRow::Absent | LiveEntityRow::DeletedShell => {
                return Ok(Some(MissingLiveEntity));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn setup_is_fixed_closed_and_renders_only_granted_powers() {
        let tmp = tempfile::tempdir().unwrap();
        let org = EntityId::now();
        let admin = EntityId::now();
        let policy = OrgAdminPolicy::new(
            org,
            BTreeSet::from([admin]),
            BTreeSet::from([OrgAdminPower::AddMember]),
        )
        .unwrap();
        {
            let vault = Vault::open(tmp.path(), crate::VaultConfig::default()).unwrap();
            vault.configure_org_admin(&policy).unwrap();
            assert!(matches!(
                vault.configure_org_admin(&policy),
                Err(OrgAdminError::AlreadyConfigured)
            ));
        }
        let vault = Vault::open(tmp.path(), crate::VaultConfig::default()).unwrap();
        let restored = vault.org_admin_policy(org).unwrap();
        assert_eq!(
            restored.visible_powers(admin),
            vec![OrgAdminPower::AddMember]
        );
        assert!(restored.authorize(admin, OrgAdminPower::AddMember).is_ok());
        assert!(matches!(
            restored.authorize(admin, OrgAdminPower::AssignRole),
            Err(OrgAdminError::Denied)
        ));
        assert!(restored.visible_powers(EntityId::now()).is_empty());
        for excluded in [
            "org:root",
            "org:self-grant",
            "org:read-private-vault",
            "core:read",
        ] {
            assert_eq!(OrgAdminPower::parse(excluded), None);
        }
        let mut value = serde_json::to_value(&policy).unwrap();
        value["member_private_key"] = serde_json::json!("forbidden");
        assert!(serde_json::from_value::<OrgAdminPolicy>(value).is_err());
    }
}
