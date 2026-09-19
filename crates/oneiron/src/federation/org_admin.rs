//! Closed organization-administration powers. No member key custody or root power.
use super::ScopeId;
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The complete administration vocabulary, fixed by the engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrgAdminPower {
    /// Enroll a member's public identity, never their private key.
    AddMember,
    /// Remove an organization membership.
    RemoveMember,
    /// Assign a non-root organization role.
    AssignRole,
    /// Reset access to a shared project, not a member vault.
    ResetSharedProjectAccess,
}
impl OrgAdminPower {
    /// Closed wire token used by Console routes and rendered actions.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AddMember => "org:add-member",
            Self::RemoveMember => "org:remove-member",
            Self::AssignRole => "org:assign-role",
            Self::ResetSharedProjectAccess => "org:reset-shared-project-access",
        }
    }
    /// Parses only named administrative powers. Root and private reads do not exist here.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "org:add-member" => Some(Self::AddMember),
            "org:remove-member" => Some(Self::RemoveMember),
            "org:assign-role" => Some(Self::AssignRole),
            "org:reset-shared-project-access" => Some(Self::ResetSharedProjectAccess),
            _ => None,
        }
    }
}

/// Immutable setup policy. Contains actor references, never member key material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrgAdminPolicy {
    org_ref: ScopeId,
    admin_refs: BTreeSet<ScopeId>,
    powers: BTreeSet<OrgAdminPower>,
}

/// A failed setup or power check; failures never fall back to owner authority.
#[derive(Debug, thiserror::Error)]
pub enum OrgAdminError {
    /// Setup is one-time, including attempts to widen it.
    #[error("organization administration is already configured")]
    AlreadyConfigured,
    /// The named actor or power has not been granted.
    #[error("organization administration power denied")]
    Denied,
    /// Store access or malformed persisted state.
    #[error(transparent)]
    Engine(#[from] crate::Error),
}

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
        OrgAdminPolicy::new(
            policy.org_ref.0,
            policy.admin_refs.iter().map(|id| id.0).collect(),
            policy.powers.clone(),
        )?;
        let key = format!("org.admin.v1.{}", policy.org_ref.0.to_hex());
        let mut txn = self.store.env.write_txn().map_err(crate::Error::from)?;
        if self
            .store
            .vault_meta
            .get(&txn, key.as_bytes())
            .map_err(crate::Error::from)?
            .is_some()
        {
            return Err(OrgAdminError::AlreadyConfigured);
        }
        let bytes = serde_json::to_vec(policy)
            .map_err(|_| crate::Error::InvariantViolation("org admin policy encoding"))?;
        self.store
            .vault_meta
            .put(&mut txn, key.as_bytes(), &bytes)
            .map_err(crate::Error::from)?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(())
    }
    /// Reads the fixed power set; absence refuses, rather than granting a default.
    pub fn org_admin_policy(&self, org_ref: EntityId) -> Result<OrgAdminPolicy, OrgAdminError> {
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let key = format!("org.admin.v1.{}", org_ref.to_hex());
        let bytes = self
            .store
            .vault_meta
            .get(&txn, key.as_bytes())
            .map_err(crate::Error::from)?
            .ok_or(OrgAdminError::Denied)?;
        let policy: OrgAdminPolicy = serde_json::from_slice(&bytes)
            .map_err(|_| crate::Error::InvariantViolation("org admin policy decoding"))?;
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
