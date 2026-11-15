//! Closed organization-administration powers. No member key custody or root power.
use super::ScopeId;
use crate::authority::{ActSurface, OwnerAct, OwnerActKind};
use crate::side_table::{self, HexId, LegacyJson, Named, SideTable};
use crate::{EntityId, Vault};
use oneiron_authority::authority::Direction;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Per-organization setup, keyed by the org's hex32 entity id. The owner's
/// setup stores it once; only the owner's amend changes it.
const ORG_ADMIN_POLICY: SideTable<HexId, OrgAdminPolicy, LegacyJson> =
    SideTable::new(&side_table::ORG_ADMIN_POLICY);

/// The owner's amends, one receipt each, by sequence.
const ORG_ADMIN_AMEND_ACTS: SideTable<u64, OrgAdminAmendReceipt, Named> =
    SideTable::new(&side_table::ORG_ADMIN_AMEND_ACT);

pub use crate::batch::shared_vault_write::OrgAdminPower;

/// Setup policy. Contains actor references, never member key material.
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
    /// Checks a requested named power against the stored policy.
    pub fn authorize(&self, admin: EntityId, power: OrgAdminPower) -> Result<(), OrgAdminError> {
        if self.admin_refs.contains(&ScopeId(admin)) && self.powers.contains(&power) {
            Ok(())
        } else {
            Err(OrgAdminError::Denied)
        }
    }

    /// Whether this row, stored under `org`, is one the readers use: it names
    /// `org` and passes setup's own checks. Any other row admits nothing.
    fn is_well_formed_for(&self, org: EntityId) -> bool {
        self.org_ref.0 == org
            && Self::new(
                self.org_ref.0,
                self.admin_refs.iter().map(|id| id.0).collect(),
                self.powers.clone(),
            )
            .is_ok()
    }

    /// What this setup changes in `stored`, as the readers read `stored`: a
    /// row that is not well formed for this setup's org admits nothing, so
    /// everything this setup names is added.
    pub fn change_from(&self, stored: &OrgAdminPolicy) -> OrgAdminChange {
        let empty = Self {
            org_ref: self.org_ref,
            admin_refs: BTreeSet::new(),
            powers: BTreeSet::new(),
        };
        let before = if stored.is_well_formed_for(self.org_ref.0) {
            stored
        } else {
            &empty
        };
        let ids = |from: &BTreeSet<ScopeId>, without: &BTreeSet<ScopeId>| -> BTreeSet<EntityId> {
            from.difference(without).map(|id| id.0).collect()
        };
        OrgAdminChange {
            added_admins: ids(&self.admin_refs, &before.admin_refs),
            removed_admins: ids(&before.admin_refs, &self.admin_refs),
            added_powers: self.powers.difference(&before.powers).copied().collect(),
            dropped_powers: before.powers.difference(&self.powers).copied().collect(),
        }
    }

    /// Which way this setup moves `stored`, by the setup's own comparator
    /// (the authority rule, `act_rule`): it widens when it seats an Admin or
    /// names a power `stored` lacks, and otherwise narrows. The owner
    /// confirm sheet reads "important" from this direction.
    pub fn direction_from(&self, stored: &OrgAdminPolicy) -> Direction {
        self.change_from(stored).direction()
    }
}

/// What an owner's amend changed in an organization's stored setup.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrgAdminChange {
    /// The Admins it seated.
    pub added_admins: BTreeSet<EntityId>,
    /// The Admins it unseated.
    pub removed_admins: BTreeSet<EntityId>,
    /// The named powers it added.
    pub added_powers: BTreeSet<OrgAdminPower>,
    /// The named powers it dropped.
    pub dropped_powers: BTreeSet<OrgAdminPower>,
}

impl OrgAdminChange {
    /// Whether the setup is the same after the change as before it.
    pub fn is_empty(&self) -> bool {
        self.added_admins.is_empty()
            && self.removed_admins.is_empty()
            && self.added_powers.is_empty()
            && self.dropped_powers.is_empty()
    }

    /// [`Direction::Widens`] when the change seats an Admin or adds a power
    /// (a loosening: someone may act who could not, or an Admin may do what
    /// it could not); otherwise [`Direction::Narrows`], as nothing refused
    /// before is allowed after.
    pub fn direction(&self) -> Direction {
        if self.added_admins.is_empty() && self.added_powers.is_empty() {
            Direction::Narrows
        } else {
            Direction::Widens
        }
    }
}

/// One owner amend of an organization's setup, as this install recorded it
/// in the write that changed the setup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrgAdminAmendReceipt {
    /// The owner's act: kind `org_admin_amend`, on the organization, `seen`
    /// zero (a vault-local receipt counter is never `seen`).
    pub act: OwnerAct,
    /// What the amend changed.
    pub change: OrgAdminChange,
    /// Vault clock seconds, informational only.
    pub at: u64,
}

/// The owner's amend as it landed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrgAdminAmendment {
    /// What the amend changed; empty when it equalled the stored setup and
    /// wrote nothing.
    pub change: OrgAdminChange,
    /// Which way it moved the setup ([`OrgAdminChange::direction`]).
    pub direction: Direction,
}

impl Vault {
    /// Stores an organization's setup, once ([`Self::amend_org_admin_as_owner`]
    /// changes it). Host callers must hold the owner credential.
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

    /// The owner amends the stored setup of `policy`'s organization: its
    /// Admins and its named powers become `policy`'s, so the owner may seat or
    /// unseat an Admin and add or drop a power (RULING ORG-ADMIN-SETUP-AMEND,
    /// the lead 16 Nov 02:1x = B: the owner may also add a power the stored
    /// setup lacks; no Admin or agent path reaches this door). The owner's
    /// own credential is revalidated in the writer, as at setup. An
    /// organization with no stored setup is refused: the setup door stores
    /// the first one. An amend equal to the stored setup writes nothing;
    /// any other records the owner's act, an [`OwnerAct`] of kind
    /// `org_admin_amend` from `surface` (audit only), with what it changed,
    /// in the same write ([`Self::org_admin_amend_acts`]; RULING
    /// ORG-ADMIN-AMEND-CONFIRM-RECEIPT = A). The amend's direction is the
    /// setup's own comparator's ([`OrgAdminPolicy::direction_from`]): an
    /// amend that seats an Admin or adds a power widens. The owner confirm
    /// sheet's loosening gate, not built yet, asks before this write for a
    /// widening amend (FIX [ORG-ADMIN-AMEND-CONFIRM-SHEET-HOOK]); until then
    /// the amend stands on the owner's own proof (ARCH-0082:113).
    pub fn amend_org_admin_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        surface: ActSurface,
        policy: &OrgAdminPolicy,
    ) -> Result<OrgAdminAmendment, OrgAdminError> {
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.owner_authored_write_in_txn(self, &txn)?.actor();
        let amendment = self.amend_org_admin_in_txn(&mut txn, actor, surface, policy)?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(amendment)
    }

    fn amend_org_admin_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        surface: ActSurface,
        policy: &OrgAdminPolicy,
    ) -> Result<OrgAdminAmendment, OrgAdminError> {
        OrgAdminPolicy::new(
            policy.org_ref.0,
            policy.admin_refs.iter().map(|id| id.0).collect(),
            policy.powers.clone(),
        )?;
        let key = HexId(policy.org_ref.0);
        let stored = ORG_ADMIN_POLICY
            .get(&self.store, txn, &key)?
            .ok_or(OrgAdminError::NotConfigured)?;
        let change = policy.change_from(&stored);
        let direction = change.direction();
        if stored == *policy {
            // The change is empty: nothing is written or recorded.
            return Ok(OrgAdminAmendment { change, direction });
        }
        ORG_ADMIN_POLICY.put(&self.store, txn, &key, policy)?;
        let act = OwnerAct::by_owner(
            owner,
            OwnerActKind::OrgAdminAmend,
            policy.org_ref.0,
            surface,
            [0; 32],
        );
        let sequence = match ORG_ADMIN_AMEND_ACTS
            .iter_rev_from(&self.store, txn, &[])?
            .next()
        {
            None => 0,
            Some(row) => row?
                .0
                .checked_add(1)
                .ok_or(crate::Error::IndexOverflow("org admin amend act sequence"))?,
        };
        let at = self.instant_in_txn(txn)?.secs();
        ORG_ADMIN_AMEND_ACTS.put(
            &self.store,
            txn,
            &sequence,
            &OrgAdminAmendReceipt {
                act,
                change: change.clone(),
                at,
            },
        )?;
        Ok(OrgAdminAmendment { change, direction })
    }

    /// Every owner amend of an organization's setup this install recorded,
    /// oldest first.
    ///
    /// # Errors
    /// A store read that fails.
    pub fn org_admin_amend_acts(&self) -> crate::Result<Vec<OrgAdminAmendReceipt>> {
        let txn = self.store.env.read_txn()?;
        Ok(ORG_ADMIN_AMEND_ACTS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, receipt)| receipt)
            .collect())
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

    /// Whether the owner's stored setup lets `admin` use `power` over shared
    /// vault `vault_id`, read in `txn`: every stored policy of an `ORG` whose
    /// workspace preset names the vault names `admin` and `power`. With no
    /// such policy stored, nothing narrows the act (RULING
    /// FIX-4887-ORG-ADMIN-POLICY = A; federation:27, "a fixed allowlist of
    /// named powers, never a blanket role"). A stored policy that fails
    /// setup's own checks admits nothing.
    pub(crate) fn org_setup_admits_admin_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
        admin: EntityId,
        power: OrgAdminPower,
    ) -> crate::error::Result<bool> {
        for org in crate::workspace_roster::preset_orgs_of_vault_in_txn(self, txn, vault_id)? {
            let Some(policy) = ORG_ADMIN_POLICY.get(&self.store, txn, &HexId(org))? else {
                continue;
            };
            if !policy.is_well_formed_for(org) || policy.authorize(admin, power).is_err() {
                return Ok(false);
            }
        }
        Ok(true)
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
