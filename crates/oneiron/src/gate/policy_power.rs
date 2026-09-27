//! Fold-verified policy-write authority for a scoped manifest row.
use super::policy_values::PolicyRowScope;
use crate::Vault;
use crate::authority::{ActorBindingStatus, AuthorityFold, FederationPactStatus, ROLE_OWNER};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::{
    FederationGrant, FederationGrantRole, FederationGrantScope, Scope, ScopeAxis, ScopeId,
    decode_federation_grant_body,
};
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use std::collections::BTreeSet;

/// Explicit delegation class; Admin presets with `verbs: All` do not acquire it.
const POLICY_WRITE_VERB: &str = "policy_write";

fn record_scope(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: super::policy_values::PolicyRowScope,
) -> Result<Option<Scope>> {
    use super::policy_values::PolicyRowScope;
    let mut record = Scope::top();
    record.verbs = ScopeAxis::Some(BTreeSet::from([POLICY_WRITE_VERB.to_owned()]));
    match scope {
        PolicyRowScope::Vault => {}
        PolicyRowScope::World(world) => {
            record.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(world)]));
        }
        PolicyRowScope::Project(project) => {
            record.audience = ScopeAxis::Some(BTreeSet::from([ScopeId(project)]));
        }
        PolicyRowScope::SubProject(child) => {
            let Some(project) = crate::workspace_roster::project_record_in_txn(vault, txn, child)?
            else {
                return Ok(None);
            };
            let [parent] = project.parents.as_slice() else {
                return Ok(None);
            };
            let parent = EntityId::from_hex(parent)?;
            if parent == child
                || crate::workspace_roster::project_record_in_txn(vault, txn, parent)?.is_none()
            {
                return Ok(None);
            }
            record.audience = ScopeAxis::Some(BTreeSet::from([ScopeId(parent)]));
        }
        PolicyRowScope::Thread(room) => {
            let Some(room_record) = crate::workspace_roster::project_room_in_txn(vault, txn, room)?
            else {
                return Ok(None);
            };
            let parent = EntityId::from_hex(&room_record.project_id)?;
            let Some(project) = crate::workspace_roster::project_record_in_txn(vault, txn, parent)?
            else {
                return Ok(None);
            };
            if project.home_room != room.to_hex() {
                return Ok(None);
            }
            record.audience = ScopeAxis::Some(BTreeSet::from([ScopeId(parent)]));
        }
    }
    Ok(Some(record))
}

fn fold_owner(fold: &AuthorityFold, actor: EntityId) -> bool {
    !fold.vault_root_is_conflicted()
        && fold.actor_bindings.iter().any(|(key, binding)| {
            binding.actor_ref == actor
                && binding.actor_class == "human"
                && binding.status == ActorBindingStatus::Active
                && fold
                    .roster
                    .get(key)
                    .is_some_and(|device| !device.revoked && device.roles & ROLE_OWNER != 0)
        })
}

fn grant_holds(
    fold: &AuthorityFold,
    vault_id: u64,
    actor: EntityId,
    grant_id: EntityId,
    grant: &FederationGrant,
    record: &Scope,
    now: u64,
) -> bool {
    if fold.vault_root_is_conflicted()
        || grant.scope != FederationGrantScope::vault(vault_id)
        || grant.member_ref != actor
        || grant.expires_at.is_some_and(|expiry| now >= expiry)
        || fold
            .pact_for_grant(&grant_id)
            .is_some_and(|pact| pact.status != FederationPactStatus::Active)
    {
        return false;
    }
    // Owner membership is not an unrestricted fold Owner binding. It must
    // cover this verb and every world/project the policy row governs too.
    if !matches!(grant.role, FederationGrantRole::Owner)
        && (!matches!(
            grant.role,
            FederationGrantRole::Admin | FederationGrantRole::Delegate
        ) || !matches!(&grant.authority_scope.verbs, ScopeAxis::Some(verbs) if verbs.contains(POLICY_WRITE_VERB)))
    {
        return false;
    }
    grant
        .authority_scope
        .admits(POLICY_WRITE_VERB, record, &Scope::top())
}

impl Vault {
    /// Resolve in the mutation snapshot; caller text cannot name its own role.
    pub(in crate::gate) fn policy_power_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: EntityId,
        scope: PolicyRowScope,
        now: u64,
    ) -> Result<bool> {
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        if fold_owner(&fold, actor) {
            return Ok(true);
        }
        let Some(record) = record_scope(self, txn, scope)? else {
            return Ok(false);
        };
        let Some(creation) = self.shared_vault_creation_in_txn(txn)? else {
            return Ok(false);
        };
        for entry in self
            .store
            .type_index
            .prefix_iter(txn, &[ENTITY_TYPE_FEDERATION_GRANT])?
        {
            let (index, _) = entry?;
            let id = crate::vault::entity_id_from_type_index_key(&index)?;
            let raw = self
                .store
                .entities
                .get(txn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("policy grant"))?;
            if EntityMetadataHeader::parse(&raw)
                .is_none_or(|header| header.entity_type != ENTITY_TYPE_FEDERATION_GRANT)
            {
                return Err(Error::CorruptedIndex("policy grant"));
            }
            let grant = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if grant_holds(&fold, creation.vault_id, actor, id, &grant, &record, now) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_grants_cover_the_entire_governed_scope() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
        let txn = vault.store.env.read_txn()?;
        let actor = crate::test_util::entity(0x6B);
        let grant_id = crate::test_util::entity(0x6C);
        let project = crate::test_util::entity(0x6D);
        let world = crate::test_util::entity(0x6E);
        let fold = crate::authority::fold_authority_log(&[]);
        let mut grant = FederationGrant::new(
            FederationGrantScope::vault(7),
            actor,
            FederationGrantRole::Admin,
            crate::federation::FederationGrantPreset::Admin,
        );
        // An ordinary Admin preset is not an explicit delegation.
        let vault_scope = record_scope(&vault, &txn, PolicyRowScope::Vault)?.unwrap();
        assert!(!grant_holds(
            &fold,
            7,
            actor,
            grant_id,
            &grant,
            &vault_scope,
            1
        ));
        grant.authority_scope.verbs =
            ScopeAxis::Some(BTreeSet::from([POLICY_WRITE_VERB.to_owned()]));
        grant.authority_scope.worlds =
            ScopeAxis::Some(BTreeSet::from([ScopeId(crate::claim::base_world_id())]));
        grant.authority_scope.audience =
            ScopeAxis::Some(BTreeSet::from([
                ScopeId(crate::claim::default_project_id()),
            ]));
        assert!(!grant_holds(
            &fold,
            7,
            actor,
            grant_id,
            &grant,
            &vault_scope,
            1
        ));
        let world_scope = record_scope(
            &vault,
            &txn,
            PolicyRowScope::World(crate::claim::base_world_id()),
        )?
        .unwrap();
        assert!(!grant_holds(
            &fold,
            7,
            actor,
            grant_id,
            &grant,
            &world_scope,
            1
        ));
        grant.authority_scope.worlds = ScopeAxis::All;
        grant.authority_scope.audience = ScopeAxis::Some(BTreeSet::from([ScopeId(project)]));
        let project_scope = record_scope(&vault, &txn, PolicyRowScope::Project(project))?.unwrap();
        assert!(grant_holds(
            &fold,
            7,
            actor,
            grant_id,
            &grant,
            &project_scope,
            1
        ));
        assert!(!grant_holds(
            &fold,
            7,
            actor,
            grant_id,
            &grant,
            &record_scope(&vault, &txn, PolicyRowScope::Project(world))?.unwrap(),
            1
        ));
        assert!(!grant_holds(
            &fold,
            7,
            actor,
            grant_id,
            &grant,
            &vault_scope,
            1
        ));
        grant.authority_scope.audience = ScopeAxis::All;
        assert!(grant_holds(
            &fold,
            7,
            actor,
            grant_id,
            &grant,
            &vault_scope,
            1
        ));
        // A narrowed Owner federation grant is not an unrestricted fold Owner.
        grant.role = FederationGrantRole::Owner;
        grant.authority_scope.audience = ScopeAxis::Some(BTreeSet::from([ScopeId(project)]));
        assert!(!grant_holds(
            &fold,
            7,
            actor,
            grant_id,
            &grant,
            &vault_scope,
            1
        ));
        assert!(grant_holds(
            &fold,
            7,
            actor,
            grant_id,
            &grant,
            &project_scope,
            1
        ));
        grant.authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
        assert!(!grant_holds(
            &fold,
            7,
            actor,
            grant_id,
            &grant,
            &project_scope,
            1
        ));
        Ok(())
    }

    #[test]
    fn child_rows_use_verified_project_ancestry() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
        let root = vault.root_project()?;
        let root_row = vault.project(root)?.unwrap();
        let leader = EntityId::from_hex(&root_row.leader)?;
        let child = crate::test_util::entity(0x6D);
        vault.put_project(
            child,
            &crate::workspace_roster::ProjectRecord::new(child, Some(root), root, leader),
            4,
        )?;
        let room = EntityId::from_hex(&vault.project(child)?.unwrap().home_room)?;
        let txn = vault.store.env.read_txn()?;
        let sub = record_scope(&vault, &txn, PolicyRowScope::SubProject(child))?.unwrap();
        let thread = record_scope(&vault, &txn, PolicyRowScope::Thread(room))?.unwrap();
        assert!(sub.audience.contains(&ScopeId(root)));
        assert!(thread.audience.contains(&ScopeId(child)));
        let actor = crate::test_util::entity(0x61);
        let grant_id = crate::test_util::entity(0x62);
        let fold = crate::authority::fold_authority_log(&[]);
        let mut grant = FederationGrant::new(
            FederationGrantScope::vault(7),
            actor,
            FederationGrantRole::Admin,
            crate::federation::FederationGrantPreset::Admin,
        );
        grant.authority_scope.verbs =
            ScopeAxis::Some(BTreeSet::from([POLICY_WRITE_VERB.to_owned()]));
        grant.authority_scope.audience = ScopeAxis::Some(BTreeSet::from([ScopeId(root)]));
        assert!(grant_holds(&fold, 7, actor, grant_id, &grant, &sub, 5));
        assert!(!grant_holds(&fold, 7, actor, grant_id, &grant, &thread, 5));
        grant.authority_scope.audience = ScopeAxis::Some(BTreeSet::from([ScopeId(child)]));
        assert!(grant_holds(&fold, 7, actor, grant_id, &grant, &thread, 5));
        assert!(!grant_holds(&fold, 7, actor, grant_id, &grant, &sub, 5));

        assert!(
            record_scope(
                &vault,
                &txn,
                PolicyRowScope::Thread(crate::test_util::entity(0x6E))
            )?
            .is_none()
        );
        assert!(
            record_scope(
                &vault,
                &txn,
                PolicyRowScope::SubProject(crate::test_util::entity(0x6F))
            )?
            .is_none()
        );
        Ok(())
    }
}
