//! Fold-verified policy-write authority for a scoped manifest row.
use super::policy_values::PolicyEvaluationScope;
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
pub(crate) const POLICY_WRITE_VERB: &str = "policy_write";

fn record_scope(context: &PolicyEvaluationScope) -> Option<Scope> {
    if (context.thread.is_some() || context.subproject.is_some()) && context.project.is_none() {
        return None;
    }
    let mut record = Scope::top();
    record.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(
        context.world.unwrap_or_else(crate::claim::base_world_id),
    )]));
    record.audience = ScopeAxis::Some(BTreeSet::from([ScopeId(
        context
            .project
            .unwrap_or_else(crate::claim::default_project_id),
    )]));
    record.verbs = ScopeAxis::Some(BTreeSet::from([POLICY_WRITE_VERB.to_owned()]));
    Some(record)
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
    context: &PolicyEvaluationScope,
    grant_id: EntityId,
    grant: &FederationGrant,
    now: u64,
) -> bool {
    if fold.vault_root_is_conflicted()
        || grant.scope != FederationGrantScope::vault(vault_id)
        || grant.member_ref != actor
        || !grant.confers_at(now)
        || fold
            .pact_for_grant(&grant_id)
            .is_some_and(|pact| pact.status != FederationPactStatus::Active)
    {
        return false;
    }
    if grant.role == FederationGrantRole::Owner {
        return true;
    }
    // A named grant, not an implicit Admin or Delegate preset. All is NOT
    // explicit: otherwise an ordinary Admin membership becomes policy power.
    if !matches!(
        grant.role,
        FederationGrantRole::Admin | FederationGrantRole::Delegate
    ) || !matches!(&grant.authority_scope.verbs, ScopeAxis::Some(verbs) if verbs.contains(POLICY_WRITE_VERB))
    {
        return false;
    }
    let Some(record) = record_scope(context) else {
        return false;
    };
    grant
        .authority_scope
        .admits(POLICY_WRITE_VERB, &record, &Scope::top())
}

impl Vault {
    /// Resolve in the mutation snapshot; caller text cannot name its own role.
    pub(crate) fn policy_power_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: EntityId,
        context: &PolicyEvaluationScope,
        now: u64,
    ) -> Result<bool> {
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        if fold_owner(&fold, actor) {
            return Ok(true);
        }
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
            if grant_holds(&fold, creation.vault_id, actor, context, id, &grant, now) {
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
    fn only_explicit_scoped_policy_write_delegation_admits_admin() {
        let actor = crate::test_util::entity(0x6B);
        let grant_id = crate::test_util::entity(0x6C);
        let project = crate::test_util::entity(0x6D);
        let mut grant = FederationGrant::new(
            FederationGrantScope::vault(7),
            actor,
            FederationGrantRole::Admin,
            crate::federation::FederationGrantPreset::Admin,
        );
        let fold = crate::authority::fold_authority_log(&[]);
        let context = PolicyEvaluationScope {
            project: Some(project),
            ..Default::default()
        };
        assert!(!grant_holds(&fold, 7, actor, &context, grant_id, &grant, 1));
        grant.authority_scope.verbs = ScopeAxis::Some(BTreeSet::from([
            "read".to_owned(),
            POLICY_WRITE_VERB.to_owned(),
        ]));
        grant.authority_scope.audience = ScopeAxis::Some(BTreeSet::from([ScopeId(project)]));
        assert!(grant_holds(&fold, 7, actor, &context, grant_id, &grant, 1));
        assert!(!grant_holds(&fold, 8, actor, &context, grant_id, &grant, 1));
        assert!(!grant_holds(
            &fold,
            7,
            actor,
            &PolicyEvaluationScope {
                project: Some(crate::test_util::entity(0x6E)),
                ..Default::default()
            },
            grant_id,
            &grant,
            1
        ));
        grant.role = FederationGrantRole::Member;
        assert!(!grant_holds(&fold, 7, actor, &context, grant_id, &grant, 1));
    }
}
