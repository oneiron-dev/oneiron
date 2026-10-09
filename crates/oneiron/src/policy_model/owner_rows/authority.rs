//! Live policy-power holders from shared membership and owner-stamped action grants.
use std::collections::BTreeSet;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::{ActionClass, ActionEnvelope, ActorBound, GrantBound, StandingConsentGrant};
use crate::error::{Error, Result};
use crate::federation::{FederationGrantRole, FederationGrantScope, decode_federation_grant_body};
use crate::{EntityId, Vault};

/// A named action grant; a broad consent about another verb cannot authorize this one.
const POLICY_CHANGE_CLASS: &str = "policy.change";
const SHARED_CREATION_KEY: &[u8] = b"shared-vault:creation:v1";

fn invalid() -> Error {
    Error::InvalidConfig("policy power could not be verified".to_owned())
}

/// Exact scope-key target for a row action grant. The digest keeps arbitrary
/// row and scope strings distinct (including separators and whitespace) within
/// the action-envelope target limit.
pub(super) fn row_target(scope: &crate::gate::PolicyRowScope, row_ref: &str) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron/policy-row-action-target/v1");
    let (kind, world, project) = match scope {
        crate::gate::PolicyRowScope::Vault => ("vault", "", ""),
        crate::gate::PolicyRowScope::World(world) => ("world", world.as_str(), ""),
        crate::gate::PolicyRowScope::Project(project) => ("project", "", project.as_str()),
        crate::gate::PolicyRowScope::WorldProject { world, project } => {
            ("world_project", world.as_str(), project.as_str())
        }
    };
    for component in [kind, world, project, row_ref] {
        hasher.update(&(component.len() as u64).to_be_bytes());
        hasher.update(component.as_bytes());
    }
    format!("policy-row:{}", hasher.finalize().to_hex())
}

/// Vault-wide policy changes reach every world and project. A world-only row
/// reaches all projects in that world; a project-only row reaches all worlds
/// in that project. A combined row requires both matching axes.
fn scope_covers(
    authority: &crate::federation::Scope,
    row_scope: &crate::gate::PolicyRowScope,
) -> bool {
    use crate::federation::{ScopeAxis, ScopeId};
    fn covers(axis: &ScopeAxis<ScopeId>, reference: &str) -> bool {
        matches!(axis, ScopeAxis::All)
            || EntityId::from_hex(reference).is_ok_and(|id| axis.contains(&ScopeId(id)))
    }
    if !authority.verbs.contains(&POLICY_CHANGE_CLASS.to_owned()) {
        return false;
    }
    match row_scope {
        crate::gate::PolicyRowScope::Vault => {
            matches!(authority.worlds, ScopeAxis::All)
                && matches!(authority.audience, ScopeAxis::All)
        }
        crate::gate::PolicyRowScope::World(world) => {
            matches!(authority.audience, ScopeAxis::All) && covers(&authority.worlds, world)
        }
        crate::gate::PolicyRowScope::Project(project) => {
            matches!(authority.worlds, ScopeAxis::All) && covers(&authority.audience, project)
        }
        crate::gate::PolicyRowScope::WorldProject { world, project } => {
            covers(&authority.worlds, world) && covers(&authority.audience, project)
        }
    }
}

/// The live membership of a shared vault: its conferring grants and the
/// Owner-role members among them.
struct LiveMembers {
    grants: Vec<crate::federation::FederationGrant>,
    owners: BTreeSet<EntityId>,
}

/// A personal vault's one owner, the embedded owner actor, while it is a live
/// person. A deleted or corrupted personal owner is not silently replaced.
fn personal_owner_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Vec<EntityId>> {
    let owner = crate::vault::embedded_owner_actor_id()?;
    Ok(
        if vault.get_entity_type_in_txn(txn, &owner)? == Some(crate::registry::ENTITY_TYPE_PERSON)
            && vault.entity_lifecycle_state_in_txn(txn, &owner)?
                == crate::identity_topology::EntityLifecycleState::Active
        {
            vec![owner]
        } else {
            Vec::new()
        },
    )
}

/// `None` for a personal vault. A shared vault whose creating owner holds no
/// live Owner grant fails closed.
fn live_shared_members_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Option<LiveMembers>> {
    // Grant expiry is read from the vault clock, not a caller-chosen event time.
    let now = vault.store.clock.now_recorded_at();
    let Some(raw) = vault.store.vault_meta.get(txn, SHARED_CREATION_KEY)? else {
        return Ok(None);
    };
    let creation: crate::federation::SharedVaultCreation =
        serde_json::from_slice(&raw).map_err(|_| invalid())?;
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    let mut grants = Vec::new();
    for entry in vault
        .store
        .type_index
        .prefix_iter(txn, &[crate::registry::ENTITY_TYPE_FEDERATION_GRANT])?
    {
        let (index, _) = entry?;
        let id = crate::vault::entity_id_from_type_index_key(&index)?;
        let raw = vault
            .store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or_else(invalid)?;
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|h| h.entity_type != crate::registry::ENTITY_TYPE_FEDERATION_GRANT)
        {
            return Err(invalid());
        }
        let grant = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if grant.scope == FederationGrantScope::vault(creation.vault_id)
            && grant.confers_at(now)
            && fold
                .pact_for_grant(&id)
                .is_none_or(|p| p.status == crate::authority::FederationPactStatus::Active)
            && vault.get_entity_type_in_txn(txn, &grant.member_ref)?
                == Some(crate::registry::ENTITY_TYPE_PERSON)
            && vault.entity_lifecycle_state_in_txn(txn, &grant.member_ref)?
                == crate::identity_topology::EntityLifecycleState::Active
        {
            grants.push(grant);
        }
    }
    let owners: BTreeSet<EntityId> = grants
        .iter()
        .filter(|g| g.role == FederationGrantRole::Owner)
        .map(|g| g.member_ref)
        .collect();
    if !owners.contains(&EntityId::from_hex(&creation.owner_ref).map_err(|_| invalid())?) {
        return Err(invalid());
    }
    Ok(Some(LiveMembers { grants, owners }))
}

impl Vault {
    /// Whether `owner` is a live owner of this vault right now: the embedded
    /// owner of a personal vault, or a live Owner-role member of a shared one.
    /// An authenticated human is not by that alone an owner.
    pub fn is_live_vault_owner(&self, owner: &crate::consent::AuthenticatedOwner) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        is_live_vault_owner_in_txn(self, &txn, &owner.actor())
    }

    /// Everyone whose membership confers authority now: the embedded owner of
    /// a personal vault, or every live member of a shared one, whatever role.
    pub(crate) fn live_member_ids(&self) -> Result<BTreeSet<EntityId>> {
        let txn = self.store.env.read_txn()?;
        Ok(match live_shared_members_in_txn(self, &txn)? {
            None => personal_owner_in_txn(self, &txn)?.into_iter().collect(),
            Some(LiveMembers { grants, .. }) => {
                grants.iter().map(|grant| grant.member_ref).collect()
            }
        })
    }
}

/// Whether `actor` is one of the vault's live owners in `txn`.
pub(crate) fn is_live_vault_owner_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<bool> {
    Ok(owners_in_txn(vault, txn)?.contains(actor))
}

/// The vault's live owners: the embedded owner of a personal vault, or every
/// live Owner-role member of a shared one. An Admin or Delegate is no owner,
/// whatever action grants it holds.
pub(super) fn owners_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Vec<EntityId>> {
    match live_shared_members_in_txn(vault, txn)? {
        None => personal_owner_in_txn(vault, txn),
        Some(members) => Ok(members.owners.into_iter().collect()),
    }
}

/// The same scope-and-target snapshot selects proposal recipients and authorizes
/// rulings. Owners are unrestricted. Admins and Delegates require BOTH a live
/// membership whose stored authority scope admits this row and an Owner-minted
/// named action grant covering the exact target. That scope is the one the
/// mint door resolved from the vault's grant rows (met with the parent for a
/// Delegate), never a role preset, so a read-only Delegate cannot silently
/// inherit policy-edit authority.
pub(super) fn holders_for_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    _claimed_now: u64,
    row_scope: &crate::gate::PolicyRowScope,
    target: &str,
) -> Result<Vec<EntityId>> {
    let Some(LiveMembers { grants, owners }) = live_shared_members_in_txn(vault, txn)? else {
        return personal_owner_in_txn(vault, txn);
    };
    let class = ActionClass::new(POLICY_CHANGE_CLASS)?;
    // An unrepresentable target cannot authorize a non-owner. Owners still
    // retain their independent role authority.
    let envelope = ActionEnvelope::new(["owner_policy_rows".to_owned()])
        .and_then(|envelope| envelope.with_target(target));
    let mut holders = owners.clone();
    for grant in grants.iter().filter(|g| {
        matches!(
            g.role,
            FederationGrantRole::Admin | FederationGrantRole::Delegate
        ) && scope_covers(&g.authority_scope, row_scope)
    }) {
        let Ok(envelope) = &envelope else {
            continue;
        };
        let required = GrantBound::action(
            ActorBound::new(grant.member_ref.to_hex())?.with_actor_class("human")?,
            class.clone(),
            envelope.clone(),
        )?;
        for live in vault.active_standing_consent_grants_in_txn(txn)? {
            let StandingConsentGrant::Action(action) = live else {
                continue;
            };
            if !action.bound().contains(&required) {
                continue;
            }
            let Some(row) = vault.consent_grant_in_txn(txn, &action.bound().digest().to_hex())?
            else {
                continue;
            };
            if row.is_active() && owners.contains(&row.owner_stamp.actor) {
                holders.insert(grant.member_ref);
                break;
            }
        }
    }
    Ok(holders.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::{BatchOp, apply_ops};
    use crate::consent::{ActionClass, ActionEnvelope, ActorBound, GrantBound};
    use crate::federation::{
        FederationGrant, FederationGrantPreset, Scope, ScopeAxis, ScopeId,
        encode_federation_grant_body,
    };
    use crate::gate::{PolicyRowAction, PolicyRowChange, PolicyRowScope};
    use crate::policy_model::PolicyRowSubmission;
    use crate::store::GateDecisionId;
    use crate::{TimeRange, VaultConfig};

    fn axis(id: EntityId) -> ScopeAxis<ScopeId> {
        ScopeAxis::Some(BTreeSet::from([ScopeId(id)]))
    }

    #[test]
    fn policy_write_scope_requires_exact_axes_and_named_verb() -> Result<()> {
        let world_a = EntityId::from_bytes([0x61; 16])?;
        let world_b = EntityId::from_bytes([0x62; 16])?;
        let project_a = EntityId::from_bytes([0x71; 16])?;
        let project_b = EntityId::from_bytes([0x72; 16])?;
        let mut scope = Scope::top();
        scope.worlds = axis(world_a);
        scope.audience = axis(project_a);
        let both = PolicyRowScope::WorldProject {
            world: world_a.to_hex(),
            project: project_a.to_hex(),
        };
        assert!(scope_covers(&scope, &both));
        assert!(!scope_covers(
            &scope,
            &PolicyRowScope::WorldProject {
                world: world_b.to_hex(),
                project: project_a.to_hex(),
            }
        ));
        assert!(!scope_covers(
            &scope,
            &PolicyRowScope::WorldProject {
                world: world_a.to_hex(),
                project: project_b.to_hex(),
            }
        ));
        assert!(!scope_covers(
            &scope,
            &PolicyRowScope::World(world_a.to_hex())
        ));
        assert!(!scope_covers(
            &scope,
            &PolicyRowScope::Project(project_a.to_hex())
        ));
        assert!(!scope_covers(&scope, &PolicyRowScope::Vault));
        scope.worlds = ScopeAxis::All;
        assert!(scope_covers(
            &scope,
            &PolicyRowScope::Project(project_a.to_hex())
        ));
        assert!(!scope_covers(
            &scope,
            &PolicyRowScope::Project(project_b.to_hex())
        ));
        assert!(!scope_covers(&scope, &PolicyRowScope::Vault));
        scope.audience = ScopeAxis::All;
        assert!(scope_covers(&scope, &PolicyRowScope::Vault));
        scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "admin".to_owned()]));
        assert!(!scope_covers(&scope, &PolicyRowScope::Vault));
        Ok(())
    }

    #[test]
    fn project_limited_admin_needs_target_pinned_owner_grant() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), VaultConfig::default())?;
        let owner_id = crate::vault::embedded_owner_actor_id()?;
        let owner =
            vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;
        let admin_id = EntityId::from_bytes([0x45; 16])?;
        vault.put_entity(
            &admin_id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )?;
        let admin =
            vault.authenticate_owner(admin_id, &admin_id.to_hex(), true, GateDecisionId::now())?;
        let creation = vault.initialize_shared_vault(
            &owner,
            84,
            None,
            &[crate::federation::InitialSharedMember {
                member_ref: owner_id,
                role: Some(FederationGrantRole::Owner),
            }],
            10,
        )?;
        let project_a = EntityId::from_bytes([0x71; 16])?.to_hex();
        let project_b = EntityId::from_bytes([0x72; 16])?.to_hex();
        let mut grant = FederationGrant::new(
            FederationGrantScope::vault(creation.vault_id),
            admin_id,
            FederationGrantRole::Admin,
            FederationGrantPreset::Admin,
        );
        grant.authority_scope.audience = axis(EntityId::from_hex(&project_a)?);
        let now = vault.store.clock.now_recorded_at();
        vault.with_write_txn(|txn| {
            apply_ops(
                &vault.store,
                &vault.config,
                &vault.analyzer,
                txn,
                vec![BatchOp::Put {
                    id: EntityId::now(),
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
                }],
                vault
                    .text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                false,
                true,
            )
        })?;
        let change = |row_ref: &str, scope: PolicyRowScope| PolicyRowChange::Add {
            row_ref: row_ref.to_owned(),
            text: "Scoped row".to_owned(),
            action: PolicyRowAction::Warn,
            scope,
        };
        let in_project = PolicyRowScope::Project(project_a);
        let bound = GrantBound::action(
            ActorBound::new(admin_id.to_hex())?.with_actor_class("human")?,
            ActionClass::new(POLICY_CHANGE_CLASS)?,
            ActionEnvelope::new(["owner_policy_rows".to_owned()])?
                .with_target(row_target(&in_project, "one-row"))?,
        )?;
        vault.create_standing_grant(&owner, bound)?;
        assert!(matches!(
            vault.submit_policy_row_change(&admin, change("one-row", in_project.clone()), 11)?,
            PolicyRowSubmission::Landed(_)
        ));
        for not_covered in [
            change("other-row", in_project),
            change("one-row", PolicyRowScope::Project(project_b)),
            change("one-row", PolicyRowScope::Vault),
        ] {
            let PolicyRowSubmission::Proposed(proposal) =
                vault.submit_policy_row_change(&admin, not_covered, 12)?
            else {
                panic!("a narrow grant must not land another row or scope");
            };
            assert_eq!(proposal.holders, vec![owner_id.to_hex()]);
        }
        Ok(())
    }
}
