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

/// The same snapshot is used to choose proposal recipients and to authorize a ruling.
/// The role grant supplies membership/expiry and the consent grant supplies the
/// owner's affirmative delegation of this *named* power. A normal Delegate
/// grant is read-only and cannot silently inherit policy-edit authority.
pub(super) fn holders_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    _claimed_now: u64,
) -> Result<Vec<EntityId>> {
    // Grant expiry is read from the vault clock, not a caller-chosen event time.
    let now = vault.store.clock.now_recorded_at();
    let Some(raw) = vault.store.vault_meta.get(txn, SHARED_CREATION_KEY)? else {
        let owner = crate::vault::embedded_owner_actor_id()?;
        // A deleted or corrupted personal owner is not silently replaced.
        return Ok(
            if vault.get_entity_type_in_txn(txn, &owner)?
                == Some(crate::registry::ENTITY_TYPE_PERSON)
                && vault.entity_lifecycle_state_in_txn(txn, &owner)?
                    == crate::identity_topology::EntityLifecycleState::Active
            {
                vec![owner]
            } else {
                Vec::new()
            },
        );
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
    let class = ActionClass::new(POLICY_CHANGE_CLASS)?;
    let envelope = ActionEnvelope::new(["owner_policy_rows".to_owned()])?;
    let mut holders = owners.clone();
    for grant in grants.iter().filter(|g| {
        matches!(
            g.role,
            FederationGrantRole::Admin | FederationGrantRole::Delegate
        )
    }) {
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
