//! Whether a person stands here as a live Connect guest (FIX 5538; L02
//! 04:5x): the vault-resident guest actor a Connect grant names, holding a
//! live Connect guest grant on this vault. Both are read in the caller's
//! transaction, each time it asks: nothing is kept across transactions, so a
//! revoked or lapsed guest stops standing on its next request.

use rmpv::Value;

use super::{GUEST_ACTOR_KEYS, GUEST_ACTOR_KIND, canonical_vault_id, pact_admits_grant};
use crate::Vault;
use crate::authority::{AuthorityFold, AuthorityVaultId};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{FederationGrant, FederationGrantScope, decode_federation_grant_body};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The origin vault `actor` stands for, read in `txn`: `None` when `actor`
/// is not a live Connect guest actor here.
pub(super) fn guest_actor_origin_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<Option<AuthorityVaultId>> {
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_PERSON,
        body,
    } = live_entity_row_in_txn(&vault.store, txn, actor)?
    else {
        return Ok(None);
    };
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut body.as_slice()) else {
        return Ok(None);
    };
    let field = |key: &str| {
        entries
            .iter()
            .find(|(name, _)| name.as_str() == Some(key))
            .and_then(|(_, value)| value.as_str())
    };
    if field(GUEST_ACTOR_KEYS[1]) != Some(GUEST_ACTOR_KIND) {
        return Ok(None);
    }
    Ok(field(GUEST_ACTOR_KEYS[3]).and_then(canonical_vault_id))
}

/// Whether `person` stands here as a live Connect guest, read in `txn`: a
/// live Connect guest actor, and a live Connect guest grant on this vault
/// that names it for its origin vault ([`connect_grant_stands_in_txn`]'s
/// checks). A door that shows a guest a vault setting reads it; it grants
/// nothing.
pub(crate) fn connect_guest_standing_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
) -> Result<bool> {
    let Some(origin) = guest_actor_origin_in_txn(vault, txn, &person)? else {
        return Ok(false);
    };
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    for entry in vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_FEDERATION_GRANT, None)?
    {
        let id = entry?;
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            body,
        } = live_entity_row_in_txn(&vault.store, txn, &id)?
        else {
            continue;
        };
        let grant = decode_federation_grant_body(&body)?;
        if grant.scope
            == (FederationGrantScope::Connect {
                peer_vault_id: origin,
            })
            && grant_stands_in_txn(vault, txn, &fold, &id, &grant, &person)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `grant_id` is a live Connect guest grant here naming `guest`,
/// read in `txn`: its row live and not withdrawn, conferring now, and bound
/// by its one Active pact. An accepted proposal's record reads it to say
/// whether the guest's grant had lapsed (FIX 3684).
pub(crate) fn connect_grant_stands_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant_id: &EntityId,
    guest: &EntityId,
) -> Result<bool> {
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_FEDERATION_GRANT,
        body,
    } = live_entity_row_in_txn(&vault.store, txn, grant_id)?
    else {
        return Ok(false);
    };
    let grant = decode_federation_grant_body(&body)?;
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    grant_stands_in_txn(vault, txn, &fold, grant_id, &grant, guest)
}

fn grant_stands_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    grant_id: &EntityId,
    grant: &FederationGrant,
    guest: &EntityId,
) -> Result<bool> {
    if grant.member_ref != *guest
        || !grant.role.is_guest()
        || !matches!(grant.scope, FederationGrantScope::Connect { .. })
        || !grant.confers_at(vault.store.clock.now_recorded_at())
        || vault.guest_grant_withdrawn_in_txn(txn, grant_id)?
    {
        return Ok(false);
    }
    Ok(pact_admits_grant(fold, grant_id, grant))
}
