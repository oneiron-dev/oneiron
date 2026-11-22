//! Whether a person stands here as a live Connect guest (FIX 5538; L02
//! 04:5x): the vault-resident guest actor a Connect grant names, holding a
//! live Connect guest grant on this vault. Both are read in the caller's
//! transaction, each time it asks: nothing is kept across transactions, so a
//! revoked or lapsed guest stops standing on its next request.

use rmpv::Value;

use super::{GUEST_ACTOR_KEYS, GUEST_ACTOR_KIND, canonical_vault_id};
use crate::Vault;
use crate::authority::{AuthorityFold, AuthorityVaultId};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{FederationGrantScope, decode_federation_grant_body};
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
        let Ok(grant) = decode_federation_grant_body(&body) else {
            continue;
        };
        if grant.scope
            == (FederationGrantScope::Connect {
                peer_vault_id: origin,
            })
            && grant_stands(vault, &fold, &id, &body, &person)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `grant_id` is a live Connect guest grant here naming `guest`,
/// read in `txn`: its row live and given by its owner's counted act that no
/// counted act ended (pass 28 R3c), conferring now, and bound by its one
/// Active pact. An accepted proposal's record reads it to say whether the
/// guest's grant had lapsed (FIX 3684).
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
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    Ok(grant_stands(vault, &fold, grant_id, &body, guest))
}

/// Whether the live Grant row `grant_id`, whose stored body is `body`, is a Connect guest
/// grant naming `guest` that the verified fold stands behind (its owner's counted giving, no
/// counted end, one Active operative pact with its peer: `guest_grant_in_fold`) and that
/// confers now.
fn grant_stands(
    vault: &Vault,
    fold: &AuthorityFold,
    grant_id: &EntityId,
    body: &[u8],
    guest: &EntityId,
) -> bool {
    let now = vault.store.clock.now_recorded_at();
    crate::federation::guest_grant_in_fold(fold, *grant_id, body, now).is_some_and(|standing| {
        let grant = standing.grant();
        grant.member_ref == *guest
            && matches!(grant.scope, FederationGrantScope::Connect { .. })
            && grant.confers_at(now)
    })
}
