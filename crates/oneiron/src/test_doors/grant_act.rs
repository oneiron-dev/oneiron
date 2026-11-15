//! The general grant act (Fable pass 28 R2), for integration tests: a person's giving or end
//! of a shared vault member's FEDERATION_GRANT row, signed in the row's own write transaction,
//! as R2's writers will sign it.

use crate::authority::{ActSurface, GrantActBy, GrantActChange, GrantFamily};
use crate::batch::{BatchOp, apply_ops};
use crate::federation::{
    FederationGrant, GrantTermsKey, encode_federation_grant_body,
    encode_federation_grant_body_keyed, federation_grant_terms,
};
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::{EntityId, Result, TimeRange, Vault};

/// `person` gives the member row `id` the terms `grant` states: the act commits to them under
/// `terms_key`, and the row is put at `id` with that key, in one write. Returns the act.
///
/// # Errors
///
/// The act's refusal (no carrier, an act the fold did not count) or a store failure; nothing
/// is written then.
pub fn give_member_grant(
    vault: &Vault,
    id: EntityId,
    grant: &FederationGrant,
    terms_key: &GrantTermsKey,
    person: EntityId,
) -> Result<[u8; 32]> {
    vault.with_write_txn(|txn| {
        let terms = federation_grant_terms(id, grant, terms_key)?;
        let act = vault.append_grant_act_in_txn(
            txn,
            GrantActBy::Person {
                person,
                surface: ActSurface::ThisInstall,
            },
            id,
            GrantFamily::SharedMember,
            GrantActChange::Give { terms },
        )?;
        put_grant_row_in_txn(
            vault,
            txn,
            id,
            encode_federation_grant_body_keyed(grant, terms_key)?,
        )?;
        Ok(act)
    })
}

/// `person` ends the member row `id`'s standing, the row left in place. Returns the act.
///
/// # Errors
///
/// The act's refusal or a store failure.
pub fn end_member_grant(vault: &Vault, id: EntityId, person: EntityId) -> Result<[u8; 32]> {
    vault.with_write_txn(|txn| {
        vault.append_grant_act_in_txn(
            txn,
            GrantActBy::Person {
                person,
                surface: ActSurface::ThisInstall,
            },
            id,
            GrantFamily::SharedMember,
            GrantActChange::End,
        )
    })
}

/// A rule's giving of the member row `id`: refused, since a rule only ends a Grant.
///
/// # Errors
///
/// Always the act's refusal, and nothing is written.
pub fn give_member_grant_by_rule(vault: &Vault, id: EntityId) -> Result<[u8; 32]> {
    vault.with_write_txn(|txn| {
        vault.append_grant_act_in_txn(
            txn,
            GrantActBy::Rule,
            id,
            GrantFamily::SharedMember,
            GrantActChange::Give { terms: [7; 32] },
        )
    })
}

/// Puts `grant` at `id` with no terms key and no act: a row as a writer before pass 28 R2 put
/// it, or another device sent it.
///
/// # Errors
///
/// A store failure.
pub fn put_unkeyed_member_grant(
    vault: &Vault,
    id: EntityId,
    grant: &FederationGrant,
) -> Result<()> {
    vault.with_write_txn(|txn| {
        put_grant_row_in_txn(vault, txn, id, encode_federation_grant_body(grant)?)
    })
}

/// Puts `grant` at `id` keyed by `terms_key`, with no act: a row widened in place.
///
/// # Errors
///
/// A store failure.
pub fn put_keyed_member_grant(
    vault: &Vault,
    id: EntityId,
    grant: &FederationGrant,
    terms_key: &GrantTermsKey,
) -> Result<()> {
    vault.with_write_txn(|txn| {
        put_grant_row_in_txn(
            vault,
            txn,
            id,
            encode_federation_grant_body_keyed(grant, terms_key)?,
        )
    })
}

fn put_grant_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    data: Vec<u8>,
) -> Result<()> {
    let now = vault.instant_in_txn(txn)?.secs();
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        txn,
        vec![BatchOp::Put {
            id,
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            row_version: None,
            data,
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
}
