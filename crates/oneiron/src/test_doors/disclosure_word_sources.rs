//! Doors for `tests/disclosure_summary_word_sources.rs` (census L5-13): the
//! general disclosure clamp, as a context pack for a non-owner audience asks
//! it of one stored record, under a contact's clearance or the owner alone.

use crate::Vault;
use crate::counterparty_contact::{CounterpartyContactRecord, CounterpartyFirstTouch};
use crate::disclosure::{DisclosureContext, DisclosureScope};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::interlocutor::{Interlocutor, InterlocutorSet};
use crate::ports::EntityStoreRead;
use oneiron_authority::federation::Scope;

/// Creates the contact `contact` for `counterparty` and clears it to
/// `clearance`, as the owner's consent surface stores a clearance.
///
/// # Errors
/// The contact or clearance write's refusal.
pub fn seed_cleared_contact(
    vault: &Vault,
    contact: EntityId,
    counterparty: &str,
    clearance: Scope,
) -> Result<()> {
    let created_at = vault.store.clock.now_recorded_at();
    let record =
        CounterpartyContactRecord::user_introduction(EntityId::now(), counterparty, created_at)?;
    vault.create_counterparty_contact(&contact, &record)?;
    let clearance = DisclosureScope::new(clearance, "contact", created_at)?;
    let mut wtxn = vault.store.env.write_txn()?;
    vault.set_counterparty_disclosure_scope_in_txn(&mut wtxn, &contact, &clearance)?;
    wtxn.commit()?;
    Ok(())
}

/// Owner-marks `record` Tier A now, by the vault's clock.
///
/// # Errors
/// A record the vault does not hold, or the mark's write error.
pub fn mark_tier_a(vault: &Vault, record: &EntityId) -> Result<()> {
    vault.set_disclosure_tier_a(record, vault.store.clock.now_recorded_at())
}

/// Whether the general clamp of an assembly the owner holds with `contact`
/// (named `counterparty`) present admits the stored `record`.
///
/// # Errors
/// A record the vault does not hold, or a read error.
pub fn clamp_admits_with_contact(
    vault: &Vault,
    contact: EntityId,
    counterparty: &str,
    record: &EntityId,
) -> Result<bool> {
    let audience = InterlocutorSet::with_session_owner(vec![Interlocutor::known_contact(
        contact,
        counterparty,
        CounterpartyFirstTouch::UserIntroduction,
    )]);
    clamp_admits(vault, audience, record)
}

/// Whether the general clamp of the owner alone admits the stored `record`.
///
/// # Errors
/// A record the vault does not hold, or a read error.
pub fn clamp_admits_owner_alone(vault: &Vault, record: &EntityId) -> Result<bool> {
    clamp_admits(
        vault,
        InterlocutorSet::with_session_owner(Vec::new()),
        record,
    )
}

fn clamp_admits(vault: &Vault, audience: InterlocutorSet, record: &EntityId) -> Result<bool> {
    let ctx = DisclosureContext::resolve(vault, audience)?;
    let rtxn = vault.store.env.read_txn()?;
    let row = vault
        .store
        .port_entity_record(&rtxn, record)?
        .ok_or(Error::EntityNotFound)?;
    ctx.admits(&vault.store, &rtxn, record, row.entity_type, None)
}
