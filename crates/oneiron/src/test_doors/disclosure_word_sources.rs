//! Doors for `tests/disclosure_summary_word_sources.rs` (census L5-13): the
//! general disclosure clamp, as a context pack for a non-owner audience asks
//! it of one stored record, under a contact's clearance or the owner alone,
//! and of a claim served at another revision than its live row.

use crate::Vault;
use crate::claim::ClaimBody;
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

/// Installs, in the default policy manifest slot, the shipped policy plus one
/// exact rule that labels `predicate` normal criticality and normal
/// sensitivity. The shipped policy declares no `conversation.summary` rule,
/// so such a claim is critical, and `Vault::put_claim` composes no consent:
/// the gate parks it at the criticality floor. With this rule the raw door
/// lands it as it lands a declared ordinary predicate.
///
/// # Errors
/// The shipped policy's decode or encode, or the manifest write's error.
pub fn install_shipped_policy_with_ordinary_predicate(
    vault: &Vault,
    predicate: &str,
) -> Result<()> {
    let rmpv::Value::Map(mut entries) =
        rmpv::decode::read_value(&mut crate::gate::default_policy_manifest()?.as_slice())
            .map_err(|_| Error::InvalidConfig("default policy".into()))?
    else {
        return Err(Error::InvalidConfig("default policy is not a map".into()));
    };
    let rule = rmpv::Value::Map(vec![
        (rmpv::Value::from("prefix"), rmpv::Value::from(predicate)),
        (rmpv::Value::from("exact"), rmpv::Value::Boolean(true)),
        (
            rmpv::Value::from("axes"),
            rmpv::Value::Map(vec![
                (
                    rmpv::Value::from("criticality"),
                    rmpv::Value::from("normal"),
                ),
                (
                    rmpv::Value::from("sensitivity"),
                    rmpv::Value::from("normal"),
                ),
            ]),
        ),
    ]);
    match entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("rules"))
    {
        Some((_, rmpv::Value::Array(rules))) => rules.push(rule),
        _ => return Err(Error::InvalidConfig("default policy has no rules".into())),
    }
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &rmpv::Value::Map(entries))
        .map_err(|_| Error::InvalidConfig("encode policy".into()))?;
    crate::test_fixtures::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &bytes,
    )
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
    clamp_admits(vault, contact_audience(contact, counterparty), record, None)
}

/// Whether the general clamp of an assembly the owner holds with `contact`
/// (named `counterparty`) present admits the claim `record` served as
/// `body`, a revision other than its live row, as a pinned hydration or a
/// history ledger serves one.
///
/// # Errors
/// A record the vault does not hold, or a read error.
pub fn clamp_admits_claim_revision_with_contact(
    vault: &Vault,
    contact: EntityId,
    counterparty: &str,
    record: &EntityId,
    body: &ClaimBody,
) -> Result<bool> {
    clamp_admits(
        vault,
        contact_audience(contact, counterparty),
        record,
        Some(body),
    )
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
        None,
    )
}

/// The owner with `contact` (named `counterparty`) present.
fn contact_audience(contact: EntityId, counterparty: &str) -> InterlocutorSet {
    InterlocutorSet::with_session_owner(vec![Interlocutor::known_contact(
        contact,
        counterparty,
        CounterpartyFirstTouch::UserIntroduction,
    )])
}

fn clamp_admits(
    vault: &Vault,
    audience: InterlocutorSet,
    record: &EntityId,
    claim_body: Option<&ClaimBody>,
) -> Result<bool> {
    let ctx = DisclosureContext::resolve(vault, audience)?;
    let rtxn = vault.store.env.read_txn()?;
    let row = vault
        .store
        .port_entity_record(&rtxn, record)?
        .ok_or(Error::EntityNotFound)?;
    ctx.admits_in(vault, &rtxn, record, row.entity_type, claim_body)
}
