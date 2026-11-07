//! Late recipient linkage (FIX 11030): a send whose party had no PERSON when
//! it was admitted still reaches the person the vault later knows by that
//! party, so that person's erase takes it.
//!
//! At admission, a frozen send that names its counterparty (the pipeline's
//! top-level `counterparty_ref`; a campaign leg's member party) and resolves
//! to no PERSON keeps the BLAKE3 digest of that exact party key. When a
//! PERSON is deleted, while its body still names its party key, each such
//! send kept under that digest is linked to it: linkage only, nothing is
//! erased then, so a reversible delete loses nothing. The actor scrub that
//! erases the person reads the links and stops and erases those sends as it
//! does a send that named the person at admission
//! ([`super::erase_outbound_intent_actor_in_txn`]). An erased send drops its
//! digest and links. A scoped MCP call names no trusted recipient and is
//! never linked: its arguments are a foreign tool's, not a party.

use std::io::Cursor;

use heed::{RoTxn, RwTxn};
use rmpv::Value;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

/// A frozen send's counterparty field, as the pipeline freezes it.
const FROZEN_COUNTERPARTY_FIELD: &str = "counterparty_ref";
/// A comm PERSON body's party key field.
const PERSON_PARTY_KEY_FIELD: &str = "party_key";
/// The BLAKE3 derive-key context of a party digest.
const PARTY_DIGEST_CONTEXT: &str = "oneiron.outbound.intent_party.v1";

/// Each unresolved send by its party digest: by the digest and the intent
/// id, the value its admission time.
const PARTIES: SideTable<([u8; 32], [u8; 32]), u64, Named> =
    SideTable::new(&side_table::OUTBOUND_INTENT_PARTY);
/// Each unresolved send's party digest, by its intent id.
const PARTY_OF_INTENT: SideTable<[u8; 32], [u8; 32], Named> =
    SideTable::new(&side_table::OUTBOUND_INTENT_PARTY_OF);
/// The sends linked to a deleted PERSON: by the person and the intent id,
/// the value when the link was made.
const LATE_RECIPIENTS: SideTable<(EntityId, [u8; 32]), u64, Named> =
    SideTable::new(&side_table::OUTBOUND_INTENT_LATE_RECIPIENT);

fn party_digest(party: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(PARTY_DIGEST_CONTEXT);
    hasher.update(party.as_bytes());
    *hasher.finalize().as_bytes()
}

/// The party key a frozen send names, when it is the pipeline's JSON.
fn payload_party(payload: &[u8]) -> Option<String> {
    let frozen: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let party = frozen.get(FROZEN_COUNTERPARTY_FIELD)?.as_str()?;
    (!party.is_empty()).then(|| party.to_owned())
}

/// The party key a PERSON body names, whatever the PERSON's lifecycle: a
/// deleted person's body is read before it goes.
fn person_party_key(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> crate::Result<Option<String>> {
    let Some(raw) = store.port_entity_record(txn, id)? else {
        return Ok(None);
    };
    if raw.entity_type != ENTITY_TYPE_PERSON || raw.body.is_empty() {
        return Ok(None);
    }
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut Cursor::new(&raw.body)) else {
        return Ok(None);
    };
    Ok(entries.into_iter().find_map(|(key, value)| {
        (key.as_str() == Some(PERSON_PARTY_KEY_FIELD))
            .then(|| {
                value
                    .as_str()
                    .filter(|party| !party.is_empty())
                    .map(str::to_owned)
            })
            .flatten()
    }))
}

/// At admission, in its writer: keeps the party digest of a send whose
/// frozen counterparty resolved to no PERSON (`recipient` is `None`).
///
/// # Errors
/// Storage faults.
pub(crate) fn record_unresolved_party_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    intent: &[u8; 32],
    payload: &[u8],
    recipient: Option<EntityId>,
) -> crate::Result<()> {
    if recipient.is_some() {
        return Ok(());
    }
    let Some(party) = payload_party(payload) else {
        return Ok(());
    };
    let digest = party_digest(&party);
    let at = crate::unix_seconds_now();
    PARTIES.put(&vault.store, txn, &(digest, *intent), &at)?;
    PARTY_OF_INTENT.put(&vault.store, txn, intent, &digest)
}

/// The derived-rows eraser (deletion/derived_rows.rs): when a PERSON is
/// deleted, links every unresolved send kept under its party's digest to
/// it, while its body still names the party. A no-op for any other row, and
/// at once while no send is unresolved.
///
/// # Errors
/// Storage faults.
pub(crate) fn link_late_recipients_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
) -> crate::Result<()> {
    if PARTY_OF_INTENT.iter_from(store, txn, &[])?.next().is_none() {
        return Ok(());
    }
    let Some(party) = person_party_key(store, txn, id)? else {
        return Ok(());
    };
    let digest = party_digest(&party);
    let sends: Vec<[u8; 32]> = PARTIES
        .scan_keys(store, txn, &digest)?
        .into_iter()
        .map(|(_, intent)| intent)
        .collect();
    let at = crate::unix_seconds_now();
    for intent in sends {
        LATE_RECIPIENTS.put(store, txn, &(*id, intent), &at)?;
    }
    Ok(())
}

/// The sends linked to the PERSON `person` since admission.
///
/// # Errors
/// Storage faults.
pub(crate) fn late_recipient_intents_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    person: &EntityId,
) -> crate::Result<Vec<[u8; 32]>> {
    Ok(LATE_RECIPIENTS
        .scan_keys(&vault.store, txn, person.as_bytes())?
        .into_iter()
        .map(|(_, intent)| intent)
        .collect())
}

/// Drops an erased send's party digest and every link naming it.
///
/// # Errors
/// Storage faults.
pub(crate) fn forget_intent_party_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    intent: &[u8; 32],
) -> crate::Result<()> {
    if let Some(digest) = PARTY_OF_INTENT.get(&vault.store, txn, intent)? {
        PARTIES.delete(&vault.store, txn, &(digest, *intent))?;
        PARTY_OF_INTENT.delete(&vault.store, txn, intent)?;
    }
    let links: Vec<(EntityId, [u8; 32])> = LATE_RECIPIENTS
        .scan_keys(&vault.store, txn, &[])?
        .into_iter()
        .filter(|(_, linked)| linked == intent)
        .collect();
    for link in links {
        LATE_RECIPIENTS.delete(&vault.store, txn, &link)?;
    }
    Ok(())
}
