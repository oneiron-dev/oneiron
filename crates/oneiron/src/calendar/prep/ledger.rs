//! Direct contact-attendee obligations, projected from the serving read.

use std::collections::HashSet;

use super::pack::{PrepItem, PrepSectionKind};
use super::wake::PrepEvent;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{claim_surfaceable, decode_claim_body};
use crate::commitment::{CommitmentStatus, decode_commitment_claim};
use crate::ports::EntityStoreRead;
use crate::store::ManifestDbs;
use crate::{EntityId, Error, Result, Vault};

pub(super) fn unscoped_ledger_prep_items(
    vault: &Vault,
    event: &PrepEvent,
    fired_at: u64,
) -> Result<Vec<(EntityId, PrepItem)>> {
    let txn = vault.store.env.read_txn()?;
    ledger_prep_items(
        vault,
        &vault.store.read(),
        vault.store.pending_scan_checks(),
        &txn,
        event,
        fired_at,
        |id| {
            Ok(vault
                .store
                .port_entity_record(&txn, id)?
                .map(|row| row.encode()))
        },
    )
}

/// `source` returns this caller's projected row, never merely its membership
/// in the PPR result. Every deciding label and rendered promise uses this cut.
pub(super) fn ledger_prep_items(
    vault: &Vault,
    store: &crate::store::StoreRead<'_>,
    pending: &crate::store::PendingScanChecks,
    txn: &heed::RoTxn<'_>,
    event: &PrepEvent,
    fired_at: u64,
    mut source: impl FnMut(&EntityId) -> Result<Option<Vec<u8>>>,
) -> Result<Vec<(EntityId, PrepItem)>> {
    let mut source_in_time = |id: &EntityId| -> Result<Option<Vec<u8>>> {
        let Some(raw) = source(id)? else {
            return Ok(None);
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("prep ledger source header"))?;
        Ok((header.learned_at <= fired_at).then_some(raw))
    };
    let mut contacts: Vec<_> = event.attendee_refs.iter().map(|id| (*id, None)).collect();
    for id in vault.claims_for_subject_from_read_in_txn(store, txn, &event.event_ref)? {
        let Some(raw) = source_in_time(&id)? else {
            continue;
        };
        let Ok(body) = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true) else {
            continue;
        };
        if body.predicate != crate::calendar::claims::PREDICATE_CALENDAR_ATTENDEE
            || !claim_surfaceable(&body)
            || !crate::gate::claim_critical_confirm_settled_in_txn(store.base(), txn, &id)?
        {
            continue;
        }
        let Ok(attendee) = crate::calendar::claims::decode_attendee_value(&body.value) else {
            continue;
        };
        let party = attendee
            .who
            .strip_prefix("mailto:")
            .unwrap_or(&attendee.who)
            .trim();
        if !party.contains('@') {
            continue;
        }
        for contact in crate::counterparty_contact::contact_ids_with_live_head_from_read_in_txn(
            store,
            pending,
            txn,
            crate::counterparty_contact::PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY,
            party,
        )? {
            contacts.push((contact, Some((party.to_owned(), id))));
        }
    }
    let mut seen = HashSet::new();
    let mut items = Vec::new();
    for (attendee, expected_party) in &contacts {
        let (ledger, label_heads) =
            match vault.commitment_ledger_for_counterparty_in_txn(store, txn, attendee, |id| {
                Ok(source_in_time(id)?.is_some())
            }) {
                Ok(ledger) => ledger,
                Err(Error::EntityNotFound | Error::InvalidEntityType(_)) => continue,
                Err(error) => return Err(error),
            };
        if expected_party
            .as_ref()
            .is_some_and(|(party, _)| ledger.counterparty.counterparty != *party)
        {
            continue;
        }
        for entry in ledger.owed_by_them.into_iter().chain(ledger.owed_to_them) {
            if seen.contains(&entry.commitment_id) {
                continue;
            }
            let Some(raw) = source_in_time(&entry.commitment_id)? else {
                continue;
            };
            // The ledger selected an open obligation. Render only the native
            // caller projection, which may mask its words or withhold its body.
            let Ok(body) = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true) else {
                continue;
            };
            let Ok(Some(record)) = decode_commitment_claim(&body) else {
                continue;
            };
            if !claim_surfaceable(&body) || record.status != CommitmentStatus::Open {
                continue;
            }
            let text = record.content.text.trim();
            if text.is_empty() {
                continue;
            }
            seen.insert(entry.commitment_id);
            let mut source_refs = vec![entry.commitment_id.to_hex()];
            for head in label_heads {
                let hex = head.to_hex();
                if !source_refs.contains(&hex) {
                    source_refs.push(hex);
                }
            }
            if let Some((_, attendee_claim)) = expected_party {
                let hex = attendee_claim.to_hex();
                if !source_refs.contains(&hex) {
                    source_refs.push(hex);
                }
            }
            items.push((
                entry.commitment_id,
                PrepItem {
                    kind: PrepSectionKind::PriorCommitment,
                    text: text.to_owned(),
                    source_refs,
                    observed_at: entry.learned_at,
                },
            ));
        }
    }
    Ok(items)
}
