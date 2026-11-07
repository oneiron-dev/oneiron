//! Exact stored on-record MESSAGE records for an order that names them
//! (LEGAL-HOLD-USE = B as a clone, owner 2026-11-05). Each selected id must
//! be a stored MESSAGE row. Its document rows (head, slot rows, updates) and
//! its outgoing edge rows follow it, copied as stored. Nothing here writes
//! live-vault state, opens a body file or follows another reference: a
//! result attachment, an asset or a model-call record is not part of this
//! extent.

use std::io;
use std::ops::Bound;
use std::os::unix::net::UnixStream;

use heed::RoTxn;
use oneiron_crypto::HybridPublicKey;
use oneiron_crypto::legal_clone::SourceComponent;
use oneiron_vault_contract::host_legal::{CaptureExtent, CaptureRequest, CaptureSource};

use super::collector::Collector;
use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{DocumentSlot, DocumentUpdateKey};
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::side_table::{self, Raw, SideTable};
use crate::store::ManifestDbs;

/// The single-row document families of a slot, with the label each stored
/// key is digested under.
const SLOT_ROWS: [(&str, SideTable<DocumentSlot, Vec<u8>, Raw>); 4] = [
    (
        "document:snapshot",
        SideTable::new(&side_table::DOCUMENT_SNAPSHOT),
    ),
    (
        "document:state_vector",
        SideTable::new(&side_table::DOCUMENT_STATE_VECTOR),
    ),
    (
        "document:shallow_since",
        SideTable::new(&side_table::DOCUMENT_SHALLOW_SINCE),
    ),
    (
        "document:update_sequence",
        SideTable::new(&side_table::SYNC_M_U_SEQ_E),
    ),
];
const UPDATES: SideTable<DocumentUpdateKey, Vec<u8>, Raw> =
    SideTable::new(&side_table::DOCUMENT_UPDATE);

/// One exact stored row of a selected message.
struct MessageRow {
    component: SourceComponent,
    family: &'static str,
    key: Vec<u8>,
    value: Vec<u8>,
}

/// Streams every selected message, in id order, under one source snapshot:
/// the custody read guard before the source writer, as a gate capture takes
/// them, both held until the HOST acknowledges the exact request and
/// transcript. A missing selected message, or a selected id whose row is not
/// a MESSAGE, fails the capture before its summary, so no ACK can claim it.
pub(super) fn capture(
    stream: &mut UnixStream,
    vault: &Vault,
    request: &CaptureRequest,
    public: &HybridPublicKey,
    ids: &[[u8; 16]],
    check: impl Fn() -> Result<()>,
) -> Result<()> {
    let _custody = vault.store.gate_custody_read_guard()?;
    let txn = vault.store.env.write_txn()?;
    check()?;
    let mut collector = Collector::pinned(stream, public, request)?;
    for id in ids {
        check()?;
        let rows = message_rows(vault, &txn, id)?;
        // Every component of one message carries the revision of its row.
        let revision = *blake3::hash(&rows[0].value).as_bytes();
        for row in &rows {
            let fingerprint = *blake3::hash(&row.value).as_bytes();
            collector.component(
                row.component,
                CaptureSource::Message(*id),
                row.family,
                &row.key,
                revision,
                row.value.len() as u64,
                fingerprint,
                &mut &row.value[..],
                &check,
            )?;
        }
    }
    check()?;
    collector.finish(0, 0, 0, ids.len() as u64, CaptureExtent::Messages, &check)?;
    // Read-only abort, after the exact durable HOST acknowledgement.
    drop(txn);
    Ok(())
}

/// The exact stored rows of message `id`: its entity row first, then its
/// document head and that slot's rows and updates, then its outgoing edges.
fn message_rows(vault: &Vault, txn: &RoTxn<'_>, id: &[u8; 16]) -> Result<Vec<MessageRow>> {
    let store = &vault.store;
    let Some(value) = store.entities().get(txn, &id[..])? else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "legal capture selected message unavailable",
        )
        .into());
    };
    let value = value.to_vec();
    if EntityMetadataHeader::parse(&value).map(|header| header.entity_type)
        != Some(ENTITY_TYPE_MESSAGE)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "legal capture selected record is not a message",
        )
        .into());
    }
    let mut rows = vec![MessageRow {
        component: SourceComponent::MessageRow,
        family: "entities",
        key: id.to_vec(),
        value,
    }];
    let entity = EntityId::from_bytes(*id)?;
    if let Some((key, value, slot)) =
        crate::entity_doc::record_head_row_in_txn(store, txn, &entity)?
    {
        rows.push(MessageRow {
            component: SourceComponent::MessageDocument,
            family: "entity_doc:head",
            key,
            value,
        });
        for (family, table) in SLOT_ROWS {
            if let Some(value) = table.get_bytes(store, txn, &slot)? {
                rows.push(MessageRow {
                    component: SourceComponent::MessageDocument,
                    family,
                    key: table.key_bytes(&slot),
                    value,
                });
            }
        }
        let mut prefix = slot.to_hex().into_bytes();
        prefix.push(b':');
        for row in UPDATES.iter_raw_from(store, txn, &prefix)? {
            let (suffix, value) = row?;
            let mut key = UPDATES.decl().prefix.to_vec();
            key.extend_from_slice(&suffix);
            rows.push(MessageRow {
                component: SourceComponent::MessageDocument,
                family: "document:update",
                key,
                value,
            });
        }
    }
    let edges = store
        .edges_out()
        .range(txn, &(Bound::Included(&id[..]), Bound::<&[u8]>::Unbounded))?;
    for row in edges {
        let (key, value) = row?;
        if !key.starts_with(&id[..]) {
            break;
        }
        rows.push(MessageRow {
            component: SourceComponent::MessageEdge,
            family: "edges_out",
            key: key.to_vec(),
            value: value.to_vec(),
        });
    }
    Ok(rows)
}
