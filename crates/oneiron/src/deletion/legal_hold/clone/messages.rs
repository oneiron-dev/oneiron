//! Exact stored on-record MESSAGE records for an order that names them
//! (LEGAL-HOLD-USE = B as a clone, owner 2026-11-05). Each selected id must
//! be a stored MESSAGE row. Its document rows (head, slot rows, updates) and
//! its outgoing edge rows follow it, copied as stored, then the result body
//! its result attachment names, when the message still holds it. Nothing
//! here writes live-vault state or follows another reference: an asset or a
//! model-call record is not part of this extent.

use std::io::{self, Read};
use std::ops::Bound;
use std::os::unix::net::UnixStream;

use heed::RoTxn;
use oneiron_crypto::HybridPublicKey;
use oneiron_crypto::legal_clone::SourceComponent;
use oneiron_vault_contract::host_legal::{CaptureExtent, CaptureRequest, CaptureSource};

use super::collector::{Collector, SummaryCounts};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::memory::MessageResultAttachment;
use crate::ports::{DocumentSlot, DocumentUpdateKey};
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::side_table::{self, Raw, SideTable};
use crate::store::ManifestDbs;
use crate::store::result_body_reader::{CodeRunResultBodyReader, Source};
use crate::store::result_body_rows::RAW_OUTPUTS;
use crate::store::result_manifest::CodeRunRawOutput;

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

/// The family label a held result body's stored key is digested under.
const RESULT_BODY_FAMILY: &str = "code_run:raw_output";

/// One exact stored row of a selected message.
struct MessageRow {
    component: SourceComponent,
    family: &'static str,
    key: Vec<u8>,
    value: Vec<u8>,
}

/// Streams every selected message, in id order, under one source snapshot:
/// every result body pinned, then the custody read guard before the source
/// writer, as a gate capture takes them, all held until the HOST
/// acknowledges the exact request and transcript. A missing selected
/// message, or a selected id whose row is not a MESSAGE, fails the capture
/// before its summary, so no ACK can claim it. A message whose attachment
/// names a body it no longer holds, or that no row holds, is captured
/// without it and named in the summary's absent list.
pub(super) fn capture(
    stream: &mut UnixStream,
    vault: &Vault,
    request: &CaptureRequest,
    public: &HybridPublicKey,
    ids: &[[u8; 16]],
    check: impl Fn() -> Result<()>,
) -> Result<()> {
    // The snapshot finds its bodies inside it, so every body is pinned
    // before it opens and stays pinned past the last read.
    let _bodies = vault.pin_all_result_bodies();
    let _custody = vault.store.gate_custody_read_guard()?;
    let txn = vault.store.env.write_txn()?;
    check()?;
    let mut collector = Collector::pinned(stream, public, request)?;
    let mut absent_result_bodies = Vec::new();
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
        let output = match result_body(vault, &txn, id, &rows[0].value)? {
            None => continue,
            Some(ResultBody::Released) => {
                absent_result_bodies.push(*id);
                continue;
            }
            Some(ResultBody::Held(output)) => output,
        };
        let Some(CodeRunResultBodyReader {
            source,
            len,
            digest,
            _pin,
        }) = vault.code_run_result_body_reader_in_txn(&txn, &output)?
        else {
            absent_result_bodies.push(*id);
            continue;
        };
        let mut input: Box<dyn Read + '_> = match source {
            // The row lends its bytes, past its tag.
            Source::Inline(row) => {
                let mut row = io::Cursor::new(row);
                row.set_position(1);
                Box::new(row)
            }
            Source::File(file) => Box::new(file),
        };
        collector.component(
            SourceComponent::MessageResultBody,
            CaptureSource::Message(*id),
            RESULT_BODY_FAMILY,
            &RAW_OUTPUTS.key_bytes(&output.handle),
            revision,
            len,
            digest,
            &mut *input,
            &check,
        )?;
    }
    check()?;
    collector.finish_counted(
        SummaryCounts {
            messages: ids.len() as u64,
            absent_result_bodies,
            ..SummaryCounts::default()
        },
        CaptureExtent::Messages,
        &check,
    )?;
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

/// What a selected message's result attachment names.
enum ResultBody {
    /// The message holds this body.
    Held(CodeRunRawOutput),
    /// The attachment names a body the message no longer holds.
    Released,
}

/// The result body the stored MESSAGE row `row` names, as a read of its
/// result finds it held: its own occurrence of that exact body, from the
/// producer run, occurrence and path the attachment names. `None` when the
/// row names no result. A world withhold on the producer's served rows is a
/// read-surface rule and is not applied: the clone copies the stored record,
/// sealed to the order's recipient.
fn result_body(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &[u8; 16],
    row: &[u8],
) -> Result<Option<ResultBody>> {
    let Some(attachment) = row
        .get(ENTITY_METADATA_HEADER_LEN..)
        .and_then(message_metadata)
        .and_then(|metadata| {
            MessageResultAttachment::from_metadata(Some(&metadata))
                .ok()
                .flatten()
        })
    else {
        return Ok(None);
    };
    let message = EntityId::from_bytes(*id)?;
    let output = attachment.output()?;
    let occurrence = attachment.message_occurrence(message)?;
    let source = &attachment.source;
    let held = crate::provenance::body::owned_body_in_txn(&vault.store, txn, &message, &occurrence)?
        .filter(|hold| {
            hold.state.held().is_some_and(|body| {
                body.blake3 == output.raw_blake3 && body.bytes == output.raw_len
            })
        })
        .and_then(|hold| hold.result)
        .is_some_and(|held| {
            held.run_id == source.run_id
                && held.occurrence == source.occurrence
                && held.path == source.path
        });
    Ok(Some(if held {
        ResultBody::Held(output)
    } else {
        ResultBody::Released
    }))
}

/// A MESSAGE body's metadata, as JSON, read in place.
fn message_metadata(body: &[u8]) -> Option<serde_json::Value> {
    let mut cursor = body;
    let Ok(rmpv::ValueRef::Map(fields)) = rmpv::decode::read_value_ref(&mut cursor) else {
        return None;
    };
    fields.into_iter().find_map(|(key, value)| match key {
        rmpv::ValueRef::String(key) if key.as_str() == Some("metadata") => {
            Some(crate::serialize::msgpack_value_to_json(&value.to_owned()))
        }
        _ => None,
    })
}
