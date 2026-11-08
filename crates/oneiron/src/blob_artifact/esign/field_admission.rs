//! Admit saved and final field marks against the immutable original page geometry.
//!
//! The original PDFs a field save or a sign act lays its fields on are
//! inspected before its writer (FIX 9609): in the host's isolated worker
//! when it has one, else natively. The writer lays the fields out on that
//! inspection when it is of the exact bytes the writer's snapshot pins; it
//! reads and parses only an item that inspection does not hold.
use super::render::{self, PageGeometry};
use super::{model::*, sealer::EsignSealerError};
use crate::{EntityId, Error, Result, Vault};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

/// The fields an event's admission lays out (FIX 9609): the one field a
/// `FieldSaved` saves, or every field of the recipient a `Signed` signs for.
pub(super) enum EventFields {
    Saved(String),
    Signer(String),
}

impl EventFields {
    /// The fields `event` lays out; `None` for an event that lays out none.
    fn of(event: &EsignEvent) -> Option<Self> {
        match event {
            EsignEvent::FieldSaved { signature } => Some(Self::Saved(signature.field.clone())),
            EsignEvent::Signed { recipient, .. } => Some(Self::Signer(recipient.clone())),
            _ => None,
        }
    }

    /// Whether `field` is one of these fields.
    fn selects(&self, field: &EsignField) -> bool {
        match self {
            Self::Saved(id) => field.id == *id,
            Self::Signer(recipient) => field.recipient == *recipient,
        }
    }
}

/// The isolated inspection's name in a refusal it caused.
const INSPECTION_TOOL: &str = "esign.inspect";

/// Why an item's inspection before the writer gave no pages (FIX 9609).
enum InspectionFailure {
    /// The PDF cannot be read: answered as a page that cannot be presented.
    Unreadable,
    /// The isolated worker refused for its memory, its deadline or its
    /// availability, under its own code: answered as a retryable failure,
    /// never as invalid input.
    Refused(String),
}

impl InspectionFailure {
    /// The isolated worker's refusal: one that may pass later keeps its
    /// code where that is a plain snake_case name, the only code a caller
    /// is shown; any other refusal says the PDF cannot be read.
    fn of(refusal: &EsignSealerError) -> Self {
        match refusal {
            EsignSealerError::Retryable { code, .. }
                if !code.is_empty()
                    && code.len() <= 64
                    && code
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') =>
            {
                Self::Refused(code.clone())
            }
            EsignSealerError::Retryable { .. } => Self::Refused("retryable".to_owned()),
            EsignSealerError::Unavailable { .. } => Self::Refused("unavailable".to_owned()),
            _ => Self::Unreadable,
        }
    }

    /// The writer's answer for this failure.
    fn error(&self) -> Error {
        match self {
            Self::Unreadable => invalid("field page cannot be presented"),
            Self::Refused(code) => Error::UpstreamToolFailure {
                tool: INSPECTION_TOOL,
                code: code.clone(),
            },
        }
    }
}

/// One item's inspection before the writer, bound to the exact bytes it
/// inspected: the item's pin and that version's content hash (FIX 9609).
struct InspectedItem {
    artifact_ref: String,
    original_version: u64,
    content_hash: [u8; 32],
    pages: std::result::Result<Vec<PageGeometry>, InspectionFailure>,
}

/// The inspections an event's items had before its writer, by item index
/// (FIX 9609). Empty: the writer reads and parses each item itself.
#[derive(Default)]
pub(super) struct InspectedPages(BTreeMap<u32, InspectedItem>);

/// Lays out each field `event` saves or signs on its item's original page,
/// refusing one that cannot be presented. An item's pages come from
/// `inspected` when it holds the bytes this snapshot pins (FIX 9609).
pub(super) fn validate_event_fields(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    state: &EsignState,
    event: &EsignEvent,
    inspected: &InspectedPages,
) -> Result<()> {
    let Some(selected) = EventFields::of(event) else {
        return Ok(());
    };
    let mut pages = BTreeMap::new();
    for field in state
        .document
        .fields
        .iter()
        .filter(|field| selected.selects(field))
    {
        // Parse each referenced item once, and retain only its bounded geometry.
        if let Entry::Vacant(entry) = pages.entry(field.item) {
            let item = state
                .document
                .items
                .get(field.item as usize)
                .ok_or_else(|| invalid("field item is missing"))?;
            entry.insert(item_pages(vault, txn, field.item, item, inspected)?);
        }
        let page = pages[&field.item]
            .get(field.geometry.page as usize - 1)
            .ok_or_else(|| invalid("field page is missing"))?;
        render::layout_field(
            field,
            state
                .signatures
                .get(&field.id)
                .map(|signature| &signature.value),
            *page,
        )
        .map_err(|_| invalid("field cannot be presented"))?;
    }
    Ok(())
}

/// `item`'s pages in the writer's snapshot: its inspection before the
/// writer when that was of the version this snapshot pins, matched by
/// content hash with no body read (FIX 9609); else its bytes read and
/// parsed here, as before.
fn item_pages<'a>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    index: u32,
    item: &EsignItem,
    inspected: &'a InspectedPages,
) -> Result<Cow<'a, [PageGeometry]>> {
    let artifact = EntityId::from_hex(&item.artifact_ref)?;
    if let Some(prior) = inspected.0.get(&index)
        && prior.artifact_ref == item.artifact_ref
        && prior.original_version == item.original_version
        && version_hash_in(vault, txn, &artifact, item.original_version)?
            == Some(prior.content_hash)
    {
        return prior
            .pages
            .as_deref()
            .map(Cow::Borrowed)
            .map_err(InspectionFailure::error);
    }
    let bytes = vault
        .read_blob_artifact_version_in_txn(txn, &artifact, item.original_version)?
        .ok_or_else(|| invalid("original PDF is missing"))?;
    render::inspect_pdf_pages_within(&bytes, vault.esign_stream_decode_bytes())
        .map(Cow::Owned)
        .map_err(|_| invalid("field page cannot be presented"))
}

/// The content hash of `artifact`'s `version`, read through the gates its
/// byte read keeps, with no body read.
fn version_hash_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    artifact: &EntityId,
    version: u64,
) -> Result<Option<[u8; 32]>> {
    vault.read_blob_artifact_version_in_txn_with_record(txn, artifact, version, |_, record| {
        Ok::<_, Error>(record.content_hash)
    })
}

/// Inspects, before any writer, the original PDFs an event will lay its
/// fields on (FIX 9609). `read` resolves in one read snapshot the document
/// state and the event's fields, as the writer selects them, or `None`
/// where the writer will append no such event. Each item's bytes and
/// content hash are read in a snapshot of their own, closed before the item
/// is inspected through the host's
/// [`EsignPageInspector`](super::EsignPageInspector), or natively where it
/// has none. A read that fails inspects nothing: the writer then reads, and
/// answers, for itself.
pub(super) fn inspect_event_pages(
    vault: &Vault,
    read: impl FnOnce(&heed::RoTxn<'_>) -> Result<Option<(EsignState, EventFields)>>,
) -> InspectedPages {
    let Ok(items) = event_items(vault, read) else {
        return InspectedPages::default();
    };
    let mut inspected = BTreeMap::new();
    for (index, item) in items {
        let Ok(Some((content_hash, bytes))) = pinned_bytes(vault, &item) else {
            continue;
        };
        let pages = inspected_pages(vault, &bytes);
        inspected.insert(
            index,
            InspectedItem {
                artifact_ref: item.artifact_ref,
                original_version: item.original_version,
                content_hash,
                pages,
            },
        );
    }
    InspectedPages(inspected)
}

/// The distinct items, by index, that the fields `read` selects lie on.
fn event_items(
    vault: &Vault,
    read: impl FnOnce(&heed::RoTxn<'_>) -> Result<Option<(EsignState, EventFields)>>,
) -> Result<BTreeMap<u32, EsignItem>> {
    let txn = vault.store.env.read_txn()?;
    let Some((state, fields)) = read(&txn)? else {
        return Ok(BTreeMap::new());
    };
    Ok(state
        .document
        .fields
        .iter()
        .filter(|field| fields.selects(field))
        .filter_map(|field| {
            let item = state.document.items.get(field.item as usize)?;
            Some((field.item, item.clone()))
        })
        .collect())
}

/// `item`'s original bytes and its version's content hash, read in one
/// snapshot that closes on return.
fn pinned_bytes(vault: &Vault, item: &EsignItem) -> Result<Option<([u8; 32], Vec<u8>)>> {
    let artifact = EntityId::from_hex(&item.artifact_ref)?;
    let txn = vault.store.env.read_txn()?;
    let Some(content_hash) = version_hash_in(vault, &txn, &artifact, item.original_version)? else {
        return Ok(None);
    };
    Ok(vault
        .read_blob_artifact_version_in_txn(&txn, &artifact, item.original_version)?
        .map(|bytes| (content_hash, bytes)))
}

/// `pdf`'s pages, outside any writer: in the host's isolated worker when it
/// has one, else natively, as the writer parsed them before FIX 9609.
fn inspected_pages(
    vault: &Vault,
    pdf: &[u8],
) -> std::result::Result<Vec<PageGeometry>, InspectionFailure> {
    if let Some(inspector) = vault.esign_page_inspector() {
        match inspector.inspect_pages(vault, pdf) {
            Ok(Some(pages)) => return Ok(pages),
            Ok(None) => {}
            Err(refusal) => return Err(InspectionFailure::of(&refusal)),
        }
    }
    render::inspect_pdf_pages_within(pdf, vault.esign_stream_decode_bytes())
        .map_err(|_| InspectionFailure::Unreadable)
}
