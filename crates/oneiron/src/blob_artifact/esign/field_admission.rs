//! Admit saved and final field marks against the immutable original page geometry.
use super::{model::*, render};
use crate::{EntityId, Result, Vault};
use std::collections::BTreeMap;

pub(super) fn validate_event_fields(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    state: &EsignState,
    event: &EsignEvent,
) -> Result<()> {
    let fields = state.document.fields.iter().filter(|field| match event {
        EsignEvent::FieldSaved { signature } => field.id == signature.field,
        EsignEvent::Signed { recipient, .. } => field.recipient == *recipient,
        _ => false,
    });
    let mut pages = BTreeMap::new();
    for field in fields {
        // Parse each referenced item once, and retain only its bounded geometry.
        if let std::collections::btree_map::Entry::Vacant(entry) = pages.entry(field.item) {
            let item = state
                .document
                .items
                .get(field.item as usize)
                .ok_or_else(|| invalid("field item is missing"))?;
            let bytes = vault
                .read_blob_artifact_version_in_txn(
                    txn,
                    &EntityId::from_hex(&item.artifact_ref)?,
                    item.original_version,
                )?
                .ok_or_else(|| invalid("original PDF is missing"))?;
            entry.insert(
                render::inspect_pdf_pages(&bytes)
                    .map_err(|_| invalid("field page cannot be presented"))?,
            );
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
