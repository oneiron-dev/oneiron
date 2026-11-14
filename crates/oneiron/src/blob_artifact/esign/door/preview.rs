//! The typed recipient preview, on the engine's document memory port.
use super::{EsignScope, lane_scope};
use crate::blob_artifact::esign::render::{
    self, DecodeAdmissionError, FieldLayout, InspectionMemory, PageGeometry,
};
use crate::blob_artifact::esign::{EsignCapability, EsignField, FieldValue};
use crate::entity_doc::document_resources::{document_resources, machine_memory_refused};
use crate::memory::Memory;
use oneiron_contracts::memory::{MemoryError, MemoryResult};
use oneiron_docedit::resource::{Hold, ResourceRefusal};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

#[doc(hidden)]
pub use oneiron_verb_wire::blob_artifact::esign::door::preview::{
    EsignSigningPreviewRequest, EsignSigningPreviewView,
};

/// Pure field layout shared by the editor and capability-scoped previews.
///
/// # Errors
/// A field that names no page or whose geometry cannot be laid out.
pub fn layout_esign_preview(
    fields: &[EsignField],
    values: &BTreeMap<String, FieldValue>,
    pages: Vec<PageGeometry>,
) -> Result<EsignSigningPreviewView, render::PdfPreparationError> {
    let fields = fields
        .iter()
        .map(|field| {
            let page = pages
                .get(field.geometry.page.saturating_sub(1) as usize)
                .ok_or(render::PdfPreparationError::InvalidGeometry)?;
            render::layout_field(field, values.get(&field.id), *page)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(EsignSigningPreviewView { pages, fields })
}

impl Memory<'_> {
    /// `vault.esign.signing.preview`: the capability's pinned PDF and fields,
    /// inspected on the registered host's document memory port. A narrowed
    /// caller's lane still bounds the ceremony and its immutable read. Like
    /// the native image door, it uses the host's queue wait and adds no
    /// operation deadline of its own; the HTTP door keeps its own deadline.
    ///
    /// # Errors
    /// An inadmissible capability/item, a lane it cannot reach, malformed
    /// PDF or field geometry, or a typed memory-floor/queue-wait refusal.
    pub fn esign_signing_preview(
        &self,
        input: &EsignSigningPreviewRequest,
    ) -> MemoryResult<EsignSigningPreviewView> {
        let token = EsignCapability::parse(&input.token)?;
        let scope = self.esign_scope()?;
        let resources = document_resources();
        let vault = self.vault();
        let ceiling = |txn: &heed::RoTxn<'_>, document| match &scope {
            EsignScope::Unrestricted => Ok(true),
            EsignScope::Credential(lane) => lane_scope::reaches(lane, txn, document),
        };
        let (page, buffered, hold) = vault.esign_preview_for_capability_admitted_within(
            &token,
            input.item,
            self.signing_caller(),
            Some(self.actor()),
            &resources,
            &ceiling,
        )?;
        let parse = Arc::new(PreviewMemory::new(hold));
        // Bound after the controller so the PDF bytes drop before their hold.
        let pdf = buffered;
        let pages = render::inspect_pdf_pages_admitted(
            &pdf,
            vault.esign_stream_decode_bytes(),
            parse.clone(),
        )
        .map_err(|_| match parse.refused() {
            Some(refusal) => MemoryError::from(machine_memory_refused(refusal)),
            None => MemoryError::bad_request("signing preview is unavailable"),
        })?;
        let fields: Vec<_> = page
            .fields
            .into_iter()
            .filter(|field| field.item as usize == input.item)
            .collect();
        let values = page
            .values
            .into_iter()
            .map(|(key, row)| (key, row.value))
            .collect();
        layout_esign_preview(&fields, &values, pages)
            .map_err(|_| MemoryError::bad_request("signing preview is unavailable"))
    }
}

/// One operation's input hold grows for the parse's peak, never a second ledger.
struct PreviewMemory(Mutex<PreviewHeld>);

struct PreviewHeld {
    hold: Hold,
    spare: u64,
    refused: Option<ResourceRefusal>,
}

impl PreviewMemory {
    fn new(hold: Hold) -> Self {
        Self(Mutex::new(PreviewHeld {
            hold,
            spare: 0,
            refused: None,
        }))
    }

    fn refused(&self) -> Option<ResourceRefusal> {
        lock(&self.0).refused
    }
}

impl InspectionMemory for PreviewMemory {
    fn admit(&self, bytes: u64) -> Result<(), DecodeAdmissionError> {
        let mut held = lock(&self.0);
        if let Some(spare) = held.spare.checked_sub(bytes) {
            held.spare = spare;
            return Ok(());
        }
        let need = bytes - held.spare;
        match held.hold.take(need) {
            Ok(()) => {
                held.spare = 0;
                Ok(())
            }
            Err(refusal) => {
                held.refused.get_or_insert(refusal);
                Err(match refusal {
                    ResourceRefusal::MemoryFloor { needed, available } => {
                        DecodeAdmissionError::MemoryFloor { needed, available }
                    }
                    ResourceRefusal::Deadline => DecodeAdmissionError::Deadline,
                })
            }
        }
    }

    fn release(&self, bytes: u64) {
        let mut held = lock(&self.0);
        held.spare = held.spare.saturating_add(bytes);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
