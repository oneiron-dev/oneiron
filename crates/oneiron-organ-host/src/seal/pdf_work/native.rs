//! Trusted native preparation when no first-party prepare organ is selected.

use std::sync::{Arc, Mutex, PoisonError};

use oneiron::blob_artifact::esign::EsignSealerError;
use oneiron::blob_artifact::esign::render::{
    DecodeAdmissionError, InspectionMemory, PdfPreparation, PdfPreparationError, PreparedEsignPdf,
    prepare_esign_pdf_with_replayed_audit_admitted,
};

use super::super::HostedSealer;
use crate::resource_memory::{FloorLease, FloorRefusal, SharedFloor};

impl HostedSealer<'_> {
    pub(super) fn prepare_esign_pdf_native(
        &self,
        original: &[u8],
        request: &PdfPreparation<'_>,
        chain: [u8; 32],
        trail: &[String],
    ) -> Result<Option<PreparedEsignPdf>, EsignSealerError> {
        let Some(floor) = self.host.floor() else {
            return Ok(None);
        };
        let memory = Arc::new(PrepareMemory {
            floor,
            state: Mutex::new(MemoryState {
                lease: None,
                refused: None,
            }),
        });
        let prepared = prepare_esign_pdf_with_replayed_audit_admitted(
            original,
            request,
            self.vault.esign_stream_decode_bytes(),
            chain,
            trail.to_vec(),
            memory.clone(),
        );
        let refused = memory
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .refused;
        if let Some(refused) = refused {
            let error = match refused {
                FloorRefusal::Floor { needed, available } => {
                    PdfPreparationError::MemoryFloor { needed, available }
                }
                FloorRefusal::Deadline => PdfPreparationError::Deadline,
            };
            return Err(EsignSealerError::Retryable {
                stage: "prepare".to_owned(),
                code: error.to_string(),
                retry_after_ms: None,
            });
        }
        prepared
            .map(Some)
            .map_err(|error| EsignSealerError::InputInvalid {
                code: error.to_string(),
            })
    }
}

struct PrepareMemory {
    floor: SharedFloor,
    state: Mutex<MemoryState>,
}

struct MemoryState {
    lease: Option<Box<dyn FloorLease>>,
    refused: Option<FloorRefusal>,
}

impl InspectionMemory for PrepareMemory {
    fn admit(&self, bytes: u64) -> Result<(), DecodeAdmissionError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        // The native fallback has neither a call deadline nor a stop handle.
        // Keep reservations pending: the inspection port has no allocated-byte
        // notification and admission is not evidence of materialization.
        let admitted = match state.lease.as_mut() {
            Some(lease) => lease.grow_pending_untimed(bytes, &|| false),
            None => self.floor.0.lease_untimed(bytes, &|| false).map(|lease| {
                state.lease = Some(lease);
            }),
        };
        admitted.map_err(|refused| {
            state.refused.get_or_insert(refused);
            match refused {
                FloorRefusal::Floor { needed, available } => {
                    DecodeAdmissionError::MemoryFloor { needed, available }
                }
                FloorRefusal::Deadline => DecodeAdmissionError::Deadline,
            }
        })
    }

    fn release(&self, bytes: u64) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(lease) = state.lease.as_mut() {
            lease.shrink(bytes);
        }
    }
}
