//! Trusted native preparation when no first-party prepare organ is selected.

use std::sync::{Arc, Mutex, PoisonError};

use oneiron::blob_artifact::esign::EsignSealerError;
use oneiron::blob_artifact::esign::render::{
    DecodeAdmissionError, InspectionMemory, PdfPreparation, PdfPreparationError, PreparedEsignPdf,
    prepare_esign_pdf_with_replayed_audit_admitted,
};

use super::super::HostedSealer;
use crate::resource_memory::FloorRefusal;

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
        // The caller reports the actual capacities of its pinned byte buffers;
        // they are outside this pool and the original is already included.
        let mut capacity = 0;
        loop {
            let lease = if capacity == 0 {
                None
            } else {
                floor
                    .0
                    .check_irreducible_peak(request.pinned_buffer_bytes, capacity)
                    .map_err(memory_refused)?;
                let lease = floor
                    .0
                    .try_lease(capacity)
                    .map_err(memory_refused)?
                    .ok_or_else(|| EsignSealerError::Retryable {
                        stage: "prepare".to_owned(),
                        code: "memory_unavailable".to_owned(),
                        retry_after_ms: None,
                    })?;
                Some(lease)
            };
            let memory = Arc::new(PrepareMemory {
                state: Mutex::new(MemoryState {
                    capacity,
                    used: 0,
                    shortfall: None,
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
            let shortfall = memory
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .shortfall;
            if let Some(needed) = shortfall {
                drop(prepared);
                drop(memory);
                drop(lease);
                capacity = needed;
                continue;
            }
            return prepared
                .map(Some)
                .map_err(|error| EsignSealerError::InputInvalid {
                    code: error.to_string(),
                });
        }
    }
}

fn memory_refused(refused: FloorRefusal) -> EsignSealerError {
    let error = match refused {
        FloorRefusal::Floor { needed, available } => {
            PdfPreparationError::MemoryFloor { needed, available }
        }
        FloorRefusal::Deadline => PdfPreparationError::Deadline,
    };
    EsignSealerError::Retryable {
        stage: "prepare".to_owned(),
        code: error.to_string(),
        retry_after_ms: None,
    }
}

struct PrepareMemory {
    state: Mutex<MemoryState>,
}

struct MemoryState {
    capacity: u64,
    used: u64,
    shortfall: Option<u64>,
}

impl InspectionMemory for PrepareMemory {
    fn admit(&self, bytes: u64) -> Result<(), DecodeAdmissionError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let needed = state.used.saturating_add(bytes);
        if needed > state.capacity {
            state.shortfall.get_or_insert(needed);
            // Cancel this attempt, not the work. The wrapper releases this
            // pool and all parsed buffers before booking a complete new pool.
            return Err(DecodeAdmissionError::Cancelled);
        }
        state.used = needed;
        Ok(())
    }

    fn release(&self, bytes: u64) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.used = state.used.saturating_sub(bytes);
    }
}
