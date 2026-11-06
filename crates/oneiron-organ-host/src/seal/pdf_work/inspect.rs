//! Inspection on the caller's original wall deadline and admitted region.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use oneiron::Vault;
use oneiron::blob_artifact::esign::EsignSealerError;
use oneiron::blob_artifact::esign::render::PageGeometry;
use oneiron_organ_protocol::{ASK_MEMORY_GROW, AskRefusal, MemoryAnswer, MemoryAsk};

use super::super::observe::{measure_asks, sized_region_call_until};
use super::{InspectArgs, SealSettings, VERB_INSPECT, inspected_pages, reply_invalid, to_value};
use crate::handlers::{Answered, AskHandler, AskHandlers, AskRequest};
use crate::host::{LentRegion, OrganHost};
use crate::resource_memory::MemoryGrow;

/// An inspection's genuine machine-memory refusal, kept apart from a
/// malformed PDF, an unavailable worker or another seal failure.
#[derive(Debug)]
pub enum PdfInspectionError {
    Floor { needed: u64, available: u64 },
    MemoryDeadline { needed: u64, waited: Duration },
    Sealer(EsignSealerError),
}

/// Inspects one admitted region without signing keys or fetch handlers.
/// Its caller holds the input's memory and editor permit until this returns.
/// The original absolute deadline bounds booking, startup, asks and execution.
pub fn inspect_pdf_region_until(
    host: &OrganHost,
    vault: &Vault,
    settings: &SealSettings,
    input: LentRegion,
    deadline: Instant,
    stream_decode_bytes: u64,
) -> Result<Vec<PageGeometry>, PdfInspectionError> {
    let args = to_value(&InspectArgs {
        stream_decode_bytes,
    })
    .map_err(|_| PdfInspectionError::Sealer(reply_invalid()))?;
    let memory = InspectionMemory::default();
    let handlers = AskHandlers::none().with(ASK_MEMORY_GROW, &memory);
    let called = sized_region_call_until(
        host,
        vault,
        settings.call(VERB_INSPECT, 1, args),
        input,
        &handlers,
        deadline,
    );
    measure_asks(vault, &handlers.asked());
    if let Some(refused) = memory
        .refused
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
    {
        return Err(refused);
    }
    let (reply, _) = called.map_err(PdfInspectionError::Sealer)?;
    inspected_pages(vault, &reply).map_err(PdfInspectionError::Sealer)
}

#[derive(Default)]
struct InspectionMemory {
    refused: Mutex<Option<PdfInspectionError>>,
}

impl AskHandler for InspectionMemory {
    fn answer(&self, ask: &AskRequest<'_>) -> Result<Answered, AskRefusal> {
        let began = Instant::now();
        let answer = MemoryGrow.answer(ask)?;
        // These are the actual control values handled above, not a parsed
        // human detail or a PDF-error guess. Only memory failures are kept.
        let refusal = match MemoryAnswer::from_value(&answer.value) {
            Ok(MemoryAnswer::Floor { needed, available }) => {
                Some(PdfInspectionError::Floor { needed, available })
            }
            Ok(MemoryAnswer::Deadline) => MemoryAsk::from_value(ask.value).ok().map(|asked| {
                PdfInspectionError::MemoryDeadline {
                    needed: asked.bytes,
                    waited: began.elapsed(),
                }
            }),
            _ => None,
        };
        if let Some(refusal) = refusal {
            self.refused
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get_or_insert(refusal);
        }
        Ok(answer)
    }
}
