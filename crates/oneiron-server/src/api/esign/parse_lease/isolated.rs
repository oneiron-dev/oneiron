//! The geometry callers' input lease, region and isolated parse.

use std::time::Instant;

use axum::response::Response;
use oneiron::blob_artifact::esign::EsignSealerError;
use oneiron::blob_artifact::esign::render::PageGeometry;
use oneiron_organ_host::seal::{PdfInspectionError, SealSettings, inspect_pdf_region_until};
use oneiron_organ_host::{CallClass, LentRegion};

use crate::machine::{MemoryLease, MemoryRefusal};
use crate::server::SyncServer;

pub(super) fn inspected(
    server: &SyncServer,
    mut lease: MemoryLease,
    deadline: Instant,
    pdf: &[u8],
    stream_decode_bytes: u64,
) -> Result<Vec<PageGeometry>, Response> {
    let bytes = u64::try_from(pdf.len()).unwrap_or(u64::MAX);
    // The original body is already materialized. Only the one additional
    // region is pending here; the host takes it without a Vec or cache copy.
    lease
        .grow_pending(bytes, deadline, &|| false)
        .map_err(super::memory_refused)?;
    let input =
        LentRegion::copy_from(pdf, "application/pdf").map_err(|_| super::super::refused())?;
    lease.materialized(bytes, input.len());
    let mut settings = SealSettings::new(Vec::new(), "esign.seal");
    settings.class = CallClass::Interactive;
    let inspected = inspect_pdf_region_until(
        &server.organs,
        &server.vault,
        &settings,
        input,
        deadline,
        stream_decode_bytes,
    );
    // The input lease covers the complete child call, including cancellation
    // and its existing grace. It does not extend into response encoding.
    drop(lease);
    inspected.map_err(|error| match error {
        PdfInspectionError::Floor { needed, available } => {
            super::memory_refused(MemoryRefusal::Floor { needed, available })
        }
        PdfInspectionError::MemoryDeadline { needed, waited } => {
            super::memory_refused(MemoryRefusal::WaitedOut { needed, waited })
        }
        PdfInspectionError::Sealer(
            EsignSealerError::Unavailable { .. } | EsignSealerError::Retryable { .. },
        ) => super::super::unavailable(),
        PdfInspectionError::Sealer(_) => super::super::refused(),
    })
}
