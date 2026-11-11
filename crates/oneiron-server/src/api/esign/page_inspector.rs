//! The engine's e-sign page inspector on this server's seal organ (FIX 9609).
//! A field save's or a sign act's original PDF is inspected in the organ's
//! own keyless process before the engine's writer: its bytes and the region
//! lent to the organ are admitted on this machine's memory line, and the
//! call ends by the deadline the editor's geometry door waits to, as the
//! geometry door's isolated inspection does (`parse_lease::isolated`).
//! Only a first-party organ's pages are admitted, checked on the install
//! and again on the slot that ran the call, as the seal's preparation is.

use std::sync::Arc;
use std::time::Instant;

use oneiron::Vault;
use oneiron::blob_artifact::esign::render::PageGeometry;
use oneiron::blob_artifact::esign::{EsignPageInspector, EsignSealerError};
use oneiron_organ_host::seal::{
    PdfInspectionError, SEAL_ORGAN, SealSettings, VERB_INSPECT,
    inspect_first_party_pdf_region_until,
};
use oneiron_organ_host::{CallClass, LentRegion, OrganHost, OrganTier};

use super::ingress::MEMORY_WAIT;
use crate::machine::{MachineMemory, MemoryRefusal};

/// [`EsignPageInspector`] over this server's organ host and memory line
/// (FIX 9609). It holds no vault: the engine passes its own with each call.
pub(crate) struct EsignOrganPageInspector {
    organs: Arc<OrganHost>,
    memory: MachineMemory,
}

impl EsignOrganPageInspector {
    /// The inspector over `organs`, admitting its inputs on `memory`.
    pub(crate) fn new(organs: Arc<OrganHost>, memory: MachineMemory) -> Self {
        Self { organs, memory }
    }
}

impl EsignPageInspector for EsignOrganPageInspector {
    /// `None` while the seal organ is not first party or offers no
    /// `seal.inspect`, and when the slot that ran the call was not first
    /// party (a reinstall raced this check): the engine then inspects
    /// natively. A third-party organ's pages never decide a field save's or
    /// a sign act's admission (review #6275).
    fn inspect_pages(
        &self,
        vault: &Vault,
        pdf: &[u8],
    ) -> Result<Option<Vec<PageGeometry>>, EsignSealerError> {
        let first_party_inspect = self.organs.spec(SEAL_ORGAN).is_some_and(|spec| {
            spec.tier == OrganTier::FirstParty && spec.verbs.iter().any(|verb| verb == VERB_INSPECT)
        });
        if !first_party_inspect {
            return Ok(None);
        }
        let deadline = Instant::now() + MEMORY_WAIT;
        let bytes = u64::try_from(pdf.len()).unwrap_or(u64::MAX);
        // The engine read the PDF already, so its bytes are held; the one
        // region lent to the organ is admitted before it is copied.
        let mut lease = self.memory.lease(bytes, deadline).map_err(memory_refused)?;
        lease.materialized(bytes, bytes);
        lease
            .grow_pending(bytes, deadline, &|| false)
            .map_err(memory_refused)?;
        let input = LentRegion::copy_from(pdf, "application/pdf").map_err(|_| {
            EsignSealerError::Retryable {
                stage: "inspect".to_owned(),
                code: "region_unavailable".to_owned(),
                retry_after_ms: None,
            }
        })?;
        lease.materialized(bytes, input.len());
        let mut settings = SealSettings::new(Vec::new(), "esign.seal");
        settings.class = CallClass::Interactive;
        let inspected = inspect_first_party_pdf_region_until(
            &self.organs,
            vault,
            &settings,
            input,
            deadline,
            vault.esign_stream_decode_bytes(),
        );
        // The lease covers the whole child call, its cancellation included.
        drop(lease);
        inspected.map_err(|error| match error {
            PdfInspectionError::Floor { needed, available } => {
                memory_refused(MemoryRefusal::Floor { needed, available })
            }
            PdfInspectionError::MemoryDeadline { needed, waited } => {
                memory_refused(MemoryRefusal::WaitedOut { needed, waited })
            }
            PdfInspectionError::Sealer(error) => error,
        })
    }
}

/// A memory refusal as the port's retryable error, coded as the signing
/// doors code theirs: the PDF was never judged.
fn memory_refused(refusal: MemoryRefusal) -> EsignSealerError {
    let code = match refusal {
        MemoryRefusal::Floor { needed, available } => {
            tracing::warn!(
                needed,
                available,
                "a signing PDF's inspection does not fit this machine's memory past its reserve"
            );
            "signing_memory_floor"
        }
        MemoryRefusal::WaitedOut { needed, waited } => {
            tracing::warn!(
                needed,
                waited_ms = u64::try_from(waited.as_millis()).unwrap_or(u64::MAX),
                "a signing PDF's inspection's wait for this machine's memory passed its deadline"
            );
            "signing_memory_waited_out"
        }
    };
    EsignSealerError::Retryable {
        stage: "inspect".to_owned(),
        code: code.to_owned(),
        retry_after_ms: None,
    }
}
