//! The host's isolated inspection of an e-sign original PDF's pages: a port
//! the engine calls before the writer of a field save or a sign act (FIX
//! 9609), so no PDF is parsed inside the writer.
use super::render::PageGeometry;
use super::sealer::EsignSealerError;
use crate::Vault;
use std::sync::{Arc, PoisonError};

/// Inspects one original PDF's page geometry in a worker the host isolates
/// and bounds in memory and time (FIX 9609). It blocks its thread; the
/// engine calls it outside every write transaction. The vault comes with
/// each call, so the port holds no vault.
pub trait EsignPageInspector: Send + Sync {
    /// `pdf`'s pages in page order, the shape `render::inspect_pdf_pages_within`
    /// returns; `None` when the host has no isolated worker now, and the
    /// engine then inspects `pdf` natively.
    ///
    /// # Errors
    /// See [`EsignSealerError`]. A refusal that may pass later (memory, the
    /// deadline, a worker not available) reaches the caller as a retryable
    /// failure; any other as a page that cannot be presented.
    fn inspect_pages(
        &self,
        vault: &Vault,
        pdf: &[u8],
    ) -> Result<Option<Vec<PageGeometry>>, EsignSealerError>;
}

impl Vault {
    /// Installs the host's [`EsignPageInspector`] on this vault handle (FIX
    /// 9609), never process-global; a later install replaces it. Without one
    /// the engine inspects natively, still before the writer.
    pub fn install_esign_page_inspector(&self, inspector: Arc<dyn EsignPageInspector>) {
        *self
            .esign_page_inspector
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(inspector);
    }

    /// The installed [`EsignPageInspector`], if any.
    pub(super) fn esign_page_inspector(&self) -> Option<Arc<dyn EsignPageInspector>> {
        self.esign_page_inspector
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}
