//! Core half of `blob_artifact::esign::sealer`: its store-layer items live in `oneiron_store::blob_artifact::esign::sealer` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::blob_artifact::esign::sealer::*;

use super::render::{PdfPreparation, PreparedEsignPdf};
use serde::{Deserialize, Serialize};

/// A prepared PDF and the signature revisions the engine wrote for it, one
/// per contents capacity, smallest first (or the one larger revision written
/// when they held too little, FIX 6270). Revision `i` is `pdf` followed by
/// `revisions[i].suffix`; its `/Contents` hole holds ASCII zeros, and its
/// ByteRange leaves out exactly that hole, delimiters included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsignSealInput {
    pub pdf: Vec<u8>,
    pub revisions: Vec<EsignSignatureRevision>,
}

/// A PAdES sealer the engine reaches through a port. It blocks: the seal
/// task runs it, never a request.
pub trait EsignSealer: Send + Sync {
    /// Seals one prepared PDF in one of the signature revisions the engine
    /// wrote for it. A sealer returns only bytes that begin with one of
    /// them, byte for byte outside its hole, with a signature it had issued
    /// for that revision in the hole.
    ///
    /// # Errors
    /// See [`EsignSealerError`].
    fn seal(
        &self,
        input: &EsignSealInput,
        request: &EsignSealRequest,
    ) -> Result<EsignSealed, EsignSealerError>;

    /// Verifies a sealed PDF, in a process that never sealed: a second
    /// opinion on what the sealer cannot check itself (the timestamp, the
    /// validation data). Its verdict alone never admits a seal.
    ///
    /// # Errors
    /// See [`EsignSealerError`]; a PDF whose signature fails is a verdict,
    /// not an error.
    fn verify(&self, pdf: &[u8]) -> Result<EsignVerdict, EsignSealerError>;

    /// Prepares one immutable original PDF for the seal in an isolated
    /// trusted process. `None` keeps the engine's trusted preparation for
    /// a sealer whose code may not choose the document the key signs.
    /// `chain`/`trail` are the engine audit replay's checked output, which
    /// the caller ran: the isolated work takes them as given and never
    /// replays the audit itself.
    ///
    /// # Errors
    /// See [`EsignSealerError`].
    fn prepare_esign_pdf(
        &self,
        original: &[u8],
        request: &PdfPreparation<'_>,
        chain: [u8; 32],
        trail: &[String],
    ) -> Result<Option<PreparedEsignPdf>, EsignSealerError>;
}
