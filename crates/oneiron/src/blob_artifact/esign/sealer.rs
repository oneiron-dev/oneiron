//! The seal port: how the engine reaches a PAdES sealer it does not link.
//!
//! The seal runs as its own organ process and the engine names none of its
//! types (ARCH-0064 section 7, ARCH-0075 organ-host). A host adapter
//! implements [`EsignSealer`] by calling that organ, which asks the engine
//! back for the signing identity, each signature and any granted fetch; the
//! signing key never leaves the engine. The engine writes the signature
//! revision itself ([`EsignSealInput`], ARCH-0075
//! `#organ-host-design-seal-binding`): the organ builds only the CMS for it,
//! and the adapter signs only attributes bound to that revision and admits
//! only output that carries a signature it issued. These mirror types carry
//! what the seal task needs: the sealed bytes, the SHA-256 evidence hash, the
//! profile reached and the verdict. The evidence hash is SHA-256 because
//! PAdES demands it; the vault addresses blobs by blake3. They never mix.

use serde::{Deserialize, Serialize};

/// A PAdES baseline profile. The serde names are the seal organ's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealProfile {
    BaselineB,
    BaselineT,
    BaselineLt,
    BaselineLta,
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsignSignatureRevision {
    /// The appended signature revision, through its `%%EOF`.
    pub suffix: Vec<u8>,
    /// `[0, hole start, hole end, rest]`, offsets in the whole revision.
    pub byte_range: [u64; 4],
}

/// One item to seal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsignSealRequest {
    /// Binds every signature of this seal to this item; a signature asked
    /// under another operation is refused.
    pub operation_id: String,
    pub profile: SealProfile,
}

/// A sealed PDF and what the sealer says of it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EsignSealed {
    pub bytes: Vec<u8>,
    /// SHA-256 of `bytes`, as the seal's evidence names it.
    pub evidence_sha256: [u8; 32],
    pub requested: SealProfile,
    pub achieved: SealProfile,
    /// Why the achieved profile is lower than the requested one, if it is.
    pub degraded: Vec<SealDegrade>,
    /// The sealer's own verification of `bytes`.
    pub self_verify: EsignVerdict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealDegrade {
    pub requested: SealProfile,
    pub achieved: SealProfile,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealVerdict {
    Passed,
    Failed,
    Indeterminate,
}

/// A sealed PDF's verification, derived from its evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EsignVerdict {
    pub verdict: SealVerdict,
    /// The failed findings, by code.
    pub reasons: Vec<String>,
    /// The lowest profile any ordinary signature reached.
    pub achieved: Option<SealProfile>,
    /// Passed, with an ordinary signature that reached a profile: what the
    /// seal task requires before it commits.
    pub self_verify_ok: bool,
    /// The sealer's full report as JSON, kept as its word: carried and
    /// stored, never parsed here.
    pub report_json: Vec<u8>,
}

impl EsignVerdict {
    #[must_use]
    pub fn valid(&self) -> bool {
        self.verdict == SealVerdict::Passed
    }
}

/// Why a seal or a verification did not complete. Stage and code are the
/// sealer's own names.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum EsignSealerError {
    #[error("seal stage {stage} failed and may succeed later: {code}")]
    Retryable {
        stage: String,
        code: String,
        retry_after_ms: Option<u64>,
    },
    #[error("seal stage {stage} failed: {code}")]
    Fatal { stage: String, code: String },
    #[error("the sealed PDF failed its own verification")]
    VerifyFailed { verdict: Box<EsignVerdict> },
    #[error("the sealer is unavailable")]
    Unavailable { retry_after_ms: Option<u64> },
    #[error("the PDF cannot be sealed: {code}")]
    InputInvalid { code: String },
    /// The signature's CMS needed `needed` DER bytes, more than the largest
    /// revision the engine wrote holds: the engine writes a larger one and
    /// seals again (FIX 6270).
    #[error("the signature needs a revision holding {needed} DER bytes")]
    ContentsShort { needed: u64 },
}

impl EsignSealerError {
    /// Whether the seal job should try again.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Retryable { .. } | Self::VerifyFailed { .. } | Self::Unavailable { .. }
        )
    }
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
}
