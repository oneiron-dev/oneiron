//! Moved from `crates/oneiron/src/blob_artifact/esign/door.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::blob_artifact::esign::model::DocumentStatus;
pub use oneiron_verb_wire::blob_artifact::esign::door::EsignCreateRequest;
pub use oneiron_verb_wire::blob_artifact::esign::door::EsignDispatchRequest;
pub use oneiron_verb_wire::blob_artifact::esign::door::EsignGetRequest;
pub use oneiron_verb_wire::blob_artifact::esign::door::EsignLinksIssueRequest;
pub use oneiron_verb_wire::blob_artifact::esign::door::EsignSealAttemptView;
pub use oneiron_verb_wire::blob_artifact::esign::door::EsignSealGetRequest;
pub use oneiron_verb_wire::blob_artifact::esign::door::EsignSealedItemView;
pub use oneiron_verb_wire::blob_artifact::esign::door::EsignSealedView;
pub use oneiron_verb_wire::blob_artifact::esign::door::EsignSigningImageRequest;
pub use oneiron_verb_wire::blob_artifact::esign::door::EsignSigningImageView;
pub use oneiron_verb_wire::blob_artifact::esign::door::EsignSigningPdfRequest;
pub use oneiron_verb_wire::blob_artifact::esign::door::EsignSigningPdfView;
pub use oneiron_verb_wire::blob_artifact::esign::door::EsignSigningSignatureRequest;
pub use oneiron_verb_wire::blob_artifact::esign::door::EsignSigningSignatureView;
pub use oneiron_verb_wire::blob_artifact::esign::door::EsignVoidRequest;
pub use oneiron_verb_wire::blob_artifact::esign::door::preview::EsignSigningPreviewRequest;
pub use oneiron_verb_wire::blob_artifact::esign::door::preview::EsignSigningPreviewView;
use serde::Deserialize;
use serde::Serialize;

/// A drafted signing document, as it landed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsignDraftView {
    pub document_ref: String,
    pub status: DocumentStatus,
    pub title: String,
    pub expires_at: u64,
    pub project_ref: Option<String>,
    /// The recipients' ids, in the draft's order.
    pub recipients: Vec<String>,
    /// How many fields the draft places.
    pub fields: usize,
}

/// One recipient's new signing link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsignIssuedLink {
    pub recipient: String,
    pub email: String,
    /// The bearer capability, shown this once: the recipient opens the
    /// host's signing page with it as the fragment (`/sign#<capability>`).
    /// The vault keeps only its digest.
    pub capability: String,
}

/// The signing links a draft holds after the issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsignLinksView {
    pub document_ref: String,
    /// The links minted now, in the draft's recipient order.
    pub issued: Vec<EsignIssuedLink>,
    /// The recipients whose earlier link still holds, and is not shown again.
    pub unchanged: Vec<String>,
}

/// What the gate made of one e-sign dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsignDispatchView {
    pub document_ref: String,
    /// `send_for_signature`, `remind` or `void`.
    pub verb: String,
    /// The dispatch's intent ref; its retry key is the tail, the key a
    /// retry of a call that named none passes as `idempotency_key`.
    pub intent_ref: String,
    /// The pipeline outcome: `delivered_to_channel` when the act landed,
    /// `held`, `suppressed` or `failed` otherwise.
    pub outcome: String,
    /// The gate's outcome (`allow`, `pending`, `deny`).
    pub gate_outcome: String,
    /// The persisted gate decision, readable with `vault.receipts.get`.
    pub gate_decision_ref: Option<String>,
    pub gate_reason_codes: Vec<String>,
    /// While the gate holds the act for the owner (`gate_outcome`
    /// `pending`), the approve-once digest his one-time press must name to
    /// release it, 64 lower-hex (FIX 6424): it pins this document, this
    /// command and this act's send ref, so the retry that spends it carries
    /// this view's retry key.
    pub approval_digest: Option<String>,
}
