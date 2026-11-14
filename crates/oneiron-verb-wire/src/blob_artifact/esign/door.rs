//! Moved from `crates/oneiron/src/blob_artifact/esign/door.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::blob_artifact::esign::delivery_settlement::EsignDeliveryReceipt;
pub use crate::blob_artifact::esign::door::preview::EsignSigningPreviewRequest;
pub use crate::blob_artifact::esign::door::preview::EsignSigningPreviewView;
use crate::blob_artifact::esign::model::EsignDocument;
use oneiron_store::blob_artifact::esign::document_view::EsignSealTrail;
use serde::Deserialize;
use serde::Serialize;

/// A signing document to draft on an existing artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignCreateRequest {
    /// The artifact the signing overlay lives on, already registered: for a
    /// one-PDF document, that PDF's own artifact.
    pub document_ref: String,
    /// The draft: its items pin each PDF's current version. With
    /// `lifecycle` set, a zero document or recipient expiry is set from its
    /// window now; without it, every expiry is explicit. A `project` binds
    /// the document, its trail and its held sign acts to that project, for
    /// one of its members or a vault owner only.
    pub draft: EsignDocument,
}

/// A signing document to read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignGetRequest {
    /// The artifact the signing overlay lives on.
    pub document_ref: String,
}

/// The document whose recipients' signing links to mint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignLinksIssueRequest {
    /// The drafted document, not yet sent.
    pub document_ref: String,
    /// Revoke every live link of the draft first and mint all afresh, for
    /// links lost before the send. Without it, only recipients holding no
    /// usable link get one.
    #[serde(default)]
    pub rotate: bool,
}

/// One send or reminder of a signing document through the dispatch gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignDispatchRequest {
    /// The signing document.
    pub document_ref: String,
    /// The recipient count the caller reviewed; a document whose recipients
    /// changed since is refused.
    pub recipient_count: usize,
    /// The signing principal an agent acts for: its autonomy dial must be
    /// `autonomous_in_envelope` for an agent's dispatch to land.
    #[serde(default)]
    pub on_behalf_of: Option<String>,
    /// A retry under the same key answers the first dispatch's receipt. A
    /// call with none is its own send, keyed on the call's invocation id when
    /// it names one, else a fresh key; its view's `intent_ref` ends in that
    /// key, and a retry of a held call passes it here.
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

/// One void of a signing document through the dispatch gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignVoidRequest {
    /// The signing document, drafted or pending.
    pub document_ref: String,
    /// The recipient count the caller reviewed.
    pub recipient_count: usize,
    /// Why the sender withdraws it; the trail and the void notice carry it.
    pub reason: String,
    /// The signing principal an agent acts for.
    #[serde(default)]
    pub on_behalf_of: Option<String>,
    /// A retry under the same key answers the first dispatch's receipt. A
    /// call with none is its own send, keyed on the call's invocation id when
    /// it names one, else a fresh key; its view's `intent_ref` ends in that
    /// key, and a retry of a held call passes it here.
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

/// One recipient ceremony act (`vault.esign.signing.act`): the signing
/// link's capability and the act it asks for. The public `POST /sign/action`
/// door takes the act alone; its capability rides in the
/// `x-oneiron-esign-capability` header, admitted before the body is read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSigningRequest {
    /// The recipient's Bearer [REDACTED] from their signing link. It is the
    /// ceremony's authority; a credential the call also presents only
    /// classes the caller (an agent's Complete is an automated sign act).
    pub token: String,
    /// Load, save one field, complete with consent, or reject.
    pub action: super::SigningAction,
}

/// One ceremony document item to download (`vault.esign.signing.pdf`):
/// the pinned original while signing, the sealed output after sealing.
/// The public `POST /sign/pdf` door takes the item alone, under the
/// `x-oneiron-esign-capability` header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSigningPdfRequest {
    /// The recipient's Bearer [REDACTED].
    pub token: String,
    /// Which of the document's items, by position.
    pub item: usize,
}

/// One downloaded ceremony item, as base64 PDF bytes. The public
/// `POST /sign/pdf` door serves the same bytes as an attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSigningPdfView {
    pub item: usize,
    pub pdf_base64: String,
}

/// One signature image to upload for a signature field
/// (`vault.esign.signing.image`), bound to the capability's recipient.
/// The public `POST /sign/image` door takes the raw PNG or JPEG bytes as
/// its body, under the `x-oneiron-esign-capability` header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSigningImageRequest {
    /// The recipient's Bearer [REDACTED].
    pub token: String,
    /// The PNG or JPEG signature image, base64.
    pub png_or_jpeg_base64: String,
}

/// The stored signature image's ref, for a signature field's value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSigningImageView {
    pub image_ref: String,
}

/// One stored signature image to read back (`vault.esign.signing.signature`),
/// under the capability that uploaded it. The public `POST /sign/signature`
/// door takes the image ref alone, under the `x-oneiron-esign-capability`
/// header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSigningSignatureRequest {
    /// The recipient's Bearer [REDACTED].
    pub token: String,
    pub image_ref: String,
}

/// One stored signature image, as base64 bytes. The public
/// `POST /sign/signature` door serves the same bytes as an image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSigningSignatureView {
    pub image_ref: String,
    pub image_base64: String,
}

/// A signing document whose seal task to observe (`vault.esign.seal.get`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSealGetRequest {
    /// The artifact the signing overlay lives on.
    pub document_ref: String,
}

/// One queued or finished seal attempt of a document: the seal task's
/// receipt row, in creation order beside its siblings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSealAttemptView {
    /// The attempt's id, hex; a sealed document's manifest names the
    /// attempt that sealed it by this same ref.
    pub attempt_ref: String,
    /// The attempt kind, `esign.seal`.
    pub kind: String,
    /// `queued`, `leased`, `completed`, `failed`, or another attempt state.
    pub state: String,
    /// The seal generation the attempt was queued for: the document and
    /// its generation, as the dedupe key spells them, while it is kept.
    pub dedupe_key: Option<String>,
    /// The worker holding or last holding the attempt's lease.
    pub lease_owner: Option<String>,
    /// Lease generations taken within this one try.
    pub attempt_count: u32,
    pub created_at: u64,
    pub updated_at: u64,
    /// The failure a failed attempt kept; the backstop queues it again.
    pub last_error: Option<String>,
    /// Native finding and sub-indication codes of a failed self-verification,
    /// including `validation_material_possible_tampering`. Empty when none was
    /// supplied; an empty list never means "verification passed".
    pub verify_reasons: Vec<String>,
}

/// One sealed item's provenance: the frozen original it came from and the
/// sealed version that replaced it, with the sealed bytes' SHA-256, hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSealedItemView {
    pub original_artifact: String,
    pub original_version: u64,
    pub sealed_artifact: String,
    pub sealed_version: u64,
    pub sha256: String,
    /// Actual profiles and every native degradation reason from this item's seal.
    pub profile: super::sealer::SealProfileEvidence,
    pub active_content: super::sealer::SealActiveContentFacts,
}

/// A sealed document's manifest: which attempt sealed it, over which
/// audit chain, and what each item became.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSealedView {
    /// The seal attempt that produced this manifest, by its attempt ref.
    pub attempt_ref: String,
    /// SHA-256 of the audit trail the seal covered, hex.
    pub audit_chain_sha256: String,
    /// Sealed on a rejection rather than a completion.
    pub rejected: bool,
    pub items: Vec<EsignSealedItemView>,
}

/// Where one document's seal stands: every seal attempt the queue still
/// holds for it, its sealed manifest once one attempt sealed it, its
/// delivery receipts, and its folded status, or why its trail does not read
/// (FIX 6554).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EsignSealView {
    pub document_ref: String,
    pub attempts: Vec<EsignSealAttemptView>,
    pub sealed: Option<EsignSealedView>,
    /// The document's delivery receipts, as `vault.esign.get` lists them,
    /// read whether or not its trail reads.
    pub delivery_receipts: Vec<EsignDeliveryReceipt>,
    /// `trail`, `readable` with the folded `status`, or `unreadable` with
    /// its error.
    #[serde(flatten)]
    pub trail: EsignSealTrail,
}
pub mod preview;
