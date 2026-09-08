//! Feedback consent: send routes, approval scope, redaction seam, preview, disclosure card, and approval validation.

use crate::entity_id::EntityId;
use crate::genui::{
    ConsentActionDecision, ConsentActionEvaluation, ConsentAskCard, Of336ComponentKind,
};

use super::bundle::{
    FEEDBACK_APPROVE_ONCE_ACTION, FEEDBACK_BUNDLE_ENCODING, FEEDBACK_REF_MAX_BYTES,
    FEEDBACK_SEND_VERB, FeedbackBundle, encode_feedback_bundle, feedback_bundle_digest,
};
use super::error::{
    FeedbackError, approval_field, checked_token, expect_field, push_framed_identity,
    push_framed_str, push_len_prefixed,
};

/// Prefix of the content-addressed approval component id.
pub const FEEDBACK_APPROVAL_COMPONENT_PREFIX: &str = "feedback-preview:";

/// Prefix of the intent/receipt `content_ref` that carries bundle lineage.
pub const FEEDBACK_CONTENT_REF_PREFIX: &str = "feedback:";

/// Prefix of the logical send identity shared by every replay of one send.
pub const FEEDBACK_LOGICAL_SEND_PREFIX: &str = "feedback-send:";

/// Domain separator for the approval component-id preimage.
const FEEDBACK_APPROVAL_DOMAIN: &[u8] = b"oneiron.feedback.approval.v1\0";

/// Scope tag opening a Send route preimage.
const FEEDBACK_SCOPE_SEND_TAG: &[u8] = b"send\0";

/// Scope tag for the air-gapped export preimage.
const FEEDBACK_SCOPE_EXPORT_TAG: &[u8] = b"export";

/// Frame byte marking an absent optional in a scope preimage.
pub(super) const FEEDBACK_FRAME_ABSENT: u8 = 0x00;

/// Frame byte marking a present optional in a scope preimage.
pub(super) const FEEDBACK_FRAME_PRESENT: u8 = 0x01;

/// The content reference that carries bundle lineage on intents and receipts.
#[must_use]
pub fn feedback_content_ref(digest: &str) -> String {
    format!("{FEEDBACK_CONTENT_REF_PREFIX}{digest}")
}

/// The logical send identity shared by every replay of one approved send.
#[must_use]
pub fn feedback_logical_send_ref(digest: &str, approval_receipt_ref: &str) -> String {
    format!("{FEEDBACK_LOGICAL_SEND_PREFIX}{digest}:{approval_receipt_ref}")
}

/// Where one approved feedback bundle is allowed to go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackSendRoute {
    /// Outbound channel token.
    pub channel: String,
    /// Outbound verb token on that channel.
    pub verb: String,
    /// Destination address on that channel.
    pub target: String,
    /// Sending channel identity, when the route has a stored one.
    pub channel_identity_ref: Option<EntityId>,
    /// Counterparty reference, when the route addresses a contact.
    pub counterparty_ref: Option<String>,
}

impl FeedbackSendRoute {
    /// Builds a route with no channel identity and no counterparty.
    #[must_use]
    pub fn new(
        channel: impl Into<String>,
        verb: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            channel: channel.into(),
            verb: verb.into(),
            target: target.into(),
            channel_identity_ref: None,
            counterparty_ref: None,
        }
    }

    /// Binds the sending channel identity.
    #[must_use]
    pub fn with_channel_identity_ref(mut self, identity_ref: EntityId) -> Self {
        self.channel_identity_ref = Some(identity_ref);
        self
    }

    /// Binds the counterparty reference.
    #[must_use]
    pub fn with_counterparty_ref(mut self, counterparty_ref: impl Into<String>) -> Self {
        self.counterparty_ref = Some(counterparty_ref.into());
        self
    }

    pub(super) fn validate(&self) -> Result<(), FeedbackError> {
        checked_token("send route channel", &self.channel, FEEDBACK_REF_MAX_BYTES)?;
        checked_token("send route verb", &self.verb, FEEDBACK_REF_MAX_BYTES)?;
        checked_token("send route target", &self.target, FEEDBACK_REF_MAX_BYTES)?;
        if let Some(reference) = self.counterparty_ref.as_deref() {
            checked_token(
                "send route counterparty_ref",
                reference,
                FEEDBACK_REF_MAX_BYTES,
            )?;
        }
        Ok(())
    }
}

/// The destination an approval authorizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedbackApprovalScope {
    /// One send over one exact route.
    Send(FeedbackSendRoute),
    /// One air-gapped export to a caller-supplied writer.
    Export,
}

impl FeedbackApprovalScope {
    /// Canonical, injective bytes describing this destination.
    ///
    /// Every variable-length field is length-prefixed and every optional is
    /// tag-framed, so no two different destinations — including ones crafted
    /// with embedded NUL bytes — can produce the same preimage.
    fn preimage(&self) -> Vec<u8> {
        match self {
            Self::Export => FEEDBACK_SCOPE_EXPORT_TAG.to_vec(),
            Self::Send(route) => {
                let mut out = FEEDBACK_SCOPE_SEND_TAG.to_vec();
                push_len_prefixed(&mut out, route.channel.as_bytes());
                push_len_prefixed(&mut out, route.verb.as_bytes());
                push_len_prefixed(&mut out, route.target.as_bytes());
                push_framed_identity(&mut out, route.channel_identity_ref.as_ref());
                push_framed_str(&mut out, route.counterparty_ref.as_deref());
                out
            }
        }
    }

    /// Human-readable destination token used in disclosure lines.
    #[must_use]
    pub fn destination_label(&self) -> String {
        match self {
            Self::Export => "air-gapped export to a caller-supplied writer".to_owned(),
            Self::Send(route) => format!(
                "send channel={} verb={} target={}",
                route.channel, route.verb, route.target
            ),
        }
    }
}

/// The content-addressed approval component id for one bundle at one
/// destination.
///
/// Binding the digest AND the destination into the component id is what makes
/// an approval non-transferable: approving bundle A for route A produces an id
/// that cannot validate bundle B, or bundle A for route B, or an export.
#[must_use]
pub fn feedback_approval_component_id(digest: &str, scope: &FeedbackApprovalScope) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FEEDBACK_APPROVAL_DOMAIN);
    hasher.update(digest.as_bytes());
    hasher.update(&[0u8]);
    hasher.update(&scope.preimage());
    let component = hasher.finalize().to_hex();
    format!("{FEEDBACK_APPROVAL_COMPONENT_PREFIX}{component}")
}

/// Something went wrong inside a redactor.
#[derive(Debug, thiserror::Error)]
pub enum FeedbackRedactionError {
    /// The redactor refused this bundle.
    #[error("the feedback redactor rejected the bundle: {0}")]
    Rejected(String),
    /// The redactor could not run.
    #[error("the feedback redactor is unavailable: {0}")]
    Unavailable(String),
}

/// The in-vault redaction seam.
///
/// Everything a person sees in the preview, everything a transport receives,
/// and everything an export writes is the OUTPUT of this trait. Nothing
/// upstream of it ever reaches a destination, which is what makes the seam
/// worth having: a later entity-recognition redactor drops in here without
/// touching consent, dispatch, or the wire contract.
pub trait FeedbackRedactor {
    /// Returns the redacted bundle, or explains why it could not.
    fn redact(&self, bundle: FeedbackBundle) -> Result<FeedbackBundle, FeedbackRedactionError>;
}

/// The redactor that redacts nothing.
///
/// Present so the pipeline is complete and testable without a model. It does
/// NOT weaken consent: a pass-through bundle still requires the same
/// per-bundle, per-destination approval as any other.
#[derive(Debug, Clone, Copy, Default)]
pub struct PassThroughFeedbackRedactor;

impl FeedbackRedactor for PassThroughFeedbackRedactor {
    fn redact(&self, bundle: FeedbackBundle) -> Result<FeedbackBundle, FeedbackRedactionError> {
        Ok(bundle)
    }
}

/// A redacted bundle, its exact encoded bytes, and their digest.
///
/// The three travel together and cannot drift: the bytes are the encoding of
/// this bundle, and the digest is the digest of those bytes. Consent, dispatch,
/// and export all read from here, so the previewed bytes are the sent bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackPreview {
    bundle: FeedbackBundle,
    pub(super) bytes: Vec<u8>,
    pub(super) digest: String,
}

impl FeedbackPreview {
    /// The redacted bundle.
    #[must_use]
    pub const fn bundle(&self) -> &FeedbackBundle {
        &self.bundle
    }

    /// The exact bytes a destination receives.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The lowercase hex digest of those bytes.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The lineage reference intents and receipts carry.
    #[must_use]
    pub fn content_ref(&self) -> String {
        feedback_content_ref(&self.digest)
    }

    /// The approval component id for this bundle at one destination.
    #[must_use]
    pub fn approval_component_id(&self, scope: &FeedbackApprovalScope) -> String {
        feedback_approval_component_id(&self.digest, scope)
    }

    /// Human-readable rendering of the redacted bundle contents.
    ///
    /// This is the CONTENT view: what would be sent. It deliberately carries
    /// no digest and no destination — those are consent facts, and they belong
    /// on the approval card's disclosure lines, where a person reads them as
    /// part of the decision rather than as part of the payload.
    pub fn display_json(&self) -> Result<String, FeedbackError> {
        serde_json::to_string_pretty(&self.bundle).map_err(FeedbackError::DisplayJson)
    }
}

/// Redacts a bundle, encodes it once, and digests the result.
///
/// The bundle is validated before redaction and again after, so a redactor
/// cannot hand back a shape that violates the wire contract.
pub fn prepare_feedback_preview<R>(
    bundle: FeedbackBundle,
    redactor: &R,
) -> Result<FeedbackPreview, FeedbackError>
where
    R: FeedbackRedactor + ?Sized,
{
    bundle.validate()?;
    let redacted = redactor.redact(bundle).map_err(FeedbackError::Redaction)?;
    let bytes = encode_feedback_bundle(&redacted)?;
    let digest = feedback_bundle_digest(&bytes);
    Ok(FeedbackPreview {
        bundle: redacted,
        bytes,
        digest,
    })
}

/// The consent data lines shown under the content view on a feedback ask.
///
/// Every consent fact a person needs to decide is here: what it is, how big it
/// is, exactly where it goes, and how far the approval reaches. The content
/// itself is the redacted bundle render the card places above these lines.
#[must_use]
pub fn feedback_approval_disclosure(
    preview: &FeedbackPreview,
    scope: &FeedbackApprovalScope,
) -> String {
    let mut lines = vec![
        format!("category: {}", preview.bundle.category.as_str()),
        format!("bundle_encoding: {FEEDBACK_BUNDLE_ENCODING}"),
        format!("bundle_digest: {}", preview.digest),
        format!("bundle_bytes: {}", preview.bytes.len()),
        format!("destination: {}", scope.destination_label()),
    ];
    if let FeedbackApprovalScope::Send(route) = scope {
        let identity = match route.channel_identity_ref {
            Some(identity_ref) => identity_ref.to_hex(),
            None => "none".to_owned(),
        };
        let counterparty = match route.counterparty_ref.as_deref() {
            Some(reference) => reference.to_owned(),
            None => "none".to_owned(),
        };
        lines.push(format!("channel_identity_ref: {identity}"));
        lines.push(format!("counterparty_ref: {counterparty}"));
    }
    lines.push("scope: this exact bundle, this exact destination, once".to_owned());
    lines.push("scope: no standing feedback grant is created".to_owned());
    lines.join("\n")
}

/// Mints the consent ask for one bundle at one destination.
///
/// The card shows the person exactly two things: the redacted content that
/// would leave the vault, rendered from the same post-redaction value the
/// bytes were encoded from, and the consent data lines that say where it goes
/// and how far the approval reaches. Deciding about content you cannot see is
/// not consent, so the content view is part of the ask rather than something a
/// caller has to remember to display.
///
/// The `prompt` is the caller's: this is a generic engine, and product copy is
/// the product's to write. A blank prompt is refused rather than silently
/// replaced with engine-authored wording.
///
/// The card is built as a validated struct literal with an EMPTY escalator
/// list on purpose. Routing through the card constructor would replace an
/// empty list with the full standing/widening set, which is exactly the
/// "always allow feedback" grant this channel must never offer. With no
/// escalators the card's actions are exactly approve-once and decline.
pub fn feedback_approval_card(
    preview: &FeedbackPreview,
    principal_ref: &str,
    prompt: &str,
    scope: &FeedbackApprovalScope,
) -> Result<ConsentAskCard, FeedbackError> {
    checked_token(
        "approval principal_ref",
        principal_ref,
        FEEDBACK_REF_MAX_BYTES,
    )?;
    if prompt.trim().is_empty() {
        return Err(FeedbackError::InvalidBundle(
            "approval prompt must not be blank".to_owned(),
        ));
    }
    let content = preview.display_json()?;
    let disclosure = feedback_approval_disclosure(preview, scope);
    let channel = match scope {
        FeedbackApprovalScope::Send(route) => Some(route.channel.clone()),
        FeedbackApprovalScope::Export => None,
    };
    let counterparty_ref = match scope {
        FeedbackApprovalScope::Send(route) => route.counterparty_ref.clone(),
        FeedbackApprovalScope::Export => None,
    };
    Ok(ConsentAskCard {
        card_id: preview.approval_component_id(scope),
        principal_ref: principal_ref.to_owned(),
        prompt: prompt.to_owned(),
        preview: format!("{content}\n\n{disclosure}"),
        verb_class: FEEDBACK_SEND_VERB.to_owned(),
        counterparty_ref,
        channel,
        origin_receipt_ref: Some(preview.content_ref()),
        scope_escalators: Vec::new(),
    })
}

/// A validated one-shot approval for one bundle at one destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackApproval {
    component_id: String,
    approval_receipt_ref: String,
}

impl FeedbackApproval {
    /// The content-addressed component id the approval was granted against.
    #[must_use]
    pub fn component_id(&self) -> &str {
        &self.component_id
    }

    /// The approval receipt this authorization is anchored to.
    #[must_use]
    pub fn approval_receipt_ref(&self) -> &str {
        &self.approval_receipt_ref
    }
}

/// Checks that a host-supplied consent evaluation authorizes THIS bundle at
/// THIS destination, once.
///
/// The evaluation is host-trusted field input, not authentication: the host
/// authenticated the owner when it evaluated the action. What this function
/// adds is the binding a host cannot get wrong by accident — the component id
/// is derived here from the preview digest and the scope, so an approval for
/// a different bundle or a different destination fails with
/// [`FeedbackError::StalePreviewDigest`] before anything happens.
pub fn validate_feedback_approval(
    preview: &FeedbackPreview,
    scope: &FeedbackApprovalScope,
    evaluation: &ConsentActionEvaluation,
) -> Result<FeedbackApproval, FeedbackError> {
    if evaluation.decision != ConsentActionDecision::ApprovedOnce {
        return Err(FeedbackError::ApprovalNotGranted {
            outcome: evaluation.decision.outcome(),
        });
    }
    if evaluation.grant_mint_intent.is_some() {
        return Err(FeedbackError::WideningNotPermitted);
    }
    let fields = &evaluation.receipt.fields;
    expect_field(
        fields,
        "component_kind",
        Of336ComponentKind::ConsentAsk.as_str(),
    )?;
    let expected = preview.approval_component_id(scope);
    let found = approval_field(fields, "component_id")?;
    if found != expected {
        return Err(FeedbackError::StalePreviewDigest {
            expected,
            found: found.to_owned(),
        });
    }
    expect_field(fields, "action_id", FEEDBACK_APPROVE_ONCE_ACTION)?;
    let receipt_id = evaluation.receipt.receipt_id.trim();
    if receipt_id.is_empty() {
        return Err(FeedbackError::ApprovalFieldMissing {
            field: "receipt_id",
        });
    }
    Ok(FeedbackApproval {
        component_id: expected,
        approval_receipt_ref: receipt_id.to_owned(),
    })
}
