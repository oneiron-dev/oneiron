//! Feedback to the engine's makers (OF-420), sent by the owner: preview the
//! exact bundle, then send that bundle, once, to the destination this server
//! is configured with. The send is the owner's approve-once on that bundle
//! and that destination; it rides the ordinary outbound pipeline, so the
//! vault's policy still decides whether it leaves now or is held.
//!
//! A bundle here carries a category, the engine version and the platform, and
//! may carry a proposal: a problem and a suggested fix (ARCH-0056
//! #proposals), sent under its own encoding token. Proposal text is shown in
//! the preview byte for byte and leaves only on this owner's send of exactly
//! that preview, so a proposal that quotes vault text has asked the owner
//! first. When this server's on-device tagger can filter, every written
//! text, a note or a proposal's problem and fix, runs through the in-vault
//! filter before the preview is made (OF-420, `crate::feedback_redaction`),
//! and the preview shows it as filtered. When it cannot, a request with a
//! note is refused, and one without leaves as built, as it did before the
//! filter.
//!
//! The preview's bytes are kept until it expires, bound to the owner, the
//! route and the bundle as built (FIX 5212). A send reads those bytes back
//! and never runs the filter again: a filter that answers twice differently
//! cannot make the sent bundle differ from the one the owner saw.

use oneiron::Vault;
use oneiron::consent::AuthenticatedOwner;
use oneiron::feedback::{
    FEEDBACK_APPROVE_ONCE_ACTION, FeedbackApprovalScope, FeedbackBundle, FeedbackCategory,
    FeedbackInboxNote, FeedbackPlatform, FeedbackPreview, FeedbackProposal,
    RetainedFeedbackPreview, UnredactedFeedback, feedback_approval_card, prepare_feedback_preview,
};
use oneiron::genui::{
    ConsentActionKind, ConsentActionRequest, ConsentActorIdentity, ConsentSurface,
};
use serde::{Deserialize, Serialize};

use super::{OwnerError, OwnerResult};
use crate::feedback_delivery::{FeedbackHost, SendFeedbackError, send_approved_feedback};
use crate::feedback_redaction::{ServerFeedbackRedactor, Unfiltered};

/// How long a preview stays good to send.
const PREVIEW_LIFETIME_SECS: u64 = 3_600;
/// How far a preview time may run ahead of this server's clock.
const PREVIEW_CLOCK_SKEW_SECS: u64 = 60;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FeedbackRequest {
    /// `bug`, `papercut`, `confusion` or `feature-wish`.
    pub(crate) category: FeedbackCategory,
    /// The owner's note; it leaves only as the in-vault filter returns it,
    /// and is refused while that filter cannot run.
    #[serde(default)]
    pub(crate) note: Option<String>,
    /// A suggested fix beside the problem; makes this a proposal.
    #[serde(default)]
    pub(crate) proposal: Option<FeedbackProposal>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SendRequest {
    pub(crate) category: FeedbackCategory,
    #[serde(default)]
    pub(crate) note: Option<String>,
    /// The proposal exactly as previewed.
    #[serde(default)]
    pub(crate) proposal: Option<FeedbackProposal>,
    /// The digest the preview returned for exactly this bundle.
    pub(crate) digest: String,
    /// The approval the preview returned: this bundle to that destination.
    pub(crate) approval: String,
    /// When the preview was made, as it returned it.
    pub(crate) previewed_at: u64,
}

/// The bundle as it would leave, and where it would go.
#[derive(Debug, Serialize)]
pub(crate) struct Preview {
    /// Send this back to send exactly these bytes.
    pub(crate) digest: String,
    /// The encoding token the bytes leave under: v1, or v2 for a proposal.
    pub(crate) encoding: &'static str,
    pub(crate) bundle: serde_json::Value,
    pub(crate) destination: String,
    /// Names this bundle going to this destination on this owner's approval;
    /// send it back unchanged.
    pub(crate) approval: String,
    /// Send it back unchanged: one preview is one send, however often the
    /// request repeats. A preview older than an hour is refused.
    pub(crate) previewed_at: u64,
}

/// What the send did.
#[derive(Debug, Serialize)]
pub(crate) struct Sent {
    pub(crate) digest: String,
    /// `delivered_to_channel`, or `held` when the vault's policy has not
    /// granted this feedback channel yet.
    pub(crate) outcome: &'static str,
    pub(crate) gate_reasons: Vec<String>,
    pub(crate) approval_receipt_ref: String,
    /// Repeating the same approved send names the same logical send.
    pub(crate) logical_send_ref: String,
    /// While the Gate holds the send for the owner, the approve-once digest
    /// his one-time press must name to release it, 64 lower-hex (FIX 6424),
    /// copied from the send's dispatch result. Not `digest`, which names the
    /// bundle. Absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) approval_digest: Option<String>,
}

pub(crate) fn preview(
    vault: &Vault,
    host: &FeedbackHost,
    owner: &AuthenticatedOwner,
    request: &FeedbackRequest,
    redactor: &ServerFeedbackRedactor,
) -> OwnerResult<Preview> {
    let built = built_bundle(request);
    let source = source_digest(&built).map_err(feedback_error)?;
    preview_view(
        vault,
        host,
        owner,
        &bundle_preview(built, redactor)?,
        &source,
    )
}

/// The preview of one built bundle, for every door that builds its own:
/// the digest, destination and approval of exactly these bytes. The bytes
/// are kept until the preview expires, bound to this owner, this route and
/// `source` ([`source_digest`] of the bundle as built), so the send carries
/// them and never filters again (FIX 5212).
pub(crate) fn preview_view(
    vault: &Vault,
    host: &FeedbackHost,
    owner: &AuthenticatedOwner,
    preview: &FeedbackPreview,
    source: &str,
) -> OwnerResult<Preview> {
    let route = host.config.route();
    let principal_ref = owner.principal_ref_for_read(vault)?;
    let approval =
        preview.approval_component_id(&FeedbackApprovalScope::Send(route.clone()), principal_ref);
    let previewed_at = vault.now_recorded_at();
    let bundle = serde_json::from_str(&preview.display_json().map_err(feedback_error)?)
        .map_err(|error| OwnerError::Host(anyhow::anyhow!("feedback bundle JSON: {error}")))?;
    vault.retain_feedback_preview(
        &approval,
        &RetainedFeedbackPreview {
            preview: preview.clone(),
            source_digest: source.to_owned(),
            principal_ref: principal_ref.to_owned(),
            route,
            issued_at: previewed_at,
            expires_at: previewed_at.saturating_add(PREVIEW_LIFETIME_SECS),
        },
    )?;
    Ok(Preview {
        digest: preview.digest().to_owned(),
        encoding: preview.encoding().as_str(),
        approval,
        previewed_at,
        bundle,
        destination: host.config.endpoint.clone(),
    })
}

pub(crate) fn send(
    vault: &Vault,
    host: &FeedbackHost,
    owner: &AuthenticatedOwner,
    request: &SendRequest,
) -> OwnerResult<Sent> {
    let built = built_bundle(&FeedbackRequest {
        category: request.category,
        note: request.note.clone(),
        proposal: request.proposal.clone(),
    });
    let source = source_digest(&built).map_err(feedback_error)?;
    send_previewed(
        vault,
        host,
        owner,
        &source,
        &request.digest,
        &request.approval,
        request.previewed_at,
    )
}

/// Sends the bundle a preview kept, for every door that builds its own: the
/// kept bytes are read back, never filtered again (FIX 5212), and must still
/// be this owner's, for this route, built from the bundle `source` digests
/// ([`source_digest`]) and unexpired; the approval and preview age are
/// rechecked here, and the send is admitted under the owner's proof in the
/// transaction that admits it.
pub(crate) fn send_previewed(
    vault: &Vault,
    host: &FeedbackHost,
    owner: &AuthenticatedOwner,
    source: &str,
    digest: &str,
    approval: &str,
    previewed_at: u64,
) -> OwnerResult<Sent> {
    let principal_ref = owner.revalidate_principal_ref(vault)?;
    let expired = || OwnerError::Changed("the preview has expired; preview it again".to_owned());
    let now = vault.now_recorded_at();
    if now.saturating_sub(previewed_at) > PREVIEW_LIFETIME_SECS
        || previewed_at > now.saturating_add(PREVIEW_CLOCK_SKEW_SECS)
    {
        return Err(expired());
    }
    let retained = vault
        .retained_feedback_preview(approval, previewed_at, now)?
        .ok_or_else(expired)?;
    let route = host.config.route();
    let another = || {
        OwnerError::Changed(
            "this preview was for another destination or another owner; preview it again"
                .to_owned(),
        )
    };
    if retained.principal_ref != principal_ref || retained.route != route {
        return Err(another());
    }
    let preview = &retained.preview;
    if preview.digest() != digest || retained.source_digest != source {
        return Err(OwnerError::Changed(
            "this bundle is not the one previewed; preview it again".to_owned(),
        ));
    }
    let scope = FeedbackApprovalScope::Send(route);
    // The approval names the owner who previewed it, so two owners' sends of
    // one bundle are two sends, and neither can send on the other's preview.
    if preview.approval_component_id(&scope, principal_ref) != approval {
        return Err(another());
    }
    // The owner's send is the answer; the card's prompt names where it goes.
    let card = feedback_approval_card(preview, principal_ref, &host.config.endpoint, &scope)
        .map_err(feedback_error)?;
    // The approval is timed at the preview, so a repeated request names the
    // same approval receipt and the outbound ledger answers it as the one send.
    let approval_request = ConsentActionRequest::new(
        card.card_id.clone(),
        FEEDBACK_APPROVE_ONCE_ACTION,
        ConsentActionKind::Approve,
        ConsentActorIdentity::SurfaceActor {
            actor_ref: principal_ref.to_owned(),
        },
        ConsentSurface::Dashboard,
        previewed_at,
    )?;
    let evaluation = card.evaluate_action(vault, &approval_request, owner)?;
    // The send carries the owner's proof to the transaction that admits it,
    // so a slip revoked while this request waited admits nothing.
    let sent = send_approved_feedback(
        vault,
        host.config.clone(),
        host.bearer.clone(),
        preview,
        &evaluation,
        owner,
        now,
    )
    .map_err(|error| match error {
        SendFeedbackError::ApprovalOrDispatch(error) => feedback_error(error),
        SendFeedbackError::Delivery(error) => {
            OwnerError::Host(anyhow::anyhow!("feedback destination: {error}"))
        }
    })?;
    Ok(Sent {
        digest: sent.bundle_digest,
        outcome: sent.dispatch.outcome.as_str(),
        gate_reasons: sent.dispatch.gate_reason_codes,
        approval_receipt_ref: sent.approval_receipt_ref,
        logical_send_ref: sent.logical_send_ref,
        approval_digest: sent.dispatch.approval_digest,
    })
}

/// The bundle as the request builds it, before any filter.
fn built_bundle(request: &FeedbackRequest) -> FeedbackBundle {
    let mut bundle = FeedbackBundle::new(
        request.category,
        env!("CARGO_PKG_VERSION"),
        FeedbackPlatform::current(),
    );
    if let Some(note) = &request.note {
        bundle = bundle.with_user_note(note.clone());
    }
    if let Some(proposal) = &request.proposal {
        bundle = bundle.with_proposal(proposal.clone());
    }
    bundle
}

/// The digest of a bundle as built, before any filter: what binds a send's
/// request to the preview it names, with no filter run on the send.
pub(crate) fn source_digest(
    bundle: &FeedbackBundle,
) -> Result<String, oneiron::feedback::FeedbackError> {
    prepare_feedback_preview(bundle.clone(), &UnredactedFeedback)
        .map(|built| built.digest().to_owned())
}

/// The bundle as it would leave: every free text in it run through
/// `redactor`, this server's in-vault filter, when it runs.
fn bundle_preview(
    bundle: FeedbackBundle,
    redactor: &ServerFeedbackRedactor,
) -> OwnerResult<FeedbackPreview> {
    prepare_feedback_preview(bundle, &redactor.door(Unfiltered::RefuseNote)).map_err(|error| {
        match error {
            // The filter could not run, and a note leaves only filtered.
            oneiron::feedback::FeedbackError::Redaction(_) => OwnerError::Refused(
                "a written note waits for in-vault redaction (OF-420); send the category alone"
                    .to_owned(),
            ),
            error => feedback_error(error),
        }
    })
}

fn feedback_error(error: oneiron::feedback::FeedbackError) -> OwnerError {
    use oneiron::feedback::FeedbackError;
    use oneiron::outbound::OutboundDispatchError;
    use oneiron::outbound_intent_ledger::IntentLedgerError;
    // An owner proof that stopped holding is the owner door's refusal.
    match error {
        FeedbackError::Dispatch(dispatch) => match *dispatch {
            OutboundDispatchError::Engine(error)
            | OutboundDispatchError::Chokepoint(IntentLedgerError::Engine(error))
                if error.kind() == oneiron::ErrorKind::ConsentOwnerNotAuthenticated =>
            {
                OwnerError::Engine(Box::new(error))
            }
            dispatch => {
                OwnerError::Invalid(FeedbackError::Dispatch(Box::new(dispatch)).to_string())
            }
        },
        error => OwnerError::Invalid(error.to_string()),
    }
}

/// Notes one inbox read returns unless it names fewer, and the most it may.
const INBOX_PAGE: usize = 100;
const INBOX_PAGE_MAX: usize = 1_000;

/// One page of the open inbox (ARCH-0056 #open-inbox): the notes after
/// arrival number `after`, oldest first. A sweep keeps the last number it
/// read and passes it back.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InboxPage {
    #[serde(default)]
    pub(crate) after: Option<u64>,
    #[serde(default)]
    pub(crate) limit: Option<usize>,
}

/// The notes anyone left this vault's open inbox, for the owner's triage
/// sweep. Nothing the inbox takes is read anywhere else.
pub(crate) fn inbox(vault: &Vault, page: &InboxPage) -> OwnerResult<Vec<FeedbackInboxNote>> {
    let limit = page.limit.unwrap_or(INBOX_PAGE).clamp(1, INBOX_PAGE_MAX);
    Ok(vault.feedback_inbox(page.after, limit)?)
}

/// Where this server's feedback goes, and whether it keeps the open inbox:
/// the effective setting, shown in the owner's status.
#[derive(Debug, Serialize)]
pub(crate) struct FeedbackStatus {
    /// `cloud`, `collector` or `github_issue`; `None` sends nowhere.
    pub(crate) destination: Option<crate::feedback_delivery::FeedbackDestination>,
    pub(crate) endpoint: Option<String>,
    /// Whether `/v1/feedback` takes keyless notes here.
    pub(crate) inbox: bool,
}

pub(crate) fn status(
    host: Option<&FeedbackHost>,
    inbox: &crate::config::FeedbackInboxConfig,
) -> FeedbackStatus {
    FeedbackStatus {
        destination: host.map(|host| host.config.destination),
        endpoint: host.map(|host| host.config.endpoint.clone()),
        inbox: inbox.enabled,
    }
}
