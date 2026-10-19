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

use oneiron::Vault;
use oneiron::consent::AuthenticatedOwner;
use oneiron::feedback::{
    FEEDBACK_APPROVE_ONCE_ACTION, FeedbackApprovalScope, FeedbackBundle, FeedbackCategory,
    FeedbackInboxNote, FeedbackPlatform, FeedbackPreview, FeedbackProposal, feedback_approval_card,
    prepare_feedback_preview,
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
}

pub(crate) fn preview(
    vault: &Vault,
    host: &FeedbackHost,
    owner: &AuthenticatedOwner,
    request: &FeedbackRequest,
    redactor: &ServerFeedbackRedactor,
) -> OwnerResult<Preview> {
    preview_view(vault, host, owner, &bundle_preview(request, redactor)?)
}

/// The preview of one built bundle, for every door that builds its own:
/// the digest, destination and approval of exactly these bytes.
pub(crate) fn preview_view(
    vault: &Vault,
    host: &FeedbackHost,
    owner: &AuthenticatedOwner,
    preview: &FeedbackPreview,
) -> OwnerResult<Preview> {
    Ok(Preview {
        digest: preview.digest().to_owned(),
        encoding: preview.encoding().as_str(),
        approval: preview.approval_component_id(
            &FeedbackApprovalScope::Send(host.config.route()),
            owner.principal_ref_for_read(vault)?,
        ),
        previewed_at: vault.now_recorded_at(),
        bundle: serde_json::from_str(&preview.display_json().map_err(feedback_error)?)
            .map_err(|error| OwnerError::Host(anyhow::anyhow!("feedback bundle JSON: {error}")))?,
        destination: host.config.endpoint.clone(),
    })
}

pub(crate) fn send(
    vault: &Vault,
    host: &FeedbackHost,
    owner: &AuthenticatedOwner,
    request: &SendRequest,
    redactor: &ServerFeedbackRedactor,
) -> OwnerResult<Sent> {
    let preview = bundle_preview(
        &FeedbackRequest {
            category: request.category,
            note: request.note.clone(),
            proposal: request.proposal.clone(),
        },
        redactor,
    )?;
    send_previewed(
        vault,
        host,
        owner,
        &preview,
        &request.digest,
        &request.approval,
        request.previewed_at,
    )
}

/// Sends one built bundle its preview approved, for every door that
/// builds its own: the digest, approval and preview age are rechecked
/// here, and the send is admitted under the owner's proof in the
/// transaction that admits it.
pub(crate) fn send_previewed(
    vault: &Vault,
    host: &FeedbackHost,
    owner: &AuthenticatedOwner,
    preview: &FeedbackPreview,
    digest: &str,
    approval: &str,
    previewed_at: u64,
) -> OwnerResult<Sent> {
    let principal_ref = owner.revalidate_principal_ref(vault)?;
    if preview.digest() != digest {
        return Err(OwnerError::Changed(
            "this bundle is not the one previewed; preview it again".to_owned(),
        ));
    }
    let scope = FeedbackApprovalScope::Send(host.config.route());
    // The approval names the owner who previewed it, so two owners' sends of
    // one bundle are two sends, and neither can send on the other's preview.
    if preview.approval_component_id(&scope, principal_ref) != approval {
        return Err(OwnerError::Changed(
            "this preview was for another destination or another owner; preview it again"
                .to_owned(),
        ));
    }
    let now = vault.now_recorded_at();
    if now.saturating_sub(previewed_at) > PREVIEW_LIFETIME_SECS
        || previewed_at > now.saturating_add(PREVIEW_CLOCK_SKEW_SECS)
    {
        return Err(OwnerError::Changed(
            "the preview has expired; preview it again".to_owned(),
        ));
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
    })
}

/// The bundle as it would leave: built from the request, every free text in
/// it run through `redactor`, this server's in-vault filter, when it runs.
fn bundle_preview(
    request: &FeedbackRequest,
    redactor: &ServerFeedbackRedactor,
) -> OwnerResult<FeedbackPreview> {
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
