//! Feedback to the engine's makers (OF-420), sent by the owner: preview the
//! exact bundle, then send that bundle, once, to the destination this server
//! is configured with. The send is the owner's approve-once on that bundle
//! and that destination; it rides the ordinary outbound pipeline, so the
//! vault's policy still decides whether it leaves now or is held.
//!
//! A bundle here carries no vault text: a category, the engine version and
//! the platform. A written note waits for in-vault redaction, which the
//! engine does not ship yet, so a request with one is refused.

use oneiron::Vault;
use oneiron::consent::AuthenticatedOwner;
use oneiron::feedback::{
    FEEDBACK_APPROVE_ONCE_ACTION, FeedbackApprovalScope, FeedbackBundle, FeedbackCategory,
    FeedbackPlatform, FeedbackPreview, PassThroughFeedbackRedactor, feedback_approval_card,
    prepare_feedback_preview,
};
use oneiron::genui::{
    ConsentActionKind, ConsentActionRequest, ConsentActorIdentity, ConsentSurface,
};
use oneiron::outbound::OutboundDispatchActor;
use serde::{Deserialize, Serialize};

use super::{OwnerError, OwnerResult};
use crate::feedback_delivery::{FeedbackHost, SendFeedbackError, send_approved_feedback};

/// How long a preview stays good to send.
const PREVIEW_LIFETIME_SECS: u64 = 3_600;
/// How far a preview time may run ahead of this server's clock.
const PREVIEW_CLOCK_SKEW_SECS: u64 = 60;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FeedbackRequest {
    /// `bug`, `papercut`, `confusion` or `feature-wish`.
    pub(crate) category: FeedbackCategory,
    /// Refused until the engine redacts notes in the vault.
    #[serde(default)]
    pub(crate) note: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SendRequest {
    pub(crate) category: FeedbackCategory,
    #[serde(default)]
    pub(crate) note: Option<String>,
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
) -> OwnerResult<Preview> {
    let preview = bundle_preview(request)?;
    Ok(Preview {
        digest: preview.digest().to_owned(),
        approval: preview.approval_component_id(
            &FeedbackApprovalScope::Send(host.config.route()),
            owner.principal_ref(),
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
) -> OwnerResult<Sent> {
    vault.recheck_owner(owner)?;
    let preview = bundle_preview(&FeedbackRequest {
        category: request.category,
        note: request.note.clone(),
    })?;
    if preview.digest() != request.digest {
        return Err(OwnerError::Changed(
            "this bundle is not the one previewed; preview it again".to_owned(),
        ));
    }
    let scope = FeedbackApprovalScope::Send(host.config.route());
    // The approval names the owner who previewed it, so two owners' sends of
    // one bundle are two sends, and neither can send on the other's preview.
    if preview.approval_component_id(&scope, owner.principal_ref()) != request.approval {
        return Err(OwnerError::Changed(
            "this preview was for another destination or another owner; preview it again"
                .to_owned(),
        ));
    }
    let now = vault.now_recorded_at();
    if now.saturating_sub(request.previewed_at) > PREVIEW_LIFETIME_SECS
        || request.previewed_at > now.saturating_add(PREVIEW_CLOCK_SKEW_SECS)
    {
        return Err(OwnerError::Changed(
            "the preview has expired; preview it again".to_owned(),
        ));
    }
    // The owner's send is the answer; the card's prompt names where it goes.
    let card = feedback_approval_card(
        &preview,
        owner.principal_ref(),
        &host.config.endpoint,
        &scope,
    )
    .map_err(feedback_error)?;
    // The approval is timed at the preview, so a repeated request names the
    // same approval receipt and the outbound ledger answers it as the one send.
    let approval = ConsentActionRequest::new(
        card.card_id.clone(),
        FEEDBACK_APPROVE_ONCE_ACTION,
        ConsentActionKind::Approve,
        ConsentActorIdentity::SurfaceActor {
            actor_ref: owner.principal_ref().to_owned(),
        },
        ConsentSurface::Dashboard,
        request.previewed_at,
    )?;
    let evaluation = card.evaluate_action(&approval, owner)?;
    let actor = OutboundDispatchActor {
        actor_class: "human".to_owned(),
        actor_ref: Some(owner.actor().to_hex()),
        actor_entity_ref: Some(owner.actor()),
    };
    let sent = send_approved_feedback(
        vault,
        host.config.clone(),
        host.bearer.clone(),
        &preview,
        &evaluation,
        actor,
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

fn bundle_preview(request: &FeedbackRequest) -> OwnerResult<FeedbackPreview> {
    if request.note.is_some() {
        return Err(OwnerError::Refused(
            "a written note waits for in-vault redaction (OF-420); send the category alone"
                .to_owned(),
        ));
    }
    let bundle = FeedbackBundle::new(
        request.category,
        env!("CARGO_PKG_VERSION"),
        FeedbackPlatform::current(),
    );
    prepare_feedback_preview(bundle, &PassThroughFeedbackRedactor).map_err(feedback_error)
}

fn feedback_error(error: oneiron::feedback::FeedbackError) -> OwnerError {
    OwnerError::Invalid(error.to_string())
}
