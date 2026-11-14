//! Door for `tests/campaign_opt_out_line.rs` (L3-02, ARCH-0059 #opt-out): the
//! campaign sender's sealing of one email send from its filed step body, as
//! the gmail and the stalwart branches seal it before the sink runs.

use crate::campaign::sender::{seal_campaign_gmail_plan, seal_campaign_native_message};
use crate::channel_identity_provider::gmail::GmailDelegatedAdapter;
use crate::error::Result;

/// One sealed campaign email: the plain-text body it sends and the content
/// ref its intent carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedCampaignEmail {
    /// The plain-text body on the wire.
    pub body_text: String,
    /// The sealed plan's or message's content ref.
    pub content_ref: String,
}

/// The gmail branch's plan for `step_body`, from `adapter`'s mailbox.
///
/// # Errors
/// As the branch: the plan does not seal.
pub fn seal_gmail(
    adapter: &GmailDelegatedAdapter,
    logical_ref: &str,
    target: &str,
    subject: &str,
    step_body: &str,
    composed_at: u64,
) -> Result<SealedCampaignEmail> {
    let plan = seal_campaign_gmail_plan(
        adapter,
        logical_ref,
        target,
        subject,
        step_body,
        composed_at,
    )?;
    Ok(SealedCampaignEmail {
        body_text: plan.body_text().to_owned(),
        content_ref: plan.content_ref().to_owned(),
    })
}

/// The stalwart branch's native message for `step_body`, from the sending
/// identity's own `sender_address`.
///
/// # Errors
/// As the branch: the message does not seal.
pub fn seal_native_mail(
    target: &str,
    subject: &str,
    step_body: &str,
    sender_address: &str,
) -> Result<SealedCampaignEmail> {
    let message = seal_campaign_native_message(target, subject, step_body, sender_address)?;
    Ok(SealedCampaignEmail {
        body_text: message.text.clone().unwrap_or_default(),
        content_ref: message.content_ref()?,
    })
}
