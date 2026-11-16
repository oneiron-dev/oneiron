//! Door for `tests/campaign_opt_out_line.rs` (L3-02, ARCH-0059 #opt-out): the
//! campaign sender's sealing of one email send from its filed step body, as
//! the gmail and the stalwart branches seal it before the sink runs, for a
//! 1:1 mail and a bulk send. Also the one-click link a bulk send freezes,
//! for oneiron-server's `tests/campaign_one_click_unsubscribe.rs`.

use std::collections::BTreeMap;

use crate::Vault;
use crate::campaign::one_click_unsubscribe::one_click_unsubscribe_uri_in_txn;
use crate::campaign::sender::{
    CampaignEmailOptOut, seal_campaign_gmail_plan, seal_campaign_native_message,
};
use crate::channel_identity_provider::gmail::GmailDelegatedAdapter;
use crate::entity_id::EntityId;
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
        &CampaignEmailOptOut::BodyLine,
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
    let message = seal_campaign_native_message(
        target,
        subject,
        step_body,
        sender_address,
        &CampaignEmailOptOut::BodyLine,
    )?;
    Ok(SealedCampaignEmail {
        body_text: message.text.clone().unwrap_or_default(),
        content_ref: message.content_ref()?,
    })
}

/// The stalwart branch's native message for a bulk send of `step_body`
/// carrying the one-click link `one_click_uri`, and the hygiene headers the
/// branch sends with it.
///
/// # Errors
/// As the branch: the message does not seal, or the link is not a
/// header-safe https URI.
pub fn seal_bulk_native_mail(
    target: &str,
    subject: &str,
    step_body: &str,
    sender_address: &str,
    one_click_uri: &str,
) -> Result<(SealedCampaignEmail, BTreeMap<String, String>)> {
    let opt_out = CampaignEmailOptOut::ListUnsubscribe(one_click_uri.to_owned());
    let message =
        seal_campaign_native_message(target, subject, step_body, sender_address, &opt_out)?;
    let sealed = SealedCampaignEmail {
        body_text: message.text.clone().unwrap_or_default(),
        content_ref: message.content_ref()?,
    };
    Ok((sealed, opt_out.hygiene_headers()?))
}

/// The one-click link a bulk send to `person` in `campaign` freezes on
/// `vault`; `None` when no origin is installed or the vault holds no key.
///
/// # Errors
/// Storage errors as they occur.
pub fn one_click_unsubscribe_uri(
    vault: &Vault,
    campaign: EntityId,
    person: EntityId,
) -> Result<Option<String>> {
    let txn = vault.store.env.read_txn()?;
    one_click_unsubscribe_uri_in_txn(vault, &txn, campaign, person)
}
