//! Page admission and persisted mailbox progress for a delegated read.

use super::*;
use crate::channel_identity_provider::mailbox_cursor::{
    advance_mailbox_cursor, mailbox_cursor_snapshot, validate_mailbox_cursor,
};
use crate::channel_identity_provider::mailbox_skipped::{
    GmailSkipStage, GmailSkippedMessage, record_gmail_skipped_message,
};
use crate::surface_event::SurfaceEventAdmission;

/// A mailbox- and identity-bound read handle supplied to the host wire.
///
/// The host resolves the token only at the provider request, through
/// [`Self::with_token_at_door`]. A released row therefore cannot resolve a
/// still-live member OAuth secret. No public constructor or credential field.
pub struct GmailReadAuthority<'a> {
    adapter: &'a GmailDelegatedAdapter,
    vault: &'a Vault,
    identity_id: EntityId,
    used: std::cell::Cell<bool>,
}

impl GmailReadAuthority<'_> {
    /// Resolve the member's token at the identity-aware SECRET-02 egress and
    /// perform the provider request inside `apply`. The token cannot escape
    /// through a return value or the durable page/cursor payload.
    ///
    /// # Errors
    ///
    /// If the identity was withdrawn, or custody is no longer readable, the
    /// callback is not invoked.
    pub fn with_token_at_door(
        &self,
        apply: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<DoorInjectionReceipt> {
        let mut guarded = |token: &[u8]| {
            apply(token)?;
            self.used.set(true);
            Ok(())
        };
        self.adapter
            .with_delegated_token_at_door(self.vault, self.identity_id, &mut guarded)
    }
}

/// Delivery idempotence is mailbox-local, while the handoff queue is vault-wide.
/// Length-prefix the normalized mailbox so a delimiter inside an address cannot
/// alias a different `(mailbox, message)` pair. Provider event IDs stay as-is.
pub(super) fn delivery_correlation_id(mailbox_address: &str, event_id: &str) -> String {
    let mailbox = AssignmentAddress::normalize(EMAIL_CHANNEL, mailbox_address);
    format!(
        "gmail:{}:{}:{event_id}",
        mailbox.as_str().len(),
        mailbox.as_str()
    )
}

impl GmailDelegatedAdapter {
    /// Reads one page through the policy-aware host wire. This low-level
    /// method does not advance durable progress; use [`Self::run_mailbox_page`]
    /// to route messages and commit the cursor after full page admission.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for an invalid token, oversized page, or a
    /// placement outside the requested policy; provider errors pass through.
    pub fn fetch_inbox_page<W: GmailReadWire + ?Sized>(
        &self,
        vault: &Vault,
        identity_id: EntityId,
        wire: &W,
        cursor: Option<&MailboxPageToken>,
    ) -> Result<GmailInboxPage> {
        if let Some(cursor) = cursor {
            validate_mailbox_cursor(cursor.as_str())?;
        }
        self.require_active_row_matches_adapter(vault, &identity_id)?;
        let authority = GmailReadAuthority {
            adapter: self,
            vault,
            identity_id,
            used: std::cell::Cell::new(false),
        };
        let page = wire.fetch_inbox_page(
            &authority,
            &self.config.mailbox_address,
            self.config.placement_policy,
            cursor,
        )?;
        if !authority.used.get() {
            return Err(Error::InvalidConfig(
                "gmail read wire did not resolve the identity-bound credential".to_owned(),
            ));
        }
        page.validate(self.config.placement_policy)?;
        Ok(page)
    }

    /// Admit one full mailbox page to the durable inbound handoff queue, then
    /// advance persisted progress. A partial or rejected page keeps its prior
    /// cursor; retrying already admitted messages uses the handoff's idempotent
    /// provider event IDs. A placement change starts from page one.
    ///
    /// A message that fails on its own account (ids or metadata that do not
    /// normalize, an envelope the adapter refuses, a routing rejection naming
    /// no identity reason) is set aside in a durable row before the page goes
    /// on (FIX 6007), so the cursor moves only once each message is admitted
    /// or set aside.
    ///
    /// # Errors
    ///
    /// Row/custody, provider, identity routing, queue, skip-record or
    /// cursor-store failures.
    pub fn run_mailbox_page<W: GmailReadWire + ?Sized>(
        &self,
        vault: &Vault,
        identity_id: EntityId,
        wire: &W,
        now: u64,
    ) -> Result<GmailMailboxRunOutcome> {
        self.require_active_row_matches_adapter(vault, &identity_id)?;
        self.verify_custody_grant(vault)?;
        let prior = mailbox_cursor_snapshot(vault, identity_id)?;
        let progress = prior.clone().unwrap_or_else(|| {
            MailboxCursor::new(
                AssignmentAddress::normalize(EMAIL_CHANNEL, &self.config.mailbox_address).as_str(),
                self.config.placement_policy,
            )
        });
        let mailbox = AssignmentAddress::normalize(EMAIL_CHANNEL, &self.config.mailbox_address);
        let progress = progress.for_binding(mailbox.as_str(), self.config.placement_policy);
        let page =
            self.fetch_inbox_page(vault, identity_id, wire, progress.next_cursor.as_ref())?;
        let mut messages_admitted = 0_usize;
        let mut skipped = Vec::new();
        for message in page.messages {
            // A withdrawn row cannot route pages fetched while it was active.
            self.require_active_row_matches_adapter(vault, &identity_id)?;
            // Kept before the message is consumed, so a skip row names it as
            // the wire returned it.
            let message_id = message.message_id.clone();
            let thread_id = message.thread_id.clone();
            let internal_date_secs = message.internal_date_secs;
            let set_aside = |stage: GmailSkipStage, reason: String| {
                record_gmail_skipped_message(
                    vault,
                    identity_id,
                    GmailSkippedMessage {
                        identity_ref: identity_id.to_hex(),
                        mailbox_address: mailbox.as_str().to_owned(),
                        message_id: message_id.clone(),
                        thread_id: thread_id.clone(),
                        internal_date_secs,
                        stage,
                        reason,
                        skipped_at: now,
                    },
                )
            };
            // Only these deterministic, message-local refusals are set aside;
            // every other failure keeps the page retryable as before.
            let inbound = match message.into_provider_inbound() {
                Ok(inbound) => inbound,
                Err(error @ Error::InvalidConfig(_)) => {
                    skipped.push(set_aside(
                        GmailSkipStage::ProviderInbound,
                        error.to_string(),
                    )?);
                    continue;
                }
                Err(error) => return Err(error),
            };
            let thread = inbound.thread_headers.clone();
            let input = match self.parse_inbound(ChannelIdentityProviderInbound::Email(inbound)) {
                Ok(input) => input,
                Err(error @ Error::InvalidConfig(_)) => {
                    skipped.push(set_aside(GmailSkipStage::Parse, error.to_string())?);
                    continue;
                }
                Err(error) => return Err(error),
            };
            match vault.enqueue_inbound_email(input, thread.as_ref(), now)? {
                SurfaceEventAdmission::Accepted(_) => messages_admitted += 1,
                // Every reason routing names is the receiving identity's,
                // which each message on the page shares: the page stays
                // retryable rather than set a mailbox's mail aside.
                SurfaceEventAdmission::Rejected(receipt) if receipt.rejection_reason.is_some() => {
                    return Err(Error::InvalidConfig(
                        "gmail mailbox message was rejected by inbound routing".to_owned(),
                    ));
                }
                SurfaceEventAdmission::Rejected(_) => {
                    skipped.push(set_aside(
                        GmailSkipStage::Routing,
                        "gmail mailbox message was rejected by inbound routing".to_owned(),
                    )?);
                }
            }
        }
        self.require_active_row_matches_adapter(vault, &identity_id)?;
        let next = MailboxCursor {
            last_complete_at: if page.next_cursor.is_none() {
                Some(now)
            } else {
                progress.last_complete_at
            },
            next_cursor: page.next_cursor,
            pages_completed: progress.pages_completed.saturating_add(1),
            ..progress
        };
        advance_mailbox_cursor(vault, identity_id, prior.as_ref(), &next)?;
        Ok(GmailMailboxRunOutcome {
            messages_admitted,
            skipped,
            progress: next,
        })
    }
}
