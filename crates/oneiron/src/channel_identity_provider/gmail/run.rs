//! Page admission and persisted mailbox progress for a delegated read.

use super::*;
use crate::channel_identity_provider::mailbox_cursor::{
    advance_mailbox_cursor, mailbox_cursor_snapshot, validate_mailbox_cursor,
};

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
    /// # Errors
    ///
    /// Row/custody, provider, routing, queue, or cursor-store failures.
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
        let message_count = page.messages.len();
        for message in page.messages {
            // A withdrawn row cannot route pages fetched while it was active.
            self.require_active_row_matches_adapter(vault, &identity_id)?;
            let inbound = message.into_provider_inbound()?;
            let input = self.parse_inbound(ChannelIdentityProviderInbound::Email(inbound))?;
            if let crate::surface_event::SurfaceEventAdmission::Rejected(_) =
                vault.enqueue_inbound_surface_event(input, now)?
            {
                return Err(Error::InvalidConfig(
                    "gmail mailbox message was rejected by inbound routing".to_owned(),
                ));
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
            messages_admitted: message_count,
            progress: next,
        })
    }
}
