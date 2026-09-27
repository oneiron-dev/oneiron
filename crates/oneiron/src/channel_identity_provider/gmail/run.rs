//! Page admission and persisted mailbox progress for a delegated read.

use super::*;
use crate::channel_identity_provider::mailbox_cursor::{
    advance_mailbox_cursor, mailbox_cursor_snapshot, validate_mailbox_cursor,
};

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
        wire: &W,
        cursor: Option<&MailboxPageToken>,
    ) -> Result<GmailInboxPage> {
        if let Some(cursor) = cursor {
            validate_mailbox_cursor(cursor.as_str())?;
        }
        let page = wire.fetch_inbox_page(
            &self.config.custody_record_ref,
            &self.config.mailbox_address,
            self.config.placement_policy,
            cursor,
        )?;
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
        let page = self.fetch_inbox_page(wire, progress.next_cursor.as_ref())?;
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
