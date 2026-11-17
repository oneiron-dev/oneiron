//! Doors for `tests/mail_reply_send_grant.rs` (PLAN L3-35 D6) and
//! `tests/mail_reply_gmail_send_grant.rs` (FIX [MAIL-REPLY-GMAIL-SEND-GRANT]):
//! a drafted reply's send by its drafter and its approval by the mailbox's
//! person, each with the provider send of a reply sent as the mailbox's own
//! account made through the test's sink in place of SMTP or Graph; a Google
//! reply's draft with the answered message's address headers the test
//! gives, and its drafter's send with the Gmail send made through the
//! test's wire, both in place of Gmail's HTTP API; and whether a revision's
//! Ask still stands. Thin wrappers over the reply doors; no reply logic
//! here. Compiled only under `--cfg oneiron_test_support` (`test_doors`);
//! hidden, never API.

use crate::channel_identity_provider::gmail::{GmailSendWire, HttpGmailSendWire};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::mail_pack::{
    MailAddressHeaders, MailReplyApproveRequest, MailReplyDraftRequest, MailReplyDraftView,
    MailReplySendRequest,
};
use crate::memory::{Memory, MemoryResult};
use crate::outbound::OutboundExecutionSink;
use crate::vault::Vault;

/// `Memory::mail_reply_send`, its provider send made through `sink`.
///
/// # Errors
///
/// The door's.
#[doc(hidden)]
pub fn mail_reply_send_into<S: OutboundExecutionSink>(
    memory: &Memory<'_>,
    input: &MailReplySendRequest,
    sink: &mut S,
) -> MemoryResult<MailReplyDraftView> {
    memory.mail_reply_send_into(input, Some(sink), None::<HttpGmailSendWire>)
}

/// `Memory::mail_reply_draft`, a Gmail message's address headers taken from
/// `answered` in place of its raw message read at Gmail.
///
/// # Errors
///
/// The door's.
#[doc(hidden)]
pub fn mail_reply_draft_with_address_headers(
    memory: &Memory<'_>,
    input: &MailReplyDraftRequest,
    answered: MailAddressHeaders,
) -> MemoryResult<MailReplyDraftView> {
    memory.mail_reply_draft_into(input, Some(answered))
}

/// `Memory::mail_reply_send` for a Google reply, its Gmail send made through
/// `wire`. The wire still resolves its token at the send authority's door
/// (`GmailSendWire`), so the mailbox's custody must be live.
///
/// # Errors
///
/// The door's.
#[doc(hidden)]
pub fn mail_reply_send_gmail_into<W: GmailSendWire>(
    memory: &Memory<'_>,
    input: &MailReplySendRequest,
    wire: W,
) -> MemoryResult<MailReplyDraftView> {
    memory.mail_reply_send_gmail_into(input, wire)
}

/// `Vault::approve_mail_reply`, its provider send made through `sink`.
///
/// # Errors
///
/// The door's.
#[doc(hidden)]
pub fn approve_mail_reply_into<S: OutboundExecutionSink>(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &MailReplyApproveRequest,
    sink: &mut S,
) -> MemoryResult<MailReplyDraftView> {
    vault.approve_mail_reply_into(owner, input, Some(sink))
}

/// Whether the Ask of revision `revision` of the draft `draft` stands, not
/// yet acked by the mailbox's person.
///
/// # Errors
///
/// Storage and codec failures.
#[doc(hidden)]
pub fn reply_ask_open(vault: &Vault, draft: EntityId, revision: u64) -> Result<bool> {
    crate::mail_pack::reply_ask_open(vault, &draft, revision)
}
