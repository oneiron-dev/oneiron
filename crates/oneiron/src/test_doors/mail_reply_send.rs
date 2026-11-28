//! Doors for `tests/mail_reply_send_grant.rs` (PLAN L3-35 D6): a drafted
//! reply's send by its drafter and its approval by the mailbox's person,
//! each with the provider send of a reply sent as the mailbox's own account
//! made through the test's sink in place of SMTP or Graph, and whether a
//! revision's Ask still stands. Thin wrappers over the reply doors; no reply
//! logic here. Compiled only under `--cfg oneiron_test_support`
//! (`test_doors`); hidden, never API.

use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::mail_pack::{MailReplyApproveRequest, MailReplyDraftView, MailReplySendRequest};
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
    memory.mail_reply_send_into(input, Some(sink))
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
