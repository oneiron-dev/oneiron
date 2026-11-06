//! Who a drafted reply goes to (fix list row 17645): the answered message's
//! `Reply-To`, else its sender, in To; with reply-all, the message's own To
//! and Cc lists in their roles; then the drafter's own Cc. The mailbox's own
//! address never receives its reply. Every address is canonical and named
//! once, To before Cc, in the order the headers name them, the first To
//! winning over a later Cc. A reply that names no To recipient, a malformed
//! address, a named group's members or more than [`MAX_REPLY_RECIPIENTS`]
//! is refused, never cut. A list's address is one opaque recipient: no group
//! is expanded into its members (fix list row 17642).

use super::state::MailReplyHeaders;
use crate::channel_identity_provider::native_mail::canonical_recipient;
use crate::memory::{MEMORY_CODE_INVALID_STATE, MemoryError, MemoryResult};
use crate::outbound::{OutboundRecipient, OutboundRecipientRole};

/// The most recipients one drafted reply names, To and Cc together. A reply
/// is an answer to a conversation, not a mailing; a longer list is refused
/// rather than cut.
pub(super) const MAX_REPLY_RECIPIENTS: usize = 50;

/// The mailboxes of one address header value, a comma-separated list
/// (`Name <a@b>, c@d`): each one's bare address. Commas inside a quoted
/// display name or an angle address do not split it. An empty group
/// (`undisclosed-recipients:;`) names no mailbox; a group that names
/// members keeps its syntax, which no address grammar takes.
fn mailboxes(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let (mut start, mut quoted, mut angled) = (0, false, false);
    for (at, character) in text.char_indices() {
        match character {
            '"' if !angled => quoted = !quoted,
            '<' if !quoted => angled = true,
            '>' if !quoted => angled = false,
            ',' if !quoted && !angled => {
                parts.push(&text[start..at]);
                start = at + 1;
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts
        .into_iter()
        .map(str::trim)
        .filter(|part| !part.is_empty() && !empty_group(part))
        .map(|part| {
            let address = match (part.rfind('<'), part.rfind('>')) {
                (Some(open), Some(close)) if open < close => &part[open + 1..close],
                _ => part,
            };
            address.trim().to_owned()
        })
        .collect()
}

/// Whether `part` is an RFC 5322 group that names no mailbox, as a message
/// sent to undisclosed recipients carries.
fn empty_group(part: &str) -> bool {
    !part.contains('@')
        && part
            .strip_suffix(';')
            .is_some_and(|name| name.trim_end().ends_with(':'))
}

/// One reply's recipients as they are gathered: each canonical address
/// once, in its first role, the mailbox's own addresses left out.
struct ReplyRecipientList<'o> {
    own: &'o [String],
    named: Vec<OutboundRecipient>,
}

impl ReplyRecipientList<'_> {
    /// Names `address` in `role`, unless it is the mailbox's own or named
    /// already.
    fn name(&mut self, role: OutboundRecipientRole, address: &str) -> MemoryResult<()> {
        let address = canonical_recipient(address).map_err(|_| {
            MemoryError::bad_request(
                "the reply names an address no mail can go to; a named group is not expanded",
            )
        })?;
        if self.own.contains(&address) || self.named.iter().any(|named| named.address == address) {
            return Ok(());
        }
        self.named.push(OutboundRecipient::new(role, address));
        Ok(())
    }

    /// Names every mailbox of the header entries `entries` in `role`.
    fn name_header(&mut self, role: OutboundRecipientRole, entries: &[String]) -> MemoryResult<()> {
        for entry in entries {
            for address in mailboxes(entry) {
                self.name(role, &address)?;
            }
        }
        Ok(())
    }
}

/// The recipients a reply to `parent` from the mailbox whose own addresses
/// are `own` names, in order: its `Reply-To`, else its sender, in To; with
/// `reply_all`, the parent's own To and Cc in their roles; then `cc`, each
/// one bare address, in Cc.
///
/// # Errors
///
/// A reply to all of a message landed before its To and Cc were kept; a
/// malformed address or a group's members; no To recipient but the
/// mailbox's own; more than [`MAX_REPLY_RECIPIENTS`].
pub(super) fn reply_recipients(
    parent: &MailReplyHeaders,
    own: &[String],
    reply_all: bool,
    cc: &[String],
) -> MemoryResult<Vec<OutboundRecipient>> {
    let mut list = ReplyRecipientList {
        own,
        named: Vec::new(),
    };
    if parent.reply_to.is_empty() {
        list.name_header(OutboundRecipientRole::To, parent.from.as_slice())?;
    } else {
        list.name_header(OutboundRecipientRole::To, &parent.reply_to)?;
    }
    if reply_all {
        let lists = parent.recipients.as_ref().ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "the message landed before its To and Cc were kept",
                &["sync the mailbox again, then reply to all"],
            )
        })?;
        list.name_header(OutboundRecipientRole::To, &lists.to)?;
        list.name_header(OutboundRecipientRole::Cc, &lists.cc)?;
    }
    for address in cc {
        list.name(OutboundRecipientRole::Cc, address.trim())?;
    }
    let named = list.named;
    if named
        .first()
        .is_none_or(|first| first.role != OutboundRecipientRole::To)
    {
        return Err(MemoryError::bad_request(
            "the reply names no To recipient but this mailbox",
        ));
    }
    if named.len() > MAX_REPLY_RECIPIENTS {
        return Err(MemoryError::bad_request(format!(
            "a reply names at most {MAX_REPLY_RECIPIENTS} recipients, To and Cc together"
        )));
    }
    Ok(named)
}

/// The addresses `recipients` names in `role`, in their place.
pub(super) fn addresses_in(
    recipients: &[OutboundRecipient],
    role: OutboundRecipientRole,
) -> Vec<String> {
    recipients
        .iter()
        .filter(|named| named.role == role)
        .map(|named| named.address.clone())
        .collect()
}
