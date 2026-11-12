//! Doors for `tests/mail_late_address_headers.rs` (fix list row 20852): the
//! address headers an IMAP or mbox landing reads from one raw message.

/// The Reply-To mailboxes the raw header block `raw` lands with from an IMAP
/// received-mail folder.
pub fn imap_landed_reply_to(raw: &[u8]) -> Vec<String> {
    crate::mail_pack::imap_landed_headers(raw).reply_to
}

/// The Reply-To mailboxes the mbox message `raw` lands with, named by its
/// header block; `None` when the import names no message for it.
pub fn mbox_landed_reply_to(raw: &[u8]) -> Option<Vec<String>> {
    crate::mail_pack::mbox_landed_headers(raw).map(|headers| headers.reply_to)
}
