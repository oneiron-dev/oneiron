//! The side tables `mail_pack` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The attachments readers opened (FIX 12559): each one's fetch, waiting or stored in its
    /// artifact bound to its thread. Key: id16(source) + blake3 (32) of the provider id and
    /// part id.
    MAIL_PACK_ATTACHMENT: VaultMeta b"mail_pack:attachment:v1:" Named
        // Restore class: The compliance log and setting are live: a restore never takes back a
        // logged search or turns a switched-off search on again (FIX 12560). An import's queue,
        // occurrences and progress stand with the rows they landed, as the image holds them
        // (FIX 12559).
        [restore: content] [family: unregistered] [tier: canonical];
    /// The opened-attachment artifacts whose message was erased, owed their own delete after
    /// that erase commits (FIX 12559). Key: id16(artifact). Value: when it was owed.
    MAIL_PACK_ATTACHMENT_ERASE: VaultMeta b"mail_pack:attachment_erase:v1:" Named
        [restore: content] [family: unregistered] [tier: canonical];
    /// The mail messages that landed with their headers only and wait for their bodies, newest
    /// first (FIX 12559). Key: id16(source) + u64be (u64::MAX less the receive time) + blake3
    /// (32) of the provider id.
    MAIL_PACK_BODY_QUEUE: VaultMeta b"mail_pack:body_queue:v1:" Named
        [restore: content] [family: unregistered] [tier: canonical];
    /// One resource a pack calendar source's pulls landed: its UID, the listing that last saw
    /// it and its start (FIX 12559). Key: id16(source) + blake3 (32) of the provider's resource
    /// id.
    MAIL_PACK_CALENDAR_RESOURCE: VaultMeta b"mail_pack:calendar_resource:v1:" Named
        [restore: content] [family: unregistered] [tier: canonical];
    /// One pack calendar source's pull progress, by the source. Key: id16.
    MAIL_PACK_CALENDAR_SYNC: VaultMeta b"mail_pack:calendar_sync:v1:" Named
        [restore: content] [family: unregistered] [tier: canonical];
    /// The re-check a kept provider delete owes the claims drawn from the message (FIX 15414):
    /// ids only (its TURN, MESSAGE revisions and each claim a check settled), its round and
    /// where it stands. Key: id16(source) + blake3 (32) of the provider id + u64be presence
    /// generation.
    MAIL_PACK_CLAIM_RECHECK: VaultMeta b"mail_pack:claim_recheck:v1:" Named
        // Restore class: A re-check and the ids it names stand with the occurrence and the findings
        // it settled, as the image holds them (FIX 15414).
        [restore: content] [family: unregistered] [tier: canonical];
    /// Each id a mail claim re-check names (FIX 15414), so an erase of the TURN, a MESSAGE
    /// revision or a settled claim reaches every re-check that names it. Key: id16(named) +
    /// id16(source) + blake3 (32) of the provider id + u64be presence generation. Value: when the
    /// re-check was owed.
    MAIL_PACK_CLAIM_RECHECK_NAMED: VaultMeta b"mail_pack:claim_recheck_named:v1:" Named
        [restore: content] [family: unregistered] [tier: canonical];
    /// The org compliance search log (FIX 12560): each change to the setting and each search made
    /// under it, recorded before the search answers. Key: u64be sequence.
    MAIL_PACK_COMPLIANCE_EVENT: VaultMeta b"mail_pack:compliance_event:v1:" Named Authored
        [restore: live] [family: unregistered] [tier: canonical]
        => crate::mail_pack::erase_compliance_actor_in_txn;
    /// The org compliance search setting, off when absent (FIX 12560). Key: ().
    MAIL_PACK_COMPLIANCE_SETTING: VaultMeta b"mail_pack:compliance_setting:v1" Named
        [restore: live] [family: unregistered] [tier: canonical];
    /// The "Forget too" provider deletes a mail source still owes (fix list row 18084): the
    /// rows of each forgotten message not yet deleted and its thread's CONVERSATION, recorded
    /// before the first row goes. Key: id16(source) + blake3 (32) of the provider id.
    MAIL_PACK_FORGET_OWED: VaultMeta b"mail_pack:forget_owed:v1:" Named
        // Restore class: An owed forget stands with the rows it still owes, as the image holds
        // them.
        [restore: content] [family: unregistered] [tier: canonical];
    /// A mail message's header-only revision its body superseded, owed its delete (FIX 15413).
    /// Key: id16(source) + blake3 (32) of the provider id + id16(MESSAGE).
    MAIL_PACK_HEADER_RETIREMENT: VaultMeta b"mail_pack:header_retirement:v1:" Named
        // Restore class: An owed header retirement stands with the revision it names, as the image
        // holds it (FIX 15413).
        [restore: content] [family: unregistered] [tier: canonical];
    /// Each place the IMAP UID map names a message by an id its header block gives (fix list
    /// row 19145), with the folder's UIDVALIDITY: a copy a later place proposing that id is
    /// proved against. Key: id16(source) + blake3 (32) of the provider id + blake3 (32) of the
    /// folder digest + u64be UID.
    MAIL_PACK_IMAP_ID_PLACE: VaultMeta b"mail_pack:imap_id_place:v1:" Named
        // Restore class: Derived beside the UID map, restored with it.
        [restore: content] [family: unregistered] [tier: canonical];
    /// Which message each UID of an IMAP folder the mail pack read holds (fix list row 17871),
    /// with the folder's UIDVALIDITY. Key: id16(source) + blake3 (32) of the folder digest +
    /// u64be UID.
    MAIL_PACK_IMAP_UID: VaultMeta b"mail_pack:imap_uid:v1:" Named
        // Restore class: A UID names one message for as long as its UIDVALIDITY stands.
        [restore: content] [family: unregistered] [tier: canonical];
    /// Where one mbox or Takeout import into a mail source stands (FIX 12559): the file, its
    /// size and change time, the archive entry and byte offset. Key: id16(source) + blake3 (32)
    /// of the path.
    MAIL_PACK_MBOX_IMPORT: VaultMeta b"mail_pack:mbox_import:v1:" Named
        [restore: content] [family: unregistered] [tier: canonical];
    /// One provider message of one mail source: its rows, revisions, stage and presence at the
    /// provider (FIX 12559). Key: id16(source) + blake3 (32) of the provider id.
    MAIL_PACK_OCCURRENCE: VaultMeta b"mail_pack:occurrence:v1:" Named
        [restore: content] [family: unregistered] [tier: canonical];
    /// The rows each imported mail message landed as (FIX 12559), so an erase of any of them
    /// scrubs that message's occurrence. Key: id16(row) + id16(source) + blake3 (32) of the
    /// provider id.
    MAIL_PACK_OCCURRENCE_ROW: VaultMeta b"mail_pack:occurrence_row:v1:" Named
        [restore: content] [family: unregistered] [tier: canonical];
    /// One drafted mail reply (FIX 15420): its thread, the message it
    /// answers, its frozen send plan, its words and where it stands; an
    /// actor's erase forgets its drafter. Key: id16(draft).
    MAIL_PACK_REPLY_DRAFT: VaultMeta b"mail_pack:reply_draft:v1:" Named Authored
        // Restore class: A drafted reply stands as the vault held it: its state and its approval.
        [restore: live] [family: unregistered] [tier: canonical]
        => crate::mail_pack::erase_reply_drafter_in_txn;
    /// One connected mail or calendar source: provider, kind, address, custody name, owner,
    /// audience and what it keeps (FIX 12559). Key: id16(source).
    MAIL_PACK_SOURCE: VaultMeta b"mail_pack:source:v1:" Named
        // Restore class: A source's owner, custody name and settings are live configuration.
        [restore: live] [family: unregistered] [tier: canonical]
        => crate::mail_pack::erase_source_actor_in_txn;
    /// A source's id by its provider, kind, account and address (FIX 12559). Key: blake3 (32).
    MAIL_PACK_SOURCE_INDEX: VaultMeta b"mail_pack:source_index:v1:" Named
        [restore: live] [family: unregistered] [tier: canonical];
    /// Where one mail source's import stands: its change anchor, its newest-first copy and its
    /// counts (FIX 12559). Key: id16(source).
    MAIL_PACK_SYNC: VaultMeta b"mail_pack:sync:v1:" Named
        [restore: content] [family: unregistered] [tier: canonical];
    /// How many times a mail thread's CONVERSATION was forgotten whole (fix list row 18084): a
    /// message landing in the thread afterwards opens a new CONVERSATION. Key: id16(source) +
    /// blake3 (32) of the thread key.
    MAIL_PACK_THREAD_EPOCH: VaultMeta b"mail_pack:thread_epoch:v1:" Named
        // Restore class: A thread's epoch stands with the conversations it named.
        [restore: content] [family: unregistered] [tier: canonical];
}
