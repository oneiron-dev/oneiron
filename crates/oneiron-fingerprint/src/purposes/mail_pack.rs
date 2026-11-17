//! Purposes of the mail pack (`crates/oneiron/src/mail_pack`).

purposes! {}

legacy_purposes! {
    /// An IMAP folder's digest (`mail_pack::imap`): plain BLAKE3 of the folder's label, with
    /// no tag or length, written as the first 16 lowercase hex digits (8 bytes). Provider
    /// ids (`imapuid.<digest>...`) and page cursors carry it, a resumed listing re-syncs
    /// when it differs, and the UID map and the sync marks are keyed by it.
    IMAP_FOLDER_DIGEST = (Blake3, NotHashed, "oneiron.mail_pack.imap_folder_digest.v1");
}
