//! The side tables `channel_identity_provider` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Node-local Gmail page cursor keyed by lower-case hex identity id. Key: hex32.
    GMAIL_MAILBOX_CURSOR: VaultMeta b"gmail:mailbox_cursor:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// A polled Gmail message a mailbox run set aside so its page could go on (FIX 6007): the
    /// identity and mailbox, the provider's message and thread ids, the stage, the full reason
    /// and when. Node-local, as the cursor is. Key: id16 (identity) + bytes32 (sha256 of the
    /// provider message id).
    GMAIL_MAILBOX_SKIPPED: VaultMeta b"gmail:mailbox_skipped:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A frozen Gmail member send plan its host kept for a send that dispatches later (FIX 1053):
    /// its From, To, Subject, body, Date, Message-ID and reply headers; dropped once delivered.
    /// Key: its content ref.
    GMAIL_SEND_PLAN: VaultMeta b"gmail:send_plan:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Native provider archive version captured by a LINE observation. Key: id16(claim).
    LINE_CHAT_ARCHIVE_PIN: VaultMeta b"line:chat_archive_pin:v1:" Named Engine
        [restore: content] [family: structure] [tier: canonical];
    /// Exact native join-version release still owed after capture teardown. Key: id16(claim).
    LINE_CHAT_ARCHIVE_RELEASE: VaultMeta b"line:chat_archive_release:v1:" Named Engine
        [restore: live] [family: unclassified] [tier: canonical];
    /// Native mail messages an inbox poll set aside after their own failure stopped it poll after
    /// poll, and at most one per identity still stopping it, short of that count: the identity and
    /// mailbox, the server's message id, the reason, the polls and when. Node-local, as the cursor
    /// is. Key: id16 (identity) + bytes32 (sha256 of the message id).
    NATIVE_MAIL_MAILBOX_SKIPPED: VaultMeta b"native_mail:mailbox_skipped:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// One Sheets write's claim on its caller's invocation (FIX 4862, REVIEW-6403): the request it
    /// bound (tool, spreadsheet id, request digest, mutation), its intent Gate record, and its send
    /// under way or settled with what it came to and its outcome Gate record, so a replay never
    /// sends an attempted write again. Key: id16 (invocation ref).
    SHEETS_WRITE_INVOCATION: VaultMeta b"sheets:write_invocation:v1:" Named
        // Restore class: A Sheets write's invocation claim records a send that left the vault: the
        // live vault's row stands, as a held connector call's does.
        [restore: live] [family: unclassified] [tier: canonical];
}
