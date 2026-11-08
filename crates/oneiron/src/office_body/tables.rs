//! The side tables `office_body` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The body frontier an office body export version projects. Key: id16 (artifact) + u64be
    /// (version).
    OFFICE_BODY_EXPORT: VaultMeta b"office_body:export:v1:" Named
        [restore: content] [family: owner OfficeBody] [tier: canonical]
        => crate::office_body::erase_export_actor_in_txn;
    /// One DOCX revision group's opaque author token. Key: id16 (artifact) + u64be (version) +
    /// u64be (consecutive group index); value: optional actor + token (FIX 595).
    OFFICE_BODY_EXPORT_AUTHOR: VaultMeta b"office_body:export_author:v1:" Named
        [restore: content] [family: owner OfficeBody] [tier: canonical]
        => crate::office_body::erase_export_author_actor_in_txn;
    /// Derived DOCX author-token lookup. Key: utf8 token; value: authoritative
    /// export and revision-author row keys, with no actor or display author.
    OFFICE_BODY_EXPORT_TOKEN_INDEX: VaultMeta b"office_body:export_token_index:v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// The office proposal a DOCX or XLSX fork joined when it was opened. Key: id16 (artifact) +
    /// id16 (fork).
    OFFICE_BODY_FORK_PROPOSAL: VaultMeta b"office_body:fork_proposal:v1:" Named
        [restore: content] [family: owner OfficeBody] [tier: canonical];
    /// A live office body's head: kind, imported source version and frontiers. Key: id16
    /// (artifact).
    OFFICE_BODY_HEAD: VaultMeta b"office_body:head:v1:" Named
        [restore: content] [family: owner OfficeBody] [tier: canonical];
    /// The live-edit route one holder ask group carries (FIX 596): the
    /// artifact, editor, asked owners and revision. Key: id16 (ask group).
    /// Sorted slot: `live_edit_ask_group` orders between `head` and
    /// `oracle`; the decl list must stay strictly ascending
    /// (side_table assert_disjoint), so it cannot sit after PROPOSAL.
    OFFICE_LIVE_EDIT_ASK_GROUP: VaultMeta b"office_body:live_edit_ask_group:v1:" Named
        [restore: content] [family: owner OfficeBody] [tier: canonical]
        => crate::office_body::erase_live_edit_ask_group_actor_in_txn;
    /// The deck oracle's latest eight-step receipt per export profile and the projector it
    /// checked; the deck export gate reads it. Key: the profile name.
    OFFICE_BODY_ORACLE: VaultMeta b"office_body:oracle:v1:" Named
        [restore: content] [family: owner OfficeBody] [tier: canonical]
        => crate::office_body::erase_oracle_actor_in_txn;
    /// An office proposal: its header (opener, run root, opened at), member forks with each one's
    /// verdict and answer, and its settlement. Key: id16 (proposal); the header's artifact is its home.
    OFFICE_BODY_PROPOSAL: VaultMeta b"office_body:proposal:v2:" Named
        [restore: content] [family: owner OfficeBody] [tier: canonical]
        => crate::office_body::erase_proposal_actor_in_txn;
}
