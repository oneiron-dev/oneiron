//! The side tables `clipboard` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Owner-selected ordinary Clipboard cleanup arms. Key: (). No clip text.
    CLIPBOARD_RETENTION: VaultMeta b"clipboard.retention.v1" Named
        [restore: content] [family: unregistered] [tier: canonical];
}
