//! The side tables `code_symbol` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Per-code-artifact code-symbol manifest row. Key: id16.
    CODE_SYMBOL_MANIFEST: VaultMeta b"code_symbol:manifest:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::code_symbol::erase_manifest_actor_in_txn;
    /// Index of symbol revisions by repo/path/name/fingerprint, empty marker value. Key:
    /// sha256(domain, repo_ref, path, name, fingerprint) "\x00" id16.
    CODE_SYMBOL_REVISION_INDEX: VaultMeta b"code_symbol:revision:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
