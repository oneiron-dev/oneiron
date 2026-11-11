//! The side tables `build_cache` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The tenant/account identity a build-cache vault is bound to. Key: ().
    BUILD_CACHE_ACCOUNT: VaultMeta b"build_cache:account:v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// A cached build/verify action result, addressed by its content-derived action key; value is a
    /// leading schema-version byte then a positional (non-named) MessagePack sequence. Key: bytes32
    /// (REAPI action key).
    BUILD_CACHE_REAPI_ROW: VaultMeta b"build_cache:reapi:v2:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// In-flight reservation marker preventing duplicate dispatch of the same build/verify action.
    /// Key: bytes32 (action key).
    BUILD_CACHE_RUNNING_RESERVATION: VaultMeta b"build_cache:running:v2:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
