//! Purposes of vault authority (`crates/oneiron/src/authority/`).

purposes! {
    /// The digest of an owner key's vouch request, by which an ask names the act
    /// (`authority/owner_key_vouch.rs`, `OwnerKeyVouchRequest::digest`). One part: the
    /// request's bytes (`OwnerKeyVouchRequest::to_bytes`).
    OWNER_KEY_VOUCH_REQUEST = "oneiron.authority.owner_key_vouch.request.v1";
}

legacy_purposes! {}
