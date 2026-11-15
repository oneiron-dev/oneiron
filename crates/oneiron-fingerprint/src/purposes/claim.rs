//! Purposes of claims (`crates/oneiron/src/claim`).
//!
//! Each legacy purpose below is an id by the legacy material rule
//! (`EntityId::derive_legacy_material`): plain BLAKE3, the tag's bytes first, then a u64
//! little-endian salt, then each part as its u64 little-endian length and its bytes. The
//! id is the first 16 bytes, with no version stamp; a reserved result takes the next salt.
//! Every one of these ids is a key that vaults already hold, so its bytes are kept until
//! the launch reset (PLAN-UC-04 stage 9).

purposes! {
    /// A room's served-form record (CALLS-8; `claim::scoped_read::served_forms::session`).
    /// Parts: one host call's identity, the form's place among its sorted forms
    /// (little-endian).
    ROOM_SERVED_FORM = "oneiron/room-served-form/v1";
}

legacy_purposes! {
    /// One weave digest setting change
    /// (`claim::scoped_read::weave_digest::changes::change_id`). Parts: the owner, the base and
    /// the time (u64 big-endian each), the step (its `Debug` text).
    WEAVE_DIGEST_SETTING_CHANGE = (Blake3, HashedFirst, "oneiron:weave-digest-setting-change:v1");
}
