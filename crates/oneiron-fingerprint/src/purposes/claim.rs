//! Purposes of claims (`crates/oneiron/src/claim`).

purposes! {
    /// A room's served-form record (CALLS-8; `claim::scoped_read::served_forms::session`).
    /// Parts: one host call's identity, the form's place among its sorted forms
    /// (little-endian).
    ROOM_SERVED_FORM = "oneiron/room-served-form/v1";
}

legacy_purposes! {}
