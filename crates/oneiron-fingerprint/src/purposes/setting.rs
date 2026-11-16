//! Purposes of the Setting primitive (`crates/oneiron/src/setting/`).

purposes! {
    /// The effect digest of one setting change, which the check-in an agent's change waits
    /// on binds (`setting/set.rs`, `effect_digest`). Parts: the row key's encoding, a flag
    /// for a value, then the value's JSON bytes when there is one.
    SET_EFFECT = "oneiron.setting.set_effect.v1";
}

legacy_purposes! {}
