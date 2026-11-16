//! Purposes of the Setting primitive (`crates/oneiron/src/setting/`).

purposes! {
    /// The effect digest of one setting change, which the check-in an agent's change waits
    /// on binds (`setting/set.rs`, `effect_digest`), until stage 6.0-1. Parts: the row key's
    /// encoding, a flag for a value, then the value's JSON bytes when there is one, then a
    /// seed's weight (its `f64` bits as a u64) when the change carries one. No site hashes
    /// under it now; it stays declared so its context string is never reused.
    SET_EFFECT = "oneiron.setting.set_effect.v1";

    /// The effect digest of one setting change, which a proposal binds and its yes names
    /// (`setting/set.rs`, `effect_digest`; DESIGN 1.5, "A proposal binds what it will
    /// write"). Parts: the row key's encoding; a flag for a value, then the value's JSON
    /// bytes when there is one; a flag for a seed's weight, then its `f64` bits as a u64
    /// when there is one; a flag for the row the change replaces, then that row's stored
    /// bytes when there is one.
    SET_EFFECT_V2 = "oneiron.setting.set_effect.v2";

    /// The digest of a pack's defaults, which the pack's head row keeps as the defaults it
    /// last weighed (`setting/pack.rs`, `defaults_digest`). Parts: the pack's name; the count
    /// of its defaults; then per default in key-name order, the key's name and the default's
    /// JSON bytes.
    PACK_DEFAULTS = "oneiron.setting.pack_defaults.v1";

    /// The digest of a pack's proposal, which a holder's yes names (`setting/pack.rs`,
    /// `proposal_digest`). Parts: the pack's name; the defaults digest the proposal was made
    /// under, as its hex; the count of waiting defaults; then per default, the key's name, the
    /// default's JSON bytes, and a flag for the row it replaces, then that row's content hash
    /// as its hex when there is one.
    PACK_PROPOSAL = "oneiron.setting.pack_proposal.v1";

    /// The target an act on one row of a catalogue key names, for every row but the key's
    /// vault value row (`oneiron-authority`, `policy_setting::setting_slot_target`; stage
    /// 7a-2). Parts: the row's stored key (`RowKey::encode`). The target is the first 16
    /// bytes.
    SLOT_TARGET = "oneiron.setting.slot_target.v1";

    /// The basis a setting row's projection records while an act a reader of its target
    /// meets does not count in full on this install (`setting/project.rs`, `basis_of`; stage
    /// 7b-2). Parts: the target's act revision; the count of counted acts as a u64; then per
    /// act in hash order, its hash and its count as a u64 (0 in full, 1 a safe move, 2 a safe
    /// move held by this install's own counting).
    PROJECTION_BASIS = "oneiron.setting.projection_basis.v1";
}

legacy_purposes! {}
