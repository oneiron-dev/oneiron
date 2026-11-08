//! The side tables `policy_model` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Owner policy-row change event. Key: event id.
    OWNER_POLICY_CHANGE_EVENT: VaultMeta b"owner_policy:change:event:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Receipt of one owner change to the secret-scan switch, in revision order. Key: u64be
    /// revision.
    OWNER_POLICY_SECRET_SCAN_RECEIPT: VaultMeta b"owner_policy:secret_scan:receipt:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Receipt of one owner change to a world's privacy settings on this machine, in revision
    /// order. Key: u64be revision.
    OWNER_POLICY_WORLD_PRIVACY_RECEIPT: VaultMeta b"owner_policy:world_privacy:receipt:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// An agent's world-privacy proposal or a widen ask, frozen, with its settlement (FIX 4480).
    /// Key: request id.
    OWNER_POLICY_WORLD_PRIVACY_REQUEST: VaultMeta b"owner_policy:world_privacy:request:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The "widen needs every owner" row: the vault's setting and per-world overrides (FIX 4480).
    /// Key: ().
    OWNER_POLICY_WORLD_PRIVACY_UNANIMITY: VaultMeta b"owner_policy:world_privacy:unanimity:v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// A "widen needs every owner" change that turns it off while on, waiting for every live
    /// Owner's yes, with its settlement (FIX 4480). Key: request id.
    OWNER_POLICY_WORLD_PRIVACY_UNANIMITY_OFF: VaultMeta b"owner_policy:world_privacy:unanimity_off:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// A device-local held policy-classification item pending human moderation. Key: hex64 (blake3
    /// hash of caller/row/content-hash/frontier-hash).
    POLICY_HOLD_QUEUE: VaultMeta b"policy-hold:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
}
