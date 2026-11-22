//! Purposes of the policy model (`oneiron-records`' `policy_model` and
//! `crates/oneiron/src/policy_model`).

purposes! {}

legacy_purposes! {
    /// A hosted legal policy's hash (`policy_model::planes`,
    /// `HostedLegalPolicy::derive_policy_hash`). SHA-256: the tag; per field its label, a
    /// NUL, the value's length (a u64, big-endian), the value and `0xff`, for the
    /// jurisdiction, the version, the output contract (`none` for none) and the policy
    /// document; the row count, framed the same way with no value; per row its ref,
    /// category, action, text, basis kind, basis subject and basis reference; the pattern
    /// rule count; per rule its id, pattern, category and role. Lowercase hex, it is the
    /// policy's `policy_hash` in the relay registry, and every verdict read and attestation
    /// names it and is compared with it (`policy_model::verdict`).
    HOSTED_LEGAL_POLICY = (Sha256, HashedFirst, "oneiron.policy_model.hosted_legal.policy.v3");
}
