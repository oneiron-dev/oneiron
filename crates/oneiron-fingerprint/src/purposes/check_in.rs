//! Purposes of a person's check-in effects (`oneiron` `check_in::effect`; ARCH-0082
//! #composing).
//!
//! An effect digest names the exact effect a check-in asks for. The pending check-in
//! stores it (`PendingCheckIn.effect_digest`, in the `CHECK_IN_PENDING` row and its key),
//! and the door that spends an approved ask compares it with the effect it runs. So each
//! keeps its bytes (K, PLAN-UC-04). Every digest is BLAKE3 derive-key with the tag as the
//! context and returns its 32 bytes. This file holds the five effects of the P2.5 delete
//! and security-control doors (2k4, 2k5, 2k5e).

purposes! {}

legacy_purposes! {
    /// An Owner policy row change (`policy_row_change_effect_digest`): the change's
    /// MessagePack encoding with field names (`rmp_serde::to_vec_named`), as the change
    /// ledger keeps it, with no length before it.
    POLICY_ROW_CHANGE = (Blake3, DeriveKeyContext, "oneiron check_in policy row change v1");

    /// Turning org compliance search on or off for a purpose
    /// (`mail_compliance_set_effect_digest`): one byte, 1 to turn it on; the purpose's
    /// length as a u64 big-endian; its bytes.
    MAIL_COMPLIANCE_SET = (Blake3, DeriveKeyContext, "oneiron check_in mail compliance set v1");

    /// Deleting a record for a reason (`record_delete_effect_digest`): the record's 16 id
    /// bytes; the reason's wire token, as its length in one byte and its bytes.
    RECORD_DELETE = (Blake3, DeriveKeyContext, "oneiron check_in record delete v1");

    /// Deleting a stored embedding space probe
    /// (`embedding_space_probe_delete_effect_digest`): the probe's 16 id bytes.
    EMBEDDING_SPACE_PROBE_DELETE =
        (Blake3, DeriveKeyContext, "oneiron check_in embedding space probe delete v1");

    /// Deleting a cleanup-archived completed attempt
    /// (`attempt_archive_delete_effect_digest`): the attempt's 16 id bytes.
    ATTEMPT_ARCHIVE_DELETE =
        (Blake3, DeriveKeyContext, "oneiron check_in attempt archive delete v1");
}
