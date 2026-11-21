//! Test doors on the checkpoint image (built only with `--cfg oneiron_test_support`).

use super::*;

impl AuthorityCheckpointV2 {
    /// The slip issuers this image's sequence index holds, for a test that
    /// compares two images built over the same rows.
    pub(crate) fn slip_issuers_for_test(&self) -> BTreeSet<AuthorityKey> {
        self.safety.issuers.clone()
    }

    /// The rows this image keeps as roster marks, for a test that compares
    /// two images built over the same rows.
    pub(crate) fn roster_marks_for_test(&self) -> BTreeSet<AuthorityEntryHash> {
        self.safety.marks.iter().map(|(hash, _)| *hash).collect()
    }

    /// The rows this image's restrictive facts were proved on, for a test
    /// that compares two images built over the same rows.
    pub(crate) fn revoke_fact_rows_for_test(&self) -> BTreeSet<AuthorityEntryHash> {
        self.safety.revoke_facts.rows_for_test()
    }

    /// The federation confirm ids and nonces this image's safety index
    /// holds, for a test that compares two images built over the same rows.
    pub(crate) fn confirm_keys_for_test(&self) -> (BTreeSet<[u8; 32]>, BTreeSet<[u8; 16]>) {
        (
            self.safety.confirm_ids.clone(),
            self.safety.confirm_nonces.clone(),
        )
    }
}
