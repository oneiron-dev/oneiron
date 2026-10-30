//! The judge a kept score was measured by (FIX 8846). A cached offline
//! preflight and a kept live goal-axis report each bind the scorer's
//! immutable judge revision and the digest of the judge rubric in force, so
//! a new judge or a revised rubric is measured again, never served the
//! scores the old one gave.
use super::*;
use serde::{Deserialize, Serialize};

/// The judge and rubric identities one kept score was taken under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct JudgeBinding {
    /// The scorer's candidate-scoring judge revision.
    pub(super) judge_revision: String,
    /// BLAKE3 of the judge rubric's text; `None` while no rubric is in force.
    pub(super) rubric: Option<[u8; 32]>,
}

impl JudgeBinding {
    /// The binding a score taken now by `judge_revision` carries.
    /// # Errors
    /// An unreadable rubric revision, or storage errors.
    pub(super) fn in_txn(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        judge_revision: &str,
    ) -> Result<Self> {
        Ok(Self {
            judge_revision: judge_revision.to_owned(),
            rubric: crate::skill_optimize::labels::judge_rubric_in_txn(vault, txn)?
                .map(|rubric| rubric.digest),
        })
    }
}

/// The pin of the judge rubric in force in `txn`, as a verdict records it
/// beside its judge revision (FIX 3585): the rubric text's BLAKE3, lower hex;
/// `None` while no rubric is in force.
/// # Errors
/// An unreadable rubric revision, or storage errors.
pub(super) fn judge_rubric_digest_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<String>> {
    Ok(crate::skill_optimize::labels::judge_rubric_in_txn(vault, txn)?
        .map(|rubric| bytes_to_hex_lower(&rubric.digest)))
}
