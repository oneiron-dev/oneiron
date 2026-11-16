//! The commitment substrate's owner Setting key (DESIGN 15-setting-primitive; restriction wave
//! 16, C120): the longest promise text a door that authors a promise admits. The crate's build
//! script lists the row in the setting catalogue. Default = today: nothing changes until the
//! owner sets the key.
//!
//! The key binds where text is authored: `vault.commitments.create` and a series edit, the
//! generic claim commit, an import batch, a docs deep review and an e-sign draft's terms. A
//! status change, a lapse sweep, a series occurrence and a synced or restored row carry text that
//! was admitted when it was written, so a lowered key strands no stored promise. Encode and decode
//! check only [`COMMITMENT_TEXT_CEILING_BYTES`], the key's top.

use rmpv::Value;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::types::{COMMITMENT_TEXT_CEILING_BYTES, COMMITMENT_TEXT_DEFAULT_MAX_BYTES};
use super::{CommitmentRecord, PREDICATE_COMMITMENT_RECORD, decode_commitment_value};
use crate::setting::{Kind, SettingValue, lower_is_tighter};
use crate::{Error, Result, Vault};

/// The `commitment.content.max_text_bytes` value: the longest promise text, in bytes, a door
/// that authors a promise admits. From one byte to [`COMMITMENT_TEXT_CEILING_BYTES`]; a larger
/// value is the looser one.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct CommitmentTextMaxBytes(pub(crate) u32);

impl SettingValue for CommitmentTextMaxBytes {
    fn check(self) -> Result<Self> {
        let bytes = usize::try_from(self.0).unwrap_or(usize::MAX);
        if bytes == 0 || bytes > COMMITMENT_TEXT_CEILING_BYTES {
            Err(Error::InvalidConfig(format!(
                "a promise's longest text is from 1 to {COMMITMENT_TEXT_CEILING_BYTES} bytes"
            )))
        } else {
            Ok(self)
        }
    }
}

/// 8,192 bytes: the longest promise text before the bound became a key.
fn default_text_max_bytes() -> CommitmentTextMaxBytes {
    CommitmentTextMaxBytes(u32::try_from(COMMITMENT_TEXT_DEFAULT_MAX_BYTES).unwrap_or(u32::MAX))
}

crate::setting::setting_keys! {
    /// The longest promise text, in bytes, a new or edited commitment may carry (default 8,192;
    /// at most 65,536). A longer one is refused where it is written: `vault.commitments.create`,
    /// a series edit, the generic claim commit, an import or docs review batch, an e-sign draft's
    /// terms. A promise already stored keeps its text through every later status change whatever
    /// the key says. A larger value is looser, so only the owner raises it; an agent's raise waits
    /// on the owner's answer.
    pub(crate) COMMITMENT_TEXT_MAX_BYTES: CommitmentTextMaxBytes = "commitment.content.max_text_bytes" {
        kind: Kind::new(default_text_max_bytes)
            .strictest(default_text_max_bytes)
            .tighter(lower_is_tighter::<CommitmentTextMaxBytes>),
    };
}

impl Vault {
    /// Refuses `record` when its promise text is longer than the owner's
    /// `commitment.content.max_text_bytes` in this transaction's snapshot: the owner's row, a key
    /// holder's tighter row within it, or the default when none stands. Only a door that authors
    /// the text calls it.
    ///
    /// # Errors
    ///
    /// `InvalidClaimBody` for text past the bound; storage errors.
    pub(crate) fn check_commitment_text_in_force_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        record: &CommitmentRecord,
    ) -> Result<()> {
        let max = COMMITMENT_TEXT_MAX_BYTES
            .read_in_txn(self, txn, &[], None)?
            .value;
        record
            .content
            .check_text_within(usize::try_from(max.0).unwrap_or(usize::MAX))
    }

    /// [`Self::check_commitment_text_in_force_in_txn`] for a claim value a generic door is about
    /// to write: a `commitment.record` value is decoded and checked; any other predicate passes.
    ///
    /// # Errors
    ///
    /// A `commitment.record` value that does not decode, or whose text is past the bound;
    /// storage errors.
    pub(crate) fn check_claim_commitment_text_in_force_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        predicate: &str,
        value: &Value,
    ) -> Result<()> {
        if predicate != PREDICATE_COMMITMENT_RECORD {
            return Ok(());
        }
        self.check_commitment_text_in_force_in_txn(txn, &decode_commitment_value(value)?)
    }
}
