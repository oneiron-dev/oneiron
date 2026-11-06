//! The physical LABELS row a scoped consumer judges in its own snapshot.

use super::{JudgeLabel, LABELS};
use crate::{Error, Result, Vault};

/// A canonical inline row, not a read grant. The constructor binds the
/// decoded label to its physical ask key and retains the full stored bytes.
pub(crate) struct CanonicalJudgeLabel {
    key: Vec<u8>,
    body: Vec<u8>,
    label: JudgeLabel,
}

impl CanonicalJudgeLabel {
    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn label(&self) -> &JudgeLabel {
        &self.label
    }

    pub(crate) fn into_label(self) -> JudgeLabel {
        self.label
    }
}

/// Reads the actual native family/key/body in `txn`; admission remains the
/// scoped consumer's job. The bytes are never reserialized as a witness.
pub(crate) fn canonical_judge_label_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ask_id: &[u8; 32],
) -> Result<Option<CanonicalJudgeLabel>> {
    let Some(body) = LABELS.get_bytes(&vault.store, txn, ask_id)? else {
        return Ok(None);
    };
    let label = LABELS.decode_value(&body)?;
    if label.ask.id != *ask_id {
        return Err(Error::CorruptedIndex("judge label identity"));
    }
    Ok(Some(CanonicalJudgeLabel {
        key: LABELS.key_bytes(ask_id),
        body,
        label,
    }))
}
