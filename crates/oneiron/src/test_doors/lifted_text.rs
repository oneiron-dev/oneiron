//! Doors for `tests/primitive_a_evidence_spans.rs` (FIX-LIST
//! EVIDENCE-SPANS-MASKED-COORDINATES): a lifted key seeded in a record's
//! stored text, as the lift sweep leaves one in a carrier's text.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Marks each place the stored text `text` of record `record` holds `value`
/// as a lifted key under the text's hash, as the lift sweep marks a carrier's
/// text: `value` goes to its own custody record and the text keeps its
/// bytes. The vault owner reads `text` as stored; every other reader reads
/// each place as the returned handle (`[secret sc..]`).
pub fn mark_lifted_key(vault: &Vault, record: EntityId, text: &str, value: &str) -> Result<String> {
    let mut wtxn = vault.store.env.write_txn()?;
    let handle = crate::batch::secret_scan::mark_text_value_in_txn(
        vault,
        &mut wtxn,
        record,
        "text:content",
        text,
        value,
    )?;
    wtxn.commit()?;
    Ok(handle)
}
