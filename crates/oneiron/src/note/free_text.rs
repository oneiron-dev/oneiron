//! Free text a NOTE carrier takes from its writer that no door screened
//! before (FIX 2375): a proposal's explainer, and the prose of a semantic
//! command this host queues and sends. Each is admitted as an authored part
//! is (OF-067): each secret the batch door's text rules place goes to
//! custody and the text keeps its handle. A hit no span places leaves the
//! text as it was written, as before, with one warning that names the
//! carrier and how many of its parts hold a hit, and nothing of the text
//! (lead ruling under the Engine's 10-22 rubric: no new refusal).

use crate::Vault;
use crate::batch::secret_scan::{Lifted, Part, admit_parts_in_txn, write_payload_hit};
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};

/// The write door's reason code a hit no span places refuses with.
const DETECTED: &str = "gate.secret_scan.detected";

/// Admits `parts` of `record`'s free text for `carrier` in the writer's
/// transaction, with `lifted` as the write's one plan. Returns whether a part
/// changed. A hit no span places changes no part and is not an error here;
/// every other error is the admission's own.
pub(super) fn admit_free_text_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: EntityId,
    carrier: &'static str,
    parts: &mut [(&str, Part<'_>)],
    lifted: &mut Lifted,
) -> Result<bool> {
    match admit_parts_in_txn(vault, txn, record, parts, lifted) {
        Err(Error::Gate(GateError::GateWriteRejected {
            outcome: "deny",
            reason_codes,
        })) if reason_codes.first() == Some(&DETECTED) => {
            let hits = parts
                .iter()
                .filter(|(_, part)| match part {
                    Part::Text(text) => write_payload_hit(text.as_bytes()).is_some(),
                    Part::Body(bytes) => write_payload_hit(bytes).is_some(),
                })
                .count();
            tracing::warn!(
                carrier,
                hits,
                "free text kept as written: a secret no span places (FIX 2375)"
            );
            Ok(false)
        }
        admitted => admitted,
    }
}
