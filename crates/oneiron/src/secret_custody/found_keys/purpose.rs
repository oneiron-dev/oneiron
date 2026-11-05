//! Purpose questions derive from the existing found-key row, not a second queue.

use heed::RoTxn;

use super::{FOUND, actions};
use crate::error::Result;
use crate::secret_custody::{SecretCustodyStatus, SecretPurposeQuestion};
use crate::store::secret_handle_purpose::PURPOSE;
use crate::{EntityId, Vault};

pub(crate) fn purpose_questions_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    record: &EntityId,
) -> Result<Vec<SecretPurposeQuestion>> {
    let Some(found) = FOUND.get(&vault.store, txn, record)? else {
        return Ok(Vec::new());
    };
    let mut questions = Vec::new();
    for key in found.keys.iter().filter(|key| key.settled.is_none()) {
        if PURPOSE.contains(&vault.store, txn, &key.custody)? {
            continue;
        }
        let Some(origin) =
            crate::batch::secret_scan::mask_origin_in_txn(&vault.store, txn, &key.custody)?
        else {
            continue;
        };
        if origin.record != *record {
            continue;
        }
        let active = crate::secret_custody::read_secret_custody_admission_in_txn(
            &vault.store,
            txn,
            &key.custody,
        )?
        .is_some_and(|row| row.status == SecretCustodyStatus::Active);
        if !active {
            continue;
        }
        let card = actions::card_in_txn(vault, txn, record, key)?;
        questions.push(SecretPurposeQuestion {
            record: *record,
            handle: card.handle,
            name: card.name,
            label: card.label,
            suggested_label: card.suggested_label,
            kind: card.kind,
            place: card.place,
            found_at: card.found_at,
        });
    }
    Ok(questions)
}
