//! A crash-retry of a live code edit whose replacement landed masked (FIX
//! 21363, the residual of FIX 2372). The operation, its stamp and its ingress
//! receipt hold each secret's handle, and the retry offers the value again.
//! A handle alone binds no value: a custody rotation keeps the handle and
//! names a new value, and the known-value index still matches every value a
//! record once held under its current handle. So the receipt keeps, from the
//! edit's landing, the custody record each handle names and its rotation
//! generation (ids and counters, never a value's fingerprint: KS-3), and a
//! replay proves the offered edit the same by re-admitting it as a plan alone,
//! in the writer, against exactly those records' entries at those
//! generations, while every one of those records still stands, live, at its
//! generation.

use std::sync::Arc;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::super::CodeFileEdit;
use super::ReceiptRow;
use super::edit::EditAdmission;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_custody::{
    SecretCustodyStatus, handle_record_in_txn, read_secret_custody_admission_in_txn,
};
use crate::store::Store;
use crate::store::known_value_index::KnownValues;

/// How a handle stands in text: `[secret sc12]` where a secret was.
const HANDLE_OPEN: &str = "[secret ";

/// One custody record a masked edit's replacement names, as it stood when
/// the edit landed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReceiptCustody {
    /// The custody record a handle names.
    record: EntityId,
    /// The record's rotation generation.
    generation: u32,
}

/// Each custody record a handle in `text` names, once, in the order the
/// handles stand, with its generation and status as `txn` reads them. A
/// handle that names no record is the text's own and names none.
fn named_custody_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    text: &str,
) -> Result<Vec<(ReceiptCustody, SecretCustodyStatus)>> {
    let mut named: Vec<(ReceiptCustody, SecretCustodyStatus)> = Vec::new();
    for handle in text_handles(text) {
        let record = match handle_record_in_txn(store, txn, handle) {
            Ok((_, record)) => record,
            Err(Error::Secret(_)) => continue,
            Err(error) => return Err(error),
        };
        if named.iter().any(|(held, _)| held.record == record) {
            continue;
        }
        let Some(held) = read_secret_custody_admission_in_txn(store, txn, &record)? else {
            continue;
        };
        named.push((
            ReceiptCustody {
                record,
                generation: held.rotation_generation,
            },
            held.status,
        ));
    }
    Ok(named)
}

/// Each handle `text` holds in its text form, in the order they stand: where
/// an admission lifted a secret, or a handle the text was written with. A
/// bracketed span that is no handle is the text's own.
fn text_handles(text: &str) -> Vec<&str> {
    let mut handles = Vec::new();
    let mut at = 0;
    while let Some(open) = text[at..].find(HANDLE_OPEN).map(|found| at + found) {
        let Some(close) = text[open..].find(']').map(|found| open + found + 1) else {
            break;
        };
        let handle = &text[open..close];
        if crate::secret_custody::parse_secret_handle(handle).is_ok() {
            handles.push(handle);
            at = close;
        } else {
            // An opener that is no handle may wrap one (`[secret note
            // [secret sc1]`): only the opener is stepped past.
            at = open + HANDLE_OPEN.len();
        }
    }
    handles
}

/// Whether `offered` is `stored` in every field but its replacement.
fn same_but_replacement(stored: &CodeFileEdit, offered: &CodeFileEdit) -> bool {
    let CodeFileEdit {
        path,
        start,
        end,
        expected,
        replacement: _,
        new_path,
    } = offered;
    *path == stored.path
        && *start == stored.start
        && *end == stored.end
        && *expected == stored.expected
        && *new_path == stored.new_path
}

impl Vault {
    /// The binding an ingress receipt keeps for `offered`, an edit whose
    /// replacement its admission changed to `admitted` in the landing writer:
    /// each record the admitted handles name, once, with its generation, when
    /// the offered replacement plans to exactly `admitted` against those
    /// records' entries at those generations. Otherwise none: a value that
    /// matched a record's earlier entry is not one a retry can prove, and
    /// such a retry refuses as before.
    ///
    /// # Errors
    /// A store failure.
    pub(super) fn landing_custody_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        document: &[u8; 32],
        offered: &CodeFileEdit,
        admitted: &CodeFileEdit,
    ) -> Result<Vec<ReceiptCustody>> {
        let bound: Vec<ReceiptCustody> =
            named_custody_in_txn(&self.store, wtxn, &admitted.replacement)?
                .into_iter()
                .map(|(custody, _)| custody)
                .collect();
        if bound.is_empty() || !self.plans_to_in_txn(wtxn, document, &bound, offered, admitted)? {
            return Ok(Vec::new());
        }
        Ok(bound)
    }

    /// Whether `offered`'s replacement, admitted in this writer as a plan
    /// alone against exactly the entries `bound` names, is `admitted`: each
    /// value it holds is the one its record held at the bound generation,
    /// and no other value that record ever held. The plan mints and writes
    /// nothing; the planned copy, which holds handles, is wiped.
    fn plans_to_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        document: &[u8; 32],
        bound: &[ReceiptCustody],
        offered: &CodeFileEdit,
        admitted: &CodeFileEdit,
    ) -> Result<bool> {
        let entries: Vec<(EntityId, u32)> = bound
            .iter()
            .map(|custody| (custody.record, custody.generation))
            .collect();
        let Some(known) = KnownValues::load_entries_in_writer(&self.store, wtxn, &entries)? else {
            return Ok(false);
        };
        let planned = self.admit_code_edit_in_txn(
            wtxn,
            document,
            offered,
            EditAdmission::Plan(Arc::new(known)),
        );
        let mut planned = match planned {
            Ok(Some(planned)) => planned,
            Ok(None) | Err(Error::Gate(_)) => return Ok(false),
            Err(error) => return Err(error),
        };
        let same = planned == *admitted;
        planned.replacement.zeroize();
        Ok(same)
    }

    /// Whether `offered`, the edit a retry offers under the operation id of
    /// `receipt`, is the edit that receipt landed: the same bytes, or, for an
    /// edit whose replacement landed masked, the same edit in every field but
    /// its replacement, whose replacement this writer re-admits, as a plan
    /// that mints and writes nothing against exactly the bound records'
    /// entries at their bound generations, to exactly the stored edit, while
    /// each record the receipt binds is still the one its handle names, not
    /// revoked, at the generation it landed at. Any other secret, and any
    /// other value a bound record once held, is no match. Only the stored and
    /// the re-admitted edits, which hold handles, are compared; the
    /// re-admitted copy is wiped.
    ///
    /// # Errors
    /// A store failure.
    pub(super) fn replays_code_edit_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        receipt: &ReceiptRow,
        offered: &CodeFileEdit,
    ) -> Result<bool> {
        if receipt.edit == *offered {
            return Ok(true);
        }
        if receipt.custody.is_empty() || !same_but_replacement(&receipt.edit, offered) {
            return Ok(false);
        }
        let named = named_custody_in_txn(&self.store, wtxn, &receipt.edit.replacement)?;
        if named.len() != receipt.custody.len()
            || named
                .iter()
                .zip(&receipt.custody)
                .any(|((held, status), bound)| {
                    *status == SecretCustodyStatus::Revoked || held != bound
                })
        {
            return Ok(false);
        }
        self.plans_to_in_txn(
            wtxn,
            &receipt.after.document_id,
            &receipt.custody,
            offered,
            &receipt.edit,
        )
    }
}
