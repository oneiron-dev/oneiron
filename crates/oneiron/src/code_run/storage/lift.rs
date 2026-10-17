//! The S7 backfill (OF-067, Engine ruling D = a). A result body stored
//! before its scan marked hits keeps its bytes, as a new one does; the
//! historical lift sweep reads it again with the scan a new body gets, and a
//! hit marks each occurrence of it, as the store marks a new one. The mark
//! redacts each occurrence's views, nulls it in an export and files its lift
//! proposal (`code_run_secret_lift_proposals`).

use heed::{RoTxn, RwTxn};

use super::super::replay::{CodeRunRawOutput, ResultOccurrence};
use super::super::support::CODE_RUN_OUTPUT_HANDLE_PREFIX;
use super::records::{RAW_OUTPUT_SECRETS, RAW_OUTPUTS, StoredBody, open_body_file};
use crate::compaction::output::OutputRef;
use crate::store::{BodyMeter, read_body_range};
use crate::{Error, Result, Vault};

/// Bytes the backfill reads of a body file at a time.
const LIFT_READ_FRAME: usize = 1 << 20;

impl Vault {
    /// The scan's hit in the stored body `handle` names, when no occurrence
    /// of it carries the scan's mark: a body stored before the mark was.
    pub(crate) fn code_run_output_lift_hit_in_txn(
        &self,
        txn: &RoTxn<'_>,
        handle: &str,
    ) -> Result<Option<&'static str>> {
        Ok(self
            .unmarked_code_run_output_in_txn(txn, handle)?
            .map(|(_, hit)| hit))
    }

    /// Marks each occurrence of the body `handle` names with the scan's hit,
    /// in the caller's transaction: each run's that holds it, or the bytes'
    /// own when no run does. The body, its taint and its replay records stay
    /// as they are. The hit's reason, or `None` when nothing is left to mark.
    pub(crate) fn lift_code_run_output_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        handle: &str,
    ) -> Result<Option<&'static str>> {
        let Some((output, reason)) = self.unmarked_code_run_output_in_txn(txn, handle)? else {
            return Ok(None);
        };
        let mut occurrences = Vec::new();
        for (run, outputs) in self.code_run_result_manifests_in_txn(txn)? {
            for held in outputs.iter().filter(|held| held.handle == handle) {
                occurrences.push(ResultOccurrence::of(Some(run), held)?);
            }
        }
        if occurrences.is_empty() {
            occurrences.push(ResultOccurrence::of(None, &output)?);
        }
        for at in occurrences {
            RAW_OUTPUT_SECRETS.put(&self.store, txn, &at.mark_key(handle), &reason.to_owned())?;
        }
        Ok(Some(reason))
    }

    /// [`Self::scanned_code_run_output_in_txn`] for a body no occurrence of which
    /// carries the scan's mark.
    fn unmarked_code_run_output_in_txn(
        &self,
        txn: &RoTxn<'_>,
        handle: &str,
    ) -> Result<Option<(CodeRunRawOutput, &'static str)>> {
        let prefix = ResultOccurrence::marks_prefix(handle);
        let marked = RAW_OUTPUT_SECRETS
            .iter_from(&self.store, txn, prefix.as_bytes())?
            .next()
            .transpose()?
            .is_some();
        if marked {
            return Ok(None);
        }
        self.scanned_code_run_output_in_txn(txn, handle)
    }

    /// The stored body `handle` names, read through the scan a new body
    /// gets and checked against its digest and length: its manifest and the
    /// scan's hit, if it has one.
    fn scanned_code_run_output_in_txn(
        &self,
        txn: &RoTxn<'_>,
        handle: &str,
    ) -> Result<Option<(CodeRunRawOutput, &'static str)>> {
        let Some(digest) = handle_digest(handle) else {
            return Ok(None);
        };
        let Some(body) = RAW_OUTPUTS.get(&self.store, txn, &handle.to_owned())? else {
            return Ok(None);
        };
        let _pin = self.pin_result_body(digest);
        let mut meter = BodyMeter::new();
        let len = match body {
            StoredBody::Inline(bytes) => {
                meter.feed(&bytes);
                bytes.len() as u64
            }
            StoredBody::File { len } => {
                let output = CodeRunRawOutput::of_ref(OutputRef {
                    hash: digest,
                    byte_len: len,
                });
                let file = open_body_file(&output, vec![self.store.body_dir()?])?;
                let mut offset = 0_u64;
                while offset < len {
                    let take = usize::try_from((len - offset).min(LIFT_READ_FRAME as u64))
                        .map_err(|_| Error::ArithmeticOverflow("code-run result body length"))?;
                    meter.feed(&read_body_range(&file, offset, take)?);
                    offset += take as u64;
                }
                len
            }
        };
        let facts = meter.finish(0);
        if facts.digest != digest || facts.len != len {
            return Err(Error::CorruptedIndex("a code-run result body drifted"));
        }
        let output = CodeRunRawOutput::of_ref(OutputRef {
            hash: digest,
            byte_len: len,
        });
        Ok(facts.secret.map(|hit| (output, hit)))
    }
}

/// The digest a body's handle names.
fn handle_digest(handle: &str) -> Option<[u8; 32]> {
    let hex = handle.strip_prefix(CODE_RUN_OUTPUT_HANDLE_PREFIX)?;
    if hex.len() != 64 {
        return None;
    }
    let mut digest = [0; 32];
    for (byte, pair) in digest.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(digest)
}
