//! Staging authority rows with each arriving ReRoot judged against the fold
//! before it (pass 27 R4).

use super::*;
use crate::authority::{readonly_fold, recovery};

impl Vault {
    /// Stages `rows` in their order in `txn`. Before each arriving ReRoot (a
    /// row carrying it, [`recovery::arriving_re_root`]) its signer is judged
    /// against the fold of the rows staged before it
    /// ([`recovery::ArrivingReRoot::refuse_on`]), so the
    /// signed-history import and the authority-log puts refuse what the ReRoot
    /// writer refuses. A gap-closing batch has no fold before its rows; the
    /// fold rule judges them (OF-469). With no arriving ReRoot the rows stage
    /// as one batch. Each row's store door reads the fold beside `beside`,
    /// every row the batch carries, as the batch's preflight did
    /// (owner-reserve delta review F2, #8360).
    pub(in crate::authority) fn stage_authority_rows_judging_re_roots_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        rows: Vec<(BatchOp, Option<recovery::ArrivingReRoot>)>,
        beside: crate::store::authority_rows::RowsBeside<'_>,
    ) -> Result<()> {
        let mut segment = Vec::with_capacity(rows.len());
        for (op, re_root) in rows {
            if let Some(re_root) = re_root {
                if !segment.is_empty() {
                    self.stage_authority_ops_in_txn(txn, std::mem::take(&mut segment), beside)?;
                }
                match self.authority_fold_readonly_in_txn(txn) {
                    Ok(fold) => re_root.refuse_on(&fold)?,
                    Err(error) if readonly_fold::is_history_incomplete(&error) => {}
                    Err(error) => return Err(error),
                }
            }
            segment.push(op);
        }
        self.stage_authority_ops_in_txn(txn, segment, beside)
    }

    fn stage_authority_ops_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        ops: Vec<BatchOp>,
        beside: crate::store::authority_rows::RowsBeside<'_>,
    ) -> Result<()> {
        apply_ops_beside_authority_rows(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
            beside,
        )
    }
}
