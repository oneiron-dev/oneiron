//! The live half of a step's read context (FIX 6352): what the step's result
//! reads see of reader state, kept for the step's replay context as each
//! read sees it, at the step's bridge position. A reader child's binding is
//! kept from the step's start. Whether its job is live is kept at each read
//! of its source. A parent's settled findings are kept at each lookup of a
//! handle that names none of its own results. The fold receipt, or none, of
//! each whole result the guest describes is kept as its card carries it:
//! this step's staged receipt first, then the committed one. The door's row
//! check on each read of another run's result is kept with the reference
//! the read was made by, withheld and refused reads too. Each answer kept is
//! the one the read goes on.

use super::*;
use crate::code_run::{CapturedReaderChild, ReaderRoute, RetainedReadVerdict, vault_ref};

/// The reader binding `gated_write` holds for run `run`, when the run is a
/// reader child: its job's task and claimed generation, its route, the
/// source its parent delegated and a scoped child's lent inputs by name.
pub(super) fn captured_reader_child(
    gated_write: &GatedActorWrite<'_>,
    run: EntityId,
) -> Option<CapturedReaderChild> {
    let child = gated_write.reader_child()?;
    Some(CapturedReaderChild {
        task: child.task,
        generation: child.generation,
        run,
        route: ReaderRoute {
            vault: vault_ref(gated_write.vault_id()),
            session_ref: gated_write.session_ref().map(str::to_owned),
            participant: gated_write.participant(),
        },
        source: child.source.clone(),
        inputs: child.scoped.as_ref().map(|spec| spec.inputs.clone()),
    })
}

impl RecordingJsHost<'_, '_> {
    /// Whether the bound reader child's job is live now, kept at the step's
    /// bridge position.
    pub(super) fn observe_reader_job_live(&mut self) -> Result<bool> {
        let live = self.gated_write.reader_job_live()?;
        self.context_capture
            .reader_reads
            .observe_job_live(self.next_seq, live);
        Ok(live)
    }

    /// The settled finding of one of the run's children that `reference`
    /// names, read with every settled finding the run's finding index
    /// selects now, which is kept at the step's bridge position.
    pub(super) fn observe_settled_finding(
        &mut self,
        storage: &ExecutorStorage<'_>,
        reference: &str,
    ) -> Result<Option<ReaderFindingRef>> {
        let selection = storage.reader_finding_selection(self.run_id)?;
        let finding = selection.select(reference).map(|held| held.finding.clone());
        self.context_capture
            .reader_reads
            .observe_findings(self.next_seq, selection);
        Ok(finding)
    }

    /// Keeps the answer the door's row check gave a read of another run's
    /// result by `reference`, under the run's callable rows when `callable`,
    /// at the step's bridge position: admitted, withheld, or the code of the
    /// refusal it named (FIX 6352).
    pub(super) fn observe_retained_read(
        &mut self,
        reference: &JsResultRef,
        callable: bool,
        answer: std::result::Result<bool, &str>,
    ) {
        self.context_capture.reader_reads.observe_retained_read(
            self.next_seq,
            reference,
            callable,
            RetainedReadVerdict::of(answer),
        );
    }

    /// The fold receipt the card of `read`, a whole result, carries: this
    /// step's staged receipt of its occurrence, else the committed one, while
    /// the receipt names the result's handle. The receipt, or that there is
    /// none, is kept.
    pub(super) fn whole_fold_receipt(
        &mut self,
        storage: &ExecutorStorage<'_>,
        read: &ResultRead,
    ) -> Result<Option<ReaderFoldReceipt>> {
        let output = read.output();
        let occurrence = OccurrenceRef::new(read.owner(), &output.path, &output.handle)?;
        let staged = self
            .receipts
            .iter()
            .find(|held| held.folded.occurrence == occurrence.occurrence)
            .cloned();
        let receipt = match staged {
            Some(receipt) => Some(receipt),
            None => storage.code_run_reader_fold(read.owner(), &output.path)?,
        }
        .filter(|receipt| receipt.folded.handle == output.handle);
        self.context_capture
            .reader_reads
            .keep_fold_card(occurrence, receipt.as_ref());
        Ok(receipt)
    }
}
