//! Fold receipts computed from the reader jobs and result ranges of a run.
//! Entry: `RecordingJsHost::fold_receipt`.
//! `ReaderFoldReceipt` is defined by `code_run`; host state stays in `engine_executor::host`.

use super::*;

/// The longest recipe a fold's `store` may name for its receipt, as JSON.
pub(super) const RECEIPT_RECIPE_MAX_BYTES: usize = 4096;

impl RecordingJsHost<'_, '_> {
    /// The fold receipt `input` names, computed here from the jobs it names
    /// (ARCH-0079 #reader-forks): its source resolved and read-checked, each
    /// task this run's child over that source, `read` the ranges of the done
    /// ones, `partial` the ones that settled short, with their reasons,
    /// `unread` the source's range less both, and each summary of its tree
    /// resolved as a read of it is. Its `folded` occurrence is filled in once
    /// the body is stored. Beside it, every occurrence it names, whose taint
    /// the folded body inherits. A refusal is the reply the guest gets.
    pub(super) fn fold_receipt(
        &mut self,
        storage: &ExecutorStorage<'_>,
        input: &StoreReceiptInput,
    ) -> Result<
        std::result::Result<
            (ReaderFoldReceipt, Vec<(EntityId, CodeRunRawOutput)>),
            serde_json::Value,
        >,
    > {
        let mut named: Vec<(EntityId, CodeRunRawOutput)> = Vec::new();
        let mut occurrence_of = |owner: EntityId, output: &CodeRunRawOutput| {
            named.push((owner, output.clone()));
            OccurrenceRef::new(owner, &output.path, &output.handle)
        };
        let (source, _) = match self.checked_read(&JsResultTarget::parse(&input.source))? {
            Ok(read) => read,
            Err(refused) => return Ok(Err(refused)),
        };
        let source_range = source.range().unwrap_or((0, source.output().raw_len));
        let source = ReceiptSource {
            occurrence: occurrence_of(source.owner(), source.output())?,
            range: source_range,
        };
        let cutoff_unix_ms = storage
            .reader_parent(self.run_id)?
            .map_or(0, |parent| parent.deadline.child_cutoff());
        let mut findings = Vec::with_capacity(input.tasks.len());
        let (mut read, mut partial, mut short) = (Vec::new(), Vec::new(), Vec::new());
        for task in &input.tasks {
            let Ok(task) = EntityId::from_hex(task) else {
                return Ok(Err(result_refusal("receipt_invalid_task")));
            };
            let Some(job) = storage
                .reader_job(task)?
                .filter(|job| job.binding.parent_run == self.run_id)
            else {
                return Ok(Err(result_refusal("receipt_task_not_own")));
            };
            let delegated = &job.binding.source;
            let (start, end) = delegated.range;
            if job.kind != ReaderJobKind::Read
                || delegated.owner != source.occurrence.owner
                || delegated.path != source.occurrence.path
                || start < source_range.0
                || end > source_range.1
            {
                return Ok(Err(result_refusal("receipt_task_other_source")));
            }
            let occurrence = match &job.finding {
                Some(finding) => {
                    match recorded_output(storage, finding.owner, &finding.path, &finding.handle)? {
                        Some(output) => Some(occurrence_of(finding.owner, &output)?),
                        None => None,
                    }
                }
                None => None,
            };
            let reason = match &job.state {
                ReaderJobState::Done if occurrence.is_some() => {
                    read.push(delegated.range);
                    None
                }
                ReaderJobState::Partial { reason } if occurrence.is_some() => {
                    short.push(delegated.range);
                    partial.push(ReceiptPartial {
                        task,
                        reason: reason.clone(),
                    });
                    Some(reason.clone())
                }
                ReaderJobState::Partial { reason } | ReaderJobState::Failed { reason } => {
                    Some(reason.clone())
                }
                _ => None,
            };
            findings.push(ReceiptFinding {
                task,
                occurrence,
                state: job.state.word().to_owned(),
                reason,
                range: delegated.range,
            });
        }
        let mut tree = Vec::with_capacity(input.tree.len());
        for node in &input.tree {
            let mut refs = Vec::with_capacity(node.inputs.len() + 1);
            for reference in std::iter::once(&node.summary).chain(&node.inputs) {
                match self.checked_read(&JsResultTarget::parse(reference))? {
                    Ok((found, _)) => refs.push(occurrence_of(found.owner(), found.output())?),
                    Err(refused) => return Ok(Err(refused)),
                }
            }
            let summary = refs.remove(0);
            tree.push(ReceiptTree {
                summary,
                inputs: refs,
            });
        }
        if input
            .recipe
            .as_ref()
            .is_some_and(|recipe| recipe.to_string().len() > RECEIPT_RECIPE_MAX_BYTES)
        {
            return Ok(Err(result_refusal("receipt_recipe_too_large")));
        }
        let read = merge_ranges(read);
        let covered = merge_ranges(read.iter().copied().chain(short).collect());
        let unread = subtract_ranges(source_range, &covered);
        let mut taint: Vec<OccurrenceRef> = Vec::new();
        for (owner, output) in &named {
            let occurrence = OccurrenceRef::new(*owner, &output.path, &output.handle)?;
            if !taint
                .iter()
                .any(|held| held.occurrence == occurrence.occurrence)
            {
                taint.push(occurrence);
            }
        }
        let substrate_ref = ReaderSubstrateRef {
            source: source.occurrence.clone(),
            findings: findings
                .iter()
                .filter_map(|finding| finding.occurrence.clone())
                .collect(),
        };
        let receipt = ReaderFoldReceipt {
            // Filled in once the folded body is stored.
            folded: source.occurrence.clone(),
            source,
            findings,
            read,
            unread,
            partial,
            cutoff_unix_ms,
            recipe: input.recipe.clone(),
            tree,
            taint,
            substrate_ref,
            unresolved: Vec::new(),
        };
        Ok(Ok((receipt, named)))
    }
}

/// `ranges` sorted and merged where they touch or overlap.
pub(super) fn merge_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.retain(|(start, end)| start < end);
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// What of `whole` the merged `covered` ranges leave.
pub(super) fn subtract_ranges(whole: (u64, u64), covered: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut left = Vec::new();
    let mut at = whole.0;
    for &(start, end) in covered {
        if end <= at || start >= whole.1 {
            continue;
        }
        if start > at {
            left.push((at, start.min(whole.1)));
        }
        at = at.max(end);
    }
    if at < whole.1 {
        left.push((at, whole.1));
    }
    left
}
