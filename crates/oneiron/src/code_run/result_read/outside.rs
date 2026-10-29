//! Reads of a code run's results for a caller outside the run: the cards
//! of its named results, and one read of one of them through the MCP door.
//! Each is read over the storage the run's rows are in: the vault's for a
//! canonical run, its session's for one bound to an off-record session
//! (FIX 4284), which never reads a room's run through the vault.

use super::{
    CodeRunRawOutput, CodeRunReplayRecord, CodeRunResultBinding, EntityId, ExecutorStorage,
    JsResultTarget, Result, ResultFacet, ResultRead, Value, Vault, card, is_result_output_path,
    refusal, resolve, unknown_handle,
};

impl Vault {
    /// The cards of a code run's named results, newest first and at most
    /// `limit` of them, and how many names it has: for a caller outside the
    /// run, who releases them under the run's own checks. A card shows a
    /// preview and a shape only of a clean body, and no guest read path.
    pub fn code_run_result_cards(
        &self,
        record: &CodeRunReplayRecord,
        limit: usize,
    ) -> Result<(Vec<Value>, usize)> {
        result_cards_in(&ExecutorStorage::Canonical(self), record, 0, limit)
    }

    /// One read of a code run's result for a caller outside the run (the
    /// MCP door): its card when `facet` is `None`, else that facet of it,
    /// with `input` less the reference. Only `run_id`'s own results resolve,
    /// by a name it bound, a handle or a range of either. An explicit
    /// `occurrence:<hex>` selects that run/path occurrence, never another
    /// occurrence that happens to hold the same bytes. `withholds` says
    /// whether the rows the run's answers were served from (`None` when one
    /// kept no set) stay where the caller is not; then the result's taint
    /// is checked as in the run. A selection past one reply pages, as
    /// nothing outside a run binds a new result, and one picked value past
    /// one reply comes back as a range ref over its own bytes, with its
    /// first page. The reply is the run's own: `{"output": ...}` or a
    /// `denied` refusal.
    pub fn read_code_run_result(
        &self,
        run_id: EntityId,
        reference: &str,
        facet: Option<ResultFacet>,
        input: Value,
        withholds: impl FnOnce(Option<&[EntityId]>) -> Result<bool>,
    ) -> Result<Value> {
        let Some(record) = self.get_code_run_replay_record(&run_id)? else {
            return Ok(unknown_handle(&[]));
        };
        // Its steps' type diagnostics kept whole are its results too (FIX
        // 8277), read under the same checks.
        let feedback = self.type_diagnostics_bodies(run_id);
        read_result_in(
            &ExecutorStorage::Canonical(self),
            &record,
            &feedback,
            reference,
            facet,
            input,
            withholds,
        )
    }
}

/// [`Vault::code_run_result_cards`] over `storage`, the newest `skip` names
/// passed over first: the cards of the record's named results, newest first
/// and at most `limit` of them, and how many names it has.
pub(crate) fn result_cards_in(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    skip: usize,
    limit: usize,
) -> Result<(Vec<Value>, usize)> {
    let mut cards = Vec::new();
    for binding in record.bindings.iter().rev().skip(skip).take(limit) {
        let Some(output) = record
            .outputs
            .iter()
            .find(|output| output.handle == binding.handle && is_result_output_path(&output.path))
        else {
            continue;
        };
        let mut card = card(storage, record.run_id, output, Some(binding.name.as_str()))?;
        if let Some(fields) = card.as_object_mut() {
            fields.remove("read");
        }
        cards.push(card);
    }
    Ok((cards, record.bindings.len()))
}

/// [`Vault::read_code_run_result`] over `storage`, for the run `record`
/// holds there: `feedback` is the type diagnostics bodies its readers read
/// beside its results (none where a run keeps none).
pub(crate) fn read_result_in(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    feedback: &[CodeRunRawOutput],
    reference: &str,
    facet: Option<ResultFacet>,
    input: Value,
    withholds: impl FnOnce(Option<&[EntityId]>) -> Result<bool>,
) -> Result<Value> {
    let run_id = record.run_id;
    let live: Vec<&CodeRunResultBinding> = record.bindings.iter().collect();
    let target = JsResultTarget::parse(reference);
    let outputs = record
        .outputs
        .iter()
        .filter(|output| is_result_output_path(&output.path))
        .chain(feedback);
    let selected = match &target.reference {
        crate::engine_executor::JsResultRef::Handle(reference)
            if reference.starts_with("occurrence:") =>
        {
            let occurrence = reference.strip_prefix("occurrence:").unwrap_or_default();
            let mut selected = None;
            for output in outputs {
                if crate::code_run::ResultOccurrence::owned(run_id, &output.path)?
                    .id()
                    .to_hex()
                    == occurrence
                {
                    selected = Some((output.clone(), None));
                    break;
                }
            }
            selected
        }
        _ => resolve(outputs, &live, &target.reference),
    };
    let Some((output, name)) = selected else {
        return Ok(unknown_handle(&live));
    };
    if withholds(record.agent_verb_rows().as_deref())? {
        return Ok(refusal("result_withheld"));
    }
    ResultRead::outside_run(storage, run_id, output, name, target.range, facet, input)
}
