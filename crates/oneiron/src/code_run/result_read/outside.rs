//! Reads of a code run's results for a caller outside the run: the cards
//! of its named results, and one read of one of them through the MCP door.

use super::{
    CodeRunReplayRecord, CodeRunResultBinding, EntityId, ExecutorStorage, JsResultTarget, Result,
    ResultFacet, ResultRead, Value, Vault, card, is_result_output_path, refusal, resolve,
    unknown_handle,
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
        let storage = ExecutorStorage::Canonical(self);
        let mut cards = Vec::new();
        for binding in record.bindings.iter().rev().take(limit) {
            let Some(output) = record.outputs.iter().find(|output| {
                output.handle == binding.handle && is_result_output_path(&output.path)
            }) else {
                continue;
            };
            let mut card = card(&storage, record.run_id, output, Some(binding.name.as_str()))?;
            if let Some(fields) = card.as_object_mut() {
                fields.remove("read");
            }
            cards.push(card);
        }
        Ok((cards, record.bindings.len()))
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
        let live: Vec<&CodeRunResultBinding> = record.bindings.iter().collect();
        let target = JsResultTarget::parse(reference);
        let outputs = record
            .outputs
            .iter()
            .filter(|output| is_result_output_path(&output.path));
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
        let storage = ExecutorStorage::Canonical(self);
        ResultRead::outside_run(&storage, run_id, output, name, target.range, facet, input)
    }
}
