//! The rows a JS host's results were served from, and whether a result
//! served from them stays on this device for the door's caller.

use super::*;

impl RecordingJsHost<'_, '_> {
    /// The rows the run's results were served from: the conservative union
    /// of every row its recorded and this step's verb answers were served
    /// from, each stored skill its callables loaded and the rows of each
    /// other run's result they read (FIX 5460), or none known when one kept
    /// no set.
    pub(in crate::engine_executor) fn result_rows(&self) -> Option<Vec<EntityId>> {
        let (skills, read) = &self.callable_rows;
        self.verb_rows()
            .zip(read.as_deref())
            .map(|(verbs, read)| [verbs.as_slice(), read, skills.as_slice()].concat())
    }

    /// The records whose words the run's recorded and this step's fold
    /// answers copy, each once (FIX 18924): known dependencies of what the
    /// run stores, apart from its input rows.
    pub(super) fn fold_sources(&self) -> Vec<EntityId> {
        let step = crate::code_run::recorded_fold_words(&self.bridge_calls);
        let mut sources: Vec<EntityId> = step
            .into_iter()
            .flat_map(|word| word.sources)
            .chain(self.recorded_fold_sources.iter().copied())
            .collect();
        sources.sort_unstable();
        sources.dedup();
        sources
    }

    /// The rows the run's recorded and this step's verb answers were served
    /// from, or none known when one answer kept no set.
    pub(in crate::engine_executor::host) fn verb_rows(&self) -> Option<Vec<EntityId>> {
        self.recorded_rows
            .as_ref()
            .zip(agent_verb_rows_of(&self.bridge_calls))
            .map(|(recorded, step)| [recorded.as_slice(), step.as_slice()].concat())
    }

    /// The rows of an own occurrence's fixed bytes. Unknown provenance uses
    /// the live union; act gates retain their verb-only row set.
    pub(super) fn occurrence_rows(
        &self,
        output: &CodeRunRawOutput,
        callable: bool,
    ) -> Option<Vec<EntityId>> {
        if callable {
            output.input_rows.clone().or_else(|| self.result_rows())
        } else {
            self.verb_rows()
        }
    }

    /// Whether the run's results stay on this device for its door's caller
    /// now (DEC-0005), by [`Self::result_rows`].
    pub(in crate::engine_executor::host) fn withholds_results(&self) -> Result<bool> {
        self.withholds_rows(self.result_rows())?
            .map_err(|code| Error::InvalidConfig(format!("stored result read refused: {code}")))
    }

    /// Whether a result served from `rows` stays on this device for the
    /// door's caller now. A scoped child's door that refuses the read on its
    /// authority answers that refusal's code (`scoped_child_authority_lapsed`
    /// or `scoped_child_parent_lease_lost`, FIX 7734), for the read to name;
    /// any other refusal is an error, as before.
    pub(in crate::engine_executor::host) fn withholds_rows(
        &self,
        rows: Option<Vec<EntityId>>,
    ) -> Result<std::result::Result<bool, &'static str>> {
        match self.gated_write.withholds_retained(rows.as_deref()) {
            Ok(withheld) => Ok(Ok(withheld)),
            Err(refusal) => match scoped_child_read_refusal(&refusal.code) {
                Some(code) => Ok(Err(code)),
                None => Err(Error::InvalidConfig(format!(
                    "stored result read refused: {}",
                    refusal.code
                ))),
            },
        }
    }
}
