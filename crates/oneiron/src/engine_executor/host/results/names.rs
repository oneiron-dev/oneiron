//! Result names and references for one JS host: the run's live names,
//! the next automatic name, binds, and the run's result a reference names.

use super::*;

impl RecordingJsHost<'_, '_> {
    /// The run's live result names, oldest first: this step's binds over
    /// the record's.
    pub(in crate::engine_executor::host) fn live_bindings(&self) -> Vec<&CodeRunResultBinding> {
        let mut live: Vec<_> = self
            .bindings
            .iter()
            .filter(|binding| !self.bound.iter().any(|held| held.name == binding.name))
            .collect();
        live.extend(&self.bound);
        live
    }

    /// The next free automatic name: `r<n>`, counting from one past the
    /// live names, past any name taken.
    pub(in crate::engine_executor::host) fn next_auto_name(&self) -> String {
        let live = self.live_bindings();
        (live.len() + 1..)
            .map(|n| format!("r{n}"))
            .find(|name| !live.iter().any(|binding| binding.name == *name))
            .unwrap_or_default()
    }

    /// Binds `name` to the result `handle` at its occurrence `path` for the
    /// record; a rebind replaces the name's entry in place.
    pub(in crate::engine_executor::host) fn bind(
        &mut self,
        name: String,
        handle: String,
        path: String,
    ) {
        let binding = CodeRunResultBinding::new(name, handle, path);
        match self.bound.iter_mut().find(|held| held.name == binding.name) {
            Some(held) => *held = binding,
            None => self.bound.push(binding),
        }
    }

    /// The run's results a read may resolve: the recorded ones and this
    /// step's own, as [`is_result_output_path`] admits them. A record-only
    /// body a verb hook's view stands in for is none of them, so no name,
    /// handle or occurrence ref reads the real result back (ARCH-0080
    /// Redact).
    pub(super) fn readable_outputs(&self) -> impl Iterator<Item = &CodeRunRawOutput> {
        self.results.iter().chain(
            self.captured
                .iter()
                .filter(|output| is_result_output_path(&output.path)),
        )
    }

    /// The run's result a reference names, and the live name bound to it.
    /// Only this run's results resolve: a handle names nothing else.
    pub(in crate::engine_executor::host) fn resolve_result(
        &self,
        reference: &JsResultRef,
    ) -> Option<(CodeRunRawOutput, Option<String>)> {
        crate::code_run::resolve_result(
            self.run_id,
            self.readable_outputs(),
            &self.live_bindings(),
            reference,
        )
    }

    /// The refusal for a reference to no result of this run, with the live
    /// names it could have meant.
    pub(in crate::engine_executor::host) fn unknown_handle(&self) -> serde_json::Value {
        crate::code_run::unknown_handle(&self.live_bindings())
    }
}
