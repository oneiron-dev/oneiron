//! The results of a shadow arm's run (PR-S1): their names, how a read of
//! one resolves and is checked, what `store`, `describe`, `can`, a facet
//! and a chunk answer, all from the arm's store and the run's results before
//! the step, frozen with their taint before the arm started.
//!
//! A read that names none of the arm's results resolves as the step's live
//! read did (FIX 6352): a reader child's delegated input, inside its range
//! and while its job was live, else a settled finding of the run's
//! children, each from the step's read context and for its owner, with the
//! taint it was frozen with. Such a read is admitted, withheld or refused as
//! the door's row check answered the live read by the same reference, under
//! the same gate, at the same bridge position. A whole result's card carries
//! the fold receipt its live card carried. What the read context cannot
//! establish stops the arm; it is never answered as `unknown_handle`, and no
//! read it cannot establish is admitted.
//!
//! A read of a result frozen from the step's source, the arm's run's or
//! another run's, reads under the taint its source occurrence reads under
//! now, at its worst with the frozen one (FIX 9468): one that went tainted
//! after the freeze is withheld, as a run's read of it is. A result the arm
//! stored reads under the mark it was written with and the taint it
//! inherited.

use serde_json::{Value, json};

use super::super::release::live_taint;
use super::super::types::{ShadowBodyRef, ShadowUnavailable, ShadowUnavailableReason as Reason};
use super::taint::{exported_mark, stored_taint};
use super::{ArmResult, ShadowBridgeHost, Taint};
use crate::code_run::{
    CodeRunRawOutput, CodeRunResultBinding, ResultFacet, ResultOccurrence, ResultRead, ResultReply,
    RetainedReadVerdict, resolve_result, result_cannot, result_refusal, unknown_handle,
};
use crate::engine_executor::{
    ACT_GATES_COUNT_CALLABLE_ROWS, JsResultTarget, parse_result_read_path, store_result_output_path,
};
use crate::secret_rotation::ArtifactTaintState;
use crate::store::BodySink;
use crate::{Error, Result};

/// How the path of a value `store` wrote ends: the only results a fold's
/// receipt is ever on.
const STORED_VALUE_SUFFIX: &str = ".result";

impl ShadowBridgeHost<'_> {
    /// The results the arm stored, each by its ref; a tainted one leaves withheld.
    pub(crate) fn own_results(&self) -> Vec<ShadowBodyRef> {
        self.results
            .iter()
            .filter(|result| result.own)
            .map(|result| {
                ShadowBodyRef::of(
                    &result.output,
                    exported_mark(result.state, result.secret.as_deref()),
                )
            })
            .collect()
    }

    /// The arm's live result names, oldest first: its binds over the run's.
    fn live_bindings(&self) -> Vec<&CodeRunResultBinding> {
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
    fn next_auto_name(&self) -> String {
        let live = self.live_bindings();
        (live.len() + 1..)
            .map(|n| format!("r{n}"))
            .find(|name| !live.iter().any(|binding| binding.name == *name))
            .unwrap_or_default()
    }

    /// Binds `name` to the result `handle` at its occurrence `path`; a
    /// rebind replaces the name's entry in place.
    pub(super) fn bind(&mut self, name: String, handle: String, path: String) {
        let binding = CodeRunResultBinding::new(name, handle, path);
        match self.bound.iter_mut().find(|held| held.name == binding.name) {
            Some(held) => *held = binding,
            None => self.bound.push(binding),
        }
    }

    /// A read of the arm's results is admitted as a run's is: never past a
    /// halted bridge or a declined TASK.
    pub(super) fn admit_read(&self) -> Result<()> {
        let refused =
            |code: &str| Error::InvalidConfig(format!("recorded output read refused: {code}"));
        if self.halted() {
            return Err(refused("host_bridge_halted"));
        }
        if self.declined {
            return Err(refused("task_declined"));
        }
        Ok(())
    }

    /// The result `target` names, read as a run's read is, with the taint it
    /// reads under, or the refusal the guest gets: one of the arm's own, else
    /// one of another run the step's read context names (FIX 6352), under
    /// the gate that counts the run's callable rows when `callable`, as the
    /// live gate does. A read the context cannot answer stops the arm.
    fn checked(
        &mut self,
        target: &JsResultTarget,
        callable: bool,
    ) -> Result<std::result::Result<(ResultRead, Taint), Value>> {
        self.admit_read()?;
        let live = self.live_bindings();
        let outputs = self.results.iter().map(|result| &result.output);
        if let Some((output, name)) = resolve_result(self.run_id, outputs, &live, &target.reference)
        {
            let taint = self.taint_of(&output)?;
            let read = ResultRead::in_arm(
                self.run_id,
                output,
                name,
                target.range,
                taint.clone(),
                false,
            );
            return Ok(read.map(|read| (read, taint)));
        }
        let unknown = unknown_handle(&live);
        let step = self.step;
        let found = match step.foreign_read(&target.reference, self.next_seq) {
            Ok(Some(found)) => found,
            Ok(None) => return Ok(Err(unknown)),
            Err(missing) => return Err(self.stop(missing)),
        };
        if let (Some((start, end)), Some((from, to))) = (found.within, target.range)
            && (from < start || to > end)
        {
            return Ok(Err(result_refusal("outside_delegated_range")));
        }
        if found.child_source {
            match step.reader_job_live(self.next_seq) {
                Ok(true) => {}
                Ok(false) => return Ok(Err(result_refusal("reader_task_settled"))),
                Err(missing) => return Err(self.stop(missing)),
            }
        }
        // The rows another run's result was served from reach the door's
        // caller only as the live row check answered (FIX 6352).
        match step.retained_read_verdict(&target.reference, callable, self.next_seq) {
            Ok(RetainedReadVerdict::Admitted) => {}
            Ok(RetainedReadVerdict::Withheld) => return Ok(Err(result_refusal("result_withheld"))),
            Ok(RetainedReadVerdict::Refused(code)) => return Ok(Err(result_refusal(code))),
            Err(missing) => return Err(self.stop(missing)),
        }
        let output = found.body.output.clone();
        let whole = found
            .within
            .is_some_and(|range| range == (0, output.raw_len));
        let range = target.range.or(found.within.filter(|_| !whole));
        let frozen = (found.body.state, found.body.secret.clone());
        let taint = live_taint(self.store, found.owner, &output, frozen)?;
        let foreign = found.owner != self.run_id;
        let read = ResultRead::in_arm(
            found.owner,
            output,
            found.name,
            range,
            taint.clone(),
            foreign,
        );
        Ok(read.map(|read| (read, taint)))
    }

    /// Whether `read` reads a result the arm itself stored, which is never a
    /// fold's: the arm folds nothing.
    fn reads_own_store(&self, read: &ResultRead) -> bool {
        let output = read.output();
        read.owner() == self.run_id
            && self.results.iter().any(|held| {
                held.own && held.output.path == output.path && held.output.handle == output.handle
            })
    }

    /// The taint the arm reads `output` under: see [`Self::held_taint`].
    fn taint_of(&self, output: &CodeRunRawOutput) -> Result<Taint> {
        self.results
            .iter()
            .find(|held| held.output.path == output.path && held.output.handle == output.handle)
            .map_or(Ok((ArtifactTaintState::Clean, None)), |held| {
                self.held_taint(held)
            })
    }

    /// The taint the arm reads `held` under (FIX 9468): a result the arm
    /// stored, as it was written; one frozen from the run, at its worst with
    /// the taint the run's occurrence of it reads under now.
    fn held_taint(&self, held: &ArmResult) -> Result<Taint> {
        let taint = (held.state, held.secret.clone());
        if held.own {
            return Ok(taint);
        }
        live_taint(self.store, self.run_id, &held.output, taint)
    }

    /// Whether the run's occurrence of `output`, frozen clean for the arm,
    /// still reads clean now (FIX 9468).
    pub(super) fn source_clean(&self, output: &CodeRunRawOutput) -> Result<bool> {
        let frozen = (ArtifactTaintState::Clean, None);
        let (state, _) = live_taint(self.store, self.run_id, output, frozen)?;
        Ok(!state.is_tainted())
    }

    /// Finishes the body `sink` wrote as a stored value of the arm, named by
    /// the digest of the bytes the wall admitted (FIX 5718 part 3), the
    /// taint of `inherit` on it, and binds it to `name`, or to the next free
    /// `r<n>`: the result and its card.
    pub(super) fn bind_stored(
        &mut self,
        sink: BodySink,
        name: Option<String>,
        inherit: &[Taint],
    ) -> Result<(CodeRunRawOutput, Value)> {
        // The same ordinal live execution names this store with (FIX 1393):
        // the step-start full-output base plus the arm's own stores so far.
        // A replayed store then reuses its frozen occurrence and taint
        // instead of colliding with a later ordinal.
        let ordinal = self.output_ordinal_base
            + self.spilled
            + self.results.iter().filter(|held| held.own).count();
        let (output, secret) = self.store.finish_named(
            |digest| store_result_output_path(digest, ordinal),
            sink,
            true,
        )?;
        let taint = match self
            .results
            .iter()
            .find(|held| held.output.path == output.path)
        {
            Some(held) => (held.state, held.secret.clone()),
            None => {
                let taint = stored_taint(secret, inherit);
                self.results.push(ArmResult {
                    output: output.clone(),
                    state: taint.0,
                    secret: taint.1.clone(),
                    own: true,
                });
                taint
            }
        };
        let name = name.unwrap_or_else(|| self.next_auto_name());
        self.bind(name.clone(), output.handle.clone(), output.path.clone());
        let read = ResultRead::in_arm(self.run_id, output.clone(), Some(name), None, taint, false);
        let card = match read {
            Ok(read) => read.arm_card(self.store)?,
            Err(_) => return Err(Error::InvariantViolation("a whole result has no range")),
        };
        Ok((output, card))
    }

    /// `store(value, name?, {sources?, receipt?})`, as a run's host stores
    /// it, in the arm alone. A fold's receipt names reader jobs, which the
    /// arm has none of: unavailable.
    pub(super) fn store_result(
        &mut self,
        name: Option<String>,
        sources: &[String],
        receipt: bool,
    ) -> Result<Value> {
        let sink = self
            .streams
            .store
            .take()
            .ok_or_else(|| Error::InvalidConfig("store sent no body".to_owned()))?;
        if self.halted() {
            return Ok(result_refusal("host_bridge_halted"));
        }
        if self.declined {
            return Ok(result_refusal("task_declined"));
        }
        if name
            .as_deref()
            .is_some_and(|name| !CodeRunResultBinding::is_valid_name(name))
        {
            return Ok(result_refusal("invalid_result_name"));
        }
        if receipt {
            let nested = ShadowUnavailable::new(Reason::NestedReplayUnsupported, "fold_receipt");
            return Err(self.stop(nested));
        }
        let mut inherit = Vec::with_capacity(sources.len());
        for source in sources {
            let target = JsResultTarget::parse(source);
            match self.checked(&target, ACT_GATES_COUNT_CALLABLE_ROWS)? {
                Ok((_, taint)) => inherit.push(taint),
                Err(refused) => return Ok(refused),
            }
        }
        let (_, card) = self.bind_stored(sink, name, &inherit)?;
        Ok(json!({ "output": card }))
    }

    /// `describe(r)`: the card of one of the arm's results, or of a range of
    /// one. A whole result's card carries the fold receipt the step's live
    /// card of it carried (FIX 6352). A result the arm stored, and one at a
    /// path no `store` writes, is no fold's.
    pub(super) fn describe_result(&mut self, target: &JsResultTarget) -> Result<Value> {
        let read = match self.checked(target, true)? {
            Ok((read, _)) => read,
            Err(refused) => return Ok(refused),
        };
        let mut card = read.arm_card(self.store)?;
        let output = read.output();
        if read.range().is_none()
            && output.path.ends_with(STORED_VALUE_SUFFIX)
            && !self.reads_own_store(&read)
        {
            let step = self.step;
            match step.fold_receipt(read.owner(), output) {
                Ok(Some(receipt)) => card["receipt"] = receipt.card(),
                Ok(None) => {}
                Err(missing) => return Err(self.stop(missing)),
            }
        }
        Ok(json!({ "output": card }))
    }

    /// `can({read: r})`: the verdict a read's checks give. With `child`, a
    /// readable result is also asked of a reader spawn, which the arm runs
    /// none of: unavailable.
    pub(super) fn can_read_result(
        &mut self,
        target: &JsResultTarget,
        child: bool,
    ) -> Result<Value> {
        let verdict = match self.checked(target, true)? {
            Ok((read, _)) => read.preflight(),
            Err(refused) => result_cannot(refused),
        };
        if !child || verdict["can"] != json!(true) {
            return Ok(json!({ "output": verdict }));
        }
        let nested = ShadowUnavailable::new(Reason::NestedReplayUnsupported, "reader_spawn");
        Err(self.stop(nested))
    }

    /// One facet of one of the arm's results. A query whose selection is
    /// past one reply is stored as a new result of the arm.
    pub(super) fn read_result(
        &mut self,
        target: &JsResultTarget,
        facet: ResultFacet,
        input: Value,
    ) -> Result<Value> {
        let read = match self.checked(target, true)? {
            Ok((read, _)) => read,
            Err(refused) => return Ok(refused),
        };
        let mut sink = match facet {
            ResultFacet::Query => Some(self.store.sink()?),
            _ => None,
        };
        let reply = read.arm_read(self.store, &self.watch, facet, input, sink.as_mut())?;
        Ok(match reply {
            ResultReply::Output(output) => json!({ "output": output }),
            ResultReply::Denied(refused) => refused,
            ResultReply::Spilled { count, next } => {
                let sink = sink.ok_or(Error::InvariantViolation(
                    "a result read spilled with no sink",
                ))?;
                let (_, card) = self.bind_stored(sink, None, &[])?;
                let mut output = json!({"derived": card, "count": count, "done": next.is_none()});
                if let Some(next) = next {
                    output["next"] = next;
                }
                json!({ "output": output })
            }
        })
    }

    /// One chunk of a body at `offset`, while the arm holds it clean; a
    /// body frozen withheld, or one that reads tainted now (FIX 9468), stops
    /// the arm, since its live read read it.
    pub(super) fn read_chunk(
        &mut self,
        output: &CodeRunRawOutput,
        clean: bool,
        offset: u64,
    ) -> Result<Option<Vec<u8>>> {
        if offset > output.raw_len {
            return Err(Error::InvalidConfig(
                "recoverable output offset exceeds source".to_owned(),
            ));
        }
        if !clean {
            let withheld = ShadowUnavailable::new(Reason::SourceWithheld, "recoverable_output");
            return Err(self.stop(withheld));
        }
        self.store
            .read_range(output.output_ref(), offset, self.reads.chunk_bytes)?
            .ok_or(Error::CorruptedIndex("shadow arm output bytes"))
            .map(Some)
    }

    /// A chunk of one of the arm's stored results, by its read path. The
    /// path names the occurrence when the card gave one: a same-byte
    /// result reads its own occurrence, never the first with its bytes.
    pub(super) fn read_stored_result(&mut self, path: &str) -> Result<Option<Vec<u8>>> {
        let Some((wanted, occurrence, offset)) = parse_result_read_path(path) else {
            return Err(Error::InvalidConfig(
                "stored result is outside this run".to_owned(),
            ));
        };
        let found = self.results.iter().find(|held| {
            if held.output.output_ref() != wanted {
                return false;
            }
            let Some(occurrence) = &occurrence else {
                return true;
            };
            ResultOccurrence::of(Some(self.run_id), &held.output)
                .is_ok_and(|mine| mine.id() == *occurrence)
        });
        let Some(held) = found else {
            return Err(Error::InvalidConfig(
                "stored result is outside this run".to_owned(),
            ));
        };
        let clean = !self.held_taint(held)?.0.is_tainted();
        let output = held.output.clone();
        self.read_chunk(&output, clean, offset)
    }
}
