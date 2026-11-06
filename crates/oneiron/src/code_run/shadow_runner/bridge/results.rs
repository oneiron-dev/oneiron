//! The results of a shadow arm's run (PR-S1): their names, how a read of
//! one resolves and is checked, what `store`, `describe`, `can`, a facet
//! and a chunk answer, all from the arm's store and the run's results before
//! the step, frozen with their taint before the arm started.

use serde_json::{Value, json};

use super::super::types::{ShadowBodyRef, ShadowUnavailable, ShadowUnavailableReason as Reason};
use super::taint::{exported_mark, stored_taint};
use super::{ArmResult, ShadowBridgeHost, Taint};
use crate::code_run::{
    CodeRunRawOutput, CodeRunResultBinding, ResultFacet, ResultOccurrence, ResultRead, ResultReply,
    resolve_result, result_cannot, result_refusal, unknown_handle,
};
use crate::engine_executor::{JsResultTarget, parse_result_read_path, store_result_output_path};
use crate::secret_rotation::ArtifactTaintState;
use crate::store::BodySink;
use crate::{Error, Result};

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

    /// The arm's result `target` names, read as a run's read is, with the
    /// taint it reads under, or the refusal the guest gets.
    fn checked(
        &self,
        target: &JsResultTarget,
    ) -> Result<std::result::Result<(ResultRead, Taint), Value>> {
        self.admit_read()?;
        let live = self.live_bindings();
        let outputs = self.results.iter().map(|result| &result.output);
        let Some((output, name)) = resolve_result(self.run_id, outputs, &live, &target.reference)
        else {
            return Ok(Err(unknown_handle(&live)));
        };
        let taint = self.taint_of(&output);
        Ok(
            ResultRead::in_arm(self.run_id, output, name, target.range, taint.clone())
                .map(|read| (read, taint)),
        )
    }

    /// The taint the arm holds `output` under.
    fn taint_of(&self, output: &CodeRunRawOutput) -> Taint {
        self.results
            .iter()
            .find(|held| held.output.path == output.path && held.output.handle == output.handle)
            .map_or((ArtifactTaintState::Clean, None), |held| {
                (held.state, held.secret.clone())
            })
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
        let card = match ResultRead::in_arm(self.run_id, output.clone(), Some(name), None, taint) {
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
            match self.checked(&JsResultTarget::parse(source))? {
                Ok((_, taint)) => inherit.push(taint),
                Err(refused) => return Ok(refused),
            }
        }
        let (_, card) = self.bind_stored(sink, name, &inherit)?;
        Ok(json!({ "output": card }))
    }

    /// `describe(r)`: the card of one of the arm's results.
    pub(super) fn describe_result(&self, target: &JsResultTarget) -> Result<Value> {
        Ok(match self.checked(target)? {
            Ok((read, _)) => json!({ "output": read.arm_card(self.store)? }),
            Err(refused) => refused,
        })
    }

    /// `can({read: r})`: the verdict a read's checks give. With `child`, a
    /// readable result is also asked of a reader spawn, which the arm runs
    /// none of: unavailable.
    pub(super) fn can_read_result(
        &mut self,
        target: &JsResultTarget,
        child: bool,
    ) -> Result<Value> {
        let verdict = match self.checked(target)? {
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
        let read = match self.checked(target)? {
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
    /// body frozen withheld stops the arm, since its live read read it.
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
        let found = self.results.iter().find_map(|held| {
            if held.output.output_ref() != wanted {
                return None;
            }
            if let Some(occurrence) = &occurrence {
                let mine = ResultOccurrence::of(Some(self.run_id), &held.output)
                    .ok()?
                    .id();
                if &mine != occurrence {
                    return None;
                }
            }
            Some((held.output.clone(), !held.state.is_tainted()))
        });
        let Some((output, clean)) = found else {
            return Err(Error::InvalidConfig(
                "stored result is outside this run".to_owned(),
            ));
        };
        self.read_chunk(&output, clean, offset)
    }
}
