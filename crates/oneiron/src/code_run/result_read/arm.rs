//! A shadow arm's reads of its own results (PR-S1, FIX 1661/2144): the
//! card, the verdict and the facets a run's reads answer, over the arm's
//! own body store and the taint each result was frozen with before the arm
//! started (`shadow_runner`). The arm's program meets the answers a read of
//! its run would give; no vault is read here, and a result that is not
//! clean shows nothing of its body, as anywhere else.

use serde_json::{Value, json};

use super::{Reply, ResultBody, ResultFacet, ResultRead, refusal};
use crate::code_run::shadow_runner::ShadowBodyStore;
use crate::code_run::{CodeRunOutputKind, CodeRunRawOutput};
use crate::entity_id::EntityId;
use crate::limit_ask::LimitWatch;
use crate::secret_rotation::ArtifactTaintState;
use crate::store::BodySink;
use crate::{Error, Result};

/// One result body in an arm's store, read by range: the whole body, or the
/// window of it a range ref names. Offsets are the window's own.
struct ArmBody<'s> {
    store: &'s ShadowBodyStore,
    output: &'s CodeRunRawOutput,
    base: u64,
    len: u64,
}

impl ResultBody for ArmBody<'_> {
    fn len(&self) -> u64 {
        self.len
    }

    fn kind(&self) -> CodeRunOutputKind {
        self.output.kind
    }

    fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let take = usize::try_from(self.len.saturating_sub(offset).min(len as u64))
            .map_err(|_| Error::ArithmeticOverflow("shadow arm result read"))?;
        self.store
            .read_range(
                self.output.output_ref(),
                self.base.saturating_add(offset),
                take,
            )?
            .ok_or(Error::CorruptedIndex("shadow arm result bytes"))
    }

    fn line_index(&self) -> Option<Vec<u64>> {
        self.store.line_index(self.output.output_ref())
    }

    fn base(&self) -> u64 {
        self.base
    }
}

impl ResultRead {
    /// An arm's read of `output`, one of the results of the arm's run `run`
    /// as `name` binds it, narrowed to `range`, under `taint`: the state and
    /// secret reason it was frozen with, or its own scan gave it in the arm.
    /// A range that is not inside the body is refused, as a run's read
    /// refuses it.
    pub(crate) fn in_arm(
        run: EntityId,
        output: CodeRunRawOutput,
        name: Option<String>,
        range: Option<(u64, u64)>,
        taint: (ArtifactTaintState, Option<String>),
    ) -> std::result::Result<Self, Value> {
        if let Some((start, end)) = range
            && (start >= end || end > output.raw_len)
        {
            let mut refused = refusal("invalid_range");
            refused["bytes"] = json!(output.raw_len);
            return Err(refused);
        }
        let (state, secret) = taint;
        Ok(Self {
            owner: run,
            output,
            name,
            range,
            state,
            secret,
        })
    }

    /// The result's bytes in the arm's `store`, narrowed to its range.
    fn arm_body<'s>(&'s self, store: &'s ShadowBodyStore) -> ArmBody<'s> {
        let (base, end) = self.range.unwrap_or((0, self.output.raw_len));
        ArmBody {
            store,
            output: &self.output,
            base,
            len: end.saturating_sub(base),
        }
    }

    /// The result's card, as a run's read makes it, from the arm's store.
    pub(crate) fn arm_card(&self, store: &ShadowBodyStore) -> Result<Value> {
        self.card_of(&self.arm_body(store))
    }

    /// One facet of the result, as a run's read reads it, from the arm's
    /// store under the `[limits]` rows `watch` froze for the arm. A
    /// selection past one reply streams into `spill`.
    pub(crate) fn arm_read(
        &self,
        store: &ShadowBodyStore,
        watch: &LimitWatch,
        facet: ResultFacet,
        input: Value,
        spill: Option<&mut BodySink>,
    ) -> Result<Reply> {
        self.read_of(&self.arm_body(store), watch, facet, input, spill)
    }
}
