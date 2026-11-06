//! The facets of one result read (OF-190 B++): `slice`, `search`, `query`
//! and `chunks`, over a run's body or a shadow arm's, each answer checked
//! for an unmarked secret before it leaves.

use super::run_body::RunBody;
use super::{
    ReadBounds, Reply, ResultBody, ResultFacet, ResultRead, chunks, occurrence_ref, query, search,
    slice, unmarked_secret,
};
use crate::Result;
use crate::code_run::ExecutorStorage;
use crate::engine_executor::RESULT_REPLY_INLINE_BYTES;
use crate::limit_ask::LimitWatch;
use crate::secret_rotation::ArtifactTaintState;
use crate::store::BodySink;
use serde_json::Value;

impl ResultRead {
    /// One facet of the result, read from `input`. A selection past one
    /// reply streams into `spill` when there is one; without one it pages.
    pub(crate) fn read(
        &self,
        storage: &ExecutorStorage<'_>,
        facet: ResultFacet,
        input: Value,
        spill: Option<&mut BodySink>,
    ) -> Result<Reply> {
        let body = RunBody::of(self, storage);
        self.read_of(&body, storage.limit_watch(), facet, input, spill)
    }

    /// [`Self::read`] over `body`, under the `[limits]` rows of `watch`.
    pub(super) fn read_of(
        &self,
        body: &dyn ResultBody,
        watch: &LimitWatch,
        facet: ResultFacet,
        input: Value,
        spill: Option<&mut BodySink>,
    ) -> Result<Reply> {
        if self.state.is_tainted() {
            return Ok(Reply::Output(self.withheld()));
        }
        let bounds = ReadBounds {
            reply_bytes: RESULT_REPLY_INLINE_BYTES,
            watch,
        };
        let reference = self.reference();
        // Chunk and page refs name the same parent the ref above names: the
        // owner's immutable occurrence, so a page of a renamed result still
        // reparses to its occurrence, not to the first result with its
        // bytes. Only a named delegated source keeps the caller's name,
        // as its ref does.
        let parent = if self.caller_named() {
            self.name
                .clone()
                .unwrap_or_else(|| self.output.handle.clone())
        } else {
            occurrence_ref(self.owner, &self.output.path).unwrap_or_else(|| {
                self.name
                    .clone()
                    .unwrap_or_else(|| self.output.handle.clone())
            })
        };
        let reply = match facet {
            ResultFacet::Slice => slice::slice(body, &reference, input, &bounds),
            ResultFacet::Search => search::search(body, &reference, input, &bounds),
            ResultFacet::Query => query::query(body, &reference, &parent, input, &bounds, spill),
            ResultFacet::Chunks => chunks::chunks(body, &reference, &parent, input, &bounds),
        }?;
        // A spilled selection is a new body, which its own sink's scan marks.
        Ok(match reply {
            Reply::Output(answer) => match unmarked_secret(&answer) {
                None => Reply::Output(answer),
                Some(reason) => {
                    Reply::Output(self.withheld_as(ArtifactTaintState::TaintedLive, Some(reason)))
                }
            },
            other => other,
        })
    }
}
