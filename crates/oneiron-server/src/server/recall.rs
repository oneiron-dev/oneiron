//! The recall verb as every server transport runs it.
//!
//! One place builds recall's execution inputs, so the HTTP facade and the
//! WebSocket read RPC run the same recall for the same request: above light
//! effort the query is embedded whenever the vault's embedder is serving, and
//! the caller's `as_of` rides along. Both doors read as the bound principal
//! under the slip it presented (ONE-1187-D6).
//! A vault with no embedder, or one still loading its model, recalls on its
//! sparse signals and says so (`sparse: true`).
//!
//! A request with a deadline (call mode, or its own `deadline_ms`) is a hard
//! cut here: the async door stops waiting when the answer is due and answers
//! with the best pack ready, so a slow stage, a writer it waits on or a busy
//! blocking pool never holds the turn (retrieval hub #call-mode).

use std::sync::Arc;
use std::time::Instant;

use oneiron::authority::VerifiedSlip;
use oneiron::memory::{
    Effort, MEMORY_CODE_INTERNAL, Memory, MemoryError, MemoryPack, MemoryResult, RecallEffort,
};
use oneiron::task_verb::sdk::{RecallDoor, RecallRequest};
use oneiron::{EdgeActorClass, EntityId};

use super::core::SyncServer;
use crate::embedder::EmbedQueryRefusal;

impl SyncServer {
    /// Runs `recall` for `memory` with the server's execution inputs.
    ///
    /// Blocking: it may embed the query and it reads the vault. Async callers
    /// take [`Self::recall_off_runtime`]; a synchronous caller that may sit on
    /// a runtime worker wraps it in [`blocking`].
    pub(crate) fn recall(
        &self,
        memory: &Memory<'_>,
        input: RecallRequest,
    ) -> MemoryResult<MemoryPack> {
        let embed = self.recall_embed(input.effort);
        oneiron::task_verb::sdk::recall_with_vector(memory, input, embed)
    }

    /// The query embedder recall runs with. Light is pure retrieval with no
    /// model call (ARCH-0044 S6); every other effort embeds the query when
    /// the vault's embedder serves.
    fn recall_embed(
        &self,
        effort: Option<RecallEffort>,
    ) -> impl FnOnce(&str) -> Option<Vec<f32>> + '_ {
        let embeds = effort.map_or(Effort::Medium, RecallEffort::level) != Effort::Light;
        move |query| embeds.then(|| self.recall_query_vector(query)).flatten()
    }

    /// [`Self::recall`] for `actor` under the slip it presented, on the
    /// blocking pool. When the request names a room turn, every read recall
    /// makes runs inside that room (ARCH-0067 §8).
    ///
    /// A request with a deadline answers by it whatever the blocking work is
    /// doing: past it, the door returns the pack recall published before its
    /// retrieval ran (no items, `partial`, under the reader's receipt), and the
    /// cut work stops at its next checkpoint.
    pub(crate) async fn recall_off_runtime(
        self: &Arc<Self>,
        actor: EntityId,
        class: EdgeActorClass,
        proof: Option<VerifiedSlip>,
        room: Option<EntityId>,
        input: RecallRequest,
    ) -> MemoryResult<MemoryPack> {
        let arrived = Instant::now();
        let (_, budget) = oneiron::memory::resolve_recall_dial(
            input.effort,
            input.deadline_ms,
            self.vault.call_mode_deadline(),
        )?;
        let (cut_sender, cut) = std::sync::mpsc::sync_channel(1);
        let server = Arc::clone(self);
        let task = tokio::task::spawn_blocking(move || {
            let publish = move |pack| {
                // The door reads at most one; a full or closed slot is moot.
                let _ = cut_sender.try_send(pack);
            };
            let door = RecallDoor {
                arrived,
                on_cut: budget.map(|_| &publish as &(dyn Fn(MemoryPack) + Sync)),
            };
            let memory = server.vault.memory(actor, class);
            let memory = match &proof {
                Some(proof) => memory.with_read_proof(proof),
                None => memory,
            };
            let embed = server.recall_embed(input.effort);
            match room {
                Some(room) => memory
                    .for_room_turn(room)?
                    .recall_at_door(input, embed, &door),
                None => oneiron::task_verb::sdk::recall_at_door(&memory, input, embed, &door),
            }
        });
        let joined = match budget {
            None => task.await,
            Some(budget) => {
                let due = tokio::time::Instant::from_std(arrived + budget);
                match tokio::time::timeout_at(due, task).await {
                    Ok(joined) => joined,
                    Err(_) => {
                        return cut.try_recv().map_err(|_| {
                            MemoryError::new(
                                MEMORY_CODE_INTERNAL,
                                "recall reached its deadline before it could read",
                                &["Retry the call, or allow a longer deadline_ms."],
                            )
                        });
                    }
                }
            }
        };
        joined.unwrap_or_else(|error| {
            tracing::warn!(%error, "recall task failed to join");
            Err(MemoryError::new(
                MEMORY_CODE_INTERNAL,
                "recall did not finish",
                &["Retry the call."],
            ))
        })
    }

    /// The query's vector, or `None` when no embedder is serving.
    fn recall_query_vector(&self, query: &str) -> Option<Vec<f32>> {
        match self.embedder.as_ref()?.embed_query(query) {
            Ok(vector) => Some(vector),
            // The model is still loading; the worker logs its own progress.
            Err(EmbedQueryRefusal::NotReady | EmbedQueryRefusal::NotConfigured) => None,
            Err(EmbedQueryRefusal::Failed) => {
                tracing::debug!("recall runs sparse: the query did not embed");
                None
            }
        }
    }
}

/// Runs blocking work from a synchronous caller that may sit on a runtime
/// worker. On a multi-thread runtime worker the worker hands its other tasks
/// to another thread first; inside a current-thread runtime the work runs on
/// a thread of its own, outside the async context; anywhere else it simply
/// runs. Not for use inside a `LocalSet`; [`crate::build_app`] asks hosts
/// not to serve from one.
pub(crate) fn blocking<R: Send>(work: impl FnOnce() -> R + Send) -> R {
    match tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(work),
        Ok(_) => std::thread::scope(|scope| {
            scope
                .spawn(work)
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
        }),
        Err(_) => work(),
    }
}
