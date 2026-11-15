//! One charged refresh of a parked run's cached prompt prefix (L2-37 PR-3).
//!
//! PR-2 gives a parked run one idle call a minute before its cached prefix
//! expires: Fold or Expire. Keep is the third call: it resends the run's
//! last request exactly as its rung sent it, with only the output limit set
//! to 1, so the provider reads (and so keeps) the cached prefix one more
//! lifetime. The answer's content is dropped; no tool runs.
//!
//! The resident pump holds each running run's answering rung slot on its
//! live-run entry ([`HeldAnsweringRung`]), drops the hold when the run
//! parks, keeps the latest answered rung there when the park left a cached
//! prefix, and refreshes that rung from its idle pass. A refresh is metered as the run's own calls and compaction spend:
//! under the run's spend scope when it has one, else on code mode's meter.

use std::sync::Arc;
use std::time::Duration;

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::llm::run_admission::RunAdmission;
use oneiron::llm::{ServedCacheHorizon, WorkClass, WorkContext};
use oneiron::{BudgetGuard, EntityId, LlmRequest, Vault};

use super::CHAT_ROLE;
use super::compaction::{AnsweringRungSlot, AnsweringRungSlots};
use super::live_lease::LiveLease;
use super::payer_funding::scope_funding;
use crate::models::{AnsweringRung, ModelRuntime};

/// The run each idle prefix refresh is admitted under, one run per call so
/// the server keeps no per-call state.
const IDLE_PREFIX_REFRESH_RUN: &str = "idle_prefix_refresh";

/// How long one refresh waits for its answer before it gives up: the
/// prefix keeps its own lifetime either way, and the pump's pass never
/// waits on a provider.
const REFRESH_TIMEOUT: Duration = Duration::from_secs(20);

/// The idle prefix refresher (L2-37 PR-3): the vault, the runtime its sends
/// go through, code mode's meter for the refreshes no scope pays for, the
/// runs' answering rung slots, and the runtime its sends block on. Built
/// once when code mode binds, set once on the server.
pub(crate) struct PrefixRefresh {
    vault: Arc<Vault>,
    models: Arc<ModelRuntime>,
    guard: BudgetGuard,
    answering: Arc<AnsweringRungSlots>,
    handle: tokio::runtime::Handle,
}

impl PrefixRefresh {
    /// The refresher over `vault`, sending through `models`, metering the
    /// refreshes no scope pays for on `guard`, holding runs' `answering`
    /// slots, and blocking its sends on `handle`.
    pub(crate) fn new(
        vault: Arc<Vault>,
        models: Arc<ModelRuntime>,
        guard: BudgetGuard,
        answering: Arc<AnsweringRungSlots>,
        handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            vault,
            models,
            guard,
            answering,
            handle,
        }
    }

    /// `run`'s answering rung slot, held while the run runs: the one held
    /// already, else a fresh one. The run's step calls fill it as they
    /// answer, beside the compaction writer's own hold of the same slot
    /// (FIX 4933).
    pub(crate) fn hold(&self, run: EntityId) -> HeldAnsweringRung {
        HeldAnsweringRung(self.answering.hold(run))
    }

    /// One charged refresh of `kept`, the run's last request as its rung
    /// sent it: the same bytes with only the output limit set to 1. Under
    /// `scope` it spends on a fresh guard on that scope and books what it
    /// spent, as a compaction pass does; with no scope it spends on code
    /// mode's meter. Returns the horizon the refresh answer stamped, or
    /// `None` when nothing was sent or answered. Blocking; the pump's pass
    /// calls it on a blocking thread.
    pub(crate) fn refresh(
        &self,
        scope: Option<&SpendScopeId>,
        kept: &AnsweringRung,
    ) -> Option<ServedCacheHorizon> {
        // The resend: the kept request's bytes with only the output limit
        // set to 1. The limit is generation-only: the provider reads the
        // cached prompt beside it, never in it (FIX 6492).
        let mut request = (*kept.request).clone();
        request
            .params
            .insert("max_tokens".to_owned(), serde_json::json!(1));
        let (guard, payer) = match scope {
            Some(scope) => {
                let payer = match scope_funding(&self.vault, Some(scope), false) {
                    Ok(payer) => payer,
                    Err(fault) => {
                        tracing::debug!(
                            %fault,
                            "an idle prefix refresh is not funded; it is skipped"
                        );
                        return None;
                    }
                };
                let guard = match AgentDispatcher::new(&self.vault).guard_for_scope(scope) {
                    Ok(guard) => guard,
                    Err(error) => {
                        tracing::debug!(
                            kind = ?error.kind(),
                            "an idle prefix refresh takes no guard; it is skipped"
                        );
                        return None;
                    }
                };
                (guard, payer)
            }
            None => (self.guard.clone(), None),
        };
        let live = scope.map(|scope| {
            LiveLease::new(
                &self.vault,
                Some(scope.clone()),
                guard.clone(),
                guard.read().limit_units,
                0,
            )
        });
        if let Some(live) = &live {
            live.book_and_revise();
        }
        let run = self
            .models
            .funded_run(IDLE_PREFIX_REFRESH_RUN, guard, payer)
            .with_work_context(WorkContext {
                class: WorkClass::Foreground,
                ..Default::default()
            });
        let horizon = self.send(&run, request, kept);
        if let Some(live) = &live
            && let Err(error) = live.book_rest()
        {
            tracing::error!(%error, "an idle prefix refresh's spend did not book on its run's scope");
        }
        horizon
    }

    /// Sends one refresh of `kept`: admitted on the seat-bound path the
    /// step call took, as exactly its rung's model, and sent on the
    /// captured rung alone while its prefix is still warm. The answer's
    /// content is dropped; its stamped horizon is the refresh's. Blocking
    /// on the runtime, up to [`REFRESH_TIMEOUT`].
    fn send(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        kept: &AnsweringRung,
    ) -> Option<ServedCacheHorizon> {
        let admitted = match self
            .models
            .admit_seat_bound(&self.vault, CHAT_ROLE, request)
        {
            Ok(admitted) => admitted,
            Err(refusal) => {
                tracing::debug!(%refusal, "an idle prefix refresh was refused; it is skipped");
                return None;
            }
        };
        let Some(ladder) = admitted.ladder.live_fork_ladder(&kept.rung) else {
            tracing::debug!("an idle prefix refresh's rung is stale; it is skipped");
            return None;
        };
        // The admitted request goes out: admission only normalizes the
        // envelope's routing (its purpose default and its registry
        // locality, both already normalized on the kept request, which the
        // step call's own admission authorized), never the messages, tools,
        // params, options or model the wire body is built from. The rung's
        // re-bind sets the same model and locality and, on this prompt-less
        // fork ladder, adds no prompt, so the bytes are the kept request's
        // with only `max_tokens` changed.
        let sent = self.handle.block_on(tokio::time::timeout(
            REFRESH_TIMEOUT,
            ladder.generate_exact_while_warm(run, admitted.request, &kept.rung, &kept.request),
        ));
        match sent {
            Ok(Ok(Some(response))) => response.usage.served_cache_horizon(),
            Ok(Ok(None)) => {
                tracing::debug!("an idle prefix refresh found its prefix cold; nothing was sent");
                None
            }
            Ok(Err(error)) => {
                tracing::debug!(%error, "an idle prefix refresh failed");
                None
            }
            Err(_) => {
                tracing::debug!("an idle prefix refresh timed out");
                None
            }
        }
    }
}

/// `run`'s answering rung slot held while the run runs (L2-37 PR-3): the
/// pump's hold beside the compaction writer's, dropped when the run parks.
pub(crate) struct HeldAnsweringRung(Arc<AnsweringRungSlot>);

impl HeldAnsweringRung {
    /// The run's latest call that answered, as its rung sent it, held now.
    pub(crate) fn latest(&self) -> Option<AnsweringRung> {
        self.0.latest()
    }
}
