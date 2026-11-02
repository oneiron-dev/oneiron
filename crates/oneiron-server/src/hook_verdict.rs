//! `ai.verdict` for fact hooks (ARCH-0080 §4 Its shape): a hook that
//! declares the generative class asks through the same decision ladder the
//! `ai.verdict` row climbs, for the reader its grant names, its evidence
//! shown only as that grant shows it (FIX 10068) and its model calls charged
//! once to its pack line (FIX 10075). The hook's budget is an accounting
//! deadline that never shortens or refuses its verdict (FIX 8842): a
//! deadline the request names stands as named.

use std::cell::RefCell;
use std::sync::{Arc, Weak};
use std::time::Instant;

use oneiron::EntityId;
use oneiron::memory::ProducerRows;
use oneiron::runtime_hooks::{
    HookSettledCallRef, HookVerdict, HookVerdictContext, HookVerdictReply,
};
use oneiron::task_verb::sdk::{AI_VERDICT_DEADLINE_MS, AiVerdictRequest};

use crate::server::SyncServer;

thread_local! {
    /// The hook decisions a browser call collects on this thread while it
    /// runs its row's hooks (FIX 8042).
    static COLLECTED: RefCell<Option<Vec<serde_json::Value>>> = const { RefCell::new(None) };
}

/// Runs `run`, collecting each hook `ai.verdict` decision this thread
/// answers meanwhile (FIX 8042): a browser batch's or library run's pre and
/// post hooks, which run on the calling thread, so the run's `model_free`
/// reads them. Record only: no ceiling is set and no verdict changes.
pub(crate) fn collect_hook_decisions<R>(run: impl FnOnce() -> R) -> (R, Vec<serde_json::Value>) {
    let outer = COLLECTED.with(|collected| collected.replace(Some(Vec::new())));
    let ran = run();
    let decisions = COLLECTED.with(|collected| collected.replace(outer));
    (ran, decisions.unwrap_or_default())
}

/// The server's verdict host for the fact-hook runner. It holds the server
/// weakly: the runner must not keep a stopping server alive.
pub(crate) struct ServerHookVerdict(Weak<SyncServer>);

impl ServerHookVerdict {
    pub(crate) fn new(server: &Arc<SyncServer>) -> Self {
        Self(Arc::downgrade(server))
    }

    /// One verdict in `context`, its reads listing in `producers` and its
    /// evidence's rows in `evidence`; beside it, the calls it settled.
    fn ask(
        &self,
        context: &HookVerdictContext,
        request_json: &str,
        producers: &ProducerRows,
        evidence: &mut Vec<EntityId>,
    ) -> (Result<String, String>, Vec<HookSettledCallRef>) {
        let Some(server) = self.0.upgrade() else {
            return (Err("the server is stopping".to_owned()), Vec::new());
        };
        let mut request: AiVerdictRequest = match serde_json::from_str(request_json) {
            Ok(request) => request,
            Err(error) => {
                return (
                    Err(format!("invalid ai.verdict request: {error}")),
                    Vec::new(),
                );
            }
        };
        request.deadline_ms = verdict_deadline_ms(request.deadline_ms, context.deadline);
        let memory = server
            .vault
            .memory(context.grant.reader, context.reader_class())
            .listing_producers(producers);
        // The hook's pack line, resolved here from its binding: every rung
        // the verdict reaches spends on it once. A hook pulls no image: it
        // has no credential lane to pull one with, and no browser holds one
        // for it.
        let line = server.vault.hook_pack_line(context);
        let (verdict, calls) = crate::decision_verdict::hook::run_hook_verdict(
            &server, context, &line, &memory, &request, evidence,
        );
        let reply = verdict
            .map_err(|error| format!("{}: {}", error.code, error.message))
            .and_then(|verdict| {
                // A browser call collecting its hooks' decisions keeps this one.
                COLLECTED.with(|collected| {
                    if let Some(decisions) = collected.borrow_mut().as_mut() {
                        decisions.push(serde_json::to_value(&verdict).unwrap_or_default());
                    }
                });
                serde_json::to_string(&verdict).map_err(|_| "the verdict did not encode".to_owned())
            });
        (reply, calls)
    }
}

impl HookVerdict for ServerHookVerdict {
    fn verdict(&self, context: &HookVerdictContext, request_json: &str) -> HookVerdictReply {
        // The rows the ask resolved its evidence to, and any its reads
        // listed; a refusal before it reads lists none.
        let mut evidence = Vec::new();
        let producers = ProducerRows::default();
        let (reply, calls) = self.ask(context, request_json, &producers, &mut evidence);
        evidence.extend(producers.take());
        HookVerdictReply {
            reply,
            evidence,
            calls,
        }
    }
}

/// A hook verdict's deadline (FIX 8842): the one its request names, as
/// named; else the `ai.verdict` default, or the hook run's time left when
/// that is longer, as a long hook budget gave its verdicts before. The
/// hook's deadline only ever lengthens a verdict's time: it never shortens
/// one and never refuses one once it has passed.
fn verdict_deadline_ms(own: Option<u64>, hook_deadline: Instant) -> Option<u64> {
    if own.is_some() {
        return own;
    }
    let left = u64::try_from(
        hook_deadline
            .saturating_duration_since(Instant::now())
            .as_millis(),
    )
    .unwrap_or(u64::MAX);
    (left > AI_VERDICT_DEADLINE_MS).then_some(left)
}
