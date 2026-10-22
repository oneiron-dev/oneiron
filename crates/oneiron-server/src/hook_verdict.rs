//! `ai.verdict` for fact hooks (ARCH-0080 §4 Its shape): a hook that
//! declares the generative class asks through the same decision ladder the
//! `ai.verdict` row climbs, for the reader its grant names. The hook's
//! budget is an accounting deadline, never the verdict's (FIX 8842): only a
//! deadline the request itself names bounds its ask.

use std::sync::{Arc, Weak};
use std::time::Instant;

use oneiron::memory::ProducerRows;
use oneiron::runtime_hooks::HookVerdict;
use oneiron::task_verb::sdk::AiVerdictRequest;
use oneiron::{EdgeActorClass, EntityId};

use crate::server::SyncServer;

/// The server's verdict host for the fact-hook runner. It holds the server
/// weakly: the runner must not keep a stopping server alive.
pub(crate) struct ServerHookVerdict(Weak<SyncServer>);

impl ServerHookVerdict {
    pub(crate) fn new(server: &Arc<SyncServer>) -> Self {
        Self(Arc::downgrade(server))
    }

    /// One verdict for `reader`, its reads listing in `producers` and its
    /// evidence's rows in `evidence`.
    fn ask(
        &self,
        reader: EntityId,
        class: EdgeActorClass,
        request_json: &str,
        producers: &ProducerRows,
        evidence: &mut Vec<EntityId>,
    ) -> Result<String, String> {
        let server = self
            .0
            .upgrade()
            .ok_or_else(|| "the server is stopping".to_owned())?;
        let request: AiVerdictRequest = serde_json::from_str(request_json)
            .map_err(|error| format!("invalid ai.verdict request: {error}"))?;
        let memory = server
            .vault
            .memory(reader, class)
            .listing_producers(producers);
        // A hook pulls no image: it has no credential lane to pull one
        // with, and no browser holds one for it.
        let verdict = crate::decision_verdict::run_verdict(
            &server, reader, class, &memory, None, None, &request, None, evidence,
        )
        .map_err(|error| format!("{}: {}", error.code, error.message))?;
        serde_json::to_string(&verdict).map_err(|_| "the verdict did not encode".to_owned())
    }
}

impl HookVerdict for ServerHookVerdict {
    fn verdict(
        &self,
        reader: EntityId,
        class: EdgeActorClass,
        request_json: &str,
        _deadline: Instant,
    ) -> (Result<String, String>, Option<Vec<EntityId>>) {
        // The rows the ask resolved its evidence to, and any its reads
        // listed; a refusal before it reads lists none. The hook run's
        // deadline is advisory: the ask runs to its own end.
        let mut evidence = Vec::new();
        let producers = ProducerRows::default();
        let reply = self.ask(reader, class, request_json, &producers, &mut evidence);
        evidence.extend(producers.take());
        (reply, Some(evidence))
    }
}
