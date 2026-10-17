//! `ai.verdict` for fact hooks (ARCH-0080 §4 Its shape): a hook that
//! declares the generative class asks through the same decision ladder the
//! `ai.verdict` row climbs, for the reader its grant names, by the end of
//! its own budget.

use std::sync::{Arc, Weak};
use std::time::Instant;

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
}

impl HookVerdict for ServerHookVerdict {
    fn verdict(
        &self,
        reader: EntityId,
        class: EdgeActorClass,
        request_json: &str,
        deadline: Instant,
    ) -> Result<String, String> {
        let server = self
            .0
            .upgrade()
            .ok_or_else(|| "the server is stopping".to_owned())?;
        let mut request: AiVerdictRequest = serde_json::from_str(request_json)
            .map_err(|error| format!("invalid ai.verdict request: {error}"))?;
        // The verdict answers inside the hook's own budget.
        let left = u64::try_from(
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        if left == 0 {
            return Err("hook deadline exceeded".to_owned());
        }
        request.deadline_ms = Some(request.deadline_ms.map_or(left, |own| own.min(left)));
        let memory = server.vault.memory(reader, class);
        // A hook pulls no image: it has no credential lane to pull one
        // with, and no browser holds one for it.
        let verdict = crate::decision_verdict::run_verdict(
            &server, reader, class, &memory, None, None, &request,
        )
        .map_err(|error| format!("{}: {}", error.code, error.message))?;
        serde_json::to_string(&verdict).map_err(|_| "the verdict did not encode".to_owned())
    }
}
