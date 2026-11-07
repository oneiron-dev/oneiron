//! Caller-bound live results exist only while an admitted consumer watches.
use std::sync::{Arc, PoisonError};

use oneiron::EntityId;
use oneiron::outbound_consent::{ConnectorCallOutcome, UntrustedToolResult};
use oneiron::task_verb::sdk::{ConnectorCallReply, ConnectorToolResult};

use super::ConnectorElicitationRegistry;

type ResultKey = (EntityId, EntityId);

pub(super) struct ObservedResult {
    watchers: usize,
    result: Option<Arc<ConnectorToolResult>>,
}

/// Owns interest before dispatch and through the observing future's teardown.
pub(crate) struct ConnectorResultInterest {
    registry: Arc<ConnectorElicitationRegistry>,
    key: ResultKey,
}

impl ConnectorElicitationRegistry {
    pub(crate) fn observe_result(
        self: &Arc<Self>,
        principal: EntityId,
        call_ref: EntityId,
    ) -> ConnectorResultInterest {
        let key = (principal, call_ref);
        let mut observed = self
            .live_results
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let entry = observed.entry(key).or_insert(ObservedResult {
            watchers: 0,
            result: None,
        });
        entry.watchers += 1;
        ConnectorResultInterest {
            registry: Arc::clone(self),
            key,
        }
    }

    /// The worker calls this after clearing its reply, before settling its row.
    /// Unwatched calls retain nothing; the original answer still owns its event.
    pub(crate) fn publish_observed_result(&self, handle: &str, result: &UntrustedToolResult) {
        let binding = {
            let live = self.lock();
            let Some(entry) = live.get(handle) else {
                return;
            };
            let Some(call_ref) = entry.call_ref else {
                return;
            };
            (entry.binding.clone(), call_ref)
        };
        let (binding, call_ref) = binding;
        let mut observed = self
            .live_results
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(entry) = observed.get_mut(&(binding.principal, call_ref)) else {
            return;
        };
        if entry.result.is_some() {
            return;
        }
        if let ConnectorCallReply::Delivered {
            result: Some(result),
            ..
        } = ConnectorCallReply::project(
            &binding.name,
            &binding.tool,
            ConnectorCallOutcome::Delivered {
                intent: binding.parent_intent,
                result: Some(result.clone()),
                result_absence: None,
                budget_steering: Vec::new(),
            },
        ) {
            entry.result = Some(Arc::new(result));
        }
    }
}

impl ConnectorResultInterest {
    pub(crate) fn call_ref(&self) -> EntityId {
        self.key.1
    }

    /// Each session has its own once gate; no global take deprives a co-watcher.
    pub(crate) fn result(&self) -> Option<Arc<ConnectorToolResult>> {
        self.registry
            .live_results
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&self.key)
            .and_then(|entry| entry.result.clone())
    }
}

impl Drop for ConnectorResultInterest {
    fn drop(&mut self) {
        let mut observed = self
            .registry
            .live_results
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = observed.get_mut(&self.key) {
            entry.watchers -= 1;
            if entry.watchers == 0 {
                observed.remove(&self.key);
            }
        }
    }
}
