//! A host-backed HydeExpander: typed work is handed to the caller's own host,
//! outside every vault transaction. Completing it never writes vault content.
use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use oneiron::memory::{Effort, Memory, MemoryError, MemoryResult};
use oneiron::query_expansion::host::*;
use oneiron::query_expansion::{CompletionRequest, EvidenceVerdict, HydeBinding, HydeExpander, HydeExpansion, HydeRequest};
use oneiron::{EntityId, Error};

/// Host work and its completion history are bounded together, per server instance.
const HOST_WORK_LIMIT: usize = 1024;

#[derive(Default)]
pub(crate) struct HydeHost {
    state: Mutex<HostState>,
    changed: Condvar,
}

#[derive(Default)]
struct HostState {
    binding: Option<HydeHostConfig>,
    generation: u64,
    work: BTreeMap<String, Work>,
}

struct Work {
    credential: [u8; 32],
    request: HydeHostWork,
    receipt: HydeHostReceipt,
    answer_at: Option<Instant>,
    answer: Option<HydeHostAnswer>,
    waiting: bool,
}

impl HydeHost {
    fn lock(&self) -> MemoryResult<MutexGuard<'_, HostState>> {
        self.state.lock().map_err(|_| MemoryError::bad_request("HyDE host state is unavailable"))
    }

    pub(crate) fn configure(&self, input: HydeHostConfigureRequest) -> MemoryResult<HydeHostConfiguration> {
        let mut state = self.lock()?;
        if let Some(binding) = &input.binding {
            if binding.expander.trim().is_empty() {
                return Err(MemoryError::bad_request("expander must not be empty"));
            }
            binding.options.validate()?;
        }
        for work in state.work.values_mut() {
            if work.receipt.status == HydeHostStatus::Pending {
                work.receipt.status = HydeHostStatus::Cancelled;
            }
        }
        state.generation = state.generation.wrapping_add(1);
        state.binding = input.binding;
        self.changed.notify_all();
        Ok(HydeHostConfiguration { binding: state.binding.clone() })
    }

    pub(crate) fn configuration(&self) -> MemoryResult<HydeHostConfiguration> {
        Ok(HydeHostConfiguration { binding: self.lock()?.binding.clone() })
    }

    pub(crate) fn pending(&self, credential: [u8; 32], input: HydeHostPendingRequest) -> MemoryResult<Vec<HydeHostWork>> {
        let limit = input.limit.unwrap_or(100);
        oneiron::memory::caps::check_limit_nonzero(limit)?;
        let state = self.lock()?;
        Ok(state.work.values().filter(|work| {
            work.credential == credential && work.receipt.status == HydeHostStatus::Pending
                && work.answer_at.is_none_or(|at| Instant::now() < at)
        }).take(limit.min(HOST_WORK_LIMIT)).map(|work| work.request.clone()).collect())
    }

    pub(crate) fn receipt(&self, credential: [u8; 32], input: HydeHostReceiptRequest) -> MemoryResult<Option<HydeHostReceipt>> {
        let state = self.lock()?;
        Ok(state.work.get(&input.request_id).filter(|work| work.credential == credential)
            .map(|work| work.receipt.clone()))
    }

    pub(crate) fn complete(&self, vault: &oneiron::Vault, credential: [u8; 32], input: HydeHostCompleteRequest) -> MemoryResult<HydeHostReceipt> {
        let mut state = self.lock()?;
        let work = state.work.get_mut(&input.request_id)
            .filter(|work| work.credential == credential)
            .ok_or_else(|| MemoryError::bad_request("unknown HyDE host request"))?;
        if !matches!(work.receipt.status, HydeHostStatus::Pending | HydeHostStatus::Expired) {
            return Err(MemoryError::bad_request("HyDE host request is already settled"));
        }
        match (&work.request.input, &input.answer) {
            (HydeHostInput::Expansion { request }, HydeHostAnswer::Expansion { expansion }) => {
                oneiron::query_expansion::validate_hyde_expansion(vault, expansion)?;
                if expansion.grounded_query != request.query {
                    return Err(MemoryError::bad_request("expansion must keep the grounded request query"));
                }
            }
            (HydeHostInput::Evidence { .. }, HydeHostAnswer::Evidence { .. })
            | (_, HydeHostAnswer::Failed { .. }) => {}
            _ => return Err(MemoryError::bad_request("HyDE answer does not match the pending stage")),
        }
        let received_bytes = serde_json::to_vec(&input.answer)
            .map_err(|_| MemoryError::bad_request("HyDE answer cannot be encoded"))?.len();
        let late = work.answer_at.is_some_and(|at| Instant::now() >= at);
        work.receipt.completed_at_ms = Some(now_ms());
        work.receipt.received_bytes = received_bytes;
        work.receipt.status = if late {
            HydeHostStatus::DiscardedDeadline
        } else if matches!(input.answer, HydeHostAnswer::Failed { .. }) {
            HydeHostStatus::Failed
        } else {
            HydeHostStatus::Completed
        };
        // Late bytes are receipted, never retained as an answer the engine could consume.
        if !late {
            work.answer = Some(input.answer);
        }
        let receipt = work.receipt.clone();
        self.changed.notify_all();
        Ok(receipt)
    }

    pub(crate) fn expander<'m, 'v>(self: &Arc<Self>, memory: &'m Memory<'v>, effort: Effort, answer_at: Option<Instant>) -> MemoryResult<Option<QueuedHyde<'m, 'v>>> {
        if !effort.requires_rerank() {
            return Ok(None);
        }
        let state = self.lock()?;
        let Some(config) = state.binding.clone() else { return Ok(None); };
        let credential = memory.hyde_host_credential_key()?;
        Ok(Some(QueuedHyde {
            host: Arc::clone(self), memory, config, answer_at,
            credential, generation: state.generation,
        }))
    }
}

pub(crate) struct QueuedHyde<'m, 'v> {
    host: Arc<HydeHost>,
    memory: &'m Memory<'v>,
    config: HydeHostConfig,
    answer_at: Option<Instant>,
    credential: [u8; 32],
    generation: u64,
}

impl QueuedHyde<'_, '_> {
    pub(crate) fn binding(&self) -> HydeBinding<'_> {
        (self, &self.config.grounding, self.config.options)
    }

    fn ask(&self, input: HydeHostInput) -> oneiron::Result<HydeHostAnswer> {
        let mut state = self.host.state.lock().map_err(|_| host_error())?;
        if self.answer_at.is_some_and(|at| Instant::now() >= at) {
            return Err(Error::RetrievalStageCut);
        }
        // A replaced binding cannot enqueue work after configure cancelled its old requests.
        if state.generation != self.generation {
            return Err(host_error());
        }
        if state.work.len() >= HOST_WORK_LIMIT {
            let retired = state.work.iter().find(|(_, work)| !work.waiting
                && work.receipt.status != HydeHostStatus::Pending).map(|(id, _)| id.clone());
            match retired {
                Some(id) => { state.work.remove(&id); }
                None => return Err(Error::InvalidConfig("HyDE host queue is full".to_owned())),
            }
        }
        let request_id = EntityId::now().to_hex();
        let requested_at_ms = now_ms();
        let deadline_at_ms = self.answer_at.map(|at| requested_at_ms.saturating_add(
            u64::try_from(at.saturating_duration_since(Instant::now()).as_millis()).unwrap_or(u64::MAX)));
        let receipt = HydeHostReceipt {
            request_id: request_id.clone(), expander: self.config.expander.clone(),
            requested_at_ms, deadline_at_ms, completed_at_ms: None,
            status: HydeHostStatus::Pending, received_bytes: 0,
        };
        state.work.insert(request_id.clone(), Work {
            credential: self.credential,
            request: HydeHostWork { request_id: request_id.clone(), expander: self.config.expander.clone(), requested_at_ms, deadline_at_ms, input },
            receipt, answer_at: self.answer_at, answer: None, waiting: true,
        });
        loop {
            let work = state.work.get_mut(&request_id).ok_or_else(host_error)?;
            if self.answer_at.is_some_and(|at| Instant::now() >= at) {
                if work.receipt.status == HydeHostStatus::Pending {
                    work.receipt.status = HydeHostStatus::Expired;
                }
                work.answer = None;
                work.waiting = false;
                return Err(Error::RetrievalStageCut);
            }
            if let Some(answer) = work.answer.take() {
                work.waiting = false;
                return match answer {
                    HydeHostAnswer::Failed { .. } => Err(host_error()),
                    answer => Ok(answer),
                };
            }
            if work.receipt.status == HydeHostStatus::Cancelled {
                work.waiting = false;
                return Err(host_error());
            }
            state = match self.answer_at {
                Some(at) => self.host.changed.wait_timeout(state, at.saturating_duration_since(Instant::now()))
                    .map_err(|_| host_error())?.0,
                None => self.host.changed.wait(state).map_err(|_| host_error())?,
            };
        }
    }
}

impl HydeExpander for QueuedHyde<'_, '_> {
    fn id(&self) -> &str { &self.config.expander }

    fn expand(&self, request: &HydeRequest) -> oneiron::Result<HydeExpansion> {
        match self.ask(HydeHostInput::Expansion { request: request.clone() })? {
            HydeHostAnswer::Expansion { expansion } => Ok(expansion),
            _ => Err(host_error()),
        }
    }

    fn assess_evidence(&self, request: &CompletionRequest) -> oneiron::Result<EvidenceVerdict> {
        let input = HydeHostInput::evidence(self.memory, request).map_err(|_| host_error())?;
        match self.ask(input)? {
            HydeHostAnswer::Evidence { verdict } => Ok(verdict),
            _ => Err(host_error()),
        }
    }
}

fn host_error() -> Error {
    Error::InvalidConfig("HyDE host did not supply an answer".to_owned())
}

fn now_ms() -> u64 {
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()).unwrap_or(u64::MAX)
}
