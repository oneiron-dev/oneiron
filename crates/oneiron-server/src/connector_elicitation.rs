//! The questions a connector asks mid-call, kept live for their caller, and
//! the caller's answers (ONE-2510).
//!
//! A connector that answers `tools/call` with questions has received the
//! call; its host hands the open exchange to a worker thread and the caller
//! gets the questions back as foreign data, with a handle. This registry,
//! one per server, holds each live question set: the handle, what it binds
//! (the original call's principal, exact grant, governing key, parent
//! intent, connector, tool, endpoint and protocol revision), its round and
//! its live lease, and the channel to its worker. The worker owns the
//! exchange; the registry holds no borrow of it, no credential and no
//! answer.
//!
//! An answer (`connector.answer`) names the handle. Holding it is not
//! authority: only the principal the question binds may answer, once per
//! round. The answer is frozen once, checked under the original grant
//! ([`oneiron::Vault::authorize_connector_elicitation_answer`]), asked of
//! the owner when the key's setting says so, and only then handed to the
//! worker, which sends exactly those bytes and answers with whatever the
//! connector says next: another round of questions under the same handle,
//! the tool's result, or a failure.
//!
//! A set's round is durable too (FIX 3837): the engine keeps it on the
//! call's row (its handle, generation and count, never the questions'
//! text), which its caller polls by `connector.call_status`, and the
//! registry knows that row, so the worker keeps it current. A round
//! never lapses: its worker waits for an answer for as long as the exchange
//! lives, and an exchange that ends unanswered leaves the questions standing
//! with their delivery uncertain.
//!
//! The calls (canon silent), each in one place:
//! - [`ELICITATION_LIVE_WAIT`]: a round's live lease, how long one answer
//!   call waits on the owner before it answers that the owner's ruling is
//!   still to come. Never an expiry.
//! - The live question sets one server holds are the `[limits]` row
//!   `connector_live_questions` (FIX 3895): a question past it still
//!   registers and waits like any other, and the row asks whether
//!   everything is okay. Only the memory floor ends a question.
//! - [`answer_connector_question`]'s owner ask: under `always ask` an answer
//!   that carries content waits for the owner's consent on exactly that
//!   answer (FIX 8808): approve once, approve and stop asking (a standing
//!   grant covers later answers), or deny, which sends a decline. Only the
//!   owner's authenticated press rules, and the send spends its once mark.
//!   Past the lease the ask stays, and the same answer given again reads
//!   its ruling.
//! - [`check_answer`]: the answer that goes is read by the release check's
//!   secret shapes; a match raises the owner's typed "is everything okay"
//!   check and never stops the answer (FIX 3841).

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use oneiron::EntityId;
use oneiron::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use oneiron::outbound_consent::{
    ConnectorAwaitingInput, ConnectorCallOutcome, ConnectorElicitationAnswer,
    ConnectorElicitationBinding, ConnectorElicitationOwnerAsk, ConnectorQuestion,
    ElicitationAnswerVerdict, UntrustedToolResult,
};
use oneiron::task_verb::sdk::{
    ConnectorAnswerAction, ConnectorAnswerRequest, ConnectorCallReply, ConnectorQuestionAnswer,
};
use rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::connector_call_host::elicitation_response;
use crate::server::SyncServer;

mod owner;
pub(crate) use owner::press_owner_consent;
use owner::{owner_rules, spend_owner_consent, withdraw_owner_ask};

/// A round's live lease, from when it arrived: how long one answer call
/// waits on the owner's ruling. Never an expiry (FIX 3837).
pub(crate) const ELICITATION_LIVE_WAIT: Duration = Duration::from_secs(120);

/// How often an answer waiting on the owner reads the ask again, for an
/// answer given through a door that wakes no waiter.
const OWNER_ASK_POLL: Duration = Duration::from_secs(2);

/// What one live question set binds: who may answer it and under what
/// authority. Ids and names only, never a question's text, an answer or a
/// credential. A round's resume state keeps it (FIX 9157).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QuestionBinding {
    /// The original call's principal: the verified actor of its caller.
    pub(crate) principal: EntityId,
    /// The exact standing grant the call ran under.
    pub(crate) grant_id: EntityId,
    /// The governing connector key the call was prepared against.
    pub(crate) key_ref: EntityId,
    /// The call's ledger intent.
    pub(crate) parent_intent: Option<[u8; 32]>,
    /// The catalog name the caller called.
    pub(crate) name: String,
    pub(crate) server: String,
    pub(crate) tool: String,
    pub(crate) endpoint: String,
    pub(crate) revision: String,
}

impl QuestionBinding {
    pub(crate) fn authority(&self) -> ConnectorElicitationBinding {
        ConnectorElicitationBinding {
            principal_ref: self.principal.to_hex(),
            grant_id: self.grant_id,
            key_ref: self.key_ref,
            name: self.name.clone(),
            server: self.server.clone(),
            tool: self.tool.clone(),
            endpoint: self.endpoint.clone(),
        }
    }
}

/// One answer for a worker to send: the frozen responses by question key,
/// as the connector's wire takes them, and where its next event goes.
pub(crate) struct AnswerCommand {
    pub(crate) responses: BTreeMap<String, Value>,
    pub(crate) reply: mpsc::SyncSender<WorkerEvent>,
}

/// What a worker met after it sent an answer.
pub(crate) enum WorkerEvent {
    /// The connector asked again: the next round, under the same handle.
    Question {
        questions: Vec<ConnectorQuestion>,
        live_until_ms: u64,
    },
    /// The call's terminal reply.
    Result(UntrustedToolResult),
    /// The answer, or the reading after it, failed; `sent` when the answer
    /// may have reached the connector.
    Failed { sent: bool, reason: &'static str },
}

/// A question set the registry took in: its handle, the end of its round's
/// live lease, the worker's end of its channel, and the live sets the
/// registry held with it.
pub(crate) struct Registered {
    pub(crate) handle: String,
    pub(crate) live_until_ms: u64,
    pub(crate) commands: mpsc::Receiver<AnswerCommand>,
    pub(crate) live: usize,
}

/// One live question set.
struct LiveQuestions {
    binding: QuestionBinding,
    generation: u64,
    /// The connector's questions this round, kept so an owner ask can quote
    /// them and a pending answer can name them. Foreign text: never logged
    /// or receipted.
    questions: Vec<ConnectorQuestion>,
    /// The end of this round's live lease.
    lease: Instant,
    live_until_ms: u64,
    /// An answer to this round is being decided or sent: a round takes one.
    claimed: bool,
    commands: mpsc::Sender<AnswerCommand>,
    /// The call whose row keeps these questions (FIX 3837), once the engine
    /// kept them.
    call_ref: Option<EntityId>,
    /// The owner ask about one exact answer to this round still to be
    /// ruled on, by the answer's digest: the same answer given again reads
    /// it, never a second ask.
    owner_ask: Option<([u8; 32], ConnectorElicitationOwnerAsk)>,
}

/// The live question sets of one server, by handle.
#[derive(Default)]
pub(crate) struct ConnectorElicitationRegistry {
    live: Mutex<HashMap<String, LiveQuestions>>,
}

impl ConnectorElicitationRegistry {
    fn lock(&self) -> MutexGuard<'_, HashMap<String, LiveQuestions>> {
        self.live.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes in a new question set and mints its handle. It never refuses
    /// one: how many it holds is the `[limits]` row's to measure
    /// (FIX 3895).
    pub(crate) fn register(
        &self,
        binding: QuestionBinding,
        questions: &[ConnectorQuestion],
    ) -> Registered {
        let mut live = self.lock();
        let handle = loop {
            let handle = mint_handle();
            if !live.contains_key(&handle) {
                break handle;
            }
        };
        let (sender, commands) = mpsc::channel();
        let (lease, live_until_ms) = round_lease();
        // Ids only: never the questions' text or the handle.
        tracing::debug!(
            server = %binding.server,
            tool = %binding.tool,
            revision = %binding.revision,
            intent = ?binding.parent_intent.map(|intent| hex(&intent)),
            questions = questions.len(),
            "connector asked for input mid-call"
        );
        live.insert(
            handle.clone(),
            LiveQuestions {
                binding,
                generation: 0,
                questions: questions.to_vec(),
                lease,
                live_until_ms,
                claimed: false,
                commands: sender,
                call_ref: None,
                owner_ask: None,
            },
        );
        Registered {
            handle,
            live_until_ms,
            commands,
            live: live.len(),
        }
    }

    /// Opens round `generation` of `handle` with `questions` and a fresh
    /// lease, and returns the lease's end (unix ms) and the call whose row
    /// keeps the questions; `None` when the set is gone.
    pub(crate) fn advance(
        &self,
        handle: &str,
        generation: u64,
        questions: &[ConnectorQuestion],
    ) -> Option<(u64, Option<EntityId>)> {
        let mut live = self.lock();
        let entry = live.get_mut(handle)?;
        let (lease, live_until_ms) = round_lease();
        entry.generation = generation;
        entry.questions = questions.to_vec();
        entry.lease = lease;
        entry.live_until_ms = live_until_ms;
        entry.claimed = false;
        entry.owner_ask = None;
        Some((live_until_ms, entry.call_ref))
    }

    /// Binds the questions `handle` names to the call `call_ref` whose row
    /// keeps them (FIX 3837); `true` when it bound them. A set whose worker
    /// already ended leaves the row's questions uncertain.
    pub(crate) fn bind_call(
        &self,
        vault: &oneiron::Vault,
        handle: &str,
        call_ref: EntityId,
    ) -> bool {
        let bound = match self.lock().get_mut(handle) {
            Some(entry) => {
                entry.call_ref = Some(call_ref);
                true
            }
            None => false,
        };
        if !bound && let Err(error) = vault.mark_connector_input_uncertain(&call_ref, handle) {
            tracing::warn!(%error, "connector call questions not marked uncertain");
        }
        bound
    }

    /// Whether the question set `handle` names is live here.
    pub(crate) fn holds(&self, handle: &str) -> bool {
        self.lock().contains_key(handle)
    }

    /// Takes in again, after a restart, the question set `handle` names on
    /// the call `call_ref` at round `generation` (FIX 9157): the same
    /// handle, binding and questions, bound to that call, with a fresh lease
    /// and channel. `None` when the set is live already.
    pub(crate) fn restore(
        &self,
        handle: &str,
        call_ref: EntityId,
        generation: u64,
        binding: QuestionBinding,
        questions: &[ConnectorQuestion],
    ) -> Option<Registered> {
        let mut live = self.lock();
        if live.contains_key(handle) {
            return None;
        }
        let (sender, commands) = mpsc::channel();
        let (lease, live_until_ms) = round_lease();
        live.insert(
            handle.to_owned(),
            LiveQuestions {
                binding,
                generation,
                questions: questions.to_vec(),
                lease,
                live_until_ms,
                claimed: false,
                commands: sender,
                call_ref: Some(call_ref),
                owner_ask: None,
            },
        );
        Some(Registered {
            handle: handle.to_owned(),
            live_until_ms,
            commands,
            live: live.len(),
        })
    }

    /// The call whose row keeps the questions `handle` names, once bound.
    pub(crate) fn call_ref(&self, handle: &str) -> Option<EntityId> {
        self.lock().get(handle).and_then(|entry| entry.call_ref)
    }

    /// Keeps the owner ask about the answer `digest` to round `generation`
    /// of `handle`, or forgets it (`None`). `false` when that round is gone.
    fn keep_owner_ask(
        &self,
        handle: &str,
        generation: u64,
        ask: Option<([u8; 32], ConnectorElicitationOwnerAsk)>,
    ) -> bool {
        match self.lock().get_mut(handle) {
            Some(entry) if entry.generation == generation => {
                entry.owner_ask = ask;
                true
            }
            _ => false,
        }
    }

    /// Drops a question set its worker ended, and withdraws the owner ask
    /// it still kept, with its parts, from `vault`'s queue: no exchange is
    /// left to send that answer to (FIX 9160).
    pub(crate) fn finish(&self, vault: Option<&oneiron::Vault>, handle: &str) {
        let kept = self.lock().remove(handle).and_then(|entry| entry.owner_ask);
        if let (Some(vault), Some((_, asked))) = (vault, kept) {
            withdraw_owner_ask(vault, &asked);
        }
    }

    /// Claims the current round of `handle` for one answer by `principal`.
    /// A round past its lease is still answered (FIX 3837).
    fn claim(&self, handle: &str, principal: EntityId) -> MemoryResult<Claim<'_>> {
        let mut live = self.lock();
        let entry = live
            .get_mut(handle)
            .filter(|entry| entry.binding.principal == principal)
            .ok_or_else(|| {
                MemoryError::not_found(
                    "no live connector question with this handle is yours to answer",
                )
            })?;
        if entry.claimed {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "an answer to this round of the connector's questions is already on its way",
                &[
                    "Wait for that answer's reply; it carries the connector's next questions, if any.",
                ],
            ));
        }
        entry.claimed = true;
        Ok(Claim {
            registry: self,
            handle: handle.to_owned(),
            generation: entry.generation,
            binding: entry.binding.clone(),
            questions: entry.questions.clone(),
            lease: entry.lease,
            live_until_ms: entry.live_until_ms,
            call_ref: entry.call_ref,
            owner_ask: entry.owner_ask.clone(),
            commands: entry.commands.clone(),
            handed: false,
        })
    }

    /// Frees round `generation` of `handle` for another answer.
    fn release(&self, handle: &str, generation: u64) {
        if let Some(entry) = self.lock().get_mut(handle)
            && entry.generation == generation
        {
            entry.claimed = false;
        }
    }
}

/// 32 random bytes, hex: a question set's handle.
fn mint_handle() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex(&bytes)
}

/// `bytes` as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// A new round's live lease end, as an instant and in unix ms.
fn round_lease() -> (Instant, u64) {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        });
    let wait_ms = u64::try_from(ELICITATION_LIVE_WAIT.as_millis()).unwrap_or(u64::MAX);
    (
        Instant::now() + ELICITATION_LIVE_WAIT,
        now_ms.saturating_add(wait_ms),
    )
}

/// One round claimed for one answer. Dropped before the answer went to the
/// worker, it frees the round again.
struct Claim<'a> {
    registry: &'a ConnectorElicitationRegistry,
    handle: String,
    generation: u64,
    binding: QuestionBinding,
    questions: Vec<ConnectorQuestion>,
    lease: Instant,
    live_until_ms: u64,
    call_ref: Option<EntityId>,
    owner_ask: Option<([u8; 32], ConnectorElicitationOwnerAsk)>,
    commands: mpsc::Sender<AnswerCommand>,
    /// The worker took the answer: it opens the next round or ends the set.
    handed: bool,
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        if !self.handed {
            self.registry.release(&self.handle, self.generation);
        }
    }
}

impl Claim<'_> {
    fn keys(&self) -> Vec<&str> {
        self.questions
            .iter()
            .map(|question| question.key.as_str())
            .collect()
    }

    /// Hands the frozen responses to the worker and waits for what it met
    /// next; `None` when the worker is gone (its exchange ended, or the
    /// server is closing).
    fn hand_over(mut self, responses: BTreeMap<String, Value>) -> Option<WorkerEvent> {
        let (reply, events) = mpsc::sync_channel(1);
        self.commands
            .send(AnswerCommand { responses, reply })
            .ok()?;
        self.handed = true;
        events.recv().ok()
    }
}

/// One answer, frozen once: the responses by key, their canonical text and
/// its digest, and whether any of it carries content.
struct FrozenAnswer {
    responses: BTreeMap<String, Value>,
    text: String,
    digest: [u8; 32],
    carries_content: bool,
}

impl FrozenAnswer {
    fn new(responses: BTreeMap<String, Value>, carries_content: bool) -> Self {
        let text = Value::Object(responses.clone().into_iter().collect()).to_string();
        let digest = *blake3::hash(text.as_bytes()).as_bytes();
        Self {
            responses,
            text,
            digest,
            carries_content,
        }
    }

    /// The answer as one JSON object, its responses by key.
    fn value(&self) -> Value {
        Value::Object(self.responses.clone().into_iter().collect())
    }

    /// Every question of the round answered `action`, with no content: what
    /// goes in place of an answer that may not.
    fn replaced(&self, action: ConnectorAnswerAction) -> BTreeMap<String, Value> {
        self.responses
            .keys()
            .map(|key| (key.clone(), elicitation_response(action, None)))
            .collect()
    }
}

/// The caller's answers as one frozen answer to the round's `keys`: each
/// key answered exactly once, content only on accept, and an accepted
/// answer's content a JSON object.
fn freeze(keys: &[&str], answers: &[ConnectorQuestionAnswer]) -> MemoryResult<FrozenAnswer> {
    let mut responses = BTreeMap::new();
    let mut carries_content = false;
    for answer in answers {
        if !keys.contains(&answer.key.as_str()) {
            return Err(MemoryError::bad_request(format!(
                "no question of this round has the key {:?}",
                answer.key
            )));
        }
        let content = match (answer.action, &answer.content) {
            (ConnectorAnswerAction::Accept, Some(Value::Object(_)) | None) => {
                answer.content.as_ref()
            }
            (ConnectorAnswerAction::Accept, Some(_)) => {
                return Err(MemoryError::bad_request(
                    "an accepted answer's content is a JSON object",
                ));
            }
            (_, Some(_)) => {
                return Err(MemoryError::bad_request(
                    "only an accepted answer carries content",
                ));
            }
            (_, None) => None,
        };
        carries_content |= content.is_some();
        let response = elicitation_response(answer.action, content);
        if responses.insert(answer.key.clone(), response).is_some() {
            return Err(MemoryError::bad_request(format!(
                "the question {:?} is answered twice",
                answer.key
            )));
        }
    }
    if responses.len() != keys.len() {
        return Err(MemoryError::bad_request(
            "every question of this round is answered, once",
        ));
    }
    Ok(FrozenAnswer::new(responses, carries_content))
}

/// What the owner made of an answer they were asked about.
enum OwnerRuling {
    Yes,
    No,
    /// The round's live lease ended first: the ask stands, and the same
    /// answer given again reads its ruling (FIX 3837).
    Pending,
    /// The ask could not be queued.
    Unasked,
}

/// `connector.answer` for the caller `memory` is bound to: its answer to the
/// round of questions `request.handle` names. Only the principal the
/// questions bind may answer, once per round. The answer is frozen once and
/// checked under the original call's exact grant; a decline or a cancel
/// always goes. An escalation leaves the round live, so a retry can land; a
/// refusal cancels it. Under `always ask` the owner's yes on exactly this
/// answer sends it and a no sends a decline; past the round's live lease
/// the round stays open, the questions come back with
/// `connector_answer_owner_pending`, and the same answer given again reads
/// the same ask (FIX 3837). The reply is what the connector said next, as
/// `connector.call` projects it. Blocking: it waits on the connector and on
/// the owner, so call it on a blocking worker.
pub(crate) fn answer_connector_question(
    server: &SyncServer,
    memory: &Memory<'_>,
    request: ConnectorAnswerRequest,
) -> MemoryResult<ConnectorCallReply> {
    let claim = server
        .connector_elicitations
        .claim(&request.handle, memory.actor())?;
    // The engine binds a round to its call's row before its caller learns
    // the handle (FIX 9161); a round with no row has nothing to answer on.
    let Some(call_ref) = claim.call_ref else {
        return Ok(gone());
    };
    let frozen = freeze(&claim.keys(), &request.answers)?;
    let authority = claim.binding.authority();
    let answer = ConnectorElicitationAnswer {
        handle: &claim.handle,
        generation: claim.generation,
        questions: &claim.questions,
        answers: &frozen.text,
        digest: frozen.digest,
    };
    let verdict = server
        .vault()
        .authorize_connector_elicitation_answer(
            memory,
            &authority,
            &frozen.value(),
            &answer,
            frozen.carries_content,
        )
        .map_err(MemoryError::from)?;
    let (responses, reasons) = match verdict {
        ElicitationAnswerVerdict::Send => (frozen.responses, Vec::new()),
        ElicitationAnswerVerdict::Refuse(reason) => (
            frozen.replaced(ConnectorAnswerAction::Cancel),
            vec!["connector_answer_refused".to_owned(), reason],
        ),
        ElicitationAnswerVerdict::Escalate(reason) => {
            return Ok(ConnectorCallReply::Refused {
                decision_ref: None,
                reasons: vec!["connector_answer_escalated".to_owned(), reason],
            });
        }
        ElicitationAnswerVerdict::AskOwner => {
            match owner_rules(server, &claim, &call_ref, &authority, &answer) {
                // The send spends the once mark the owner's press left
                // (FIX 8808); one already spent sends nothing again.
                OwnerRuling::Yes if spend_owner_consent(server.vault(), &call_ref, &answer) => {
                    (frozen.responses, Vec::new())
                }
                OwnerRuling::Yes => {
                    return Ok(ConnectorCallReply::Refused {
                        decision_ref: None,
                        reasons: vec!["connector_answer_owner_consent_spent".to_owned()],
                    });
                }
                OwnerRuling::No => (
                    frozen.replaced(ConnectorAnswerAction::Decline),
                    vec!["connector_answer_owner_declined".to_owned()],
                ),
                OwnerRuling::Pending => return Ok(owner_pending(claim, call_ref)),
                OwnerRuling::Unasked => {
                    return Ok(ConnectorCallReply::Refused {
                        decision_ref: None,
                        reasons: vec!["connector_answer_owner_ask_unqueued".to_owned()],
                    });
                }
            }
        }
    };
    check_answer(server, &claim, &authority, &responses);
    let (name, tool, intent) = (
        claim.binding.name.clone(),
        claim.binding.tool.clone(),
        claim.binding.parent_intent,
    );
    let handle = claim.handle.clone();
    let Some(event) = claim.hand_over(responses) else {
        return Ok(gone().noting(reasons));
    };
    Ok(match event {
        WorkerEvent::Question {
            questions,
            live_until_ms,
        } => ConnectorCallReply::awaiting_input(
            &name,
            &tool,
            call_ref,
            ConnectorAwaitingInput {
                handle,
                questions,
                live_until_ms,
            },
        ),
        WorkerEvent::Result(result) => ConnectorCallReply::project(
            &name,
            &tool,
            ConnectorCallOutcome::Delivered {
                intent,
                result: Some(result),
            },
        ),
        WorkerEvent::Failed {
            sent: false,
            reason,
        } => ConnectorCallReply::Refused {
            decision_ref: None,
            reasons: vec![reason.to_owned()],
        },
        WorkerEvent::Failed { sent: true, reason } => ConnectorCallReply::PendingDelivery {
            call_ref: None,
            reasons: vec![reason.to_owned()],
        },
    }
    .noting(reasons))
}

/// Runs the release check's secret shapes over the answer about to go, as
/// it goes (FIX 3841, ruled 10-22): a match raises the owner's typed "is
/// everything okay" check on detached work, and the answer goes either way.
/// Nothing here refuses, holds or waits on the check, its storage or the
/// owner; a check that cannot be raised is logged.
fn check_answer(
    server: &SyncServer,
    claim: &Claim<'_>,
    authority: &ConnectorElicitationBinding,
    responses: &BTreeMap<String, Value>,
) {
    let answer = Value::Object(responses.clone().into_iter().collect());
    let digest = *blake3::hash(answer.to_string().as_bytes()).as_bytes();
    // The check reads a copy: what goes is `responses`, untouched.
    if !oneiron::batch::export::redact_credentials(&mut answer.clone()) {
        return;
    }
    let vault = Arc::clone(server.vault());
    let (authority, handle, generation) =
        (authority.clone(), claim.handle.clone(), claim.generation);
    let raise = move || {
        if let Err(error) = vault.queue_connector_elicitation_answer_check(
            &authority, &handle, generation, digest, &answer,
        ) {
            tracing::warn!(%error, "connector answer check not queued");
        }
    };
    match tokio::runtime::Handle::try_current() {
        Ok(runtime) => drop(runtime.spawn_blocking(raise)),
        Err(_) => {
            if let Err(error) = std::thread::Builder::new()
                .name("connector-answer-check".to_owned())
                .spawn(raise)
            {
                tracing::warn!(%error, "connector answer check not started");
            }
        }
    }
}

/// The reply to an answer whose live exchange ended before it went:
/// nothing was sent, and the call's row keeps the questions, uncertain
/// (FIX 3837).
fn gone() -> ConnectorCallReply {
    ConnectorCallReply::Refused {
        decision_ref: None,
        reasons: vec!["connector_question_gone".to_owned()],
    }
}

/// The reply to an answer still waiting on the owner past the round's live
/// lease: the round's questions again, with the reason. Nothing was sent;
/// the claim is released, so the same answer given again reads the ruling.
fn owner_pending(claim: Claim<'_>, call_ref: EntityId) -> ConnectorCallReply {
    ConnectorCallReply::awaiting_input(
        &claim.binding.name,
        &claim.binding.tool,
        call_ref,
        ConnectorAwaitingInput {
            handle: claim.handle.clone(),
            questions: claim.questions.clone(),
            live_until_ms: claim.live_until_ms,
        },
    )
    .noting(vec!["connector_answer_owner_pending".to_owned()])
}
