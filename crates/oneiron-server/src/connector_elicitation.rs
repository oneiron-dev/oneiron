//! The questions a connector asks mid-call, kept live for their caller, and
//! the caller's answers (ONE-2510).
//!
//! A connector that answers `tools/call` with questions has received the
//! call; its host hands the open exchange to a worker thread and the caller
//! gets the questions back as foreign data, with a handle. This registry,
//! one per server, holds each live question set: the handle, what it binds
//! (the original call's principal, exact grant, governing key, parent
//! intent, connector, tool, endpoint and protocol revision), its round and
//! its deadline, and the channel to its worker. The worker owns the
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
//! The calls (canon silent), each in one place:
//! - [`ELICITATION_WAIT`]: a round of questions lapses this long after it
//!   arrived; its worker then cancels it and ends the session.
//! - The live question sets one server holds are the `[limits]` row
//!   `connector_live_questions` (FIX 3895): a question past it still
//!   registers and waits like any other, and the row asks whether
//!   everything is okay. Only the memory floor and a round's deadline end
//!   a question.
//! - [`answer_connector_question`]'s owner ask: under `always ask` an answer
//!   that carries content waits, within the round's deadline, for the
//!   owner's yes on exactly that answer; a no sends a decline, a lapse
//!   cancels.
//! - [`check_answer`]: the answer that goes is read by the release check's
//!   secret shapes; a match raises the owner's typed "is everything okay"
//!   check and never stops the answer (FIX 3841).

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use oneiron::EntityId;
use oneiron::llm::decision::{DecisionAnswer, DecisionAsks};
use oneiron::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use oneiron::outbound_consent::{
    ConnectorAwaitingInput, ConnectorCallOutcome, ConnectorElicitationAnswer,
    ConnectorElicitationBinding, ConnectorQuestion, ElicitationAnswerVerdict, UntrustedToolResult,
};
use oneiron::task_verb::sdk::{
    ConnectorAnswerAction, ConnectorAnswerRequest, ConnectorCallReply, ConnectorQuestionAnswer,
};
use rand_core::{OsRng, RngCore as _};
use serde_json::Value;

use crate::connector_call_host::elicitation_response;
use crate::server::SyncServer;

/// How long one round of a connector's questions stays live, from when it
/// arrived.
pub(crate) const ELICITATION_WAIT: Duration = Duration::from_secs(120);

/// How often an answer waiting on the owner reads the ask again, for an
/// answer given through a door that wakes no waiter.
const OWNER_ASK_POLL: Duration = Duration::from_secs(2);

/// What one live question set binds: who may answer it and under what
/// authority. Ids and names only, never a question's text, an answer or a
/// credential.
#[derive(Debug, Clone)]
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
        expires_at_ms: u64,
    },
    /// The call's terminal reply.
    Result(UntrustedToolResult),
    /// The answer, or the reading after it, failed; `sent` when the answer
    /// may have reached the connector.
    Failed { sent: bool, reason: &'static str },
}

/// A question set the registry took in: its handle, its round's deadline,
/// the worker's end of its channel, and the live sets the registry held
/// with it.
pub(crate) struct Registered {
    pub(crate) handle: String,
    pub(crate) deadline: Instant,
    pub(crate) expires_at_ms: u64,
    pub(crate) commands: mpsc::Receiver<AnswerCommand>,
    pub(crate) live: usize,
}

/// One live question set.
struct LiveQuestions {
    binding: QuestionBinding,
    generation: u64,
    /// The connector's questions this round, kept only so an owner ask can
    /// quote them. Foreign text: never logged or receipted.
    questions: Vec<ConnectorQuestion>,
    deadline: Instant,
    /// An answer to this round is being decided or sent: a round takes one.
    claimed: bool,
    commands: mpsc::Sender<AnswerCommand>,
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
        let (deadline, expires_at_ms) = round_deadline();
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
                deadline,
                claimed: false,
                commands: sender,
            },
        );
        Registered {
            handle,
            deadline,
            expires_at_ms,
            commands,
            live: live.len(),
        }
    }

    /// Opens round `generation` of `handle` with `questions` and a fresh
    /// deadline; `None` when the set is gone.
    pub(crate) fn advance(
        &self,
        handle: &str,
        generation: u64,
        questions: &[ConnectorQuestion],
    ) -> Option<(Instant, u64)> {
        let mut live = self.lock();
        let entry = live.get_mut(handle)?;
        let (deadline, expires_at_ms) = round_deadline();
        entry.generation = generation;
        entry.questions = questions.to_vec();
        entry.deadline = deadline;
        entry.claimed = false;
        Some((deadline, expires_at_ms))
    }

    /// Drops a question set its worker ended.
    pub(crate) fn finish(&self, handle: &str) {
        self.lock().remove(handle);
    }

    /// Claims the current round of `handle` for one answer by `principal`.
    fn claim(&self, handle: &str, principal: EntityId) -> MemoryResult<Claim<'_>> {
        let mut live = self.lock();
        let entry = live
            .get_mut(handle)
            .filter(|entry| entry.binding.principal == principal)
            .filter(|entry| Instant::now() < entry.deadline)
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
            deadline: entry.deadline,
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

/// A new round's deadline, as an instant and in unix ms.
fn round_deadline() -> (Instant, u64) {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        });
    let wait_ms = u64::try_from(ELICITATION_WAIT.as_millis()).unwrap_or(u64::MAX);
    (
        Instant::now() + ELICITATION_WAIT,
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
    deadline: Instant,
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
    /// next; `None` when the worker is gone (its round lapsed, or the server
    /// is closing).
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
    /// The round lapsed first.
    Lapsed,
    /// The ask could not be queued.
    Unasked,
}

/// `connector.answer` for the caller `memory` is bound to: its answer to the
/// round of questions `request.handle` names. Only the principal the
/// questions bind may answer, once per round. The answer is frozen once and
/// checked under the original call's exact grant; a decline or a cancel
/// always goes. An escalation leaves the round live, so a retry can land; a
/// refusal cancels it. Under `always ask` the owner's yes on exactly this
/// answer sends it, a no sends a decline, and a lapse leaves the worker to
/// cancel. The reply is what the connector said next, as `connector.call`
/// projects it. Blocking: it waits on the connector and on the owner, so
/// call it on a blocking worker.
pub(crate) fn answer_connector_question(
    server: &SyncServer,
    memory: &Memory<'_>,
    request: ConnectorAnswerRequest,
) -> MemoryResult<ConnectorCallReply> {
    let claim = server
        .connector_elicitations
        .claim(&request.handle, memory.actor())?;
    let frozen = freeze(&claim.keys(), &request.answers)?;
    let authority = claim.binding.authority();
    let verdict = server
        .vault()
        .authorize_connector_elicitation_answer(&authority, frozen.digest, frozen.carries_content)
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
            match owner_rules(server, &claim, &authority, &frozen) {
                OwnerRuling::Yes => (frozen.responses, Vec::new()),
                OwnerRuling::No => (
                    frozen.replaced(ConnectorAnswerAction::Decline),
                    vec!["connector_answer_owner_declined".to_owned()],
                ),
                OwnerRuling::Lapsed => return Ok(lapsed()),
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
        return Ok(lapsed().noting(reasons));
    };
    Ok(match event {
        WorkerEvent::Question {
            questions,
            expires_at_ms,
        } => ConnectorCallReply::awaiting_input(
            &name,
            &tool,
            ConnectorAwaitingInput {
                handle,
                questions,
                expires_at_ms,
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
    let mut checked = Value::Object(responses.clone().into_iter().collect());
    let digest = *blake3::hash(checked.to_string().as_bytes()).as_bytes();
    // The check reads a copy: what goes is `responses`, untouched.
    if !oneiron::batch::export::redact_credentials(&mut checked) {
        return;
    }
    let vault = Arc::clone(server.vault());
    let (authority, handle, generation) =
        (authority.clone(), claim.handle.clone(), claim.generation);
    let raise = move || {
        if let Err(error) =
            vault.queue_connector_elicitation_answer_check(&authority, &handle, generation, digest)
        {
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

/// The reply to an answer whose round lapsed before it went: nothing was
/// sent, and the worker cancels the questions.
fn lapsed() -> ConnectorCallReply {
    ConnectorCallReply::Refused {
        decision_ref: None,
        reasons: vec!["connector_question_lapsed".to_owned()],
    }
}

/// Asks the owner about exactly `frozen`, and waits for the ruling within
/// the round's deadline. A lapsed ask is withdrawn, so it leaves the
/// owner's queue, and so are the linked parts of a long one once it is
/// decided or lapses (FIX 3842).
fn owner_rules(
    server: &SyncServer,
    claim: &Claim<'_>,
    authority: &ConnectorElicitationBinding,
    frozen: &FrozenAnswer,
) -> OwnerRuling {
    let answer = ConnectorElicitationAnswer {
        handle: &claim.handle,
        generation: claim.generation,
        questions: &claim.questions,
        answers: &frozen.text,
        digest: frozen.digest,
    };
    let asked = match server
        .vault()
        .queue_connector_elicitation_owner_ask(authority, &answer)
    {
        Ok(asked) => asked,
        Err(error) => {
            tracing::warn!(%error, "connector elicitation owner ask not queued");
            return OwnerRuling::Unasked;
        }
    };
    let asks = server.decision_host().asks();
    let ruling = owner_ruling(asks, asked.seq, claim.deadline);
    for part in asked.parts {
        drop(asks.withdraw(part));
    }
    ruling
}

/// Waits for the owner's ruling on ask `seq` until `deadline`; a lapsed ask
/// is withdrawn.
fn owner_ruling(asks: &DecisionAsks, seq: u64, deadline: Instant) -> OwnerRuling {
    let runtime = tokio::runtime::Handle::try_current().ok();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            drop(asks.withdraw(seq));
            return OwnerRuling::Lapsed;
        }
        let wait = left.min(OWNER_ASK_POLL);
        let answered = match &runtime {
            Some(runtime) => match runtime.block_on(tokio::time::timeout(wait, asks.answered(seq)))
            {
                Ok(answered) => Some(answered.map(|answer| answer.answer)),
                Err(_) => None,
            },
            None => {
                std::thread::sleep(wait);
                match asks.get(seq) {
                    Ok(Some(ask)) if ask.withdrawn_at.is_some() => {
                        Some(Ok(DecisionAnswer::Abstain))
                    }
                    Ok(Some(ask)) => ask.answer.map(|answer| Ok(answer.answer)),
                    Ok(None) => Some(Ok(DecisionAnswer::Abstain)),
                    Err(error) => Some(Err(error)),
                }
            }
        };
        match answered {
            None => {}
            Some(Ok(DecisionAnswer::Noul(true))) => return OwnerRuling::Yes,
            // A no, an abstain or a withdrawn ask declines.
            Some(_) => return OwnerRuling::No,
        }
    }
}
