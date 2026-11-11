//! A remote task's form question, parked for the owner (FIX 16029).
//!
//! An MCP 2025-11-25 task in `input_required` sends its requests while its
//! `tasks/result` is open. The served poller parks a form `elicitation/create`
//! of a Deferred send here, in one writer: the request (session, request id,
//! message, requested schema) sealed under the intent's own ConnectorResume
//! subject at the form round's generation; one row naming the round, its
//! phase, its question digest, the session it came in (as a digest), its Ask
//! and the field names, never a value; and one owner Ask that names the
//! connector, the tool and the field names. A question is parked only from
//! the session the task is polled in now (its handle's), and a round belongs
//! to that session: the same question asked again in a renewed session is a
//! new round, and an answer is claimed only in the session it was parked in.
//!
//! The owner reads the sealed question and submits the values
//! ([`Vault::submit_remote_task_input`]), or declines or cancels it on the Ask
//! ([`Vault::press_remote_task_input_ask`]). Each writes the row's phase and
//! answers the round's own Ask, checked by its typed identity, in one
//! transaction, and wakes the Ask's waiters after the commit. Values come
//! only from the owner's own submission, and an accept is admitted only
//! while the send's authority admits that very answer, as a live answer is
//! checked under its grant: the grant that admitted the send, live under
//! today's policy and naming the send's principal, on an active connector
//! key whose catalog still routes, admitting the send's server, tool and
//! endpoint at the data class the tool and the answer's own content reach
//! (credential content is Secret), and neither the key's tool setting nor
//! its elicitation setting never allow. The submit checks that, and the
//! claim checks it again before any byte goes out; an accept it no longer
//! admits is Refused, never sent.
//!
//! The poller claims the answer for a question with the same digest in the
//! same session only ([`Vault::claim_remote_task_answer_in_txn`]): the row is
//! Sending in the writer that commits before the POST, so a crash after the
//! POST leaves it Sending, or Uncertain once recorded, and it is never sent
//! again. A sent answer retires its sealed generation. A different question
//! is a new round: in one writer every generation the stable subject ever
//! published or retired has its retirement staged before the next one, above
//! them all, is minted, the old Ask is withdrawn and the new one queued.
//! The task's end, and an erase of the call, its actor or its recipient,
//! forget the row, retire the subject (whether or not a row committed) and
//! withdraw the Ask. An Ask is withdrawn only once its typed identity (this
//! queue, the question id and correlation of that intent, question and
//! round) proves it the row's own, never by its number alone. The pass that
//! forgets ended questions also reconciles the Asks with the rows, which a
//! restore can leave apart (the rows are live, the Asks content). The ledger
//! row, its payload, state, budget and settlement stay as they are, and
//! `tools/call` is never sent again.

mod form_schema;
mod owner_ask;
mod question;

pub use self::question::{
    ParkedInput, RemoteTaskAnswer, RemoteTaskFormQuestion, RemoteTaskInputChoice,
    RemoteTaskInputPhase, RemoteTaskInputView,
};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use self::form_schema::FormSchema;
use self::owner_ask::{ANSWER, ASK_QUEUE, ask_matches, ask_round, input_ask};
use super::remote_task_poll::RemoteTaskPoll;
use super::settlement::intent_settlement_in_txn;
use super::types::{FrozenOutboundCall, IntentLedgerError, IntentLedgerResult, IntentState};
use crate::connector_key::SlateDisposition;
use crate::consent::AuthenticatedOwner;
use crate::llm::decision::DecisionAsk;
use crate::model_decision::DecisionAnswer;
use crate::outbound_consent::{ConnectorElicitationBinding, ElicitationAnswerVerdict};
use crate::secret_custody::{
    open_connector_resume_in_txn, retire_connector_resume_in_txn, seal_connector_resume_in_txn,
};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// Each parked question, by its send's intent id.
const INPUTS: SideTable<[u8; 32], RemoteTaskInputRow, Named> =
    SideTable::new(&side_table::OUTBOUND_REMOTE_TASK_INPUT);

/// The domain an intent's task-input custody subject derives under, from its
/// intent id: apart from the ledger payload's own custody ref
/// (`oneiron outbound ledger payload custody v1`) and from every connector
/// call's resume ref.
const INPUT_CUSTODY_DOMAIN: &str = "oneiron outbound remote task input custody v1";

/// The domain a row's digest of the MCP session its round came in derives
/// under.
const SESSION_DIGEST_DOMAIN: &str = "oneiron outbound remote task input session v1";

const NOT_DEFERRED: &str = "the intent is not a Deferred send with a remote task";
const NOT_POLLED: &str = "the send's remote task is not polled here";
const OTHER_SESSION: &str = "the question came in a session its task is not polled in";
const NOT_ITS_ASK: &str = "the task question's ask is not this round's";

/// One parked question's row: metadata and the sealed carrier, no
/// plaintext.
#[derive(Clone, Serialize, Deserialize)]
struct RemoteTaskInputRow {
    generation: u32,
    phase: RemoteTaskInputPhase,
    question_digest: [u8; 32],
    ask: u64,
    field_names: Vec<String>,
    connector: String,
    tool: String,
    parked_at: u64,
    /// [`session_digest`] of the MCP session the round was parked in, the
    /// one its task was polled in then; `None` for a server that keeps no
    /// session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session: Option<[u8; 32]>,
    /// [`SealedTaskInput`] sealed at `generation`; empty once a sent answer
    /// retired it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    sealed: Vec<u8>,
}

impl RemoteTaskInputRow {
    fn parked(&self) -> ParkedInput {
        ParkedInput {
            generation: self.generation,
            phase: self.phase,
            question_digest: self.question_digest,
            ask: self.ask,
        }
    }
}

/// What one reconciling pass over the parked questions has to change
/// ([`Vault::forget_ended_remote_task_inputs`]), as its snapshot read it.
#[derive(Default)]
struct InputReconciliation {
    /// Parked questions whose send is no longer Deferred.
    ended: Vec<[u8; 32]>,
    /// Rows waiting for the owner whose Ask is gone.
    waiting: Vec<[u8; 32]>,
    /// Open owner Asks of this queue that no row is bound to.
    unbound: Vec<u64>,
}

impl InputReconciliation {
    fn is_empty(&self) -> bool {
        self.ended.is_empty() && self.waiting.is_empty() && self.unbound.is_empty()
    }
}

/// What the seal keeps of a round: the request, and the owner's answer once
/// submitted.
#[derive(Serialize, Deserialize)]
struct SealedTaskInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session: Option<String>,
    request_id: Value,
    message: String,
    requested_schema: Value,
    /// MCP's `ElicitResult` of the owner's accept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    answer: Option<Value>,
}

/// Intent `intent`'s one task-input custody subject, stable across its form
/// rounds: each round seals at its own generation.
fn input_subject(intent: &[u8; 32]) -> crate::Result<EntityId> {
    let derived = blake3::derive_key(INPUT_CUSTODY_DOMAIN, intent);
    let bytes = derived
        .first_chunk::<16>()
        .ok_or(crate::Error::CorruptedIndex(
            "outbound remote task input custody ref",
        ))?;
    EntityId::from_bytes(*bytes)
        .map_err(|_| crate::Error::CorruptedIndex("outbound remote task input custody ref"))
}

/// The digest a row keeps of MCP session `session`, never the id itself.
fn session_digest(session: Option<&str>) -> Option<[u8; 32]> {
    session.map(|session| blake3::derive_key(SESSION_DIGEST_DOMAIN, session.as_bytes()))
}

fn carrier_corrupt() -> crate::Error {
    crate::Error::CorruptedIndex("outbound remote task input carrier")
}

/// An owner door's refusal.
fn refused(reason: &str) -> crate::Error {
    crate::Error::InvalidConfig(reason.to_owned())
}

/// A ledger fault inside an owner door, as the door reports it.
fn owner_error(error: IntentLedgerError) -> crate::Error {
    match error {
        IntentLedgerError::Engine(error) => error,
        other => refused(&other.to_string()),
    }
}

/// Seals `carrier` for `subject` at `generation`, in `wtxn`.
fn seal_carrier_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    subject: &EntityId,
    generation: u32,
    carrier: &SealedTaskInput,
) -> crate::Result<Vec<u8>> {
    let plain = Zeroizing::new(serde_json::to_vec(carrier).map_err(|_| carrier_corrupt())?);
    seal_connector_resume_in_txn(&vault.store, wtxn, subject, generation, &plain)
}

/// Opens what [`seal_carrier_in_txn`] sealed. The caller holds a writer or
/// took the custody read guard before `txn`.
fn open_carrier_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
    generation: u32,
    sealed: &[u8],
) -> crate::Result<SealedTaskInput> {
    let plain = open_connector_resume_in_txn(&vault.store, txn, subject, generation, sealed)?;
    serde_json::from_slice(&plain).map_err(|_| carrier_corrupt())
}

/// Row `intent` when it is Sending at round `generation`.
fn sending_row_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    intent: &[u8; 32],
    generation: u32,
) -> crate::Result<Option<RemoteTaskInputRow>> {
    Ok(INPUTS
        .get(&vault.store, txn, intent)?
        .filter(|row| row.generation == generation && row.phase == RemoteTaskInputPhase::Sending))
}

/// How row `intent`'s remote task is polled now, as its handle keeps it:
/// with it the task's authoritative session, the one the connector renewed
/// it to when it ended the last (FIX 16028). `None` when the row keeps no
/// polled task.
fn task_poll_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    intent: &[u8; 32],
) -> IntentLedgerResult<Option<RemoteTaskPoll>> {
    Ok(intent_settlement_in_txn(vault, txn, intent)?
        .remote_task
        .and_then(|handle| handle.poll))
}

/// The generation the next round under the stable `subject` seals at (L04):
/// above every generation custody holds or held for it (its newest entry or
/// retirement marker, an aborted writer's included, or the reach of the
/// retirement standing for it) and above `current`'s round, so no round
/// reuses a generation ever published or retired, a forgotten question's
/// included. 0 for a subject custody never held.
fn next_generation_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
    current: Option<&RemoteTaskInputRow>,
) -> IntentLedgerResult<u32> {
    let custody = vault
        .store
        .connector_resume_high_water_in_txn(txn, subject)?;
    let row = current.map(|row| u64::from(row.generation));
    match custody.max(row) {
        None => Ok(0),
        Some(high) => high
            .checked_add(1)
            .and_then(|next| u32::try_from(next).ok())
            .ok_or(IntentLedgerError::InvalidRecord(
                "outbound remote task input generation",
            )),
    }
}

/// Why the send's authority does not admit the owner's accept `answer` (the
/// `ElicitResult` it sends) on row `intent`, read in `txn`; `None` while it
/// does. The send is still Deferred and names the grant that admitted it
/// (its typed capability provenance, ONE-1885), the principal admission
/// derived from that grant, and its governing key. The answer then meets
/// exactly the check a live answer meets under its grant
/// ([`Vault::elicitation_answer_grant_verdict_in_txn`], ONE-2510): that very
/// grant there, the principal's and live under today's policy, on a
/// governing key that is there and active and a catalog that still routes,
/// admitting the send's server, tool and endpoint, with arguments granted,
/// at the data class the tool's slate class and the answer's own content
/// reach together (FIX 8807: credential content is Secret). Last, neither
/// the key's setting for the tool nor its elicitation setting is never
/// allow. The owner's own submission is their consent on exactly this
/// answer, which an `always ask` elicitation setting asks for. A call that
/// names no grant, principal or governing key never declared form
/// elicitation, so it is refused too.
fn accept_refusal_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    intent: &[u8; 32],
    answer: &Value,
) -> crate::Result<Option<String>> {
    let refuse = |reason: &str| -> crate::Result<Option<String>> { Ok(Some(reason.to_owned())) };
    let Some(mut record) = super::store::get_ledger_record(vault, txn, intent)
        .map_err(owner_error)?
        .filter(|record| record.state == IntentState::Deferred)
    else {
        return refuse("the task's send is no longer deferred");
    };
    let Some(grant_id) = record
        .capability_provenance()
        .map(|capability| capability.grant_id())
    else {
        return refuse("the task's send names no grant");
    };
    let Some(principal) =
        super::payload::admitting_actor_in_txn(vault, txn, intent).map_err(owner_error)?
    else {
        return refuse("the task's send names no principal");
    };
    super::payload::open_payload_in_txn(vault, txn, &mut record).map_err(owner_error)?;
    let call = FrozenOutboundCall::from_record(&record);
    let view = crate::outbound_consent::FrozenToolCallView::read(&call)?;
    let Some(key_ref) = view.key_ref().and_then(|hex| EntityId::from_hex(hex).ok()) else {
        return refuse("the task's send names no connector key");
    };
    // The send's own binding, as a live question binds its call's: the
    // catalog name a poll routes by is the send's server.
    let binding = ConnectorElicitationBinding {
        principal_ref: principal.to_hex(),
        grant_id,
        key_ref,
        name: view.server().to_owned(),
        server: view.server().to_owned(),
        tool: view.tool().to_owned(),
        endpoint: view.endpoint().to_owned(),
    };
    let mut read = Vec::new();
    match vault.elicitation_answer_grant_verdict_in_txn(txn, &binding, answer, &mut read)? {
        None | Some(ElicitationAnswerVerdict::Send | ElicitationAnswerVerdict::AskOwner) => {}
        Some(
            ElicitationAnswerVerdict::Escalate(reason) | ElicitationAnswerVerdict::Refuse(reason),
        ) => {
            return Ok(Some(format!(
                "the grant that admitted the task's send does not admit this answer ({reason})"
            )));
        }
    }
    let Some(key) = crate::connector_key::read_key_for_pack_in_txn(vault, txn, &key_ref)? else {
        return refuse("the connector key of the task's send is gone");
    };
    let tool = crate::connector_key::connector_tool_setting_in_txn(
        &vault.store,
        txn,
        &key_ref,
        &key,
        view.tool(),
    )?;
    if tool == SlateDisposition::NeverAllow {
        return refuse("the connector's setting for this tool is now never allow");
    }
    let elicitation =
        crate::connector_key::connector_elicitation_setting_in_txn(&vault.store, txn, &key_ref)?;
    if elicitation == SlateDisposition::NeverAllow {
        return refuse("the connector's elicitation setting is now never allow");
    }
    Ok(None)
}

impl Vault {
    /// Parks the form question `question` of row `intent`'s remote task in
    /// `wtxn`, the poller's writer: its request sealed under the intent's
    /// task-input subject, its row, and its owner Ask, all in this one
    /// commit. The question must come in the session the task is polled in
    /// now. The same question already parked in that same session (the same
    /// digest) changes nothing and returns its row. A different question,
    /// or the same one in another session, is the next round: its generation
    /// is above every one the stable subject ever published or retired,
    /// their retirement is staged before it is minted, the old Ask is
    /// withdrawn and a new one queued.
    ///
    /// # Errors
    /// A schema that is not a flat object of string, number, integer or
    /// boolean fields (strings with choices included), as MCP form mode
    /// allows, or that states a constraint the form check cannot enforce; a
    /// row that is not a Deferred send with a polled remote task, whose
    /// connector or tool the question does not name, or whose task is polled
    /// in another session than the question came in; storage, custody and
    /// ask-queue faults.
    pub fn park_remote_task_input_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        intent: &[u8; 32],
        question: &RemoteTaskFormQuestion,
    ) -> IntentLedgerResult<ParkedInput> {
        let schema = FormSchema::read(&question.requested_schema)
            .map_err(IntentLedgerError::InvalidInput)?;
        let record = super::store::get_ledger_record(self, wtxn, intent)?
            .filter(|record| record.state == IntentState::Deferred)
            .ok_or(IntentLedgerError::InvalidInput(NOT_DEFERRED))?;
        let poll = intent_settlement_in_txn(self, wtxn, intent)?
            .remote_task
            .ok_or(IntentLedgerError::InvalidInput(NOT_DEFERRED))?
            .poll
            .ok_or(IntentLedgerError::InvalidInput(NOT_POLLED))?;
        // The task's authoritative session: a question from any other is not
        // this task's now.
        if poll.session != question.session {
            return Err(IntentLedgerError::InvalidInput(OTHER_SESSION));
        }
        if record.server != question.connector || record.tool != question.tool {
            return Err(IntentLedgerError::InvalidInput(
                "the question names another send's connector or tool",
            ));
        }
        let digest = question.digest();
        let session = session_digest(question.session.as_deref());
        let current = INPUTS.get(&self.store, wtxn, intent)?;
        // A round belongs to the session it was parked in: the same question
        // in a renewed session never takes this path, so it never inherits
        // the old session's answer.
        if let Some(row) = current
            .as_ref()
            .filter(|row| row.question_digest == digest && row.session == session)
        {
            return Ok(row.parked());
        }
        let subject = input_subject(intent)?;
        // L04: the next generation is above every one the stable subject
        // ever published or retired, and their retirement is staged before
        // it is minted, in this writer.
        let generation = next_generation_in_txn(self, wtxn, &subject, current.as_ref())?;
        retire_connector_resume_in_txn(&self.store, wtxn, &subject)?;
        if let Some(row) = &current {
            self.withdraw_input_ask_in_txn(wtxn, intent, row);
        }
        let carrier = SealedTaskInput {
            session: question.session.clone(),
            request_id: question.request_id.clone(),
            message: question.message.clone(),
            requested_schema: question.requested_schema.clone(),
            answer: None,
        };
        let sealed = seal_carrier_in_txn(self, wtxn, &subject, generation, &carrier)?;
        let mut row = RemoteTaskInputRow {
            generation,
            phase: RemoteTaskInputPhase::AwaitingOwner,
            question_digest: digest,
            ask: 0,
            field_names: schema.field_names(),
            connector: question.connector.clone(),
            tool: question.tool.clone(),
            parked_at: self.now_recorded_at(),
            session,
            sealed,
        };
        let principal = super::payload::admitting_actor_in_txn(self, wtxn, intent)?;
        let (request, state) = input_ask(intent, &row, principal)?;
        row.ask = self.queue_decision_ask_in_txn(wtxn, &request, Some(&state))?;
        INPUTS.put(&self.store, wtxn, intent, &row)?;
        Ok(row.parked())
    }

    /// Row `intent`'s parked question, if one is parked.
    ///
    /// # Errors
    /// Storage and row-codec faults.
    pub fn remote_task_input(&self, intent: &[u8; 32]) -> IntentLedgerResult<Option<ParkedInput>> {
        let txn = self
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)?;
        Ok(INPUTS
            .get(&self.store, &txn, intent)?
            .as_ref()
            .map(RemoteTaskInputRow::parked))
    }

    /// The parked question of row `intent`, opened for the owner: the
    /// message, the requested schema and the field names, its phase and its
    /// round. `None` when none is parked.
    ///
    /// # Errors
    /// A proof that is not the owner's; a question whose sent answer retired
    /// its carrier; custody and storage faults.
    pub fn remote_task_input_question(
        &self,
        owner: &AuthenticatedOwner,
        intent: &[u8; 32],
    ) -> crate::Result<Option<RemoteTaskInputView>> {
        let _custody = self.store.gate_custody_read_guard()?;
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let Some(row) = INPUTS.get(&self.store, &txn, intent)? else {
            return Ok(None);
        };
        if row.sealed.is_empty() {
            return Err(refused(
                "the task's question was answered; it is no longer kept",
            ));
        }
        let carrier = open_carrier_in_txn(
            self,
            &txn,
            &input_subject(intent)?,
            row.generation,
            &row.sealed,
        )?;
        Ok(Some(RemoteTaskInputView {
            generation: row.generation,
            phase: row.phase,
            connector: row.connector,
            tool: row.tool,
            message: carrier.message,
            requested_schema: carrier.requested_schema,
            field_names: row.field_names,
            ask: row.ask,
            parked_at: row.parked_at,
        }))
    }

    /// The owner's values for round `generation` of row `intent`'s parked
    /// question, checked against its frozen schema and sealed beside the
    /// request as an accept, in one writer with the round's own Ask, checked
    /// by its typed identity, answered Answer: the row is Ready and the Ask
    /// answered together, or neither. The Ask's waiters wake once the write
    /// committed.
    ///
    /// # Errors
    /// A proof that is not the owner's; no question parked; a stale round;
    /// a question not waiting for the owner; an Ask that is not this
    /// round's or that was answered another way or withdrawn; a field the
    /// schema does not name, a required field left out, a value of the wrong
    /// type, outside its choices, bounds, pattern or format; a send whose
    /// authority does not admit this answer (it is no longer Deferred; the
    /// grant that admitted it is gone, no longer live, names another
    /// principal, or does not admit its server, tool, endpoint or the data
    /// class the answer reaches, as a live answer is checked; its connector
    /// key is gone or not active or its catalog no longer routes; the key's
    /// setting for the tool or for elicitation is now never allow), whose
    /// reason the refusal names; custody and storage faults. Nothing is
    /// written then.
    pub fn submit_remote_task_input(
        &self,
        owner: &AuthenticatedOwner,
        intent: &[u8; 32],
        generation: u32,
        content: Map<String, Value>,
    ) -> crate::Result<()> {
        let answered = self.with_write_txn_grouped(|txn| {
            let by = owner.revalidate_in_txn(self, txn)?;
            let mut row = INPUTS
                .get(&self.store, txn, intent)?
                .ok_or_else(|| refused("no question is parked for the task"))?;
            if row.generation != generation {
                return Err(refused("the task's question changed since it was read"));
            }
            if row.phase != RemoteTaskInputPhase::AwaitingOwner {
                return Err(refused(
                    "the task's question is no longer waiting for the owner",
                ));
            }
            let Some(ask) = self.decision_ask_in_txn(txn, row.ask)? else {
                return Err(refused(NOT_ITS_ASK));
            };
            if !ask_matches(intent, &row, &ask)? {
                return Err(refused(NOT_ITS_ASK));
            }
            let subject = input_subject(intent)?;
            let mut carrier = open_carrier_in_txn(self, txn, &subject, generation, &row.sealed)?;
            FormSchema::read(&carrier.requested_schema)
                .and_then(|schema| schema.check(&content))
                .map_err(refused)?;
            let mut answer = Map::new();
            answer.insert("action".to_owned(), Value::String("accept".to_owned()));
            answer.insert("content".to_owned(), Value::Object(content));
            let answer = Value::Object(answer);
            // The answer the grant would refuse as a live one is refused
            // here, and the owner is told why.
            if let Some(reason) = accept_refusal_in_txn(self, txn, intent, &answer)? {
                return Err(refused(&reason));
            }
            carrier.answer = Some(answer);
            row.sealed = seal_carrier_in_txn(self, txn, &subject, generation, &carrier)?;
            row.phase = RemoteTaskInputPhase::Ready;
            INPUTS.put(&self.store, txn, intent, &row)?;
            let answered = self.answer_owner_queue_ask_in_txn(
                txn,
                ASK_QUEUE,
                row.ask,
                by,
                DecisionAnswer::Choice(ANSWER.to_owned()),
            )?;
            Ok(answered.then_some(row.ask))
        })?;
        if let Some(seq) = answered {
            self.signal_decision_answer(seq);
        }
        Ok(())
    }

    /// The owner's Decline or Cancel on decision ask `seq`, before the ask
    /// answer door records the answer: only an Ask of a parked question,
    /// proved that question's own by its typed identity (this queue, the
    /// question id and correlation of its intent, digest and round), is
    /// handled, and its phase and its Ask's answer are written in one
    /// writer, its waiters woken once that committed. A question waiting
    /// for the owner takes the press's phase, with no content. The same
    /// press again changes nothing. A press on a question the poller already
    /// claimed (Sending, Sent, Uncertain, Refused) answers its still open Ask
    /// with the press and changes nothing else: the answer claimed before it
    /// stands. An Ask of any other queue is left alone, for the answer door.
    ///
    /// # Errors
    /// A proof that is not the owner's; an Ask whose question is no longer
    /// parked, is another round's, or was answered another way before the
    /// poller claimed it; an Ask withdrawn or answered otherwise. Nothing
    /// changes then, and the caller records no answer, so the Ask stays as
    /// it was.
    pub fn press_remote_task_input_ask(
        &self,
        owner: &AuthenticatedOwner,
        seq: u64,
        choice: RemoteTaskInputChoice,
    ) -> crate::Result<()> {
        if !self
            .decision_ask(seq)?
            .is_some_and(|ask| ask.queue_pin.model == ASK_QUEUE)
        {
            return Ok(());
        }
        let answered = self.with_write_txn_grouped(|txn| {
            let by = owner.revalidate_in_txn(self, txn)?;
            let ask = self
                .decision_ask_in_txn(txn, seq)?
                .ok_or_else(|| refused("the ask is no longer queued"))?;
            let Some(round) = ask_round(&ask)? else {
                return Err(refused("the ask is not a task question's"));
            };
            let intent = round.intent;
            let Some(mut row) = INPUTS.get(&self.store, txn, &intent)? else {
                return Err(refused("the ask's task question is no longer parked"));
            };
            if !ask_matches(&intent, &row, &ask)? {
                return Err(refused("the ask is not the task's current question"));
            }
            let pressed = choice.phase();
            match row.phase {
                RemoteTaskInputPhase::AwaitingOwner => {
                    row.phase = pressed;
                    INPUTS.put(&self.store, txn, &intent, &row)?;
                }
                phase if phase == pressed => {}
                // The poller claimed an answer already: the press settles
                // the Ask, and the claimed answer stands.
                RemoteTaskInputPhase::Sending
                | RemoteTaskInputPhase::Sent
                | RemoteTaskInputPhase::Uncertain
                | RemoteTaskInputPhase::Refused => {
                    if !ask.is_open() {
                        return Ok(None);
                    }
                }
                RemoteTaskInputPhase::Ready
                | RemoteTaskInputPhase::Declined
                | RemoteTaskInputPhase::Cancelled => {
                    return Err(refused(
                        "the task's question was already answered another way",
                    ));
                }
            }
            let answer = DecisionAnswer::Choice(choice.option().to_owned());
            let answered = self.answer_owner_queue_ask_in_txn(txn, ASK_QUEUE, seq, by, answer)?;
            Ok(answered.then_some(seq))
        })?;
        if let Some(seq) = answered {
            self.signal_decision_answer(seq);
        }
        Ok(())
    }

    /// The intents whose parked question the owner answered (Ready,
    /// Declined or Cancelled) and no poller claimed yet.
    ///
    /// # Errors
    /// Storage and row-codec faults.
    pub fn remote_task_inputs_ready(&self) -> IntentLedgerResult<Vec<[u8; 32]>> {
        let txn = self
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)?;
        let mut ready = Vec::new();
        for row in INPUTS.iter_from(&self.store, &txn, &[])? {
            let (intent, row) = row?;
            if row.phase.owner_answered() {
                ready.push(intent);
            }
        }
        Ok(ready)
    }

    /// Claims, in `wtxn`, the owner's answer to row `intent`'s parked
    /// question for a question whose digest is `question_digest`, asked in
    /// MCP session `session` (the live one the poller read it in): only
    /// while the send is Deferred, the owner answered, the round was parked
    /// in that session and the task is polled in it now. An accept is
    /// admitted only while the send's authority still admits it, read again
    /// here before any byte is returned; one it no longer admits is Refused
    /// in this writer and never returned (a Decline or Cancel carries no
    /// content and is always sent). The row is Sending in this writer, which
    /// the caller commits before its POST. `None` for a changed question, a
    /// round of another session, an unanswered, refused or already claimed
    /// one, or none.
    ///
    /// # Errors
    /// Custody, storage and row-codec faults.
    pub fn claim_remote_task_answer_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        intent: &[u8; 32],
        question_digest: &[u8; 32],
        session: Option<&str>,
    ) -> IntentLedgerResult<Option<RemoteTaskAnswer>> {
        let Some(mut row) = INPUTS.get(&self.store, wtxn, intent)? else {
            return Ok(None);
        };
        if row.question_digest != *question_digest
            || row.session != session_digest(session)
            || !row.phase.owner_answered()
        {
            return Ok(None);
        }
        // The task's authoritative session now: an answer is never claimed
        // for a session the task is no longer polled in.
        let polled_in = task_poll_in_txn(self, wtxn, intent)?
            .is_some_and(|poll| poll.session.as_deref() == session);
        if !polled_in {
            return Ok(None);
        }
        let deferred = super::store::get_ledger_record(self, wtxn, intent)?
            .is_some_and(|record| record.state == IntentState::Deferred);
        if !deferred {
            return Ok(None);
        }
        let carrier = open_carrier_in_txn(
            self,
            wtxn,
            &input_subject(intent)?,
            row.generation,
            &row.sealed,
        )?;
        // The frozen accept meets its grant again, as it is now: one the
        // grant narrowed past since the submit is Refused, never sent.
        if row.phase == RemoteTaskInputPhase::Ready {
            let answer = carrier.answer.as_ref().ok_or_else(carrier_corrupt)?;
            if let Some(reason) = accept_refusal_in_txn(self, wtxn, intent, answer)? {
                row.phase = RemoteTaskInputPhase::Refused;
                INPUTS.put(&self.store, wtxn, intent, &row)?;
                tracing::warn!(
                    reason = "remote_task_input_answer_refused",
                    refusal = %reason,
                    generation = row.generation,
                    "the owner's answer to a background task's question is no longer admitted; \
                     it is not sent, and the question shows it refused"
                );
                return Ok(None);
            }
        }
        let result = match row.phase {
            RemoteTaskInputPhase::Declined => json!({ "action": "decline" }),
            RemoteTaskInputPhase::Cancelled => json!({ "action": "cancel" }),
            _ => carrier.answer.ok_or_else(carrier_corrupt)?,
        };
        let result = Zeroizing::new(serde_json::to_vec(&result).map_err(|_| carrier_corrupt())?);
        row.phase = RemoteTaskInputPhase::Sending;
        INPUTS.put(&self.store, wtxn, intent, &row)?;
        Ok(Some(RemoteTaskAnswer {
            generation: row.generation,
            request_id: carrier.request_id,
            session: carrier.session,
            result,
        }))
    }

    /// Records, in `wtxn`, that the connector accepted the answer to round
    /// `generation` of row `intent`'s question: Sent, its sealed generation
    /// retired. Whether a Sending row of that round changed.
    ///
    /// # Errors
    /// Custody and storage faults.
    pub fn record_remote_task_answer_sent_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        intent: &[u8; 32],
        generation: u32,
    ) -> IntentLedgerResult<bool> {
        let Some(mut row) = sending_row_in_txn(self, wtxn, intent, generation)? else {
            return Ok(false);
        };
        retire_connector_resume_in_txn(&self.store, wtxn, &input_subject(intent)?)?;
        row.phase = RemoteTaskInputPhase::Sent;
        row.sealed = Vec::new();
        INPUTS.put(&self.store, wtxn, intent, &row)?;
        Ok(true)
    }

    /// Records, in `wtxn`, that whether the connector took the answer to
    /// round `generation` of row `intent`'s question is unknown: Uncertain,
    /// never sent again. Whether a Sending row of that round changed.
    ///
    /// # Errors
    /// Storage faults.
    pub fn record_remote_task_answer_uncertain_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        intent: &[u8; 32],
        generation: u32,
    ) -> IntentLedgerResult<bool> {
        let Some(mut row) = sending_row_in_txn(self, wtxn, intent, generation)? else {
            return Ok(false);
        };
        row.phase = RemoteTaskInputPhase::Uncertain;
        INPUTS.put(&self.store, wtxn, intent, &row)?;
        Ok(true)
    }

    /// Forgets row `intent`'s parked question in `wtxn`: its row goes, its
    /// task-input subject's retirement is staged whether or not a row
    /// committed, and its owner Ask, once its typed identity proves it the
    /// row's own, is withdrawn. The task's end and the erase of its call,
    /// actor or recipient run it in their writer; the custody finisher
    /// retires the keys after commit
    /// ([`Self::finish_remote_task_input_retirements`]).
    ///
    /// # Errors
    /// Custody and storage faults. A row that does not read still goes.
    pub fn forget_remote_task_input_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        intent: &[u8; 32],
    ) -> IntentLedgerResult<()> {
        self.forget_input_in_txn(wtxn, intent).map(|_| ())
    }

    /// [`Self::forget_remote_task_input_in_txn`] in a writer of its own, the
    /// Ask's waiters woken and the key retirement carried out after its
    /// commit.
    ///
    /// # Errors
    /// Custody and storage faults, before the commit.
    pub fn forget_remote_task_input(&self, intent: &[u8; 32]) -> IntentLedgerResult<()> {
        let withdrawn =
            self.try_with_write_txn_grouped(|txn| self.forget_input_in_txn(txn, intent))?;
        if let Some(seq) = withdrawn {
            self.signal_decision_answer(seq);
        }
        self.finish_remote_task_input_retirements();
        Ok(())
    }

    /// Forgets every parked question whose send is no longer Deferred (it
    /// settled, stopped, or its row is gone), and reconciles the owner Asks
    /// with the rows that stay: a restore brings the Asks back as its image
    /// holds them (DECISION_ASK is content) while the rows stand as they are
    /// live (L04). An open Ask this queue minted (its typed identity proves
    /// it) whose intent keeps no row, or whose row is another question,
    /// round or Ask, is withdrawn; a row waiting for the owner whose Ask is
    /// gone, withdrawn or another ask's (a restored image can number another
    /// ask with it) gets its Ask queued again. The served poller runs it on
    /// every pass, polled or not. It reads one snapshot first and opens its
    /// one writer only when that snapshot finds something to change, which
    /// the writer checks again. After the commit the Asks' waiters wake, and
    /// every task-input key retirement a committed writer staged and nobody
    /// carried out yet, an earlier pass's or a stopped process's included,
    /// is carried out. How many questions it forgot.
    ///
    /// # Errors
    /// Custody, storage, row-codec and ask-queue faults, before the commit.
    pub fn forget_ended_remote_task_inputs(&self) -> IntentLedgerResult<usize> {
        let plan = self.input_reconciliation()?;
        let (forgot, withdrawn) = if plan.is_empty() {
            (0, Vec::new())
        } else {
            self.try_with_write_txn_grouped(|txn| -> IntentLedgerResult<(usize, Vec<u64>)> {
                let mut forgot = 0;
                let mut withdrawn = Vec::new();
                for intent in &plan.ended {
                    let parked = INPUTS.get(&self.store, txn, intent)?.is_some();
                    let deferred = super::store::get_ledger_record(self, txn, intent)?
                        .is_some_and(|record| record.state == IntentState::Deferred);
                    if parked && !deferred {
                        withdrawn.extend(self.forget_input_in_txn(txn, intent)?);
                        forgot += 1;
                    }
                }
                for intent in &plan.waiting {
                    if let Some(row) = INPUTS
                        .get(&self.store, txn, intent)?
                        .filter(|row| row.phase == RemoteTaskInputPhase::AwaitingOwner)
                    {
                        self.requeue_missing_input_ask_in_txn(txn, intent, row)?;
                    }
                }
                for seq in plan.unbound {
                    withdrawn.extend(self.withdraw_unbound_input_ask_in_txn(txn, seq)?);
                }
                Ok((forgot, withdrawn))
            })?
        };
        for seq in withdrawn {
            self.signal_decision_answer(seq);
        }
        self.finish_remote_task_input_retirements();
        Ok(forgot)
    }

    /// Carries out the task-input key retirements a committed writer staged
    /// (a sent answer, a new round, a forgotten question). One that cannot
    /// run now is logged and runs on the next housekeeping pass.
    pub fn finish_remote_task_input_retirements(&self) {
        self.finish_connector_resume_retirements_after_commit();
    }

    /// [`Self::forget_remote_task_input_in_txn`], naming the Ask it
    /// withdrew, for its waiters' signal once the writer committed. The
    /// subject's retirement is staged before the row goes, so a custody
    /// fault there writes nothing and the caller can keep what finds the
    /// intent again (the ledger's poll writers keep its poll row).
    pub(super) fn forget_input_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        intent: &[u8; 32],
    ) -> IntentLedgerResult<Option<u64>> {
        retire_connector_resume_in_txn(&self.store, wtxn, &input_subject(intent)?)?;
        let row = INPUTS.get(&self.store, wtxn, intent).ok().flatten();
        INPUTS.delete(&self.store, wtxn, intent)?;
        Ok(row.and_then(|row| self.withdraw_input_ask_in_txn(wtxn, intent, &row)))
    }

    /// Withdraws the owner Ask of `row`, the question of `intent`, in
    /// `wtxn`, as the ask queue withdraws: only while the ask at its number
    /// is open and its typed identity proves it that row's own; any other
    /// ask there is left alone. The number withdrawn, for its waiters'
    /// signal once the writer committed. A withdrawal that fails is logged,
    /// and the write goes on as it would without it.
    fn withdraw_input_ask_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        intent: &[u8; 32],
        row: &RemoteTaskInputRow,
    ) -> Option<u64> {
        match self.withdraw_own_input_ask_in_txn(wtxn, intent, row) {
            Ok(withdrawn) => withdrawn.then_some(row.ask),
            Err(error) => {
                tracing::warn!(
                    reason = "remote_task_input_ask_not_withdrawn",
                    ask = row.ask,
                    error = %error,
                    "the owner ask of a task question that went was not withdrawn; the \
                     question is forgotten as before"
                );
                None
            }
        }
    }

    /// [`Self::withdraw_input_ask_in_txn`]'s check and withdrawal.
    fn withdraw_own_input_ask_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        intent: &[u8; 32],
        row: &RemoteTaskInputRow,
    ) -> crate::Result<bool> {
        let Some(ask) = self.decision_ask_in_txn(wtxn, row.ask)? else {
            return Ok(false);
        };
        if !ask.is_open() || !ask_matches(intent, row, &ask)? {
            return Ok(false);
        }
        self.withdraw_decision_ask_in_txn(wtxn, row.ask)
    }

    /// Queues the owner Ask of `row`, a question of `intent` waiting for the
    /// owner, again in `wtxn` when its Ask is gone: no ask at its number,
    /// another ask there, or its own withdrawn. An open ask that is the same
    /// ask (a restored one) is taken as it is, as the queue takes it.
    fn requeue_missing_input_ask_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        intent: &[u8; 32],
        mut row: RemoteTaskInputRow,
    ) -> IntentLedgerResult<()> {
        if !self.input_ask_missing_in_txn(wtxn, intent, &row)? {
            return Ok(());
        }
        let principal = super::payload::admitting_actor_in_txn(self, wtxn, intent)?;
        let (request, state) = input_ask(intent, &row, principal)?;
        row.ask = self.queue_decision_ask_in_txn(wtxn, &request, Some(&state))?;
        INPUTS.put(&self.store, wtxn, intent, &row)?;
        Ok(())
    }

    /// Whether the owner Ask of `row`, a question of `intent`, is gone: no
    /// ask at its number, another ask there, or its own withdrawn.
    fn input_ask_missing_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        intent: &[u8; 32],
        row: &RemoteTaskInputRow,
    ) -> IntentLedgerResult<bool> {
        Ok(match self.decision_ask_in_txn(txn, row.ask)? {
            None => true,
            Some(ask) => !ask_matches(intent, row, &ask)? || ask.withdrawn_at.is_some(),
        })
    }

    /// Whether open Ask `ask` of this queue is the one its question's row is
    /// bound to: `None` for an ask whose typed identity does not prove it
    /// this queue's own (it is left alone), `Some(false)` when its intent
    /// keeps no row, or a row of another question, round or Ask.
    fn input_ask_bound_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        ask: &DecisionAsk,
    ) -> IntentLedgerResult<Option<bool>> {
        let Some(round) = ask_round(ask)? else {
            return Ok(None);
        };
        let bound = INPUTS
            .get(&self.store, txn, &round.intent)?
            .is_some_and(|row| {
                row.ask == ask.seq
                    && row.question_digest == round.question_digest
                    && row.generation == round.generation
            });
        Ok(Some(bound))
    }

    /// What [`Self::forget_ended_remote_task_inputs`] has to change, read
    /// in one snapshot before its writer, which checks each again: the
    /// parked questions whose send is no longer Deferred, the rows waiting
    /// for the owner whose Ask is gone, and the open owner Asks this queue
    /// minted that no row is bound to.
    fn input_reconciliation(&self) -> IntentLedgerResult<InputReconciliation> {
        let txn = self
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)?;
        let mut plan = InputReconciliation::default();
        for row in INPUTS.iter_from(&self.store, &txn, &[])? {
            let (intent, row) = row?;
            let deferred = super::store::get_ledger_record(self, &txn, &intent)?
                .is_some_and(|record| record.state == IntentState::Deferred);
            if !deferred {
                plan.ended.push(intent);
            } else if row.phase == RemoteTaskInputPhase::AwaitingOwner
                && self.input_ask_missing_in_txn(&txn, &intent, &row)?
            {
                plan.waiting.push(intent);
            }
        }
        for ask in self.open_queue_asks_in_txn(&txn, ASK_QUEUE)? {
            if self.input_ask_bound_in_txn(&txn, &ask)? == Some(false) {
                plan.unbound.push(ask.seq);
            }
        }
        Ok(plan)
    }

    /// Withdraws ask `seq` in `wtxn` when it is still open, this queue's
    /// own by its typed identity, and bound to no row. The number
    /// withdrawn, for its waiters' signal once the writer committed.
    fn withdraw_unbound_input_ask_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        seq: u64,
    ) -> IntentLedgerResult<Option<u64>> {
        let Some(ask) = self.decision_ask_in_txn(wtxn, seq)? else {
            return Ok(None);
        };
        if !ask.is_open() || self.input_ask_bound_in_txn(wtxn, &ask)? != Some(false) {
            return Ok(None);
        }
        Ok(self.withdraw_decision_ask_in_txn(wtxn, seq)?.then_some(seq))
    }
}
