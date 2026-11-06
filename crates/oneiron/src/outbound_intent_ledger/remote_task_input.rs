//! A remote task's form question, parked for the owner (FIX 16029).
//!
//! An MCP 2025-11-25 task in `input_required` sends its requests while its
//! `tasks/result` is open. The served poller parks a form `elicitation/create`
//! of a Deferred send here, in one writer: the request (session, request id,
//! message, requested schema) sealed under the intent's own ConnectorResume
//! subject at the form round's generation; one row naming the round, its
//! phase, its question digest, its Ask and the field names, never a value;
//! and one owner Ask that names the connector, the tool and the field names.
//! The owner reads the sealed question and submits the values
//! ([`Vault::submit_remote_task_input`]), or declines or cancels it on the Ask
//! ([`Vault::press_remote_task_input_ask`]). Values come only from the
//! owner's own submission.
//!
//! The poller claims the answer for a question with the same digest only
//! ([`Vault::claim_remote_task_answer_in_txn`]): the row is Sending in the
//! writer that commits before the POST, so a crash after the POST leaves it
//! Sending, or Uncertain once recorded, and it is never sent again. A sent
//! answer retires its sealed generation. A different question is a new round:
//! in one writer the current generation's retirement is staged before the
//! next generation is minted, the old Ask is withdrawn and the new one queued.
//! The task's end, and an erase of the call, its actor or its recipient,
//! forget the row, retire the subject (whether or not a row committed) and
//! withdraw the Ask. The ledger row, its payload, state, budget and
//! settlement stay as they are, and `tools/call` is never sent again.

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
use self::owner_ask::{ANSWER, ASK_QUEUE, ask_matches, input_ask};
use super::settlement::intent_settlement_in_txn;
use super::types::{FrozenOutboundCall, IntentLedgerError, IntentLedgerResult, IntentState};
use crate::connector_key::SlateDisposition;
use crate::consent::AuthenticatedOwner;
use crate::model_decision::DecisionAnswer;
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

const NOT_DEFERRED: &str = "the intent is not a Deferred send with a remote task";

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

/// Refuses an owner answer the send's policy no longer admits: the send is
/// no longer Deferred, or the governing key's setting for the tool is now
/// never allow. A call that names no governing key has no setting to read.
fn refuse_never_allowed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    intent: &[u8; 32],
) -> crate::Result<()> {
    let mut record = super::store::get_ledger_record(vault, txn, intent)
        .map_err(owner_error)?
        .filter(|record| record.state == IntentState::Deferred)
        .ok_or_else(|| refused("the task's send is no longer deferred"))?;
    super::payload::open_payload_in_txn(vault, txn, &mut record).map_err(owner_error)?;
    let call = FrozenOutboundCall::from_record(&record);
    let view = crate::outbound_consent::FrozenToolCallView::read(&call)?;
    let Some(key_ref) = view.key_ref().and_then(|hex| EntityId::from_hex(hex).ok()) else {
        return Ok(());
    };
    let key = crate::connector_key::read_key_for_pack_in_txn(vault, txn, &key_ref)?
        .ok_or(crate::Error::EntityNotFound)?;
    let setting = crate::connector_key::connector_tool_setting_in_txn(
        &vault.store,
        txn,
        &key_ref,
        &key,
        view.tool(),
    )?;
    if setting == SlateDisposition::NeverAllow {
        return Err(refused(
            "the connector's setting for this tool is now never allow",
        ));
    }
    Ok(())
}

impl Vault {
    /// Parks the form question `question` of row `intent`'s remote task in
    /// `wtxn`, the poller's writer: its request sealed under the intent's
    /// task-input subject, its row, and its owner Ask, all in this one
    /// commit. The same question already parked (the same digest) changes
    /// nothing and returns its row. A different one is the next round: the
    /// current generation's retirement is staged before the next generation
    /// is minted, the old Ask is withdrawn and a new one queued.
    ///
    /// # Errors
    /// A schema that is not a flat object of string, number, integer or
    /// boolean fields (strings with choices included), as MCP form mode
    /// allows; a row that is not a Deferred send with a remote task, or
    /// whose connector or tool the question does not name; storage, custody
    /// and ask-queue faults.
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
        if intent_settlement_in_txn(self, wtxn, intent)?
            .remote_task
            .is_none()
        {
            return Err(IntentLedgerError::InvalidInput(NOT_DEFERRED));
        }
        if record.server != question.connector || record.tool != question.tool {
            return Err(IntentLedgerError::InvalidInput(
                "the question names another send's connector or tool",
            ));
        }
        let digest = question.digest();
        let current = INPUTS.get(&self.store, wtxn, intent)?;
        if let Some(row) = current.as_ref().filter(|row| row.question_digest == digest) {
            return Ok(row.parked());
        }
        let subject = input_subject(intent)?;
        let generation = match &current {
            None => 0,
            Some(row) => {
                // L04: the current generation retires before the next one
                // is minted, in this writer.
                retire_connector_resume_in_txn(&self.store, wtxn, &subject)?;
                self.withdraw_remote_task_input_ask_in_txn(wtxn, row.ask);
                row.generation
                    .checked_add(1)
                    .ok_or(IntentLedgerError::InvalidRecord(
                        "outbound remote task input generation",
                    ))?
            }
        };
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
    /// request as an accept: the row is Ready, and its Ask is answered
    /// Answer once the write committed.
    ///
    /// # Errors
    /// A proof that is not the owner's; no question parked; a stale round;
    /// a question not waiting for the owner; a field the schema does not
    /// name, a required field left out, a value of the wrong type, outside
    /// its choices or its bounds; a send no longer Deferred, or whose tool's
    /// setting is now never allow; custody and storage faults.
    pub fn submit_remote_task_input(
        &self,
        owner: &AuthenticatedOwner,
        intent: &[u8; 32],
        generation: u32,
        content: Map<String, Value>,
    ) -> crate::Result<()> {
        let ask = self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
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
            refuse_never_allowed_in_txn(self, txn, intent)?;
            let subject = input_subject(intent)?;
            let mut carrier = open_carrier_in_txn(self, txn, &subject, generation, &row.sealed)?;
            FormSchema::read(&carrier.requested_schema)
                .and_then(|schema| schema.check(&content))
                .map_err(refused)?;
            let mut answer = Map::new();
            answer.insert("action".to_owned(), Value::String("accept".to_owned()));
            answer.insert("content".to_owned(), Value::Object(content));
            carrier.answer = Some(Value::Object(answer));
            row.sealed = seal_carrier_in_txn(self, txn, &subject, generation, &carrier)?;
            row.phase = RemoteTaskInputPhase::Ready;
            INPUTS.put(&self.store, txn, intent, &row)?;
            Ok(row.ask)
        })?;
        if let Err(error) =
            self.answer_decision_ask(owner, ask, DecisionAnswer::Choice(ANSWER.to_owned()))
        {
            tracing::warn!(
                reason = "remote_task_input_ask_not_answered",
                ask,
                error = %error,
                "the owner ask of a task question the owner answered stays open; the answer \
                 is kept as before"
            );
        }
        Ok(())
    }

    /// The owner's Decline or Cancel on decision ask `seq`, before the ask
    /// answer door records the answer, which resolves the Ask: only an open
    /// Ask of a parked question, bound to that question's intent, digest and
    /// round, sets its phase, with no content. Any other ask is left alone.
    /// The same press again changes nothing.
    ///
    /// # Errors
    /// A proof that is not the owner's; an Ask whose question is no longer
    /// parked, is another round's, or was answered another way. Nothing
    /// changes then, and the caller records no answer, so the Ask stays
    /// open.
    pub fn press_remote_task_input_ask(
        &self,
        owner: &AuthenticatedOwner,
        seq: u64,
        choice: RemoteTaskInputChoice,
    ) -> crate::Result<()> {
        let Some(ask) = self.decision_ask(seq)? else {
            return Ok(());
        };
        if ask.queue_pin.model != ASK_QUEUE || !ask.is_open() {
            return Ok(());
        }
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let mut found = None;
            for row in INPUTS.iter_from(&self.store, txn, &[])? {
                let (intent, row) = row?;
                if row.ask == seq {
                    found = Some((intent, row));
                    break;
                }
            }
            let Some((intent, mut row)) = found else {
                return Err(refused("the ask's task question is no longer parked"));
            };
            if !ask_matches(&intent, &row, &ask)? {
                return Err(refused("the ask is not the task's current question"));
            }
            let pressed = choice.phase();
            if row.phase == pressed {
                return Ok(());
            }
            if row.phase != RemoteTaskInputPhase::AwaitingOwner {
                return Err(refused(
                    "the task's question is no longer waiting for the owner",
                ));
            }
            row.phase = pressed;
            INPUTS.put(&self.store, txn, &intent, &row)
        })
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
    /// question for a question whose digest is `question_digest`: only while
    /// the send is Deferred and the owner answered. The row is Sending in
    /// this writer, which the caller commits before its POST. `None` for a
    /// changed question, an unanswered or already claimed one, or none.
    ///
    /// # Errors
    /// Custody, storage and row-codec faults.
    pub fn claim_remote_task_answer_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        intent: &[u8; 32],
        question_digest: &[u8; 32],
    ) -> IntentLedgerResult<Option<RemoteTaskAnswer>> {
        let Some(mut row) = INPUTS.get(&self.store, wtxn, intent)? else {
            return Ok(None);
        };
        if row.question_digest != *question_digest || !row.phase.owner_answered() {
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
    /// committed, and its owner Ask is withdrawn. The task's end and the
    /// erase of its call, actor or recipient run it in their writer; the
    /// custody finisher retires the keys after commit
    /// ([`Self::finish_remote_task_input_retirements`]).
    ///
    /// # Errors
    /// Custody and storage faults. A row that does not read still goes.
    pub fn forget_remote_task_input_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        intent: &[u8; 32],
    ) -> IntentLedgerResult<()> {
        let row = INPUTS.get(&self.store, wtxn, intent).ok().flatten();
        INPUTS.delete(&self.store, wtxn, intent)?;
        retire_connector_resume_in_txn(&self.store, wtxn, &input_subject(intent)?)?;
        if let Some(row) = row {
            self.withdraw_remote_task_input_ask_in_txn(wtxn, row.ask);
        }
        Ok(())
    }

    /// [`Self::forget_remote_task_input_in_txn`] in a writer of its own, the
    /// key retirement carried out after its commit.
    ///
    /// # Errors
    /// Custody and storage faults, before the commit.
    pub fn forget_remote_task_input(&self, intent: &[u8; 32]) -> IntentLedgerResult<()> {
        self.try_with_write_txn_grouped(|txn| self.forget_remote_task_input_in_txn(txn, intent))?;
        self.finish_remote_task_input_retirements();
        Ok(())
    }

    /// Forgets every parked question whose send is no longer Deferred (it
    /// settled, stopped, or its row is gone), in one writer, and carries out
    /// the key retirements after its commit. How many it forgot.
    ///
    /// # Errors
    /// Custody, storage and row-codec faults, before the commit.
    pub fn forget_ended_remote_task_inputs(&self) -> IntentLedgerResult<usize> {
        let forgot = self.try_with_write_txn_grouped(|txn| -> IntentLedgerResult<usize> {
            let mut ended = Vec::new();
            for row in INPUTS.iter_from(&self.store, txn, &[])? {
                let (intent, _) = row?;
                let deferred = super::store::get_ledger_record(self, txn, &intent)?
                    .is_some_and(|record| record.state == IntentState::Deferred);
                if !deferred {
                    ended.push(intent);
                }
            }
            for intent in &ended {
                self.forget_remote_task_input_in_txn(txn, intent)?;
            }
            Ok(ended.len())
        })?;
        if forgot > 0 {
            self.finish_remote_task_input_retirements();
        }
        Ok(forgot)
    }

    /// Carries out the task-input key retirements a committed writer staged
    /// (a sent answer, a new round, a forgotten question). One that cannot
    /// run now is logged and runs on the next housekeeping pass.
    pub fn finish_remote_task_input_retirements(&self) {
        self.finish_connector_resume_retirements_after_commit();
    }

    /// Withdraws a parked question's owner Ask `seq` in `wtxn`, as the ask
    /// queue withdraws. A withdrawal that fails is logged, and the write
    /// goes on as it would without it.
    fn withdraw_remote_task_input_ask_in_txn(&self, wtxn: &mut heed::RwTxn<'_>, seq: u64) {
        if let Err(error) = self.withdraw_decision_ask_in_txn(wtxn, seq) {
            tracing::warn!(
                reason = "remote_task_input_ask_not_withdrawn",
                ask = seq,
                error = %error,
                "the owner ask of a task question that went was not withdrawn; the \
                 question is forgotten as before"
            );
        }
    }
}
