//! An erased dispatch target's instructions and briefing, out of the attempt
//! payloads that carry them (FIX 7076).
//!
//! An agent dispatch's payload (a Dreamer envelope whose input is an agent
//! dispatch input) snapshots its target's AGENT_DEF body, the definition's
//! instructions with it, and its context spec, the briefing with it; a
//! direct spawn's receipt and a planned launch's plan receipt hold the ask's
//! need and notes (OF-541, FIX 7444). Each is the target's: the AGENT_DEF
//! the dispatch runs as ([`agent_dispatch_actor`]), not its requester. A hard
//! erase of that target leaves them absent in every row that carries them,
//! in every state and retry generation, by one deterministic rewrite; every
//! other input member, the envelope's parent and every row field stay, so
//! each strict reader reads the erased row. Only the hard causes call in: a
//! delete keeps the text.
//!
//! A BYOA runner attempt carries its task's copies (FIX 7502): a CLI
//! connector's argv, and the staged job its connector or its bound work pins.
//! They are the TASK's its `task_ref` names. The same pass leaves them out of
//! the task's rows, out of the original request record a row of the task
//! names, and out of every row that pins one of the task's staged jobs, whose
//! artifacts go with them. Every other payload member stays, as does every
//! row field but the task's own failure text, which becomes one fixed
//! marker (FIX 7618); `task_ref` stays for the late-write fence.
//! The same pass drops the library-program pins of the task's tries (CUA
//! E4), which hold its arguments and goal.
//!
//! The ask and its briefing are the asker's too (FIX 9181): an erased
//! asker's receipts and briefing leave the rows that carry them, its target's
//! instructions staying (`asker`).

mod asker;
mod response;

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use crate::agent_def::AGENT_DEF_BODY_KEYS;
use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AGENT_DISPATCH_INPUT_KEYS, agent_dispatch_actor,
    decode_agent_dispatch_input, record_dispatch_input,
};
use crate::browser_library::{PROGRAM_ADMISSION_KIND, admission_payload_actor};
use crate::conversation::{TURN_ACTION_ATTEMPT_KIND, TurnActionAttempt};
use crate::dispatch_byoa::{
    BYOA_ATTEMPT_KIND, ByoaAttemptPayload, ByoaConnectorSpec, ERASED_TASK_FAILURE_REASON,
    RunnerTaskSource, StagedInputPin, decode_byoa_attempt_payload, encode_byoa_attempt_payload,
};
use crate::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload, encode_dreamer_attempt_payload,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::federation::RepoAccessRefusal;
use crate::ports::{DeletionMarker, EntityStoreRead, TombstoneStoreRead};
use crate::store::Store;
use crate::write_envelope::WriteActor;

use super::encoding::{decode_record, encode_record};
use super::types::{AttemptId, AttemptRecord};

// FIX 7115: the payload text in checkpoint images, a row-held response.
pub(crate) use self::response::{
    attempt_payload_family, attempt_payload_owners, attempt_payload_scan, attempt_row_opaque,
    retire_attempt_payload_in_txn,
};

/// The input member that holds the AGENT_DEF snapshot.
const KEY_DEFINITION: &str = AGENT_DISPATCH_INPUT_KEYS[4];
/// The input member that holds the serialized context spec.
const KEY_CONTEXT_SPEC: &str = AGENT_DISPATCH_INPUT_KEYS[5];
/// The input member that holds a direct spawn's receipt: its ask's need and
/// notes text (OF-541).
const KEY_DIRECT_SPAWN: &str = AGENT_DISPATCH_INPUT_KEYS[22];
/// The input member that holds a planned launch's plan receipt: its ask's
/// need and notes, and the plan's reasons (OF-541).
const KEY_PLAN: &str = AGENT_DISPATCH_INPUT_KEYS[19];
/// The AGENT_DEF body key of the definition's instructions.
const KEY_INSTRUCTIONS: &str = AGENT_DEF_BODY_KEYS[3];
/// The context spec's briefing member, as it serializes.
const KEY_BRIEFING: &str = "briefing";
const ERR_UNREWRITABLE: &str = "an agent dispatch payload's text could not be erased";

fn unrewritable() -> Error {
    Error::InvariantViolation(ERR_UNREWRITABLE)
}

/// Whose text an erase takes out of a dispatch payload.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TextOwner {
    /// The dispatch target's: its definition's instructions, and the ask and
    /// briefing it was given.
    Target,
    /// The asker's (FIX 9181): its ask's receipts and the briefing the ask
    /// became; the instructions are the target's and stay.
    Asker,
}

/// Who owns `record`'s dispatch text: its target AGENT_DEF, the actor the
/// dispatch runs as. `None` for a row that is no agent dispatch, or whose
/// input does not decode: it names no owner.
fn dispatch_payload_actor(record: &AttemptRecord) -> Option<EntityId> {
    let input = record_dispatch_input(record)?;
    agent_dispatch_actor(&input)
        .ok()
        .map(WriteActor::entity_ref)
}

/// Leaves `record`'s dispatch instructions, briefing, direct spawn receipt
/// and plan receipt absent, keeping every other input member, the
/// envelope's parent and every row field; for an erased asker (`owner`),
/// all but the instructions. `false` when the row is no agent dispatch or
/// carries none of them, so an erased row is not written again. The same
/// payload always comes out the same, so each retry generation of one
/// payload is rewritten alike. `record` changes only on success.
fn erase_dispatch_payload_text(record: &mut AttemptRecord, owner: TextOwner) -> Result<bool> {
    if record.kind != DREAMER_RUNNER_ATTEMPT_KIND {
        return Ok(false);
    }
    let mut payload = decode_dreamer_attempt_payload(&record.payload)?;
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return Ok(false);
    }
    let input = decode_agent_dispatch_input(&payload.input)?;
    let instructions = owner == TextOwner::Target && input.definition.instructions.is_some();
    let briefing = input
        .context_spec
        .as_ref()
        .is_some_and(|spec| spec.briefing.is_some());
    let direct_spawn = input.direct_spawn.is_some();
    let plan = input.plan.is_some();
    if !instructions && !briefing && !direct_spawn && !plan {
        return Ok(false);
    }
    let Value::Map(entries) = &mut payload.input else {
        return Err(unrewritable());
    };
    for (key, value) in entries.iter_mut() {
        match key.as_str() {
            Some(KEY_DEFINITION) if instructions => {
                *value = Value::Binary(without_instructions(value)?);
            }
            Some(KEY_CONTEXT_SPEC) if briefing => {
                *value = Value::from(without_briefing(value)?);
            }
            // Nil decodes as no receipt: the ask's text leaves with it.
            Some(KEY_DIRECT_SPAWN) if direct_spawn => *value = Value::Nil,
            _ => {}
        }
    }
    // The plan's key goes whole: present, it must hold a whole receipt, and
    // absent it decodes as no plan.
    entries.retain(|(key, _)| !plan || key.as_str() != Some(KEY_PLAN));
    // The strict decoder every reader uses reads the erased input, with
    // all four absent (the instructions kept for an erased asker).
    let erased = decode_agent_dispatch_input(&payload.input)?;
    if (owner == TextOwner::Target && erased.definition.instructions.is_some())
        || erased
            .context_spec
            .as_ref()
            .is_some_and(|spec| spec.briefing.is_some())
        || erased.direct_spawn.is_some()
        || erased.plan.is_some()
    {
        return Err(unrewritable());
    }
    record.payload = encode_dreamer_attempt_payload(&payload)?;
    Ok(true)
}

/// The AGENT_DEF body in `value` without its instructions key; every other
/// key keeps its place and its bytes.
fn without_instructions(value: &Value) -> Result<Vec<u8>> {
    let Value::Binary(body) = value else {
        return Err(unrewritable());
    };
    let mut cursor = body.as_slice();
    let Ok(Value::Map(mut members)) = rmpv::decode::read_value(&mut cursor) else {
        return Err(unrewritable());
    };
    members.retain(|(key, _)| key.as_str() != Some(KEY_INSTRUCTIONS));
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(members)).map_err(|_| unrewritable())?;
    Ok(out)
}

/// The serialized context spec in `value` with its briefing null, as a spec
/// with no briefing serializes; every other member keeps its place.
fn without_briefing(value: &Value) -> Result<String> {
    let json = value.as_str().ok_or_else(unrewritable)?;
    let mut spec: serde_json::Value = serde_json::from_str(json).map_err(|_| unrewritable())?;
    let briefing = spec.get_mut(KEY_BRIEFING).ok_or_else(unrewritable)?;
    *briefing = serde_json::Value::Null;
    serde_json::to_string(&spec).map_err(|_| unrewritable())
}

/// Whether `id` is a stored row of a type other than AGENT_DEF, which no
/// dispatch targets. A missing row may have been one.
fn names_no_agent(store: &Store, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(store
        .port_entity_raw(txn, id)?
        .as_deref()
        .and_then(crate::batch::EntityMetadataHeader::parse)
        .is_some_and(|header| header.entity_type != crate::registry::ENTITY_TYPE_AGENT_DEF))
}

/// [`erase_attempt_payload_actors_in_txn`] for one erased actor.
///
/// # Errors
///
/// Storage errors, and a matching payload that cannot be rewritten.
pub(crate) fn erase_attempt_payload_actor_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    erase_attempt_payload_actors_in_txn(store, txn, &BTreeSet::from([*actor]))
}

/// Leaves every attempt payload whose dispatch target is among `actors`
/// without its instructions, briefing and ask text, every one whose asker is
/// among them, or whose planned intent an asker's erase took, without its
/// ask and briefing (FIX 9181), and every BYOA copy of a TASK
/// among them without its task (FIX 7502), in the erase's transaction,
/// walking the whole ledger, every state and retry generation, and an
/// archived row's marker follows its row when it archived it as it stood,
/// as does its run's snapshot. A second walk empties whole every
/// `browser.program.admit` payload captured under one of them (FIX 10718).
/// A Dreamer row that does not decode names no
/// owner and stays; a matching row that cannot be rewritten, or a storage
/// error, fails the erase. Only an id stored as AGENT_DEF, or a missing one,
/// is a dispatch target; any erased id may be a BYOA row's task.
///
/// # Errors
///
/// Storage errors, and a matching payload that cannot be rewritten.
pub(crate) fn erase_attempt_payload_actors_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    actors: &BTreeSet<EntityId>,
) -> Result<()> {
    if actors.is_empty() {
        return Ok(());
    }
    let mut owners = BTreeSet::new();
    for actor in actors {
        if !names_no_agent(store, txn, actor)? {
            owners.insert(*actor);
        }
    }
    // A BYOA row's task is the TASK its `task_ref` names, as canonical hex.
    let tasks: BTreeSet<String> = actors.iter().map(EntityId::to_hex).collect();
    // The planned intents an asker's erase took; the intents' own erase ran
    // first in this transaction (FIX 9181).
    let asker_intents =
        crate::agent_dispatch::AgentDispatcher::asker_erased_intent_keys_in(store, txn)?;
    let mut rewrites = Vec::new();
    let mut byoa = ByoaRows::default();
    let mut reply_jobs = Vec::new();
    for row in store.attempt_records.iter(txn)? {
        let (key, raw) = row?;
        let Ok(id) = AttemptId::from_bytes(&key) else {
            continue;
        };
        let Ok(mut record) = decode_record(&raw, id) else {
            continue;
        };
        if record.kind == TURN_ACTION_ATTEMPT_KIND {
            // A turn action keeps the slip its requester's request was
            // admitted on; the requester's erase takes it out, in every
            // state (FIX 10668). A payload that does not decode names no
            // requester and stays.
            if let Ok(mut action) = TurnActionAttempt::decode(&record) {
                let requester = action.actor;
                if actors.contains(&requester) && action.scrub_actor_instrument(&requester) {
                    record.payload = action.encode()?;
                    rewrites.push((raw.into_owned(), record));
                }
            }
        } else if record.kind == BYOA_ATTEMPT_KIND {
            byoa.gather(&raw, record, &tasks);
        } else if record.kind == crate::outbound::CONNECTOR_REPLY_JOB_KIND {
            // A connector reply job carries its event's sender, chat and
            // receiving identity (FIX 2405): any erased id it names takes
            // the event's payload, and the job's result, with it.
            if crate::outbound::erase_connector_reply_job_payload(&mut record, actors)? {
                reply_jobs.push(record.id);
                rewrites.push((raw.into_owned(), record));
            }
        } else if dispatch_payload_actor(&record).is_some_and(|actor| owners.contains(&actor))
            && erase_dispatch_payload_text(&mut record, TextOwner::Target)?
        {
            rewrites.push((raw.into_owned(), record));
        } else if asker::asker_owned(&record, actors, &asker_intents)
            && erase_dispatch_payload_text(&mut record, TextOwner::Asker)?
        {
            rewrites.push((raw.into_owned(), record));
        }
    }
    erase_program_admission_payloads_in_txn(store, txn, actors, &mut rewrites)?;
    let jobs = byoa.erase_copies(store, txn, &mut rewrites)?;
    // No row this pass writes pins them now; their jobs' artifacts go by the
    // artifact's own rules (FIX 7502).
    crate::dispatch_byoa::erase_staged_input_in_txn(store, txn, &jobs, actors)?;
    crate::outbound::erase_connector_reply_results_in_txn(store, txn, &reply_jobs)?;
    // A bound TASK's tries pin its arguments and goal (CUA E4): they go with
    // the TASK, archived tries' too.
    crate::task_verb::erase_task_workflows_in_txn(store, txn, actors)?;
    // The erase authors nothing, so the plain encoder writes the row: the
    // side-row wall that could refuse a write does not stand in its way.
    let mut rewritten = Vec::with_capacity(rewrites.len());
    for (before, record) in rewrites {
        let after = encode_record(&record)?;
        store
            .attempt_records
            .put(txn, record.id.as_bytes(), &after)?;
        crate::vault_cleanup::refresh_archived_attempt_in_txn(
            store, txn, record.id, &before, &after,
        )?;
        rewritten.push((record.id, before, after));
    }
    // Each rewritten row's run snapshot moves with its mark (FIX 7517).
    crate::vault_cleanup::erase_attempt_references_in_txn(store, txn, &rewritten)
}

/// Empties whole every `browser.program.admit` payload captured under one
/// of `actors` (FIX 10718): the payload holds the source scope's actor
/// and the proposal's literal args, so an erased actor's goes whole, as
/// an erased task's undecodable payload does (FIX 5736). Each emptied row
/// joins `rewrites`; a payload that does not decode names no actor and
/// stays. The emptied job decode-fails into the undecodable receipt path
/// (FIX 10716).
///
/// # Errors
///
/// Storage errors.
fn erase_program_admission_payloads_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actors: &BTreeSet<EntityId>,
    rewrites: &mut Vec<(Vec<u8>, AttemptRecord)>,
) -> Result<()> {
    for row in store.attempt_records.iter(txn)? {
        let (key, raw) = row?;
        let Ok(id) = AttemptId::from_bytes(&key) else {
            continue;
        };
        let Ok(mut record) = decode_record(&raw, id) else {
            continue;
        };
        if record.kind != PROGRAM_ADMISSION_KIND {
            continue;
        }
        let owned =
            admission_payload_actor(&record.payload).is_some_and(|actor| actors.contains(&actor));
        if owned && !record.payload.is_empty() {
            record.payload.clear();
            rewrites.push((raw.into_owned(), record));
        }
    }
    Ok(())
}

/// The BYOA rows the pass's cursor kept: each row of an erased task, and
/// each row that pins a staged job or carries bound work, so what they name
/// resolves after the cursor with no second walk.
#[derive(Default)]
struct ByoaRows {
    rows: BTreeMap<AttemptId, ByoaRow>,
    /// The rows whose `task_ref` names an erased TASK.
    tasks: BTreeSet<AttemptId>,
}

/// One kept BYOA row: its stored bytes, the row, and its payload when that
/// decodes.
struct ByoaRow {
    raw: Vec<u8>,
    record: AttemptRecord,
    payload: Option<ByoaAttemptPayload>,
}

impl ByoaRows {
    fn gather(&mut self, raw: &[u8], record: AttemptRecord, tasks: &BTreeSet<String>) {
        let payload = decode_byoa_attempt_payload(&record.payload).ok();
        let task = record
            .task_ref
            .as_ref()
            .is_some_and(|task| tasks.contains(task));
        let typed = payload
            .as_ref()
            .is_some_and(|payload| dev_refs_match(payload, tasks));
        let refers = payload
            .as_ref()
            .is_some_and(|payload| payload.work.is_some() || pins(payload).next().is_some());
        if !task && !typed && !refers {
            return;
        }
        if task || typed {
            self.tasks.insert(record.id);
        }
        let id = record.id;
        self.rows.insert(
            id,
            ByoaRow {
                raw: raw.to_vec(),
                record,
                payload,
            },
        );
    }

    /// Leaves each copy of an erased task out of the rows that hold it: the
    /// task's own rows, the original request record each of them names, and
    /// every row that pins one of their staged jobs. Each changed row joins
    /// `rewrites`. Answers those jobs' digests, for their artifacts to go.
    fn erase_copies(
        mut self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        rewrites: &mut Vec<(Vec<u8>, AttemptRecord)>,
    ) -> Result<BTreeSet<[u8; 32]>> {
        let mut owned = self.tasks.clone();
        for id in &self.tasks {
            let source = self
                .rows
                .get(id)
                .and_then(|row| row.payload.as_ref())
                .and_then(|payload| payload.work.as_ref())
                .and_then(|work| work.task_source);
            let Some(RunnerTaskSource::CliAttempt(source)) = source else {
                continue;
            };
            let Ok(source) = AttemptId::from_bytes(&source) else {
                continue;
            };
            if !self.rows.contains_key(&source) {
                let Some(row) = read_byoa_row(store, txn, source)? else {
                    continue;
                };
                self.rows.insert(source, row);
            }
            owned.insert(source);
        }
        let mut jobs = BTreeSet::new();
        for id in &owned {
            if let Some(payload) = self.rows.get(id).and_then(|row| row.payload.as_ref()) {
                jobs.extend(pins(payload).map(|pin| pin.blake3));
            }
        }
        for (id, row) in self.rows {
            let ByoaRow {
                raw,
                mut record,
                payload,
            } = row;
            let own = owned.contains(&id);
            match payload {
                Some(mut payload) => {
                    let changed = erase_byoa_payload(&mut payload, own, &jobs);
                    let scrubbed = own && scrub_erased_task_failure_reason(&mut record.last_error);
                    if changed {
                        record.payload =
                            encode_byoa_attempt_payload(&payload).map_err(|_| unrewritable())?;
                    }
                    if changed || scrubbed {
                        rewrites.push((raw, record));
                    }
                }
                // A task's row whose payload does not decode has no readable
                // erased form, so its payload goes whole and the erase goes
                // on (Engine on FIX 5736).
                None if own && !record.payload.is_empty() => {
                    tracing::warn!(
                        attempt = %crate::entity_id::bytes_to_hex_lower(record.id.as_bytes()),
                        "attempt payload erase: an erased task's undecodable payload was emptied"
                    );
                    record.payload.clear();
                    scrub_erased_task_failure_reason(&mut record.last_error);
                    rewrites.push((raw, record));
                }
                None => {}
            }
        }
        Ok(jobs)
    }
}

/// The BYOA row `id`, read by its key: an original request record the cursor
/// kept no copy of. `None` when it is gone or is no BYOA row.
fn read_byoa_row(store: &Store, txn: &heed::RoTxn<'_>, id: AttemptId) -> Result<Option<ByoaRow>> {
    let Some(raw) = store.attempt_records.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let Ok(record) = decode_record(&raw, id) else {
        return Ok(None);
    };
    if record.kind != BYOA_ATTEMPT_KIND {
        return Ok(None);
    }
    let payload = decode_byoa_attempt_payload(&record.payload).ok();
    Ok(Some(ByoaRow {
        raw: raw.into_owned(),
        record,
        payload,
    }))
}

/// Whether a dev-runner payload names an erased actor, diagnostic or evidence
/// row by a typed reference (FIX 7621). No staged job text enters this match.
fn dev_refs_match(payload: &ByoaAttemptPayload, erased: &BTreeSet<String>) -> bool {
    let Some(refs) = payload.dev_refs.as_ref() else {
        return false;
    };
    std::iter::once(&refs.actor)
        .chain(refs.diagnostics.iter())
        .chain(refs.evidence.iter())
        .any(|id| erased.contains(&bytes_to_hex_lower(id)))
}

/// The staged jobs `payload` pins: its CLI connector's and its bound work's.
fn pins(payload: &ByoaAttemptPayload) -> impl Iterator<Item = &StagedInputPin> {
    let cli = match &payload.connector {
        ByoaConnectorSpec::CliSandbox(spec) => spec.staged_input.as_ref(),
        _ => None,
    };
    let work = payload
        .work
        .as_ref()
        .and_then(|work| work.staged_input.as_ref());
    cli.into_iter().chain(work)
}

impl Store {
    /// Whether a live BYOA row still pins staged job `digest` (FIX 7612).
    /// Pins on a hard-erased attempt, TASK, actor, diagnostic or evidence row
    /// are not live. Only connector references and deletion markers are read,
    /// never the staged job's text.
    ///
    /// # Errors
    ///
    /// Storage errors from the attempt ledger or deletion-marker reads.
    pub(crate) fn live_staged_input_pin_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        digest: &[u8; 32],
    ) -> Result<bool> {
        for row in self.attempt_records.iter(txn)? {
            let (key, raw) = row?;
            let Ok(id) = AttemptId::from_bytes(&key) else {
                continue;
            };
            let Ok(record) = decode_record(&raw, id) else {
                continue;
            };
            if record.kind != BYOA_ATTEMPT_KIND {
                continue;
            }
            let Ok(payload) = decode_byoa_attempt_payload(&record.payload) else {
                continue;
            };
            if !pins(&payload).any(|pin| pin.blake3 == *digest) {
                continue;
            }
            let attempt = EntityId::from_bytes_unchecked(*record.id.as_bytes());
            let mut live = !self.port_deletion_marked(txn, DeletionMarker::HardDelete, &attempt)?;
            if live
                && let Some(task) = record
                    .task_ref
                    .as_deref()
                    .and_then(|task| EntityId::from_hex(task).ok())
            {
                live = !self.port_deletion_marked(txn, DeletionMarker::HardDelete, &task)?;
            }
            if live && let Some(refs) = payload.dev_refs.as_ref() {
                for id in std::iter::once(&refs.actor)
                    .chain(refs.diagnostics.iter())
                    .chain(refs.evidence.iter())
                {
                    let Ok(id) = EntityId::from_bytes(*id) else {
                        continue;
                    };
                    if self.port_deletion_marked(txn, DeletionMarker::HardDelete, &id)? {
                        live = false;
                        break;
                    }
                }
            }
            if live {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Replaces an erased task's failure text with the fixed marker (FIX 7618):
/// a scrubbed row carries no reason that may quote the task. `None` stays
/// absent, so Completed/Cancelled rows keep their shape, and the stale-lease
/// code stays, already content-free and driving `StaleCheckout` truth.
/// Answers whether `last_error` changed, so an erased row is not written again.
fn scrub_erased_task_failure_reason(last_error: &mut Option<String>) -> bool {
    let Some(reason) = last_error.as_deref() else {
        return false;
    };
    if reason == ERASED_TASK_FAILURE_REASON || reason == RepoAccessRefusal::StaleLease.public_code()
    {
        return false;
    }
    *last_error = Some(ERASED_TASK_FAILURE_REASON.to_owned());
    true
}

/// Leaves `payload` holding no copy of an erased task (FIX 7502). A row of
/// the task (`own`) loses its argv and every staged pin; any other row loses
/// each pin to one of the erased `jobs`, and a CLI row its argv with it, as
/// its task is that job's file. Every other member stays, so each reader
/// reads the erased row, and an empty argv names no runner task: a bound
/// work's CLI seats are passed over. `false` when nothing changes, so an
/// erased row is not written again.
fn erase_byoa_payload(
    payload: &mut ByoaAttemptPayload,
    own: bool,
    jobs: &BTreeSet<[u8; 32]>,
) -> bool {
    let erased =
        |pin: Option<&StagedInputPin>| pin.is_some_and(|pin| own || jobs.contains(&pin.blake3));
    let mut changed = false;
    if let ByoaConnectorSpec::CliSandbox(spec) = &mut payload.connector {
        let job = erased(spec.staged_input.as_ref());
        if (own || job) && !spec.argv.is_empty() {
            spec.argv.clear();
            changed = true;
        }
        if job {
            spec.staged_input = None;
            changed = true;
        }
    }
    if let Some(work) = &mut payload.work
        && erased(work.staged_input.as_ref())
    {
        work.staged_input = None;
        changed = true;
    }
    changed
}

/// A late write's fence (FIX 7076): when `record` is an agent dispatch
/// whose target bears the permanent hard-delete marker, its instructions,
/// briefing, direct spawn receipt and plan receipt leave it before it is
/// encoded, so a copy read before the erase writes back the erased bytes;
/// when an erase took its asker instead, all but the instructions do (FIX
/// 9181). Only that marker counts: a soft delete, an archive or a gone
/// actor keeps the text. Read in the writer's transaction. A marker that cannot be read,
/// or a payload that cannot be rewritten, leaves `record` as it was and is
/// logged without its content: the fence never fails the write it stands in.
pub(super) fn scrub_hard_erased_payload_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &mut AttemptRecord,
) {
    if record.kind == TURN_ACTION_ATTEMPT_KIND {
        // A turn action whose requester bears the marker writes back no
        // slip (FIX 10668), as the pass leaves it.
        let Ok(mut action) = TurnActionAttempt::decode(record) else {
            return;
        };
        let requester = action.actor;
        if !action.holds_slip() {
            return;
        }
        match store.port_deletion_marked(txn, DeletionMarker::HardDelete, &requester) {
            Ok(false) => {}
            Ok(true) => {
                if action.scrub_actor_instrument(&requester) {
                    match action.encode() {
                        Ok(bytes) => record.payload = bytes,
                        Err(_) => tracing::warn!(
                            attempt = %crate::entity_id::bytes_to_hex_lower(record.id.as_bytes()),
                            "attempt payload fence: an erased requester's slip could not be removed"
                        ),
                    }
                }
            }
            Err(_) => {
                tracing::warn!(
                    attempt = %crate::entity_id::bytes_to_hex_lower(record.id.as_bytes()),
                    "attempt payload fence: the requester's hard-delete marker could not be read"
                );
            }
        }
        return;
    }
    if record.kind == BYOA_ATTEMPT_KIND {
        scrub_hard_erased_task_copy_in_txn(store, txn, record);
        return;
    }
    let Some(actor) = dispatch_payload_actor(record) else {
        return;
    };
    match store.port_deletion_marked(txn, DeletionMarker::HardDelete, &actor) {
        Ok(false) => {
            if asker::asker_erased_in(store, txn, record)
                && erase_dispatch_payload_text(record, TextOwner::Asker).is_err()
            {
                tracing::warn!(
                    attempt = %crate::entity_id::bytes_to_hex_lower(record.id.as_bytes()),
                    "attempt payload fence: an erased asker's dispatch text could not be removed"
                );
            }
        }
        Ok(true) => {
            if erase_dispatch_payload_text(record, TextOwner::Target).is_err() {
                tracing::warn!(
                    attempt = %crate::entity_id::bytes_to_hex_lower(record.id.as_bytes()),
                    "attempt payload fence: an erased target's dispatch text could not be removed"
                );
            }
        }
        Err(_) => {
            tracing::warn!(
                attempt = %crate::entity_id::bytes_to_hex_lower(record.id.as_bytes()),
                "attempt payload fence: the target's hard-delete marker could not be read"
            );
        }
    }
}

/// The fence for a BYOA row (FIX 7502, 7621): when the TASK its `task_ref`
/// names, or any actor, diagnostic or evidence row its typed refs name, bears
/// the permanent hard-delete marker, the row's copies leave before it is
/// encoded, as the pass leaves them: its argv and its staged pins, or a payload
/// that does not decode, whole, and its failure text becomes the fixed marker
/// (FIX 7618). Logged without content, never failing the write, as the fence
/// above.
fn scrub_hard_erased_task_copy_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &mut AttemptRecord,
) {
    let task = record
        .task_ref
        .as_deref()
        .and_then(|task| EntityId::from_hex(task).ok());
    let mut erased = match task {
        Some(task) => match store.port_deletion_marked(txn, DeletionMarker::HardDelete, &task) {
            Ok(erased) => erased,
            Err(_) => {
                tracing::warn!(
                    attempt = %crate::entity_id::bytes_to_hex_lower(record.id.as_bytes()),
                    "attempt payload fence: the task's hard-delete marker could not be read"
                );
                return;
            }
        },
        None => false,
    };
    let decoded = decode_byoa_attempt_payload(&record.payload);
    if !erased
        && let Ok(payload) = &decoded
        && let Some(refs) = payload.dev_refs.as_ref()
    {
        for id in std::iter::once(&refs.actor)
            .chain(refs.diagnostics.iter())
            .chain(refs.evidence.iter())
        {
            let Ok(id) = EntityId::from_bytes(*id) else {
                continue;
            };
            match store.port_deletion_marked(txn, DeletionMarker::HardDelete, &id) {
                Ok(true) => {
                    erased = true;
                    break;
                }
                Ok(false) => {}
                Err(_) => {
                    tracing::warn!(
                        attempt = %crate::entity_id::bytes_to_hex_lower(record.id.as_bytes()),
                        "attempt payload fence: a typed ref's hard-delete marker could not be read"
                    );
                    return;
                }
            }
        }
    }
    if !erased {
        return;
    }
    match decoded {
        Ok(mut payload) => {
            let changed = erase_byoa_payload(&mut payload, true, &BTreeSet::new());
            // The fence defends the pass's marker too: a late copy read
            // before the erase writes back no failure text quoting the
            // task, even when its payload holds no copy to scrub.
            scrub_erased_task_failure_reason(&mut record.last_error);
            if !changed {
                return;
            }
            match encode_byoa_attempt_payload(&payload) {
                Ok(bytes) => record.payload = bytes,
                Err(_) => tracing::warn!(
                    attempt = %crate::entity_id::bytes_to_hex_lower(record.id.as_bytes()),
                    "attempt payload fence: an erased task's copies could not be removed"
                ),
            }
        }
        Err(_) => {
            record.payload.clear();
            scrub_erased_task_failure_reason(&mut record.last_error);
        }
    }
}
