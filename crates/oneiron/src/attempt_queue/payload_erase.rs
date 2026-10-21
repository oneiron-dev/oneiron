//! An erased dispatch target's instructions and briefing, out of the attempt
//! payloads that carry them (FIX 7076).
//!
//! An agent dispatch's payload (a Dreamer envelope whose input is an agent
//! dispatch input) snapshots its target's AGENT_DEF body, the definition's
//! instructions with it, and its context spec, the briefing with it. Both
//! are the target's: the AGENT_DEF the dispatch runs as
//! ([`agent_dispatch_actor`]), not its requester. A hard erase of that target
//! leaves both absent in every row that carries them, in every state and
//! retry generation, by one deterministic rewrite; every other input member,
//! the envelope's parent and every row field stay, so each strict reader
//! reads the erased row. Only the hard causes call in: a delete keeps the
//! text.
//!
//! A BYOA runner attempt carries its task's copies (FIX 7502): a CLI
//! connector's argv, and the staged job its connector or its bound work pins.
//! They are the TASK's its `task_ref` names. The same pass leaves them out of
//! the task's rows, out of the original request record a row of the task
//! names, and out of every row that pins one of the task's staged jobs, whose
//! artifacts go with them. Every other payload member and row field stays.
//! The same pass drops the library-program pins of the task's tries (CUA
//! E4), which hold its arguments and goal.

mod response;

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use crate::agent_def::AGENT_DEF_BODY_KEYS;
use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AGENT_DISPATCH_INPUT_KEYS, agent_dispatch_actor,
    decode_agent_dispatch_input, record_dispatch_input,
};
use crate::dispatch_byoa::{
    BYOA_ATTEMPT_KIND, ByoaAttemptPayload, ByoaConnectorSpec, RunnerTaskSource, StagedInputPin,
    decode_byoa_attempt_payload, encode_byoa_attempt_payload,
};
use crate::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload, encode_dreamer_attempt_payload,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{DeletionMarker, EntityStoreRead, TombstoneStoreRead};
use crate::store::Store;
use crate::write_envelope::WriteActor;

use super::encoding::{decode_record, encode_record};
use super::types::{AttemptId, AttemptRecord};

// FIX 7115: the payload text in checkpoint images, a row-held response.
pub(crate) use self::response::{
    attempt_payload_family, attempt_payload_owners, attempt_payload_stub,
    retire_attempt_payload_in_txn,
};

/// The input member that holds the AGENT_DEF snapshot.
const KEY_DEFINITION: &str = AGENT_DISPATCH_INPUT_KEYS[4];
/// The input member that holds the serialized context spec.
const KEY_CONTEXT_SPEC: &str = AGENT_DISPATCH_INPUT_KEYS[5];
/// The input member that holds a direct spawn's receipt: its ask's need and
/// notes text (OF-541).
const KEY_DIRECT_SPAWN: &str = AGENT_DISPATCH_INPUT_KEYS[22];
/// The AGENT_DEF body key of the definition's instructions.
const KEY_INSTRUCTIONS: &str = AGENT_DEF_BODY_KEYS[3];
/// The context spec's briefing member, as it serializes.
const KEY_BRIEFING: &str = "briefing";
const ERR_UNREWRITABLE: &str = "an agent dispatch payload's text could not be erased";

fn unrewritable() -> Error {
    Error::InvariantViolation(ERR_UNREWRITABLE)
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

/// Leaves `record`'s dispatch instructions, briefing and direct spawn
/// receipt absent, keeping every other input member, the envelope's parent
/// and every row field. `false` when the row is no agent dispatch or carries
/// none of them, so an erased row is not written again. The same payload
/// always comes out the same, so each retry generation of one payload is
/// rewritten alike. `record` changes only on success.
fn erase_dispatch_payload_text(record: &mut AttemptRecord) -> Result<bool> {
    if record.kind != DREAMER_RUNNER_ATTEMPT_KIND {
        return Ok(false);
    }
    let mut payload = decode_dreamer_attempt_payload(&record.payload)?;
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return Ok(false);
    }
    let input = decode_agent_dispatch_input(&payload.input)?;
    let instructions = input.definition.instructions.is_some();
    let briefing = input
        .context_spec
        .as_ref()
        .is_some_and(|spec| spec.briefing.is_some());
    let direct_spawn = input.direct_spawn.is_some();
    if !instructions && !briefing && !direct_spawn {
        return Ok(false);
    }
    let Value::Map(entries) = &mut payload.input else {
        return Err(unrewritable());
    };
    for (key, value) in entries {
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
    // The strict decoder every reader uses reads the erased input, with
    // all three absent.
    let erased = decode_agent_dispatch_input(&payload.input)?;
    if erased.definition.instructions.is_some()
        || erased
            .context_spec
            .as_ref()
            .is_some_and(|spec| spec.briefing.is_some())
        || erased.direct_spawn.is_some()
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
/// without its instructions and briefing, and every BYOA copy of a TASK
/// among them without its task (FIX 7502), in the erase's transaction: one
/// pass over the whole ledger, every state and retry generation, and an
/// archived row's marker follows its row when it archived it as it stood,
/// as does its run's snapshot. A Dreamer row that does not decode names no
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
    let mut rewrites = Vec::new();
    let mut byoa = ByoaRows::default();
    for row in store.attempt_records.iter(txn)? {
        let (key, raw) = row?;
        let Ok(id) = AttemptId::from_bytes(&key) else {
            continue;
        };
        let Ok(mut record) = decode_record(&raw, id) else {
            continue;
        };
        if record.kind == BYOA_ATTEMPT_KIND {
            byoa.gather(&raw, record, &tasks);
        } else if dispatch_payload_actor(&record).is_some_and(|actor| owners.contains(&actor))
            && erase_dispatch_payload_text(&mut record)?
        {
            rewrites.push((raw.into_owned(), record));
        }
    }
    let jobs = byoa.erase_copies(store, txn, &mut rewrites)?;
    // No row this pass writes pins them now; their jobs' artifacts go by the
    // artifact's own rules (FIX 7502).
    crate::dispatch_byoa::erase_staged_input_in_txn(store, txn, &jobs)?;
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
        let refers = payload
            .as_ref()
            .is_some_and(|payload| payload.work.is_some() || pins(payload).next().is_some());
        if !task && !refers {
            return;
        }
        if task {
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
                    if erase_byoa_payload(&mut payload, own, &jobs) {
                        record.payload =
                            encode_byoa_attempt_payload(&payload).map_err(|_| unrewritable())?;
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
/// briefing and direct spawn receipt leave it before it is encoded, so a
/// copy read before the erase writes back the erased bytes. Only that
/// marker counts: a soft delete, an archive or a gone actor keeps the text.
/// Read in the writer's transaction. A marker that cannot be read, or a
/// payload that cannot be rewritten, leaves `record` as it was and is logged
/// without its content: the fence never fails the write it stands in.
pub(super) fn scrub_hard_erased_payload_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &mut AttemptRecord,
) {
    if record.kind == BYOA_ATTEMPT_KIND {
        scrub_hard_erased_task_copy_in_txn(store, txn, record);
        return;
    }
    let Some(actor) = dispatch_payload_actor(record) else {
        return;
    };
    match store.port_deletion_marked(txn, DeletionMarker::HardDelete, &actor) {
        Ok(false) => {}
        Ok(true) => {
            if erase_dispatch_payload_text(record).is_err() {
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

/// The fence for a BYOA row (FIX 7502): when the TASK its `task_ref` names
/// bears the permanent hard-delete marker, the task's copies leave the row
/// before it is encoded, as the pass leaves them: its argv and its staged
/// pins, or a payload that does not decode, whole. Logged without content,
/// never failing the write, as the fence above.
fn scrub_hard_erased_task_copy_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &mut AttemptRecord,
) {
    let Some(task) = record
        .task_ref
        .as_deref()
        .and_then(|task| EntityId::from_hex(task).ok())
    else {
        return;
    };
    match store.port_deletion_marked(txn, DeletionMarker::HardDelete, &task) {
        Ok(false) => {}
        Ok(true) => match decode_byoa_attempt_payload(&record.payload) {
            Ok(mut payload) => {
                if !erase_byoa_payload(&mut payload, true, &BTreeSet::new()) {
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
            Err(_) => record.payload.clear(),
        },
        Err(_) => {
            tracing::warn!(
                attempt = %crate::entity_id::bytes_to_hex_lower(record.id.as_bytes()),
                "attempt payload fence: the task's hard-delete marker could not be read"
            );
        }
    }
}
