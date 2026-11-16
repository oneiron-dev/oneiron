//! Doors for `tests/read_lineage_cost.rs`, Fable pass 30's MEASURE.md
//! (bench only; never merged): what a source-audience lineage walk and a
//! stored floor each cost per read, and what raising a floor costs a write.
//!
//! Every timing door opens ONE transaction for the call and times each row
//! with [`Instant`]. A read door reads the row's own bytes before its timer
//! starts, as a scoped read hands them to the audience conjunct.

use std::collections::{BTreeSet, HashMap};
use std::time::Instant;

use crate::error::{Error, Result};
use crate::memory::{
    ImportedTurnStamp, Memory, MemoryResult, SourceAttribution, WitnessAuthor, WitnessMessage,
    WitnessTurn,
};
use crate::ports::EntityStoreRead;
use crate::source_audience::{self, SourceAudienceBirth};
use crate::{EntityId, Vault};

/// One row's time and verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowTime {
    /// Nanoseconds the row took.
    pub ns: u64,
    /// Whether the row read to the viewer (a read door), or whether its floor
    /// was written (the write door).
    pub verdict: bool,
}

/// The `DERIVED` side table as stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloorTableBytes {
    /// Rows with a floor.
    pub entries: u64,
    /// Bytes of their full keys.
    pub key_bytes: u64,
    /// Bytes of their values.
    pub value_bytes: u64,
}

/// One mail TURN a door landed, bound as a mail landing binds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandedTurn {
    /// The TURN.
    pub turn: EntityId,
    /// Its MESSAGE rows, in order.
    pub messages: Vec<EntityId>,
    /// The thread policy the CONVERSATION, the TURN and its MESSAGEs are
    /// bound to.
    pub thread: EntityId,
}

fn nanos(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// Turns the bench's switch on or off: with it on, the source-audience walk
/// (`walk.rs` `word_sources`) also follows a row's birth inputs and its
/// registered dependencies. Shape (a) made correct.
pub fn set_follow_birth_inputs(on: bool) {
    source_audience::set_follow_birth_inputs(on);
}

/// Times `source_audience::readable_with_read_in` for `viewer` on each of
/// `ids`, in one read transaction.
///
/// # Errors
///
/// A row this vault does not hold; storage and walk failures.
pub fn time_mail_walk(vault: &Vault, ids: &[EntityId], viewer: EntityId) -> Result<Vec<RowTime>> {
    let txn = vault.store.env.read_txn()?;
    let dbs = vault.store.read();
    let viewers = [viewer];
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let raw = dbs
            .port_entity_raw(&txn, id)?
            .ok_or(Error::EntityNotFound)?;
        let start = Instant::now();
        let verdict =
            source_audience::readable_with_read_in(vault, &dbs, &txn, *id, &raw, &viewers)?;
        out.push(RowTime {
            ns: nanos(start),
            verdict,
        });
    }
    Ok(out)
}

/// Times shape (b)'s read for `viewer` on each of `ids`, in one read
/// transaction: the row's stored floor (`derived_policies_in`), its own
/// binding only when its bytes carry the source-audience stamp (a stamped row
/// with no binding reads to no one), then one lookup per source in a map kept
/// for the call, filled by `actor_reads_in` on a miss.
///
/// # Errors
///
/// A row this vault does not hold; storage failures.
pub fn time_floor_probe(vault: &Vault, ids: &[EntityId], viewer: EntityId) -> Result<Vec<RowTime>> {
    let txn = vault.store.env.read_txn()?;
    let dbs = vault.store.read();
    let mut verdicts: HashMap<EntityId, bool> = HashMap::new();
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let raw = dbs
            .port_entity_raw(&txn, id)?
            .ok_or(Error::EntityNotFound)?;
        let start = Instant::now();
        let mut sources: Vec<EntityId> = source_audience::derived_policies_in(vault, &txn, id)?
            .map(|floor| floor.into_iter().collect())
            .unwrap_or_default();
        let mut verdict = true;
        if source_audience::row_obligation(&raw).is_present() {
            match source_audience::binding_in(vault, &txn, id)? {
                Some(policy) => sources.push(policy),
                None => verdict = false,
            }
        }
        if verdict {
            for source in &sources {
                let reads = if let Some(known) = verdicts.get(source) {
                    *known
                } else {
                    let reads = source_audience::actor_reads_in(vault, &txn, source, viewer)?;
                    verdicts.insert(*source, reads);
                    reads
                };
                if !reads {
                    verdict = false;
                    break;
                }
            }
        }
        out.push(RowTime {
            ns: nanos(start),
            verdict,
        });
    }
    Ok(out)
}

/// Times shape (b)'s write on each of `rows`, in ONE write transaction: per
/// row its own bytes, `lineage_word_sources_in` (every and supports),
/// `dependency_sources_in` and `input_rows_in_txn`; for each direct source
/// its stored floor (`derived_policies_in`) and its binding (`binding_in`);
/// one `add_derived_policies_in_txn` when the set is not empty. Answers the
/// per-row times and the nanoseconds of the whole write, its commit included.
///
/// # Errors
///
/// A row this vault does not hold; storage failures.
pub fn time_raise_floor(vault: &Vault, rows: &[EntityId]) -> Result<(Vec<RowTime>, u64)> {
    let mut out = Vec::with_capacity(rows.len());
    let whole = Instant::now();
    vault.with_write_txn(|txn| {
        for row in rows {
            let start = Instant::now();
            let raw = vault.get_raw_in(txn, row)?.ok_or(Error::EntityNotFound)?;
            let (every, supports) = vault.lineage_word_sources_in(txn, *row, &raw)?;
            let mut direct: BTreeSet<EntityId> = every.into_iter().collect();
            direct.extend(supports);
            direct.extend(crate::ports::dependency_sources_in(&vault.store, txn, row)?);
            direct.extend(crate::store::birth_record::input_rows_in_txn(
                &vault.store,
                txn,
                row,
            )?);
            direct.remove(row);
            let mut add = BTreeSet::new();
            for source in &direct {
                if let Some(floor) = source_audience::derived_policies_in(vault, txn, source)? {
                    add.extend(floor);
                }
                if let Some(policy) = source_audience::binding_in(vault, txn, source)? {
                    add.insert(policy);
                }
            }
            let verdict = !add.is_empty();
            if verdict {
                source_audience::add_derived_policies_in_txn(vault, txn, row, &add)?;
            }
            out.push(RowTime {
                ns: nanos(start),
                verdict,
            });
        }
        Ok(())
    })?;
    Ok((out, nanos(whole)))
}

/// Writes each row's floor with `add_derived_policies_in_txn`, as the
/// fixture built the row: the policies of the sources it named. One write
/// per `chunk` rows.
///
/// # Errors
///
/// Storage failures.
pub fn write_floors(
    vault: &Vault,
    floors: &[(EntityId, BTreeSet<EntityId>)],
    chunk: usize,
) -> Result<()> {
    for part in floors.chunks(chunk.max(1)) {
        vault.with_write_txn(|txn| {
            for (row, policies) in part {
                if !policies.is_empty() {
                    source_audience::add_derived_policies_in_txn(vault, txn, row, policies)?;
                }
            }
            Ok(())
        })?;
    }
    Ok(())
}

/// The row's stored floor, if it has one.
///
/// # Errors
///
/// Storage failures.
pub fn stored_floor(vault: &Vault, row: EntityId) -> Result<Option<BTreeSet<EntityId>>> {
    let txn = vault.store.env.read_txn()?;
    source_audience::derived_policies_in(vault, &txn, &row)
}

/// The source-audience policies a read of `row` by `viewers` meets along
/// the walk's lineage (`read_audience_in`), with the switch as it stands.
///
/// # Errors
///
/// Storage failures.
pub fn walk_policies(
    vault: &Vault,
    row: EntityId,
    viewers: &[EntityId],
) -> Result<BTreeSet<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    let dbs = vault.store.read();
    source_audience::read_audience_in(vault, &dbs, &txn, &[row], viewers)
}

/// The `DERIVED` side table's entries and bytes.
///
/// # Errors
///
/// Storage failures.
pub fn floor_table_bytes(vault: &Vault) -> Result<FloorTableBytes> {
    let (entries, key_bytes, value_bytes) =
        source_audience::binding_door::derived_table_bytes(vault)?;
    Ok(FloorTableBytes {
        entries,
        key_bytes,
        value_bytes,
    })
}

/// Writes a new source policy read by `readers`, created by `by`; its id.
///
/// # Errors
///
/// Storage failures.
pub fn create_source_policy(
    vault: &Vault,
    readers: BTreeSet<EntityId>,
    by: EntityId,
) -> Result<EntityId> {
    let at = vault.now_recorded_at();
    vault.with_write_txn(|txn| {
        source_audience::create_source_policy_in_txn(vault, txn, readers, false, by, at)
    })
}

/// The body a mail landing mints a thread's CONVERSATION with.
fn mail_conversation_body(thread_key: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(
        &mut out,
        &rmpv::Value::Map(vec![
            (
                rmpv::Value::from(crate::memory::IMPORTED_SOURCE_KEY),
                rmpv::Value::from("mail"),
            ),
            (
                rmpv::Value::from("import_conversation"),
                rmpv::Value::from(thread_key),
            ),
            (
                rmpv::Value::from("import_kind"),
                rmpv::Value::from("mail_thread"),
            ),
        ]),
    )
    .map_err(|_| Error::InvalidConfig("encode a mail thread body".into()))?;
    Ok(out)
}

/// Lands one mail TURN of `texts.len()` MESSAGEs in the thread whose
/// CONVERSATION is `conversation`, as `mail_pack::landing` does: through
/// `witness_imported`, stamped with the birth minted from the source policy
/// `source`, and in the same write the CONVERSATION, the TURN and each
/// MESSAGE are bound to the thread's policy (`thread_policy_in_txn`, keyed by
/// the CONVERSATION's hex). `memory` is the landing's writer.
///
/// # Errors
///
/// The witness door's refusals; storage failures.
pub fn land_mail_turn(
    vault: &Vault,
    memory: &Memory<'_>,
    actor: EntityId,
    source: EntityId,
    conversation: EntityId,
    texts: &[String],
    occurred_at: u64,
) -> MemoryResult<LandedTurn> {
    let birth = {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        SourceAudienceBirth::mint_in(vault, &txn, &source)?
    };
    let turn = EntityId::now();
    let messages: Vec<EntityId> = texts.iter().map(|_| EntityId::now()).collect();
    let thread_key = conversation.to_hex();
    let witness = WitnessTurn {
        conversation_ref: thread_key.clone(),
        turn_ref: Some(turn.to_hex()),
        thread_audience: None,
        messages: texts
            .iter()
            .zip(&messages)
            .enumerate()
            .map(|(order, (text, id))| WitnessMessage {
                id: Some(id.to_hex()),
                author: WitnessAuthor::User,
                message_type: "import.mail".to_owned(),
                content: text.clone(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: u32::try_from(order).unwrap_or(u32::MAX),
                quote: None,
            })
            .collect(),
        occurred_at,
        assertions: Default::default(),
    };
    let imported_at = vault.now_recorded_at();
    let stamp = ImportedTurnStamp {
        source: "mail",
        imported_at,
        conversation_body: mail_conversation_body(&thread_key)?,
        message_occurred: vec![occurred_at; texts.len()],
        source_audience: Some(birth),
        attribution: SourceAttribution::Unbound,
    };
    let mut thread = None;
    let receipt = memory.witness_imported(&witness, &stamp, |wtxn| {
        let policy = source_audience::thread_policy_in_txn(
            vault,
            wtxn,
            &source,
            &thread_key,
            actor,
            imported_at,
        )?;
        for record in [conversation, turn].iter().chain(&messages) {
            source_audience::bind_record_in_txn(vault, wtxn, record, &policy)?;
        }
        thread = Some(policy);
        Ok(())
    })?;
    let thread = thread.ok_or_else(|| {
        crate::memory::MemoryError::bad_request("the landing bound no thread policy")
    })?;
    Ok(LandedTurn {
        turn: receipt.turn_id,
        messages,
        thread,
    })
}
