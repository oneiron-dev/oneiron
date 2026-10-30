//! The rows a code run's callables answered from (FIX 5763): each stored
//! skill its callable calls read and loaded, and the rows of every result a
//! read took from another run. A step's host counts them beside the rows its
//! verb answers were served from; the replay record keeps them across steps,
//! so a later step's host starts from them and the record lists them
//! ([`super::CodeRunReplayRecord::result_rows`]).
//!
//! The record spells them under its `callable_rows` entry, written only once
//! a callable or a read added a row or lost the set: a run whose callables
//! added none keeps the record bytes it had before.

use rmpv::Value;

use super::support::{decode_array, entity_id_value, entity_value, pinned_map, required};
use crate::{EntityId, Result};

const CALLABLE_ROWS_KEYS: [&str; 2] = ["skills", "reads"];

/// The rows a run's callables answered from, as its replay record keeps them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodeRunCallableRows {
    /// Each stored skill a callable call read and loaded.
    skills: Vec<EntityId>,
    /// The rows of every result a read took from another run; `None` once
    /// one kept no set.
    reads: Option<Vec<EntityId>>,
}

impl Default for CodeRunCallableRows {
    fn default() -> Self {
        Self {
            skills: Vec::new(),
            reads: Some(Vec::new()),
        }
    }
}

impl CodeRunCallableRows {
    /// Whether no callable or read added a row and every set is known: the
    /// record spells no entry then.
    fn is_empty(&self) -> bool {
        self.skills.is_empty() && self.reads.as_ref().is_some_and(Vec::is_empty)
    }

    /// The rows as a step's host holds them: the skills its callables loaded,
    /// and the rows its reads took (`None` once one kept no set).
    pub(crate) fn host_parts(&self) -> (Vec<EntityId>, Option<Vec<EntityId>>) {
        (self.skills.clone(), self.reads.clone())
    }

    /// Keeps a step host's rows among these, each once. A read set that is
    /// not known on either side stays unknown.
    pub(crate) fn keep(&mut self, (skills, reads): &(Vec<EntityId>, Option<Vec<EntityId>>)) {
        self.skills.extend_from_slice(skills);
        self.skills.sort_unstable();
        self.skills.dedup();
        self.reads = self
            .reads
            .take()
            .zip(reads.as_deref())
            .map(|(mut held, reads)| {
                held.extend_from_slice(reads);
                held.sort_unstable();
                held.dedup();
                held
            });
    }

    /// `verbs`, the rows the run's verb answers were served from, with these
    /// beside them, as a step's host counts its result rows; `None` once a
    /// read kept no set.
    pub(crate) fn beside(&self, verbs: Vec<EntityId>) -> Option<Vec<EntityId>> {
        let reads = self.reads.as_deref()?;
        Some([verbs.as_slice(), reads, self.skills.as_slice()].concat())
    }
}

fn ids_value(ids: &[EntityId]) -> Value {
    Value::Array(ids.iter().copied().map(entity_id_value).collect())
}

/// The record's `callable_rows` entry: `None` when it would hold no row and
/// no unknown set, so the record keeps the bytes it had before.
pub(super) fn encode_callable_rows(rows: &CodeRunCallableRows) -> Option<Value> {
    if rows.is_empty() {
        return None;
    }
    Some(Value::Map(vec![
        (Value::from(CALLABLE_ROWS_KEYS[0]), ids_value(&rows.skills)),
        (
            Value::from(CALLABLE_ROWS_KEYS[1]),
            rows.reads.as_deref().map_or(Value::Nil, ids_value),
        ),
    ]))
}

/// Decodes the record's `callable_rows` entry; an absent one holds no row.
pub(super) fn decode_callable_rows(value: Option<&Value>) -> Result<CodeRunCallableRows> {
    let Some(value) = value else {
        return Ok(CodeRunCallableRows::default());
    };
    let fields = pinned_map(value, &CALLABLE_ROWS_KEYS, "code-run callable rows")?;
    let skills = decode_array(
        required(fields[0], "missing callable rows skills")?,
        entity_value,
    )?;
    let reads = match required(fields[1], "missing callable rows reads")? {
        Value::Nil => None,
        reads => Some(decode_array(reads, entity_value)?),
    };
    Ok(CodeRunCallableRows { skills, reads })
}
