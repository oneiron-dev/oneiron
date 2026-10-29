//! The rows a run's callable skill calls stood on (FIX 5763): each stored
//! skill a callable loaded, and the rows of every other run's result a read
//! took. The run's replay record keeps them beside its verb answers, so a
//! later step's host and every reader outside the run judge the run's
//! results by the rows its own step judged them by (FIX 5460).

use rmpv::Value;

use crate::{EntityId, Result};

use super::replay::CodeRunReplayRecord;
use super::support::{decode_array, entity_id_value, entity_value, pinned_map, required};

const CODE_RUN_CALLABLE_ROWS_KEYS: [&str; 2] = ["skills", "read"];

/// The rows a run's callable calls stood on, as its record keeps them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeRunCallableRows {
    /// Each stored skill a callable call read and loaded, in call order.
    pub skills: Vec<EntityId>,
    /// The rows of each other run's result a read took; `None` once one
    /// kept no set.
    pub read: Option<Vec<EntityId>>,
}

impl Default for CodeRunCallableRows {
    /// None loaded and none read: a known, empty set.
    fn default() -> Self {
        Self {
            skills: Vec::new(),
            read: Some(Vec::new()),
        }
    }
}

impl CodeRunCallableRows {
    /// Every row the callables stood on: what their reads took, then the
    /// skills they loaded. `None` when a read kept no set.
    #[must_use]
    pub fn rows(&self) -> Option<Vec<EntityId>> {
        self.read
            .as_deref()
            .map(|read| [read, self.skills.as_slice()].concat())
    }
}

impl CodeRunReplayRecord {
    /// The rows the run's results were served from (FIX 5460, 5763): every
    /// row its verb answers listed, then each other run's result its
    /// callables read and each stored skill they loaded. `None` when one kept
    /// no set: no caller off this device is released such a run's results.
    #[must_use]
    pub fn result_rows(&self) -> Option<Vec<EntityId>> {
        self.agent_verb_rows()
            .zip(self.callable_rows.rows())
            .map(|(mut rows, callable)| {
                rows.extend(callable);
                rows
            })
    }
}

fn entity_array(ids: &[EntityId]) -> Value {
    Value::Array(ids.iter().copied().map(entity_id_value).collect())
}

pub(super) fn encode_callable_rows(rows: &CodeRunCallableRows) -> Value {
    Value::Map(vec![
        (
            Value::from(CODE_RUN_CALLABLE_ROWS_KEYS[0]),
            entity_array(&rows.skills),
        ),
        (
            Value::from(CODE_RUN_CALLABLE_ROWS_KEYS[1]),
            rows.read
                .as_deref()
                .map_or(Value::Nil, entity_array),
        ),
    ])
}

pub(super) fn decode_callable_rows(value: &Value) -> Result<CodeRunCallableRows> {
    let fields = pinned_map(value, &CODE_RUN_CALLABLE_ROWS_KEYS, "code-run callable rows")?;
    let read = match required(fields[1], "missing callable read rows")? {
        Value::Nil => None,
        read => Some(decode_array(read, entity_value)?),
    };
    Ok(CodeRunCallableRows {
        skills: decode_array(
            required(fields[0], "missing callable skill rows")?,
            entity_value,
        )?,
        read,
    })
}
