//! Retained app state is charged to the server's retained-memory line
//! (`limits.retained_memory_bytes`), never capped per session or per hub
//! (rule 5). State larger than the whole line runs alone; past the line, an
//! open meets the memory floor and a retained ring falls back to a resync.
use super::AppError;
use crate::byte_line::{ByteLine, HeldBytes};
use crate::wire_telemetry::LimitQuestions;
use std::sync::Arc;

/// The line live-query retention is charged to, and where its crossing asks.
pub(crate) struct Budget {
    line: Arc<ByteLine>,
    questions: Arc<LimitQuestions>,
}
impl Budget {
    pub(crate) fn new(line: Arc<ByteLine>, questions: Arc<LimitQuestions>) -> Arc<Self> {
        Arc::new(Self { line, questions })
    }

    /// A line of its own of `total` bytes.
    #[cfg(test)]
    pub(super) fn of(total: usize) -> Arc<Self> {
        Self::new(
            Arc::new(ByteLine::new(
                crate::wire_telemetry::LimitRow::RetainedMemoryBytes,
                total,
            )),
            Arc::default(),
        )
    }
}

pub(super) struct Reservation {
    budget: Arc<Budget>,
    held: HeldBytes,
}
impl Reservation {
    pub(super) fn new(budget: Arc<Budget>, bytes: usize) -> Result<Self, AppError> {
        let held = budget
            .line
            .try_reserve_alone(bytes, &budget.questions)
            .ok_or_else(AppError::memory_floor)?;
        Ok(Self { budget, held })
    }
    pub(super) fn resize(&mut self, bytes: usize) -> Result<(), AppError> {
        if self
            .budget
            .line
            .try_resize(&mut self.held, bytes, &self.budget.questions)
        {
            Ok(())
        } else {
            Err(AppError::memory_floor())
        }
    }
}

/// Conservative heap estimate, including Value slots and map-node overhead.
pub(super) fn value_bytes(value: &serde_json::Value) -> usize {
    use serde_json::Value;
    std::mem::size_of::<Value>()
        + match value {
            Value::String(s) => s.capacity(),
            Value::Array(a) => {
                a.capacity() * std::mem::size_of::<Value>()
                    + a.iter().map(value_bytes).sum::<usize>()
            }
            Value::Object(o) => o
                .iter()
                .map(|(k, v)| 128 + k.capacity() + value_bytes(v))
                .sum(),
            _ => 0,
        }
}
