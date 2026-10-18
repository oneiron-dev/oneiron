//! A run's immutable seat pin: born once per run, loaded again on resume.
//! An agent run's seat also keeps the type stamp its dispatch carried
//! (DOOR-111 S5); every other run's seat is born generic.
use serde::{Deserialize, Serialize};

use super::{ModelSeat, SeatChoiceReceipt, SeatDecisions, SeatKind, SeatPool, SeatTask, invalid};
use crate::llm::ModelLocality;
use crate::side_table::{self, LegacyJson, SideTable};
use crate::task_type::TaskTypeRef;
use crate::{EntityId, Vault, error::Result};

/// A run's immutable seat pin. Key: id16 (run).
const RUN_SEATS: SideTable<EntityId, StoredRunSeat, LegacyJson> =
    SideTable::new(&side_table::LLM_RUN_SEAT);

/// What a run's seat was born for. A task seat keeps the stamp its dispatch
/// carried; a generic one (an `execute_code` run, a reader child, a summary
/// job) keeps none. `SeatKind::Attempt` alone does not say which.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum RunSeatBinding {
    Generic,
    Task { type_ref: TaskTypeRef },
}

/// An agent run's seat receipt and the type stamp it was born under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskSeatReceipt {
    pub type_ref: TaskTypeRef,
    pub receipt: SeatChoiceReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRunSeat {
    version: u8,
    task_hash: String,
    kind: SeatKind,
    binding: RunSeatBinding,
    warm_scope: String,
    facet: String,
    locality: ModelLocality,
    receipt: SeatChoiceReceipt,
}

impl StoredRunSeat {
    fn from_seat(task: &SeatTask, binding: RunSeatBinding, seat: &ModelSeat) -> Result<Self> {
        Ok(Self {
            version: 1,
            task_hash: task_hash(task)?,
            kind: task.kind,
            binding,
            warm_scope: task.warm_scope.clone(),
            facet: task.facet.clone(),
            locality: seat.locality,
            receipt: seat.receipt.clone(),
        })
    }

    fn validate_for(&self, task: &SeatTask) -> Result<()> {
        if self.version != 1
            || self.task_hash != task_hash(task)?
            || self.kind != task.kind
            || self.warm_scope != task.warm_scope
            || self.facet != task.facet
            || self.locality != task.locality
            || self.receipt.why.trim().is_empty()
        {
            return Err(invalid("stored run seat disagrees with task identity"));
        }
        Ok(())
    }
}

fn task_hash(task: &SeatTask) -> Result<String> {
    let bytes = serde_json::to_vec(task).map_err(|error| invalid(error.to_string()))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

impl SeatPool {
    fn resume(&mut self, task: &SeatTask, row: &StoredRunSeat) -> Result<ModelSeat> {
        row.validate_for(task)?;
        if let Some(seat) = self
            .seats
            .iter()
            .find(|seat| seat.kind == task.kind && seat.warm_scope == task.warm_scope)
        {
            if !seat.warm
                || seat.model != row.receipt.model
                || seat.effort != row.receipt.effort
                || seat.locality != row.locality
                || seat.facet != task.facet
            {
                return Err(invalid("stored run seat conflicts with live seat"));
            }
            let mut reused = seat.clone();
            reused.receipt.reused = true;
            return Ok(reused);
        }
        let id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| invalid("seat id exhausted"))?;
        self.next_id = id;
        let mut receipt = row.receipt.clone();
        receipt.reused = true;
        let seat = ModelSeat {
            id,
            kind: task.kind,
            warm_scope: task.warm_scope.clone(),
            facet: task.facet.clone(),
            model: row.receipt.model.clone(),
            locality: row.locality,
            effort: row.receipt.effort,
            receipt,
            warm: true,
        };
        self.seats.push(seat.clone());
        Ok(seat)
    }
}

impl Vault {
    /// Resolve a run's seat at birth or load its immutable pin on resume. The
    /// row is committed before the first provider call and survives a restart.
    /// Child/follower owners use the same door with their own `SeatKind` and
    /// access-scoped warm prefix; raw LLM calls do not enter it. The seat is
    /// born generic: an agent run's is born through
    /// [`Self::birth_task_model_seat`].
    pub fn birth_model_seat(
        &self,
        run_id: EntityId,
        task: &SeatTask,
        decisions: &SeatDecisions,
    ) -> Result<ModelSeat> {
        self.birth_run_seat(run_id, RunSeatBinding::Generic, task, decisions)
    }

    /// An agent run's seat (DOOR-111 S5), born as [`Self::birth_model_seat`]
    /// births one and stamped in the same row with `type_ref`, the stamp its
    /// dispatch carried. A resume under another stamp, or of a seat born
    /// generic, refuses.
    pub fn birth_task_model_seat(
        &self,
        run_id: EntityId,
        type_ref: &TaskTypeRef,
        task: &SeatTask,
        decisions: &SeatDecisions,
    ) -> Result<ModelSeat> {
        let binding = RunSeatBinding::Task {
            type_ref: type_ref.clone(),
        };
        self.birth_run_seat(run_id, binding, task, decisions)
    }

    fn birth_run_seat(
        &self,
        run_id: EntityId,
        binding: RunSeatBinding,
        task: &SeatTask,
        decisions: &SeatDecisions,
    ) -> Result<ModelSeat> {
        let mut pool = self
            .model_seats
            .lock()
            .map_err(|_| invalid("seat pool poisoned"))?;
        let txn = self.store.env.read_txn()?;
        let prior = RUN_SEATS.get(&self.store, &txn, &run_id)?;
        drop(txn);
        if let Some(row) = prior {
            if row.binding != binding {
                return Err(invalid("stored run seat was born under another binding"));
            }
            return pool.resume(task, &row);
        }
        let seat = pool.birth(self, task, decisions)?;
        let row = StoredRunSeat::from_seat(task, binding, &seat)?;
        let result = (|| {
            let mut txn = self.store.env.write_txn()?;
            // Single-vault writer serialization keeps a second birth from
            // overwriting a run pin if another handle reached this key first.
            if RUN_SEATS.contains(&self.store, &txn, &run_id)? {
                return Err(invalid("run seat was concurrently bound"));
            }
            RUN_SEATS.put(&self.store, &mut txn, &run_id, &row)?;
            txn.commit()?;
            Ok(())
        })();
        if result.is_err()
            && !seat.receipt.reused
            && let Some(saved) = pool.seats.iter_mut().find(|saved| saved.id == seat.id)
        {
            saved.warm = false;
        }
        result?;
        Ok(seat)
    }

    /// Durable choice receipt for one run, independent of the current model catalog.
    pub fn model_seat_receipt(&self, run_id: EntityId) -> Result<Option<SeatChoiceReceipt>> {
        Ok(self.stored_run_seat(run_id)?.map(|row| row.receipt))
    }

    /// An agent run's seat receipt with the stamp it was born under; `None`
    /// while no seat is born for `run_id`. A seat born generic is no task's,
    /// so it refuses here rather than read as an unstamped task.
    pub fn task_model_seat_receipt(&self, run_id: EntityId) -> Result<Option<TaskSeatReceipt>> {
        self.stored_run_seat(run_id)?
            .map(|row| match row.binding {
                RunSeatBinding::Task { type_ref } => Ok(TaskSeatReceipt {
                    type_ref,
                    receipt: row.receipt,
                }),
                RunSeatBinding::Generic => Err(invalid(format!(
                    "run {} was seated generic, not as a task",
                    run_id.to_hex()
                ))),
            })
            .transpose()
    }

    fn stored_run_seat(&self, run_id: EntityId) -> Result<Option<StoredRunSeat>> {
        let row = RUN_SEATS.get(&self.store, &self.store.env.read_txn()?, &run_id)?;
        if let Some(row) = &row
            && (row.version != 1 || row.receipt.why.trim().is_empty())
        {
            return Err(invalid("invalid stored run seat"));
        }
        Ok(row)
    }
}
