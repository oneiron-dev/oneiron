//! Seat-birth model routing above the raw LLM call seam.
//! A host supplies the typed judgment; the engine owns eligibility, reuse and pinning.
use std::collections::BTreeSet;

mod policy;
pub use policy::{SeatPolicy, SeatPrecedence};

use serde::{Deserialize, Serialize};

use super::registry::ModelWireFormat;
use super::{CallPurpose, LlmCapability, ModelId, ModelLocality, ReasoningEffort};
use crate::{
    Vault,
    error::{Error, Result},
};

const DESCRIPTION_PREFIX: &[u8] = b"llm:model_description:v1:";

fn invalid(reason: impl Into<String>) -> Error {
    Error::InvalidConfig(reason.into())
}

/// A description is keyed by the fully revisioned model ID. Absence is not a
/// recommendation; the router cannot judge an undocumented model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelDescription {
    pub model: ModelId,
    /// Capability profile, not a provider, tier or model-family name.
    pub facet: String,
    pub owner: Option<String>,
    pub measured: Option<String>,
    pub benchmarks: Option<String>,
    pub vendor: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DescriptionSource {
    Owner,
    Measured,
    Benchmarks,
    Vendor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescriptionLine {
    pub source: DescriptionSource,
    pub text: String,
}

impl ModelDescription {
    pub fn validate(&self) -> Result<()> {
        self.validate_with(&SeatPolicy::bundled()?)
    }

    fn validate_with(&self, policy: &SeatPolicy) -> Result<()> {
        if self.facet.trim().is_empty()
            || self.facet.len() > policy.facet_max_bytes
            || [
                self.owner.as_ref(),
                self.measured.as_ref(),
                self.benchmarks.as_ref(),
                self.vendor.as_ref(),
            ]
            .into_iter()
            .flatten()
            .any(|text| text.trim().is_empty() || text.len() > policy.line_max_bytes)
            || [&self.owner, &self.measured, &self.benchmarks, &self.vendor]
                .into_iter()
                .all(Option::is_none)
        {
            return Err(invalid("invalid model description"));
        }
        Ok(())
    }

    /// Lines in the policy's evidence order. The judge sees every line and its
    /// source; vendor copy cannot silently stand in for an owner's line.
    pub fn lines(&self, order: &[DescriptionSource]) -> Vec<DescriptionLine> {
        order
            .iter()
            .filter_map(|source| {
                let text = match source {
                    DescriptionSource::Owner => &self.owner,
                    DescriptionSource::Measured => &self.measured,
                    DescriptionSource::Benchmarks => &self.benchmarks,
                    DescriptionSource::Vendor => &self.vendor,
                };
                text.as_ref().map(|text| DescriptionLine {
                    source: *source,
                    text: text.clone(),
                })
            })
            .collect()
    }
}

fn description_key(model: &ModelId) -> Vec<u8> {
    [DESCRIPTION_PREFIX, model.as_str().as_bytes()].concat()
}

impl Vault {
    /// Resolve the owner manifest row, or the shipped default data for v2
    /// manifests that do not set an explicit seat policy.
    pub fn seat_policy(&self) -> Result<SeatPolicy> {
        match self
            .model_manifest()?
            .and_then(|manifest| manifest.seat_policy)
        {
            Some(policy) => {
                policy.validate()?;
                Ok(policy)
            }
            None => SeatPolicy::bundled(),
        }
    }

    /// Set a revision-pinned description for a registered MODEL identity.
    pub fn set_model_description(&self, description: &ModelDescription) -> Result<()> {
        description.validate_with(&self.seat_policy()?)?;
        if self.model_registry_row(&description.model)?.is_none() {
            return Err(invalid("model description requires a registered model"));
        }
        let bytes = serde_json::to_vec(description).map_err(|e| invalid(e.to_string()))?;
        let mut txn = self.store.env.write_txn()?;
        self.store
            .vault_meta
            .put(&mut txn, &description_key(&description.model), &bytes)?;
        txn.commit()?;
        Ok(())
    }

    pub fn model_description(&self, model: &ModelId) -> Result<Option<ModelDescription>> {
        let policy = self.seat_policy()?;
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &description_key(model))?
            .map(|bytes| {
                let description: ModelDescription =
                    serde_json::from_slice(&bytes).map_err(|e| invalid(e.to_string()))?;
                description.validate_with(&policy)?;
                if &description.model != model {
                    return Err(invalid("model description identity mismatch"));
                }
                Ok(description)
            })
            .transpose()
    }
}

/// Kind is part of warm-seat eligibility; a follower never borrows a child seat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeatKind {
    Attempt,
    Child,
    Follower,
}

/// A host-scoped seat birth. `warm_scope` identifies a compatible prefix and
/// access scope; distinct scopes must not share a cached prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeatTask {
    pub kind: SeatKind,
    pub warm_scope: String,
    pub task: String,
    pub purpose: CallPurpose,
    pub facet: String,
    pub required: Vec<LlmCapability>,
    pub min_context_tokens: u64,
    pub locality: ModelLocality,
    pub override_model: Option<ModelId>,
    pub override_effort: Option<ReasoningEffort>,
}

/// The judge receives only models admitted by the engine's route, capability,
/// context and description checks. Tiers and role defaults are not inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatCandidate {
    pub model: ModelId,
    pub wire: ModelWireFormat,
    pub locality: ModelLocality,
    pub description: Vec<DescriptionLine>,
    pub reasoning: bool,
    /// Composed policy default, or this model's first rung when none is authored.
    pub default_effort: ReasoningEffort,
    pub allowed_efforts: Vec<ReasoningEffort>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatJudgment {
    pub model: ModelId,
    /// None takes the cheap first rung for the chosen model.
    pub effort: Option<ReasoningEffort>,
    pub why: String,
}

pub trait SeatJudge: Send + Sync {
    fn judge(&self, task: &SeatTask, candidates: &[SeatCandidate]) -> Result<SeatJudgment>;
}

/// Plain-language choice receipt; retained on the seat even if policies change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeatChoiceReceipt {
    pub model: ModelId,
    pub effort: ReasoningEffort,
    pub why: String,
    pub reused: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelSeat {
    id: u64,
    kind: SeatKind,
    warm_scope: String,
    facet: String,
    model: ModelId,
    locality: ModelLocality,
    effort: ReasoningEffort,
    receipt: SeatChoiceReceipt,
    warm: bool,
}

impl ModelSeat {
    pub fn id(&self) -> u64 {
        self.id
    }
    pub fn model(&self) -> &ModelId {
        &self.model
    }
    pub fn effort(&self) -> ReasoningEffort {
        self.effort
    }
    pub fn locality(&self) -> ModelLocality {
        self.locality
    }
    pub fn receipt(&self) -> &SeatChoiceReceipt {
        &self.receipt
    }

    /// The model and effort are immutable for this seat's whole life.
    pub fn bind(&self, request: &mut super::LlmRequest) {
        request.model = self.model.clone();
        request.envelope.locality = self.locality;
        request.envelope.seat_effort = Some(self.effort);
        request.params.remove("reasoning_effort");
        if self.effort != ReasoningEffort::None {
            request
                .params
                .insert("reasoning_effort".into(), serde_json::json!(self.effort));
        }
    }
}

/// Session-owned pool: no process-global mutable seat state. Hosts keep the pool
/// with the run tree and call `fold_epoch` only at a safe epoch boundary.
#[derive(Debug, Default)]
pub struct SeatPool {
    seats: Vec<ModelSeat>,
    next_id: u64,
}

impl SeatPool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seat(&self, id: u64) -> Option<&ModelSeat> {
        self.seats.iter().find(|seat| seat.id == id)
    }

    pub fn birth(
        &mut self,
        vault: &Vault,
        task: &SeatTask,
        judge: &dyn SeatJudge,
    ) -> Result<ModelSeat> {
        if task.task.trim().is_empty()
            || task.facet.trim().is_empty()
            || task.warm_scope.trim().is_empty()
        {
            return Err(invalid("seat task, facet and warm scope are required"));
        }
        let allowed = vault
            .model_route(super::manifest::ModelSlot::Llm)?
            .ok_or_else(|| invalid("model manifest not configured"))?;
        let route = task.locality;
        let rank = |locality| match locality {
            ModelLocality::OnDevice => 0,
            ModelLocality::OwnServer => 1,
            ModelLocality::ThirdParty => 2,
        };
        if rank(route) > rank(allowed) {
            return Err(invalid("seat route widens manifest"));
        }
        let policy = vault.seat_policy()?;
        let descriptions = vault.description_policy()?;
        let purpose = super::routing::purpose_key(&task.purpose);
        // A widening level refuses the birth before any judgment or receipt.
        let composed = policy.compose_defaults(&purpose, descriptions.as_ref())?;
        let rows = vault.model_registry_rows()?;
        let mut candidates = Vec::new();
        for row in rows {
            let catalog = row.catalog;
            if catalog.locality != route
                || catalog.context_window_tokens < task.min_context_tokens
                || !task
                    .required
                    .iter()
                    .all(|required| catalog.supports(required))
                || task
                    .override_model
                    .as_ref()
                    .is_some_and(|id| id != &catalog.model)
            {
                continue;
            }
            let Some(description) = vault.model_description(&catalog.model)? else {
                continue;
            };
            if description.facet != task.facet {
                continue;
            }
            let reasoning = catalog.supports(&LlmCapability::Reasoning);
            let model_policy = descriptions.as_ref().and_then(|configured| {
                configured
                    .models
                    .iter()
                    .find(|model| model.model == catalog.model)
            });
            if model_policy
                .is_some_and(|model| model.wire != row.wire || model.locality != catalog.locality)
            {
                return Err(invalid("description policy disagrees with model catalog"));
            }
            let ladder = model_policy.map_or_else(
                || policy.ladder(&catalog.model, row.wire, reasoning),
                |model| model.effort_ladder.clone(),
            );
            let Ok(default_effort) = policy.resolve_default(&ladder, composed) else {
                continue;
            };
            // A holder request is known before judgment: filter, never judge, a
            // candidate it would widen.
            if task
                .override_effort
                .is_some_and(|effort| policy.choose(composed, Some(effort), &ladder).is_err())
            {
                continue;
            }
            candidates.push(SeatCandidate {
                reasoning,
                wire: row.wire,
                default_effort,
                allowed_efforts: ladder,
                model: catalog.model,
                locality: route,
                description: description.lines(&policy.evidence_order),
            });
        }
        if candidates.is_empty() {
            return Err(invalid("no described model eligible for seat"));
        }
        let eligible: BTreeSet<_> = candidates.iter().map(|c| &c.model).collect();
        if let Some(seat) = self.seats.iter().find(|seat| {
            seat.warm
                && seat.kind == task.kind
                && seat.warm_scope == task.warm_scope
                && seat.facet == task.facet
                && seat.locality == route
                && eligible.contains(&seat.model)
                && candidates
                    .iter()
                    .find(|candidate| candidate.model == seat.model)
                    .is_some_and(|candidate| {
                        policy
                            .choose(composed, Some(seat.effort), &candidate.allowed_efforts)
                            .is_ok()
                    })
                && task
                    .override_effort
                    .is_none_or(|effort| effort == seat.effort)
        }) {
            let mut reused = seat.clone();
            reused.receipt.reused = true;
            return Ok(reused);
        }
        if self
            .seats
            .iter()
            .any(|seat| seat.warm && seat.kind == task.kind && seat.warm_scope == task.warm_scope)
        {
            return Err(invalid("model or effort change requires an epoch fold"));
        }
        let judgment = judge.judge(task, &candidates)?;
        let candidate = candidates
            .iter()
            .find(|c| c.model == judgment.model)
            .ok_or_else(|| invalid("seat judgment selected ineligible model"))?;
        let effort = policy.choose(
            composed,
            task.override_effort.or(judgment.effort),
            &candidate.allowed_efforts,
        )?;
        if judgment.why.trim().is_empty()
            || (effort != ReasoningEffort::None
                && (!candidate.reasoning || candidate.wire == ModelWireFormat::Gemini))
        {
            return Err(invalid("invalid seat judgment or effort"));
        }
        let id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| invalid("seat id exhausted"))?;
        self.next_id = id;
        let seat = ModelSeat {
            id,
            kind: task.kind,
            warm_scope: task.warm_scope.clone(),
            facet: task.facet.clone(),
            model: judgment.model.clone(),
            locality: route,
            effort,
            receipt: SeatChoiceReceipt {
                model: judgment.model,
                effort,
                why: judgment.why,
                reused: false,
            },
            warm: true,
        };
        self.seats.push(seat.clone());
        Ok(seat)
    }

    /// A fold retires just the old prefix. The old seat remains inspectable and
    /// pinned; a new judgment may choose a different revision for the new seat.
    pub fn fold_epoch(
        &mut self,
        vault: &Vault,
        old_id: u64,
        task: &SeatTask,
        judge: &dyn SeatJudge,
    ) -> Result<ModelSeat> {
        let old = self
            .seats
            .iter()
            .position(|seat| seat.id == old_id)
            .ok_or_else(|| invalid("unknown seat"))?;
        if !self.seats[old].warm {
            return Err(invalid("cannot fold a retired seat"));
        }
        if self.seats[old].warm_scope != task.warm_scope || self.seats[old].kind != task.kind {
            return Err(invalid("epoch fold changes seat scope"));
        }
        self.seats[old].warm = false;
        match self.birth(vault, task, judge) {
            Ok(seat) => Ok(seat),
            Err(error) => {
                self.seats[old].warm = true;
                Err(error)
            }
        }
    }
}

const RUN_SEAT_PREFIX: &[u8] = b"llm:run_seat:v1:";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRunSeat {
    version: u8,
    task_hash: String,
    kind: SeatKind,
    warm_scope: String,
    facet: String,
    locality: ModelLocality,
    receipt: SeatChoiceReceipt,
}

fn run_seat_key(run_id: crate::EntityId) -> Vec<u8> {
    [RUN_SEAT_PREFIX, run_id.as_bytes()].concat()
}

impl StoredRunSeat {
    fn from_seat(task: &SeatTask, seat: &ModelSeat) -> Result<Self> {
        Ok(Self {
            version: 1,
            task_hash: task_hash(task)?,
            kind: task.kind,
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
    /// access-scoped warm prefix; raw LLM calls do not enter it.
    pub fn birth_model_seat(
        &self,
        run_id: crate::EntityId,
        task: &SeatTask,
        judge: &dyn SeatJudge,
    ) -> Result<ModelSeat> {
        let mut pool = self
            .model_seats
            .lock()
            .map_err(|_| invalid("seat pool poisoned"))?;
        let key = run_seat_key(run_id);
        let txn = self.store.env.read_txn()?;
        let prior = self
            .store
            .vault_meta
            .get(&txn, &key)?
            .map(|bytes| bytes.to_vec());
        drop(txn);
        if let Some(bytes) = prior {
            let row: StoredRunSeat =
                serde_json::from_slice(&bytes).map_err(|error| invalid(error.to_string()))?;
            return pool.resume(task, &row);
        }
        let seat = pool.birth(self, task, judge)?;
        let row = StoredRunSeat::from_seat(task, &seat)?;
        let bytes = serde_json::to_vec(&row).map_err(|error| invalid(error.to_string()))?;
        let result = (|| {
            let mut txn = self.store.env.write_txn()?;
            // Single-vault writer serialization keeps a second birth from
            // overwriting a run pin if another handle reached this key first.
            if self.store.vault_meta.get(&txn, &key)?.is_some() {
                return Err(invalid("run seat was concurrently bound"));
            }
            self.store.vault_meta.put(&mut txn, &key, &bytes)?;
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
    pub fn model_seat_receipt(&self, run_id: crate::EntityId) -> Result<Option<SeatChoiceReceipt>> {
        self.store
            .vault_meta
            .get(&self.store.env.read_txn()?, &run_seat_key(run_id))?
            .map(|bytes| {
                let row: StoredRunSeat =
                    serde_json::from_slice(&bytes).map_err(|error| invalid(error.to_string()))?;
                if row.version != 1 || row.receipt.why.trim().is_empty() {
                    return Err(invalid("invalid stored run seat"));
                }
                Ok(row.receipt)
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests;
