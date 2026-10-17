//! Seat-birth model routing above the raw LLM call seam.
//! A host's ladder answers the typed pick; the engine owns eligibility, reuse and pinning.
use std::collections::BTreeSet;

mod decisions;
pub use decisions::{SeatDecisions, SeatNotes};
mod policy;
pub use policy::{SeatPolicy, SeatPrecedence};

use serde::{Deserialize, Serialize};

use super::registry::ModelWireFormat;
use super::{CallPurpose, LlmCapability, ModelId, ModelLocality, ReasoningEffort};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{
    Vault,
    error::{Error, Result},
};

/// One revision-pinned model description. Key: string (model id).
const DESCRIPTIONS: SideTable<String, ModelDescription, LegacyJson> =
    SideTable::new(&side_table::LLM_MODEL_DESCRIPTION);

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

    /// Lines in the policy's evidence order. The seat pick sees every line and its
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

    /// The level a call outside any seat birth carries for `purpose` on
    /// `model`: the vault's authored default, composed as a birth composes
    /// it, else `fallback`, on the model's ladder as a birth reads it (the
    /// description policy's row first, refused when it disagrees with the
    /// registry) and under the vault ceiling. A model without reasoning or on
    /// the Gemini wire carries `none`, as a birth allows it. A level the
    /// ladder does not admit comes down to its highest admitted rung below
    /// that level, else up to its lowest admitted rung unless that widens an
    /// authored level under narrow-only precedence; that is the vault's word,
    /// so it comes back as authored. With no rung admitted (a ceiling below
    /// the whole ladder) the call carries `none`.
    pub fn purpose_effort(
        &self,
        purpose: &super::CallPurpose,
        model: &ModelId,
        reasoning: bool,
        fallback: ReasoningEffort,
    ) -> Result<PurposeEffort> {
        let policy = self.seat_policy()?;
        let descriptions = self.description_policy()?;
        let composed = policy
            .compose_defaults(&super::routing::purpose_key(purpose), descriptions.as_ref())?;
        let described = descriptions
            .as_ref()
            .and_then(|row| row.models.iter().find(|row| &row.model == model));
        let registered = self.model_registry_row(model)?;
        if let (Some(row), Some(registered)) = (described, &registered)
            && (row.wire != registered.wire || row.locality != registered.catalog.locality)
        {
            return Err(invalid("description policy disagrees with model catalog"));
        }
        let wire = registered
            .map(|row| row.wire)
            .or_else(|| described.map(|row| row.wire))
            .unwrap_or(ModelWireFormat::OpenaiCompat);
        if !reasoning || wire == ModelWireFormat::Gemini {
            return Ok(PurposeEffort::Authored(ReasoningEffort::None));
        }
        let ladder = described.map_or_else(
            || policy.ladder(model, wire, reasoning),
            |row| row.effort_ladder.clone(),
        );
        let wanted = composed.unwrap_or(fallback);
        if policy.admits(wanted, &ladder) {
            return Ok(match composed {
                Some(effort) => PurposeEffort::Authored(effort),
                None => PurposeEffort::Fallback(fallback),
            });
        }
        let rank = policy::effort_rank;
        let admitted = || {
            ladder
                .iter()
                .copied()
                .filter(|rung| policy.admits(*rung, &ladder))
        };
        if let Some(lower) = admitted()
            .filter(|rung| rank(*rung) <= rank(wanted))
            .max_by_key(|rung| rank(*rung))
        {
            return Ok(PurposeEffort::Authored(lower));
        }
        let Some(higher) = admitted().min_by_key(|rung| rank(*rung)) else {
            return Ok(PurposeEffort::Authored(ReasoningEffort::None));
        };
        if composed.is_some() && policy.precedence == SeatPrecedence::NarrowOnly {
            return Err(invalid(
                "authored effort has no rung at or below it on the model ladder",
            ));
        }
        Ok(PurposeEffort::Authored(higher))
    }

    /// Set a revision-pinned description for a registered MODEL identity.
    pub fn set_model_description(&self, description: &ModelDescription) -> Result<()> {
        description.validate_with(&self.seat_policy()?)?;
        if self.model_registry_row(&description.model)?.is_none() {
            return Err(invalid("model description requires a registered model"));
        }
        let mut txn = self.store.env.write_txn()?;
        DESCRIPTIONS.put(
            self,
            &mut txn,
            &description.model.as_str().to_owned(),
            description,
        )?;
        txn.commit()?;
        Ok(())
    }

    pub fn model_description(&self, model: &ModelId) -> Result<Option<ModelDescription>> {
        let policy = self.seat_policy()?;
        let txn = self.store.env.read_txn()?;
        DESCRIPTIONS
            .get(&self.store, &txn, &model.as_str().to_owned())?
            .map(|description| {
                description.validate_with(&policy)?;
                if &description.model != model {
                    return Err(invalid("model description identity mismatch"));
                }
                Ok(description)
            })
            .transpose()
    }
}

/// Where a call's level came from: the vault's policy, or the caller's own
/// fallback, which a caller may pair with controls of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurposeEffort {
    Authored(ReasoningEffort),
    Fallback(ReasoningEffort),
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

/// The pick sees only models admitted by the engine's route, capability,
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
        decisions: &SeatDecisions,
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
        let (index, picked) = decisions.pick(task, &candidates)?;
        let candidate = &candidates[index];
        let effort = policy.choose(
            composed,
            task.override_effort.or(picked),
            &candidate.allowed_efforts,
        )?;
        if effort != ReasoningEffort::None
            && (!candidate.reasoning || candidate.wire == ModelWireFormat::Gemini)
        {
            return Err(invalid("invalid seat pick or effort"));
        }
        let why = decisions
            .notes
            .why(task, &candidates, &candidate.model, effort)?;
        if why.trim().is_empty() {
            return Err(invalid("a seat pick needs its why"));
        }
        let model = candidate.model.clone();
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
            model: model.clone(),
            locality: route,
            effort,
            receipt: SeatChoiceReceipt {
                model,
                effort,
                why,
                reused: false,
            },
            warm: true,
        };
        self.seats.push(seat.clone());
        Ok(seat)
    }

    /// A fold retires just the old prefix. The old seat remains inspectable and
    /// pinned; a new pick may choose a different revision for the new seat.
    pub fn fold_epoch(
        &mut self,
        vault: &Vault,
        old_id: u64,
        task: &SeatTask,
        decisions: &SeatDecisions,
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
        match self.birth(vault, task, decisions) {
            Ok(seat) => Ok(seat),
            Err(error) => {
                self.seats[old].warm = true;
                Err(error)
            }
        }
    }
}

/// A run's immutable seat pin. Key: id16 (run).
const RUN_SEATS: SideTable<crate::EntityId, StoredRunSeat, LegacyJson> =
    SideTable::new(&side_table::LLM_RUN_SEAT);

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
            return pool.resume(task, &row);
        }
        let seat = pool.birth(self, task, decisions)?;
        let row = StoredRunSeat::from_seat(task, &seat)?;
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
    pub fn model_seat_receipt(&self, run_id: crate::EntityId) -> Result<Option<SeatChoiceReceipt>> {
        RUN_SEATS
            .get(&self.store, &self.store.env.read_txn()?, &run_id)?
            .map(|row| {
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
