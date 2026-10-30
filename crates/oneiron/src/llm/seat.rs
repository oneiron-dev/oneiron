//! Seat-birth model routing above the raw LLM call seam.
//! A host's ladder answers the typed pick; the engine owns eligibility, reuse and pinning.
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

mod decisions;
pub use decisions::{SeatDecisions, SeatNotes, SeatPickReadings};
mod policy;
pub use policy::{SeatPolicy, SeatPrecedence};
mod run;
pub use run::TaskSeatReceipt;

use serde::{Deserialize, Serialize};

use super::decision::TypedDecision;
use super::registry::ModelWireFormat;
use super::run_admission::offer_id;
use super::{CallPurpose, LlmCapability, ModelId, ModelLocality, ReasoningEffort};
use crate::agent_def::{AgentModel, list_admits, listed_entry, no_listed_model};
use crate::authority::WorldModelRoutes;
use crate::retrieval_depth::RetrievalDeadline;
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{
    EntityId, Vault,
    error::{Error, Result},
};

/// One revision-pinned model description. Key: string (model id).
const DESCRIPTIONS: SideTable<String, ModelDescription, LegacyJson> =
    SideTable::new(&side_table::LLM_MODEL_DESCRIPTION);

fn invalid(reason: impl Into<String>) -> Error {
    Error::InvalidConfig(reason.into())
}

/// Whether the worlds' order pre-admits a seat model at a locality (FIX
/// 11768): [`WorldModelRoutes::Inherit`] admits all; an ordered list admits
/// an on-device seat only on its exact `model@on_device` id, and a server
/// seat when some id starts with its `model@` prefix (built from the seat's
/// own model string, never parsed out of an id) with a remainder that is
/// not `on_device`. The full `model@place` id gates later at the ladder.
/// An over-cap id truncated inside its model part cannot prefix-match;
/// exclusion is the fail-closed direction.
fn routes_prefilter_admits(
    routes: &WorldModelRoutes,
    model: &ModelId,
    locality: ModelLocality,
) -> bool {
    match routes {
        WorldModelRoutes::Inherit => true,
        WorldModelRoutes::Ordered(ids) => {
            if locality == ModelLocality::OnDevice {
                let id = offer_id(model, "on_device");
                ids.iter().any(|named| named == &id)
            } else {
                let prefix = format!("{}@", model.as_str());
                ids.iter().any(|named| {
                    named
                        .strip_prefix(prefix.as_str())
                        .is_some_and(|rest| rest != "on_device")
                })
            }
        }
    }
}

/// Whether the host's served set admits a seat model at a locality (FIX
/// 2745): `None` admits all (the host supplied no set, as before); a set
/// admits the models it serves at exactly this locality, mirroring the
/// served-plus-locality conditions the send-time admission answers with
/// (`admit_seat_bound`). The send-time exact-prompt check stays at the
/// call, not here: served-plus-locality only.
fn served_admits(
    served: Option<&BTreeMap<ModelId, ModelLocality>>,
    model: &ModelId,
    locality: ModelLocality,
) -> bool {
    served.is_none_or(|set| set.get(model).is_some_and(|at| *at == locality))
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// The waking agent's model list (FIX 4472). When it holds any, the seat
    /// is born on a listed model alone, with the owner's `when` read first.
    /// Empty: the agent lists none, and any eligible model may seat it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listed: Vec<AgentModel>,
    /// The run's worlds (FIX 11768): the worlds' own order narrows the
    /// birth's pick to the routes it names. Empty: the birth inherits the
    /// vault's order, as before. Deliberately not task identity: the `All`
    /// snapshot legitimately changes as worlds are edited, and a changed
    /// world set must not brick durable re-entry by changing the pin hash.
    /// Empty-worlds serialization is unchanged, so pre-existing pin hashes
    /// stay stable. Re-derived per entry; the birth-time filter judges the
    /// current routes.
    #[serde(skip)]
    pub worlds: Vec<EntityId>,
    /// The models the host's router serves now, with where each runs (FIX
    /// 2745): the birth admits only these, at the task's route. None: the
    /// host supplied no set, and the birth admits all, as before.
    /// Deliberately not task identity: the served set legitimately changes
    /// as routes are configured and mesh peers come and go, and a changed
    /// set must not brick durable re-entry by changing the pin hash (the
    /// hash is blake3 over the serialized task, `seat/run.rs`). The skip is
    /// load-bearing: a serialized served set bricks every re-entry on
    /// config change. Re-derived per entry; the birth-time filter judges
    /// the current set.
    #[serde(skip)]
    pub served: Option<BTreeMap<ModelId, ModelLocality>>,
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
/// Beside the model, effort and why, it keeps the pick's complete typed reads
/// (FIX 9926), carried with the seat on reuse and resume.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeatChoiceReceipt {
    pub model: ModelId,
    pub effort: ReasoningEffort,
    pub why: String,
    pub reused: bool,
    /// Every model-pick read of the birth, in the order asked: one for 64 or
    /// fewer candidates; for more, each round's batch reads, the final last.
    #[serde(default)]
    pub model_decisions: Vec<TypedDecision>,
    /// The effort pick's read; `None` when that pick did not run (a holder
    /// fixed the effort, or the model has one rung).
    #[serde(default)]
    pub effort_decision: Option<TypedDecision>,
}

#[derive(Debug, Clone, PartialEq)]
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

    /// Births a seat for `task`, or reuses a compatible warm one. A fresh
    /// seat's pick and its note run on one clock: the seat budget, cut to
    /// `parent_at` when the parent a child is born under is due before that
    /// budget ends (FIX 8230), never enlarged. `None`: the seat budget alone.
    /// The clock bounds only how long the pick deliberates; no candidate is
    /// filtered by it.
    pub fn birth(
        &mut self,
        vault: &Vault,
        task: &SeatTask,
        decisions: &SeatDecisions,
        parent_at: Option<Instant>,
    ) -> Result<ModelSeat> {
        if task.task.trim().is_empty()
            || task.facet.trim().is_empty()
            || task.warm_scope.trim().is_empty()
        {
            return Err(invalid("seat task, facet and warm scope are required"));
        }
        // A pin outside the agent's list refuses before any judgment.
        if task
            .override_model
            .as_ref()
            .is_some_and(|model| !list_admits(&task.listed, model))
        {
            return Err(invalid("pinned model is not in the agent's model list"));
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
            // A model its provider retired seats no one; its row stays for
            // the lists and receipts that name it.
            if row.is_stale() {
                continue;
            }
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
                || !list_admits(&task.listed, &catalog.model)
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
            // The owner's own words on when the agent takes this model come
            // first, so the pick chooses among the agent's list by them.
            let mut lines = description.lines(&policy.evidence_order);
            if let Some(entry) = listed_entry(&task.listed, &catalog.model) {
                lines.insert(
                    0,
                    DescriptionLine {
                        source: DescriptionSource::Owner,
                        text: entry.when.clone(),
                    },
                );
            }
            candidates.push(SeatCandidate {
                reasoning,
                wire: row.wire,
                default_effort,
                allowed_efforts: ladder,
                model: catalog.model,
                locality: route,
                description: lines,
            });
        }
        // The run's worlds pre-filter the pick (FIX 11768): a candidate
        // the worlds' order cannot name seats no one, pins included. Seat
        // candidates hold model and locality, no origin, so this is a
        // pre-filter only: on-device admits on its exact
        // `offer_id(model, "on_device")`; a server candidate admits when
        // some id carries its `model@` prefix with a remainder that is not
        // `on_device` (the prefix is built from the candidate's own model
        // string, never parsed out of an id). The ladder gates the full
        // `model@place` id later, in leg 2. An over-cap id the 128-byte rule
        // truncated inside its model part cannot prefix-match; its
        // exclusion here is the fail-closed direction. Empty worlds inherit
        // with no storage read, as the Engine's Bottom mapping is explicitly
        // no-worlds/no-gate, so an empty-worlds birth reads what it read
        // before. A routes read that fails closes the birth: no candidate
        // is admitted and the empty-candidates refusal below fires; the
        // storage error never propagates.
        let routes = if task.worlds.is_empty() {
            WorldModelRoutes::Inherit
        } else {
            vault
                .store
                .env
                .read_txn()
                .ok()
                .and_then(|txn| {
                    vault
                        .world_model_routes_in_txn(&txn, task.worlds.clone())
                        .ok()
                })
                .unwrap_or(WorldModelRoutes::Ordered(Vec::new()))
        };
        // The host's served set pre-filters the pick beside the worlds'
        // order (FIX 2745): a candidate the host's router does not serve at
        // the task's route seats no one, so the birth refuses here instead
        // of bearing a seat every call refuses. No set inherits, as before.
        candidates.retain(|candidate| {
            routes_prefilter_admits(&routes, &candidate.model, candidate.locality)
                && served_admits(task.served.as_ref(), &candidate.model, candidate.locality)
        });
        // With a list, no fallback: the wake holds rather than run unlisted.
        if candidates.is_empty() {
            return Err(if task.listed.is_empty() {
                invalid("no described model eligible for seat")
            } else {
                no_listed_model(&task.listed)
            });
        }
        let eligible: BTreeSet<_> = candidates.iter().map(|c| &c.model).collect();
        if let Some(seat) = self.seats.iter().find(|seat| {
            seat.warm
                && seat.kind == task.kind
                && seat.warm_scope == task.warm_scope
                && seat.facet == task.facet
                && seat.locality == route
                && eligible.contains(&seat.model)
                && list_admits(&task.listed, &seat.model)
                && routes_prefilter_admits(&routes, &seat.model, seat.locality)
                && served_admits(task.served.as_ref(), &seat.model, seat.locality)
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
        // Only a pre-admitted warm seat holds the fold (FIX 11768): a warm
        // seat the worlds' order no longer pre-admits retires, and the fresh
        // pick below runs instead of refusing reuse with a fold error. A
        // warm seat the host no longer serves retires the same way (FIX
        // 2745).
        if self.seats.iter().any(|seat| {
            seat.warm
                && seat.kind == task.kind
                && seat.warm_scope == task.warm_scope
                && routes_prefilter_admits(&routes, &seat.model, seat.locality)
                && served_admits(task.served.as_ref(), &seat.model, seat.locality)
        }) {
            return Err(invalid("model or effort change requires an epoch fold"));
        }
        let started = Instant::now();
        let budget = parent_at.map_or(decisions.budget, |at| {
            decisions.budget.min(at.saturating_duration_since(started))
        });
        let deadline = RetrievalDeadline::hard(started, budget);
        let (index, picked, readings) = decisions.pick_before(task, &candidates, &deadline)?;
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
            .why(task, &candidates, &candidate.model, effort, &deadline)?;
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
                model_decisions: readings.model_decisions,
                effort_decision: readings.effort_decision,
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
        match self.birth(vault, task, decisions, None) {
            Ok(seat) => Ok(seat),
            Err(error) => {
                self.seats[old].warm = true;
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests;
