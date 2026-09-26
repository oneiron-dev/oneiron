//! Vault-owned description routing above the raw LLM call seam.
//!
//! A generative seat is selected once and persisted; schema verdicts are selected
//! independently for each call. The judge is host-supplied, so this layer does not
//! hard-code a model, a prompt, or a quality threshold.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{
    BudgetGuard, CallPurpose, DurableStepContext, DurableStepResult, LlmBackend, LlmRequest,
    ModelId, ModelLocality, ModelTierRef, ReasoningEffort, ResponseFormat, StepOutcome,
    call_as_step,
};
use crate::{
    Vault,
    error::{Error, Result},
};

const POLICY_KEY: &[u8] = b"llm:description_policy:v1";
const MEASUREMENTS_KEY: &[u8] = b"llm:description_measurements:v1";
const SEAT_PREFIX: &[u8] = b"llm:routed_seat:v1:";
const REASK_PREFIX: &[u8] = b"llm:description_reask:v1:";

fn invalid(reason: impl Into<String>) -> Error {
    Error::InvalidConfig(reason.into())
}

/// The owner line stays attached to its exact model revision. A newer revision
/// may use lower-ranked evidence temporarily, but does not inherit this line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerModelLine {
    pub model: ModelId,
    pub text: String,
    /// Owner's quality estimate on the same millionths scale as measurements.
    pub expected_quality: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelDescription {
    pub model: ModelId,
    pub locality: ModelLocality,
    pub owner: Option<OwnerModelLine>,
    pub public_benchmark: Option<String>,
    pub vendor: Option<String>,
    /// Cheapest supported effort first. The owner can override this per seat.
    pub effort_ladder: Vec<ReasoningEffort>,
}

impl ModelDescription {
    fn line<'a>(&'a self, measurement: Option<&'a MeasuredDescription>) -> Option<&'a str> {
        self.owner
            .as_ref()
            .filter(|line| line.model == self.model)
            .map(|line| line.text.as_str())
            .or_else(|| measurement.map(|line| line.text.as_str()))
            .or(self.public_benchmark.as_deref())
            .or(self.vendor.as_deref())
    }
}

/// Hidden-by-default vault configuration; no UI or model names are shipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptionPolicy {
    pub models: Vec<ModelDescription>,
    /// Configured by the owner, not fixed by the routing implementation.
    pub contradiction_margin_millionths: u32,
    pub vault_effort: Option<ReasoningEffort>,
    pub purpose_effort: BTreeMap<String, ReasoningEffort>,
    pub global_effort: Option<ReasoningEffort>,
}

impl DescriptionPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.contradiction_margin_millionths > 1_000_000
            || self.models.is_empty()
            || self.models.iter().any(|row| {
                row.effort_ladder.is_empty()
                    || row.owner.as_ref().is_some_and(|line| {
                        line.text.trim().is_empty()
                            || line.expected_quality > 1_000_000
                            || line.model.provider() != row.model.provider()
                            || line.model.name() != row.model.name()
                    })
                    || (row.owner.is_none()
                        && row.public_benchmark.as_deref().is_none_or(str::is_empty)
                        && row.vendor.as_deref().is_none_or(str::is_empty))
            })
            || self.models.iter().enumerate().any(|(i, row)| {
                self.models[i + 1..]
                    .iter()
                    .any(|other| other.model == row.model)
            })
        {
            return Err(invalid("invalid description routing policy"));
        }
        Ok(())
    }
}

/// Vault-measured real-task evidence, never substituted for an owner's line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasuredDescription {
    pub model: ModelId,
    pub text: String,
    pub quality_millionths: u32,
}

/// A typed, task-specific judgment. The host provides the judgment; this
/// layer keeps evidence ordering, constraints, and seat pinning deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptionJudgment {
    pub fitness: u32,
    pub reason: String,
}

pub trait DescriptionJudge {
    fn judge(&self, task: &str, model: &ModelId, description: &str) -> DescriptionJudgment;
}

/// Overrides filter the description candidates; they never bypass judgment.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeatSettings {
    pub allowed_models: Option<Vec<ModelId>>,
    pub effort: Option<ReasoningEffort>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub inference_overrides: BTreeMap<String, serde_json::Value>,
}

/// Inputs fixed when a generative seat is born.
pub struct SeatBirth<'a> {
    pub id: &'a str,
    pub role: &'a str,
    pub task: &'a str,
    pub purpose: &'a CallPurpose,
    pub settings: &'a SeatSettings,
    pub tier: &'a super::TierPrecedence,
}

/// Existing step and backend machinery for a one-shot verdict call.
pub struct VerdictExecution<'a> {
    pub context: &'a DurableStepContext<'a>,
    pub backend: &'a dyn LlmBackend,
    pub guard: &'a BudgetGuard,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutedSeat {
    pub id: String,
    pub role: String,
    pub model: ModelId,
    pub locality: ModelLocality,
    pub effort: ReasoningEffort,
    pub tier: ModelTierRef,
    pub inference_overrides: BTreeMap<String, serde_json::Value>,
    pub receipt: String,
}

impl RoutedSeat {
    /// Rebind every generative call from the persisted seat. A later call
    /// cannot change its model, effort, locality, or seat-level tier.
    pub fn bind(&self, request: &mut LlmRequest) {
        request.model = self.model.clone();
        request.envelope.locality = self.locality;
        request.envelope.tier.per_seat = Some(self.tier.clone());
        for (key, value) in &self.inference_overrides {
            request.params.insert(key.clone(), value.clone());
        }
        request
            .params
            .insert("reasoning_effort".into(), serde_json::json!(self.effort));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReaskTrigger {
    RevisionChanged,
    MeasuredContradiction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptionReask {
    pub identity: String,
    pub owner_model: ModelId,
    pub observed_model: ModelId,
    pub trigger: ReaskTrigger,
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|err| invalid(err.to_string()))
}
fn decode<'a, T: Deserialize<'a>>(value: &'a [u8]) -> Result<T> {
    serde_json::from_slice(value).map_err(|err| invalid(err.to_string()))
}
fn seat_key(id: &str) -> Result<Vec<u8>> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(invalid("invalid routed seat id"));
    }
    Ok([SEAT_PREFIX, id.as_bytes()].concat())
}
fn purpose_key(purpose: &CallPurpose) -> String {
    match purpose {
        CallPurpose::Other { name } => format!("other:{name}"),
        other => serde_json::to_value(other)
            .expect("known purpose")
            .as_str()
            .expect("purpose serializes as string")
            .to_owned(),
    }
}
fn effort_for(
    policy: &DescriptionPolicy,
    chosen: &ModelDescription,
    settings: &SeatSettings,
    purpose: &CallPurpose,
) -> Result<ReasoningEffort> {
    let effort = settings
        .effort
        .or(policy.vault_effort)
        .or_else(|| policy.purpose_effort.get(&purpose_key(purpose)).copied())
        .or(policy.global_effort)
        .unwrap_or(chosen.effort_ladder[0]);
    if !chosen.effort_ladder.contains(&effort) {
        return Err(invalid("effort not supported by selected model"));
    }
    Ok(effort)
}

fn resolve<'a>(
    policy: &'a DescriptionPolicy,
    measurements: &'a BTreeMap<ModelId, MeasuredDescription>,
    settings: &SeatSettings,
    task: &str,
    judge: &dyn DescriptionJudge,
) -> Result<(&'a ModelDescription, DescriptionJudgment)> {
    policy
        .models
        .iter()
        .filter(|row| {
            settings
                .allowed_models
                .as_ref()
                .is_none_or(|allowed| allowed.contains(&row.model))
        })
        .filter_map(|row| {
            row.line(measurements.get(&row.model))
                .map(|line| (row, judge.judge(task, &row.model, line)))
        })
        .filter(|(_, verdict)| verdict.fitness > 0 && !verdict.reason.trim().is_empty())
        .max_by_key(|(_, verdict)| verdict.fitness)
        .ok_or_else(|| invalid("no description candidate passed judgment"))
}

impl Vault {
    pub fn set_description_policy(&self, policy: &DescriptionPolicy) -> Result<()> {
        policy.validate()?;
        let mut txn = self.store.env.write_txn()?;
        self.store
            .vault_meta
            .put(&mut txn, POLICY_KEY, &encode(policy)?)?;
        txn.commit()?;
        Ok(())
    }
    pub fn description_policy(&self) -> Result<Option<DescriptionPolicy>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, POLICY_KEY)?
            .map(|bytes| {
                let policy: DescriptionPolicy = decode(&bytes)?;
                policy.validate()?;
                Ok(policy)
            })
            .transpose()
    }
    pub fn record_model_measurement(&self, measurement: MeasuredDescription) -> Result<()> {
        if measurement.quality_millionths > 1_000_000 || measurement.text.trim().is_empty() {
            return Err(invalid("invalid measured description"));
        }
        let mut txn = self.store.env.write_txn()?;
        let mut rows: BTreeMap<ModelId, MeasuredDescription> = self
            .store
            .vault_meta
            .get(&txn, MEASUREMENTS_KEY)?
            .map(|bytes| decode(&bytes))
            .transpose()?
            .unwrap_or_default();
        rows.insert(measurement.model.clone(), measurement);
        self.store
            .vault_meta
            .put(&mut txn, MEASUREMENTS_KEY, &encode(&rows)?)?;
        txn.commit()?;
        Ok(())
    }
    /// Persist each trigger before returning it to the host's owner-ask queue.
    /// Revision identities include the new revision; contradictions are one ask
    /// per pinned owner line even when the measured score later fluctuates.
    pub fn check_description_drift(&self) -> Result<Vec<DescriptionReask>> {
        let mut txn = self.store.env.write_txn()?;
        let Some(bytes) = self.store.vault_meta.get(&txn, POLICY_KEY)? else {
            return Ok(vec![]);
        };
        let policy: DescriptionPolicy = decode(&bytes)?;
        policy.validate()?;
        let measurements: BTreeMap<ModelId, MeasuredDescription> = self
            .store
            .vault_meta
            .get(&txn, MEASUREMENTS_KEY)?
            .map(|bytes| decode(&bytes))
            .transpose()?
            .unwrap_or_default();
        let mut emitted = vec![];
        for row in &policy.models {
            let Some(owner) = &row.owner else { continue };
            let trigger = if owner.model != row.model {
                Some(ReaskTrigger::RevisionChanged)
            } else if measurements.get(&row.model).is_some_and(|measured| {
                owner.expected_quality.abs_diff(measured.quality_millionths)
                    > policy.contradiction_margin_millionths
            }) {
                Some(ReaskTrigger::MeasuredContradiction)
            } else {
                None
            };
            let Some(trigger) = trigger else { continue };
            let subject = if trigger == ReaskTrigger::RevisionChanged {
                row.model.as_str()
            } else {
                owner.model.as_str()
            };
            let identity =
                blake3::hash(format!("{}|{:?}|{subject}", owner.model, trigger).as_bytes())
                    .to_hex()
                    .to_string();
            let key = [REASK_PREFIX, identity.as_bytes()].concat();
            if self.store.vault_meta.get(&txn, &key)?.is_none() {
                let reask = DescriptionReask {
                    identity,
                    owner_model: owner.model.clone(),
                    observed_model: row.model.clone(),
                    trigger,
                };
                self.store
                    .vault_meta
                    .put(&mut txn, &key, &encode(&reask)?)?;
                emitted.push(reask);
            }
        }
        txn.commit()?;
        Ok(emitted)
    }
    /// A durable re-ask can be recovered by identity if delivery fails after
    /// check_description_drift commits. An owner reply updates policy explicitly.
    pub fn description_reask(&self, identity: &str) -> Result<Option<DescriptionReask>> {
        if identity.len() != 64 || !identity.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid("invalid description re-ask identity"));
        }
        let key = [REASK_PREFIX, identity.as_bytes()].concat();
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &key)?
            .map(|bytes| decode(&bytes))
            .transpose()
    }
    /// Mint once; a repeated seat id returns the original pin, not a new route.
    pub fn route_seat(
        &self,
        birth: SeatBirth<'_>,
        judge: &dyn DescriptionJudge,
    ) -> Result<RoutedSeat> {
        let SeatBirth {
            id,
            role,
            task,
            purpose,
            settings,
            tier,
        } = birth;
        let key = seat_key(id)?;
        if settings
            .inference_overrides
            .keys()
            .any(|key| key.trim().is_empty() || key == "reasoning_effort")
        {
            return Err(invalid("invalid seat inference override"));
        }
        let (policy_bytes, measurement_bytes, existing) = {
            let txn = self.store.env.read_txn()?;
            (
                self.store
                    .vault_meta
                    .get(&txn, POLICY_KEY)?
                    .map(|b| b.to_vec()),
                self.store
                    .vault_meta
                    .get(&txn, MEASUREMENTS_KEY)?
                    .map(|b| b.to_vec()),
                self.store.vault_meta.get(&txn, &key)?.map(|b| b.to_vec()),
            )
        };
        if let Some(bytes) = existing {
            return decode(&bytes);
        }
        let policy_bytes =
            policy_bytes.ok_or_else(|| invalid("description policy not configured"))?;
        let policy: DescriptionPolicy = decode(&policy_bytes)?;
        policy.validate()?;
        let measurements: BTreeMap<ModelId, MeasuredDescription> = measurement_bytes
            .as_deref()
            .map(decode)
            .transpose()?
            .unwrap_or_default();
        let (chosen, verdict) = resolve(&policy, &measurements, settings, task, judge)?;
        let effort = effort_for(&policy, chosen, settings, purpose)?;
        let seat = RoutedSeat {
            id: id.into(),
            role: role.into(),
            model: chosen.model.clone(),
            locality: chosen.locality,
            effort,
            tier: tier.resolved().clone(),
            inference_overrides: settings.inference_overrides.clone(),
            receipt: format!(
                "model {} with {} effort: {}",
                chosen.model,
                serde_json::to_value(effort)
                    .expect("effort serializes as a string")
                    .as_str()
                    .expect("effort is a string"),
                verdict.reason
            ),
        };
        let mut txn = self.store.env.write_txn()?;
        if let Some(bytes) = self.store.vault_meta.get(&txn, &key)? {
            return decode(&bytes);
        }
        if self.store.vault_meta.get(&txn, POLICY_KEY)?.as_deref() != Some(policy_bytes.as_slice())
            || self
                .store
                .vault_meta
                .get(&txn, MEASUREMENTS_KEY)?
                .as_deref()
                != measurement_bytes.as_deref()
        {
            return Err(invalid("description evidence changed during seat birth"));
        }
        self.store.vault_meta.put(&mut txn, &key, &encode(&seat)?)?;
        txn.commit()?;
        Ok(seat)
    }
    pub fn routed_seat(&self, id: &str) -> Result<Option<RoutedSeat>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &seat_key(id)?)?
            .map(|bytes| decode(&bytes))
            .transpose()
    }
    fn description_measurements(&self) -> Result<BTreeMap<ModelId, MeasuredDescription>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, MEASUREMENTS_KEY)?
            .map(|bytes| decode(&bytes))
            .transpose()
            .map(Option::unwrap_or_default)
    }
    /// Each schema verdict is routed independently. Only the current call's
    /// messages are sent: no cached generative seat prefix is copied or mutated.
    pub async fn call_routed_verdict(
        &self,
        task: &str,
        judge: &dyn DescriptionJudge,
        settings: &SeatSettings,
        mut request: LlmRequest,
        execution: VerdictExecution<'_>,
    ) -> DurableStepResult<StepOutcome> {
        if !matches!(
            request.envelope.response_format,
            ResponseFormat::Json { .. }
        ) {
            return Err(crate::llm::DurableStepError::Engine(invalid(
                "schema verdict requires JSON schema",
            )));
        }
        let policy = self
            .description_policy()?
            .ok_or_else(|| invalid("description policy not configured"))?;
        let measurements = self.description_measurements()?;
        let (chosen, _) = resolve(&policy, &measurements, settings, task, judge)?;
        request.model = chosen.model.clone();
        request.envelope.locality = chosen.locality;
        request.envelope.tier.per_seat = None;
        let effort = effort_for(&policy, chosen, settings, &request.envelope.purpose)?;
        request
            .params
            .insert("reasoning_effort".into(), serde_json::json!(effort));
        request
            .messages
            .retain(|message| message.role == super::LlmMessageRole::User);
        call_as_step(
            execution.context,
            execution.backend,
            execution.guard,
            request,
        )
        .await
    }
}

#[cfg(test)]
mod tests;
