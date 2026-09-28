//! Vault-owned description routing above the raw LLM call seam.
//!
//! A generative seat is selected once and persisted; schema verdicts are selected
//! independently for each call. The judge is host-supplied, so this layer does not
//! hard-code a model, a prompt, or a quality threshold.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::registry::ModelWireFormat;
use super::seat::{DescriptionSource, SeatPolicy};
use super::{
    BudgetGuard, CallPurpose, ContentPart, DurableStepContext, DurableStepResult, LlmBackend,
    LlmMessage, LlmMessageRole, LlmRequest, ModelId, ModelLocality, ModelTierRef, ReasoningEffort,
    ResponseFormat, StepOutcome, call_as_step,
};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{
    Vault,
    error::{Error, Result},
};

const POLICY: SideTable<(), DescriptionPolicy, LegacyJson> =
    SideTable::new(&side_table::LLM_DESCRIPTION_POLICY);
const MEASUREMENTS: SideTable<(), BTreeMap<ModelId, MeasuredDescription>, LegacyJson> =
    SideTable::new(&side_table::LLM_DESCRIPTION_MEASUREMENTS);
const REASKS: SideTable<String, DescriptionReask, LegacyJson> =
    SideTable::new(&side_table::LLM_DESCRIPTION_REASK);
const SEATS: SideTable<String, RoutedSeat, LegacyJson> =
    SideTable::new(&side_table::LLM_ROUTED_SEAT);

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
    pub wire: ModelWireFormat,
    pub locality: ModelLocality,
    pub owner: Option<OwnerModelLine>,
    pub public_benchmark: Option<String>,
    pub vendor: Option<String>,
    /// Cheapest supported effort first. The owner can override this per seat.
    pub effort_ladder: Vec<ReasoningEffort>,
}

impl ModelDescription {
    /// The first available line in the seat policy's evidence order.
    fn line<'a>(
        &'a self,
        measurement: Option<&'a MeasuredDescription>,
        order: &[DescriptionSource],
    ) -> Option<&'a str> {
        order.iter().find_map(|source| match source {
            DescriptionSource::Owner => self
                .owner
                .as_ref()
                .filter(|line| line.model == self.model)
                .map(|line| line.text.as_str()),
            DescriptionSource::Measured => measurement.map(|line| line.text.as_str()),
            DescriptionSource::Benchmarks => self.public_benchmark.as_deref(),
            DescriptionSource::Vendor => self.vendor.as_deref(),
        })
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
    fn judge(
        &self,
        task: &str,
        model: &ModelId,
        description: &str,
        effort: ReasoningEffort,
    ) -> DescriptionJudgment;
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
    pub wire: ModelWireFormat,
    pub locality: ModelLocality,
    pub effort: ReasoningEffort,
    pub tier: ModelTierRef,
    pub inference_overrides: BTreeMap<String, serde_json::Value>,
    pub receipt: String,
}

impl RoutedSeat {
    /// Rebind every generative call from the persisted seat. Provider options
    /// that could shadow its effective controls are refused before mutation.
    pub fn bind(&self, request: &mut LlmRequest) -> Result<()> {
        apply_controls(request, self.wire, self.effort, &self.inference_overrides)?;
        request.model = self.model.clone();
        request.envelope.locality = self.locality;
        request.envelope.tier.per_seat = Some(self.tier.clone());
        request.envelope.seat_effort = Some(self.effort);
        Ok(())
    }
}

/// One current schema-verdict payload. History belongs in neither field:
/// system instructions and the current input are supplied explicitly, not
/// inferred from the roles of a generative session's messages.
pub struct VerdictPayload {
    pub instructions: Option<String>,
    pub input: Vec<ContentPart>,
}

impl VerdictPayload {
    fn messages(self) -> Result<Vec<LlmMessage>> {
        if self.input.is_empty() {
            return Err(invalid("empty verdict payload"));
        }
        let mut messages = Vec::new();
        if let Some(instructions) = self.instructions {
            if instructions.trim().is_empty() {
                return Err(invalid("empty verdict instructions"));
            }
            messages.push(LlmMessage {
                role: LlmMessageRole::System,
                content: vec![ContentPart::Text { text: instructions }],
            });
        }
        messages.push(LlmMessage {
            role: LlmMessageRole::User,
            content: self.input,
        });
        Ok(messages)
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
    #[serde(default)]
    pub acknowledged: bool,
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
    Ok(SEATS.key_bytes(&id.to_owned()))
}
pub(crate) fn purpose_key(purpose: &CallPurpose) -> String {
    match purpose {
        CallPurpose::Other { name } => format!("other:{name}"),
        other => serde_json::to_value(other)
            .expect("known purpose")
            .as_str()
            .expect("purpose serializes as string")
            .to_owned(),
    }
}
fn validate_overrides(overrides: &BTreeMap<String, serde_json::Value>) -> Result<()> {
    if overrides.keys().any(|key| {
        key.trim().is_empty()
            || matches!(
                key.as_str(),
                "reasoning_effort"
                    | "reasoning"
                    | "thinking"
                    | "model"
                    | "messages"
                    | "stream"
                    | "response_format"
                    | "tools"
                    | "provider_options"
                    | "output_config"
                    | "system"
                    | "cachedContent"
                    | "thinkingConfig"
                    | "thinking_config"
            )
    }) {
        return Err(invalid("invalid routed inference override"));
    }
    Ok(())
}

/// The Gemini adapter spells these five public params differently on the
/// wire. Seat overrides compare and write the effective wire field, not the
/// caller's spelling, so a later alias cannot win during adapter iteration.
fn gemini_wire_field(key: &str) -> &str {
    match key {
        "max_tokens" => "maxOutputTokens",
        "top_p" => "topP",
        "top_k" => "topK",
        "presence_penalty" => "presencePenalty",
        "frequency_penalty" => "frequencyPenalty",
        other => other,
    }
}

/// Reject fields that would win after the adapter merges provider options.
/// Unknown provider-specific fields remain available, but cannot shadow a
/// routed inference setting or carry a competing reasoning dial.
fn apply_controls(
    request: &mut LlmRequest,
    wire: ModelWireFormat,
    effort: ReasoningEffort,
    overrides: &BTreeMap<String, serde_json::Value>,
) -> Result<()> {
    validate_overrides(overrides)?;
    let mut resolved_overrides = BTreeMap::new();
    for (key, value) in overrides {
        let wire_key = if wire == ModelWireFormat::Gemini {
            gemini_wire_field(key)
        } else {
            key
        };
        if resolved_overrides
            .insert(wire_key.to_owned(), value.clone())
            .is_some()
        {
            return Err(invalid("duplicate routed provider parameter"));
        }
    }
    for options in request.provider_options.values() {
        let fields = options
            .as_object()
            .ok_or_else(|| invalid("invalid provider options"))?;
        if fields.keys().any(|key| {
            resolved_overrides.contains_key(if wire == ModelWireFormat::Gemini {
                gemini_wire_field(key)
            } else {
                key
            }) || matches!(
                key.as_str(),
                "reasoning_effort"
                    | "reasoning"
                    | "thinking"
                    | "thinkingConfig"
                    | "thinking_config"
                    | "output_config"
                    | "model"
            )
        }) {
            return Err(invalid("provider options shadow routed inference controls"));
        }
    }
    // The Anthropic adapter merges output_config into its final wire JSON.
    // Preserve independent format/limits, but never the call's effort.
    let mut output_config = match request.params.get("output_config") {
        Some(serde_json::Value::Object(fields)) if wire == ModelWireFormat::AnthropicMessages => {
            Some(fields.clone())
        }
        Some(_) => return Err(invalid("invalid routed output_config")),
        None => None,
    };
    // Gemini has no effort enum mapping without an owner-supplied budget.
    // Refuse an unsupported non-None setting instead of misreporting it.
    if effort != ReasoningEffort::None && wire == ModelWireFormat::Gemini {
        return Err(invalid(
            "Gemini effort requires an explicit provider policy",
        ));
    }
    request.params.retain(|key, _| {
        let wire_key = if wire == ModelWireFormat::Gemini {
            gemini_wire_field(key)
        } else {
            key
        };
        !resolved_overrides.contains_key(wire_key)
    });
    request.params.extend(resolved_overrides);
    request.params.remove("reasoning");
    request.params.remove("thinking");
    request.params.remove("thinkingConfig");
    request.params.remove("thinking_config");
    request.params.remove("reasoning_effort");
    request.params.remove("output_config");
    if let Some(fields) = output_config.as_mut() {
        fields.remove("effort");
    }
    if effort != ReasoningEffort::None {
        if wire == ModelWireFormat::AnthropicMessages {
            output_config
                .get_or_insert_with(serde_json::Map::new)
                .insert("effort".into(), serde_json::json!(effort));
        } else {
            request
                .params
                .insert("reasoning_effort".into(), serde_json::json!(effort));
        }
    }
    if let Some(fields) = output_config.filter(|fields| !fields.is_empty()) {
        request
            .params
            .insert("output_config".into(), serde_json::Value::Object(fields));
    }
    Ok(())
}
/// Seats and verdicts share the seat policy's composition, ceiling and
/// evidence order; this router adds no default of its own.
fn resolve<'a>(
    policy: &'a DescriptionPolicy,
    seat_policy: &SeatPolicy,
    measurements: &'a BTreeMap<ModelId, MeasuredDescription>,
    settings: &SeatSettings,
    purpose: &CallPurpose,
    task: &str,
    judge: &dyn DescriptionJudge,
) -> Result<(&'a ModelDescription, DescriptionJudgment, ReasoningEffort)> {
    let composed = seat_policy.compose_defaults(&purpose_key(purpose), Some(policy))?;
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
            let effort = seat_policy
                .choose(composed, settings.effort, &row.effort_ladder)
                .ok()?;
            row.line(measurements.get(&row.model), &seat_policy.evidence_order)
                .map(|line| (row, judge.judge(task, &row.model, line, effort), effort))
        })
        .filter(|(_, verdict, _)| verdict.fitness > 0 && !verdict.reason.trim().is_empty())
        .max_by_key(|(_, verdict, _)| verdict.fitness)
        .ok_or_else(|| invalid("no description candidate passed judgment"))
}

impl Vault {
    pub fn set_description_policy(&self, policy: &DescriptionPolicy) -> Result<()> {
        policy.validate()?;
        let mut txn = self.store.env.write_txn()?;
        POLICY.put(&self.store, &mut txn, &(), policy)?;
        txn.commit()?;
        Ok(())
    }
    pub fn description_policy(&self) -> Result<Option<DescriptionPolicy>> {
        let txn = self.store.env.read_txn()?;
        POLICY
            .get(&self.store, &txn, &())?
            .map(|policy| {
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
        let mut rows = MEASUREMENTS
            .get(&self.store, &txn, &())?
            .unwrap_or_default();
        rows.insert(measurement.model.clone(), measurement);
        MEASUREMENTS.put(&self.store, &mut txn, &(), &rows)?;
        txn.commit()?;
        Ok(())
    }
    /// Persist each trigger before returning it to the host's owner-ask queue.
    /// Revision identities include the new revision; contradictions are one ask
    /// per pinned owner line even when the measured score later fluctuates.
    pub fn check_description_drift(&self) -> Result<Vec<DescriptionReask>> {
        let mut txn = self.store.env.write_txn()?;
        let Some(policy) = POLICY.get(&self.store, &txn, &())? else {
            return Ok(vec![]);
        };
        policy.validate()?;
        let measurements = MEASUREMENTS
            .get(&self.store, &txn, &())?
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
            if !REASKS.contains(&self.store, &txn, &identity)? {
                let reask = DescriptionReask {
                    identity,
                    owner_model: owner.model.clone(),
                    observed_model: row.model.clone(),
                    trigger,
                    acknowledged: false,
                };
                REASKS.put(&self.store, &mut txn, &reask.identity, &reask)?;
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
        let txn = self.store.env.read_txn()?;
        REASKS.get(&self.store, &txn, &identity.to_owned())
    }
    /// Recover owner asks persisted before their first delivery. A crash
    /// between trigger persistence and handoff cannot hide a pending ask.
    pub fn pending_description_reasks(&self) -> Result<Vec<DescriptionReask>> {
        let txn = self.store.env.read_txn()?;
        let mut pending = Vec::new();
        for entry in REASKS.iter_from(&self.store, &txn, &[])? {
            let (_, ask) = entry?;
            if !ask.acknowledged {
                pending.push(ask);
            }
        }
        Ok(pending)
    }
    /// Acknowledge only after the owner work is durably handed off. A retry
    /// leaves the same trigger identity and cannot mint a second owner ask.
    pub fn acknowledge_description_reask(&self, identity: &str) -> Result<()> {
        if identity.len() != 64 || !identity.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid("invalid description re-ask identity"));
        }
        let mut txn = self.store.env.write_txn()?;
        let mut ask = REASKS
            .get(&self.store, &txn, &identity.to_owned())?
            .ok_or_else(|| invalid("unknown description re-ask"))?;
        if ask.identity != identity {
            return Err(invalid("description re-ask identity mismatch"));
        }
        ask.acknowledged = true;
        REASKS.put(&self.store, &mut txn, &identity.to_owned(), &ask)?;
        txn.commit()?;
        Ok(())
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
        seat_key(id)?;
        validate_overrides(&settings.inference_overrides)?;
        let (policy_bytes, measurement_bytes, existing) = {
            let txn = self.store.env.read_txn()?;
            (
                POLICY.get_bytes(&self.store, &txn, &())?,
                MEASUREMENTS.get_bytes(&self.store, &txn, &())?,
                SEATS.get(&self.store, &txn, &id.to_owned())?,
            )
        };
        if let Some(seat) = existing {
            return Ok(seat);
        }
        let policy_bytes =
            policy_bytes.ok_or_else(|| invalid("description policy not configured"))?;
        let policy: DescriptionPolicy = POLICY.decode_value(&policy_bytes)?;
        policy.validate()?;
        let measurements = measurement_bytes
            .as_deref()
            .map(|bytes| MEASUREMENTS.decode_value(bytes))
            .transpose()?
            .unwrap_or_default();
        let (chosen, verdict, effort) = resolve(
            &policy,
            &self.seat_policy()?,
            &measurements,
            settings,
            purpose,
            task,
            judge,
        )?;
        let seat = RoutedSeat {
            id: id.into(),
            role: role.into(),
            model: chosen.model.clone(),
            wire: chosen.wire,
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
        if let Some(seat) = SEATS.get(&self.store, &txn, &id.to_owned())? {
            return Ok(seat);
        }
        if POLICY.get_bytes(&self.store, &txn, &())?.as_deref() != Some(policy_bytes.as_slice())
            || MEASUREMENTS.get_bytes(&self.store, &txn, &())? != measurement_bytes
        {
            return Err(invalid("description evidence changed during seat birth"));
        }
        SEATS.put(&self.store, &mut txn, &id.to_owned(), &seat)?;
        txn.commit()?;
        Ok(seat)
    }
    pub fn routed_seat(&self, id: &str) -> Result<Option<RoutedSeat>> {
        seat_key(id)?;
        let txn = self.store.env.read_txn()?;
        SEATS.get(&self.store, &txn, &id.to_owned())
    }
    fn description_measurements(&self) -> Result<BTreeMap<ModelId, MeasuredDescription>> {
        let txn = self.store.env.read_txn()?;
        Ok(MEASUREMENTS
            .get(&self.store, &txn, &())?
            .unwrap_or_default())
    }
    /// Build the one current verdict request before durable hashing. Generative
    /// history and provider cache references cannot cross this boundary.
    pub fn routed_verdict_request(
        &self,
        task: &str,
        judge: &dyn DescriptionJudge,
        settings: &SeatSettings,
        mut request: LlmRequest,
        payload: VerdictPayload,
    ) -> Result<LlmRequest> {
        if !matches!(
            request.envelope.response_format,
            ResponseFormat::Json { .. }
        ) {
            return Err(invalid("schema verdict requires JSON schema"));
        }
        let policy = self
            .description_policy()?
            .ok_or_else(|| invalid("description policy not configured"))?;
        let measurements = self.description_measurements()?;
        let (chosen, _, effort) = resolve(
            &policy,
            &self.seat_policy()?,
            &measurements,
            settings,
            &request.envelope.purpose,
            task,
            judge,
        )?;
        request.model = chosen.model.clone();
        request.envelope.locality = chosen.locality;
        request.envelope.tier.per_seat = None;
        // Provider cache refs and raw system fields can carry an old seat's
        // prefix even with fresh messages. Only VerdictPayload may supply this
        // call's instructions. Strip these before the durable step hash.
        request.params.remove("cachedContent");
        request.params.remove("system");
        for options in request.provider_options.values_mut() {
            let fields = options
                .as_object_mut()
                .ok_or_else(|| invalid("invalid provider options"))?;
            fields.remove("cachedContent");
            fields.remove("system");
        }
        apply_controls(
            &mut request,
            chosen.wire,
            effort,
            &settings.inference_overrides,
        )?;
        // Schema verdicts are independent calls: replace the generating
        // seat's wire pin with this verdict's actual judged effort.
        request.envelope.seat_effort = Some(effort);
        request.messages = payload.messages()?;
        Ok(request)
    }

    /// Route every schema verdict independently without changing a pinned
    /// generative seat. Native structured output and the step shim stay below.
    pub async fn call_routed_verdict(
        &self,
        task: &str,
        judge: &dyn DescriptionJudge,
        settings: &SeatSettings,
        request: LlmRequest,
        payload: VerdictPayload,
        execution: VerdictExecution<'_>,
    ) -> DurableStepResult<StepOutcome> {
        let request = self.routed_verdict_request(task, judge, settings, request, payload)?;
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
