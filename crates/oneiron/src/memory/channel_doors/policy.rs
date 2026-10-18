use serde::{Deserialize, Serialize};

use super::*;
use crate::claim::{ClaimBody, ClaimReadStatus, ClaimSubject, PointRead};
use crate::delivery_window::{
    DELIVERY_WINDOW_CLAIM_PREDICATES, DELIVERY_WINDOW_SCHEMA_VERSION,
    DeliveryWindowApnsInterruptionLevel, DeliveryWindowContextCondition,
    DeliveryWindowEvaluationContext, DeliveryWindowEvaluator, DeliveryWindowPolicyClaim,
    DeliveryWindowResolution, DeliveryWindowTimeWindow, DeliveryWindowVerbClass,
    PREDICATE_DELIVERY_WINDOW_CHANNEL, PREDICATE_DELIVERY_WINDOW_CONTEXT,
    PREDICATE_DELIVERY_WINDOW_QUIET, is_delivery_window_claim_predicate,
};
use crate::memory::{ClaimInput, CommitReceipt};

/// Every policy variant restricts interruptions only. Its value is encoded
/// into the engine's existing delivery_window.* claim family.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeliveryWindowRule {
    Quiet {
        window: DeliveryWindowTimeWindow,
    },
    Context {
        when: DeliveryWindowContextCondition,
    },
    Channel {
        channel: String,
        window: Option<DeliveryWindowTimeWindow>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeliveryWindowPolicyPutRequest {
    /// Actor, sending identity or recipient whose dispatches this row covers.
    pub subject_ref: EntityId,
    /// Stable row key within this subject and policy kind. Replacing it uses
    /// the ordinary gated claim supersession path.
    pub policy_key: String,
    pub rule: DeliveryWindowRule,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub valid_from: Option<u64>,
    #[serde(default)]
    pub valid_to: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeliveryWindowPolicyRequest {
    pub subject_ref: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeliveryWindowPolicyRetractRequest {
    pub claim_ref: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryWindowPolicyRow {
    pub claim_ref: EntityId,
    pub subject_ref: EntityId,
    pub policy_key: Option<String>,
    pub rule: DeliveryWindowRule,
    pub reason: String,
    pub approval: String,
    pub lifecycle: String,
    pub source: Option<String>,
    pub valid_from: Option<u64>,
    pub valid_to: Option<u64>,
    pub stale: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryWindowPolicies {
    pub rows: Vec<DeliveryWindowPolicyRow>,
}

/// A read-only policy preview. This cannot schedule, approve or release a
/// send; dispatch always evaluates live policy again at its own effect door.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeliveryWindowEvaluateRequest {
    pub subject_refs: Vec<EntityId>,
    pub delivery_epoch_secs: u64,
    pub local_minute_of_day: u16,
    pub verb_class: DeliveryWindowVerbClass,
    pub channel: String,
    #[serde(default)]
    pub active_contexts: Vec<DeliveryWindowContextCondition>,
    #[serde(default)]
    pub interrupt_surface: Option<String>,
    #[serde(default)]
    pub degrade_to: Option<String>,
    #[serde(default)]
    #[schemars(with = "Option<String>")]
    pub apns_interruption_level: Option<DeliveryWindowApnsInterruptionLevel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryWindowPreview {
    pub policy_refs: Vec<EntityId>,
    pub resolution: DeliveryWindowResolution,
}

fn policy_value(rule: &DeliveryWindowRule, reason: Option<&str>) -> (String, serde_json::Value) {
    let (predicate, mut value) = match rule {
        DeliveryWindowRule::Quiet { window } => (
            PREDICATE_DELIVERY_WINDOW_QUIET,
            serde_json::json!({"window": window, "tz": "user-local"}),
        ),
        DeliveryWindowRule::Context { when } => (
            PREDICATE_DELIVERY_WINDOW_CONTEXT,
            serde_json::json!({"when": when}),
        ),
        DeliveryWindowRule::Channel { channel, window } => {
            let mut value = serde_json::json!({"channel": channel});
            if let Some(window) = window {
                value["window"] = serde_json::json!(window);
            }
            (PREDICATE_DELIVERY_WINDOW_CHANNEL, value)
        }
    };
    value["schema_version"] = serde_json::json!(DELIVERY_WINDOW_SCHEMA_VERSION);
    value["applies_to"] = serde_json::json!("interrupt");
    if let Some(reason) = reason {
        value["reason"] = serde_json::json!(reason);
    }
    (predicate.to_owned(), value)
}

fn policy_row(id: EntityId, body: &ClaimBody) -> MemoryResult<DeliveryWindowPolicyRow> {
    let policy = DeliveryWindowPolicyClaim::from_claim_body(body)?;
    let malformed = || MemoryError::bad_request("delivery-window policy has no typed variant");
    let rule = match policy.predicate.as_str() {
        PREDICATE_DELIVERY_WINDOW_QUIET => DeliveryWindowRule::Quiet {
            window: policy.window.ok_or_else(malformed)?,
        },
        PREDICATE_DELIVERY_WINDOW_CONTEXT => DeliveryWindowRule::Context {
            when: policy.context.ok_or_else(malformed)?,
        },
        PREDICATE_DELIVERY_WINDOW_CHANNEL => DeliveryWindowRule::Channel {
            channel: policy.channel.ok_or_else(malformed)?,
            window: policy.window,
        },
        _ => return Err(malformed()),
    };
    let ClaimSubject::Entity(subject_ref) = body.subject else {
        return Err(malformed());
    };
    let policy_key = body.scope.as_ref().and_then(|scope| {
        let json = crate::serialize::msgpack_value_to_json(scope);
        json.get("delivery_window_key")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    });
    Ok(DeliveryWindowPolicyRow {
        claim_ref: id,
        subject_ref,
        policy_key,
        rule,
        reason: policy.reason,
        approval: body.approval.as_str().to_owned(),
        lifecycle: body.lifecycle.as_str().to_owned(),
        source: body.source.map(|source| source.as_str().to_owned()),
        valid_from: body.valid_from,
        valid_to: body.valid_to,
        stale: body.stale,
    })
}

impl Memory<'_> {
    /// Read each claim through the caller's own read lane, including its
    /// approval, source and generated-origin evidence. A preview never
    /// accepts client-supplied effective policy or approval flags.
    fn delivery_window_bodies(
        &self,
        subjects: &[EntityId],
    ) -> MemoryResult<Vec<(EntityId, ClaimBody)>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let mut ids = std::collections::BTreeSet::new();
        for subject in subjects {
            self.channel_readable(*subject)?;
            ids.extend(self.vault.claims_for_subject(subject)?);
        }
        self.produced_from(ids.iter().copied());
        let reads = ids.into_iter().map(PointRead::id).collect::<Vec<_>>();
        let mut policies = Vec::new();
        for row in lane.read(&reads, None)?.value.into_iter().flatten() {
            let Some(bytes) = row.body.as_deref() else {
                continue;
            };
            let body = crate::claim::decode_claim_body(bytes, true)?;
            if DELIVERY_WINDOW_CLAIM_PREDICATES.contains(&body.predicate.as_str())
                && matches!(body.subject, ClaimSubject::Entity(subject) if subjects.contains(&subject))
            {
                policies.push((row.id, body));
            }
        }
        Ok(policies)
    }

    pub fn delivery_window_policies(
        &self,
        input: DeliveryWindowPolicyRequest,
    ) -> MemoryResult<DeliveryWindowPolicies> {
        let rows = self
            .delivery_window_bodies(&[input.subject_ref])?
            .into_iter()
            .map(|(id, body)| policy_row(id, &body))
            .collect::<MemoryResult<Vec<_>>>()?;
        Ok(DeliveryWindowPolicies { rows })
    }

    pub fn delivery_window_put_as(
        &self,
        owner: &AuthenticatedOwner,
        input: DeliveryWindowPolicyPutRequest,
    ) -> MemoryResult<CommitReceipt> {
        self.channel_owner(owner)?;
        self.channel_readable(input.subject_ref)?;
        if input.policy_key.trim().is_empty() {
            return Err(MemoryError::bad_request("policy_key is not empty"));
        }
        let (predicate, value) = policy_value(&input.rule, input.reason.as_deref());
        // The normal claim writer performs structural validation, the gate,
        // owner-authorship revalidation and supersession in its transaction.
        self.clone()
            .with_owner_authorship(owner)
            .claim_upsert(&ClaimInput {
                id: None,
                predicate,
                subject_ref: input.subject_ref.to_hex(),
                value,
                confidence: 1.0,
                source: "user_stated".to_owned(),
                world_ref: None,
                relationship_ref: None,
                scope: Some(serde_json::json!({"delivery_window_key": input.policy_key})),
                valid_from: input.valid_from,
                valid_to: input.valid_to,
                occurred_at: None,
                learned_at: None,
                salience: None,
            })
    }

    pub fn delivery_window_retract_as(
        &self,
        owner: &AuthenticatedOwner,
        input: DeliveryWindowPolicyRetractRequest,
    ) -> MemoryResult<CommitReceipt> {
        self.channel_owner(owner)?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        self.produced_from([input.claim_ref]);
        let read = lane.read(&[PointRead::id(input.claim_ref)], None)?;
        let body = read
            .value
            .into_iter()
            .flatten()
            .next()
            .and_then(|row| row.body)
            .ok_or_else(|| MemoryError::not_found("delivery-window policy not found"))?;
        let body = crate::claim::decode_claim_body(&body, true)?;
        if !is_delivery_window_claim_predicate(&body.predicate) {
            return Err(MemoryError::bad_request(
                "claim_ref must name a delivery-window policy",
            ));
        }
        self.clone()
            .with_owner_authorship(owner)
            .claim_retract(&input.claim_ref.to_hex())
    }

    pub fn delivery_window_evaluate(
        &self,
        input: DeliveryWindowEvaluateRequest,
    ) -> MemoryResult<DeliveryWindowPreview> {
        let policies = self.delivery_window_bodies(&input.subject_refs)?;
        let claims = policies
            .iter()
            .map(|(_, body)| DeliveryWindowPolicyClaim::from_claim_body(body))
            .collect::<crate::Result<Vec<_>>>()?;
        let mut context = DeliveryWindowEvaluationContext::new(
            input.delivery_epoch_secs,
            input.local_minute_of_day,
            input.verb_class,
        )?
        .channel(input.channel);
        for condition in input.active_contexts {
            context = context.active_context(condition);
        }
        if let Some(surface) = input.interrupt_surface {
            context = context.interrupt_surface(surface);
        }
        if let Some(surface) = input.degrade_to {
            context = context.degrade_to(surface);
        }
        if let Some(level) = input.apns_interruption_level {
            context = context.apns_interruption_level(level);
        }
        Ok(DeliveryWindowPreview {
            policy_refs: policies.into_iter().map(|(id, _)| id).collect(),
            resolution: DeliveryWindowEvaluator::resolve(&context, &claims),
        })
    }
}
