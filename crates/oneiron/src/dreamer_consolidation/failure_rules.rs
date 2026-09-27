//! Resident-owned v1 failure rules for the two Dreamer consolidation call sites.
//!
//! These rows only narrow what a failed call may publish. They never override
//! the step layer's retry authority, budget trap, or the claim trust gate.

use crate::error::{Error, Result};
use crate::llm::{CallClass, FinishReason, LlmRequest, LlmResponse};
use crate::write_envelope::WriteActor;
use crate::{ClaimLifecycleStatus, ClaimSource, ClaimSubject, EdgeActorClass, EntityId, Vault};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub(crate) const KEY: &[u8] = b"dreamer:consolidation:failure_rules:v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Stage {
    Extraction,
    Conflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Failure {
    Retryable,
    Fatal,
    Budget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Route {
    StepRetry,
    DeclaredFallback,
    BudgetTrap,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    stage: Stage,
    failure: Failure,
    route: Route,
    consolidation_eligible: bool,
    effector_eligible: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRules {
    author: String,
    rules: FailureRules,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FailureRules {
    version: u8,
    rows: Vec<Rule>,
}

fn invalid() -> Error {
    Error::InvalidConfig("invalid Dreamer failure rule rows".into())
}

impl FailureRules {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let rules: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        rules.validate()?;
        Ok(rules)
    }

    fn validate(&self) -> Result<()> {
        let mut keys = BTreeSet::new();
        for row in &self.rows {
            if !keys.insert((row.stage, row.failure)) {
                return Err(invalid());
            }
            match (row.failure, row.route, row.value.as_ref()) {
                (Failure::Fatal, Route::DeclaredFallback, Some(value))
                    if match row.stage {
                        Stage::Extraction => {
                            value
                                .get("candidates")
                                .is_some_and(serde_json::Value::is_array)
                                && value
                                    .get("persons")
                                    .is_some_and(serde_json::Value::is_array)
                        }
                        Stage::Conflict => {
                            value.get("resolution").and_then(serde_json::Value::as_str)
                                == Some("escalate")
                        }
                    } => {}
                (Failure::Retryable, Route::StepRetry, None)
                | (Failure::Budget, Route::BudgetTrap, None)
                    if !row.consolidation_eligible && !row.effector_eligible => {}
                _ => return Err(invalid()),
            }
            // A fallback never authorizes an outward effect; the ordinary
            // trust/approval gate still decides effector eligibility.
            if row.effector_eligible {
                return Err(invalid());
            }
        }
        if self.version != 1 || keys.len() != 6 {
            return Err(invalid());
        }
        Ok(())
    }

    fn row(&self, stage: Stage, failure: Failure) -> &Rule {
        self.rows
            .iter()
            .find(|row| row.stage == stage && row.failure == failure)
            .expect("validated exhaustive failure rules")
    }

    pub(super) fn bind(&self, stage: Stage, request: &mut LlmRequest) {
        let CallClass::Durable { fallback } = &mut request.envelope.class else {
            unreachable!("consolidation steps are durable")
        };
        fallback.name = "json_rules_v1".into();
        fallback.config = Some(serde_json::json!({"version":1,"rows":[{
            "failure":"fatal", "value":self.row(stage, Failure::Fatal).value
        }]}));
    }

    pub(super) fn accepts(&self, stage: Stage, response: &LlmResponse) -> bool {
        if let FinishReason::Other { name } = &response.finish_reason
            && name.starts_with("fallback:")
        {
            return self.row(stage, Failure::Fatal).consolidation_eligible;
        }
        true
    }
}

/// The existing `self.memory.put_claim` first-party trap is the resident
/// authoring surface. Its subject is the host-bound resident, never Dreamer.
pub(crate) const PREDICATE: &str = "core.dreamer_failure_rules";

pub(crate) fn prepare_authored_claim(predicate: &str, value: &Value) -> Result<Option<Vec<u8>>> {
    if predicate != PREDICATE {
        return Ok(None);
    }
    let json = super::value_projection::rmpv_to_json(value);
    let bytes = serde_json::to_vec(&json).map_err(|_| invalid())?;
    FailureRules::parse(&bytes)?;
    Ok(Some(bytes))
}

/// A policy is a host-bound action, not an assertion to use as corroboration:
/// a Proposed claim can carry it only when its gate decision was `allow`.
/// Pending and denied writes remain inert despite their durable claim rows.
pub(crate) fn admitted_authored_claim(
    vault: &Vault,
    id: &EntityId,
    actor: WriteActor,
) -> Result<bool> {
    if actor.actor_class() != EdgeActorClass::Agent || actor == vault.dreamer_authority()? {
        return Ok(false);
    }
    let Some(body) = vault.get_claim(id)? else {
        return Ok(false);
    };
    if body.predicate != PREDICATE
        || body.subject != ClaimSubject::Entity(actor.entity_ref())
        || body.source != Some(ClaimSource::Generated)
        || body.lifecycle != ClaimLifecycleStatus::Active
    {
        return Ok(false);
    }
    let txn = vault.store.env.read_txn()?;
    let decisions = vault
        .store
        .gate_decisions_for_claim_in_txn(&txn, id.as_bytes())?;
    Ok(decisions.last().is_some_and(|record| {
        record.outcome == "allow"
            && record.content_kind == "claim"
            && record.actor_ref.as_deref() == Some(actor.entity_ref().to_hex().as_str())
    }))
}

pub(crate) fn resident_record(actor: WriteActor, json: &[u8]) -> Result<Vec<u8>> {
    if actor.actor_class() != EdgeActorClass::Agent {
        return Err(invalid());
    }
    let rules = FailureRules::parse(json)?;
    serde_json::to_vec(&StoredRules {
        author: actor.entity_ref().to_hex(),
        rules,
    })
    .map_err(|_| invalid())
}

pub(super) fn load(vault: &Vault) -> Result<Option<FailureRules>> {
    let txn = vault.store.env.read_txn()?;
    vault
        .store
        .vault_meta
        .get(&txn, KEY)?
        .map(|bytes| {
            let stored: StoredRules = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            EntityId::from_hex(&stored.author).map_err(|_| invalid())?;
            stored.rules.validate()?;
            Ok(stored.rules)
        })
        .transpose()
}

impl Vault {
    /// Host configuration door. Agent-authored rows use the first-party
    /// `self.memory.put_claim` trap, with the resident actor bound by its host.
    pub fn set_dreamer_failure_rules(&self, actor: WriteActor, json: &[u8]) -> Result<()> {
        let bytes = resident_record(actor, json)?;
        if actor == self.dreamer_authority()?
            || self
                .read_entity_header(&actor.entity_ref())?
                .is_none_or(|row| row.entity_type != crate::registry::ENTITY_TYPE_PERSON)
        {
            return Err(invalid());
        }
        let mut txn = self.store.env.write_txn()?;
        self.store.vault_meta.put(&mut txn, KEY, &bytes)?;
        txn.commit()?;
        Ok(())
    }
}
