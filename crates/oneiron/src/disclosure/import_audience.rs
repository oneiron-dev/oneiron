//! The standing import audience rule (OF-492): the owner's answer to one
//! sensitive-topic ask, kept as a private `disclosure.import_audience` CLAIM on the
//! topic. It names who the topic's LATER imports are shared with; the import that
//! raised the ask stays private. Only [`Vault::settle_import_audience`] writes it, from
//! an answer the decision-ask door authenticated as the owner, and the topic's cluster
//! names the rule it settled to, so a claim written at the id another way is no rule.

use rmpv::Value;

use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ingest::{ImportAudience, ImportAudienceState};
use crate::llm::decision::{AskRole, AskTo, DecisionAnswer, HolderKind};

use super::tier_classification::{PREDICATE_DISCLOSURE_IMPORT_AUDIENCE, read_stored_claim_body};

const RULE_CLAIM_DOMAIN: &[u8] = b"oneiron.disclosure.import_audience.v1";
const AUDIENCE_ONLY_ME: &str = "only_me";
const AUDIENCE_SOURCE: &str = "source";

/// The deterministic rule CLAIM id: one per topic.
pub fn import_audience_rule_ref(topic: &EntityId) -> Result<EntityId> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RULE_CLAIM_DOMAIN);
    hasher.update(topic.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    EntityId::from_bytes(bytes).map_err(|_| invalid())
}

/// Strict decode of a `disclosure.import_audience` value: the topic, its audience and
/// the ask it answered.
pub(super) fn decode_import_audience_value(
    value: &Value,
) -> Result<(EntityId, ImportAudience, u64)> {
    let Value::Map(entries) = value else {
        return Err(invalid());
    };
    let [(topic_key, topic), (audience_key, audience), (ask_key, ask)] = entries.as_slice() else {
        return Err(invalid());
    };
    if [topic_key, audience_key, ask_key]
        .iter()
        .map(|key| key.as_str())
        .ne(["topic", "audience", "ask"].map(Some))
    {
        return Err(invalid());
    }
    let audience = match audience {
        Value::String(text) if text.as_str() == Some(AUDIENCE_ONLY_ME) => ImportAudience::OnlyMe,
        Value::String(text) if text.as_str() == Some(AUDIENCE_SOURCE) => ImportAudience::Source,
        project => ImportAudience::Project {
            project: decode_id(project)?,
        },
    };
    Ok((
        decode_id(topic)?,
        audience,
        ask.as_u64().ok_or_else(invalid)?,
    ))
}

fn import_audience_value(topic: EntityId, audience: ImportAudience, seq: u64) -> Value {
    Value::Map(vec![
        (Value::from("topic"), id_value(topic)),
        (
            Value::from("audience"),
            match audience {
                ImportAudience::OnlyMe => Value::from(AUDIENCE_ONLY_ME),
                ImportAudience::Source => Value::from(AUDIENCE_SOURCE),
                ImportAudience::Project { project } => id_value(project),
            },
        ),
        (Value::from("ask"), Value::from(seq)),
    ])
}

impl Vault {
    /// Settles one asked topic once the owner answered its ask, once: the answer lands
    /// as the topic's `disclosure.import_audience` CLAIM and the cluster is marked
    /// settled, in one transaction. The ask must still be the frozen one (question,
    /// contract, owner target and the topic as its correlation), answered by a person as
    /// the owner, with one of the frozen options. `None` while the topic is clear or its
    /// ask is unanswered; a settled topic returns its rule again.
    pub fn settle_import_audience(&self, topic: &EntityId) -> Result<Option<EntityId>> {
        self.with_write_txn_grouped(|txn| {
            let Some(mut cluster) = self.import_audience_cluster_in_txn(txn, topic)? else {
                return Ok(None);
            };
            let (seq, question, evidence, options) = match &cluster.state {
                ImportAudienceState::Clear => return Ok(None),
                ImportAudienceState::Settled { rule, .. } => return Ok(Some(*rule)),
                ImportAudienceState::Asked {
                    seq,
                    question,
                    evidence,
                    options,
                } => (*seq, question, evidence, options),
            };
            let Some(ask) = self.decision_ask_in_txn(txn, seq)? else {
                return Ok(None);
            };
            if ask.question != *question
                || ask.evidence != *evidence
                || ask.to != AskTo::owner()
                || ask.correlation != Some(*topic)
            {
                return Err(invalid());
            }
            let Some(answer) = ask.answer else {
                return Ok(None);
            };
            if answer.role != AskRole::Owner || answer.kind != HolderKind::Person {
                return Err(invalid());
            }
            let DecisionAnswer::Choice(label) = answer.answer else {
                return Err(invalid());
            };
            let audience = options
                .iter()
                .find(|option| option.label == label)
                .map(|option| option.audience)
                .ok_or_else(invalid)?;
            let rule = import_audience_rule_ref(topic)?;
            let claim = ClaimBody::new(
                PREDICATE_DISCLOSURE_IMPORT_AUDIENCE,
                ClaimSubject::Entity(*topic),
                import_audience_value(*topic, audience, seq),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            )?;
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            self.put_disclosure_claim_in_txn(txn, &rule, &claim, now)?;
            cluster.state = ImportAudienceState::Settled {
                seq,
                rule,
                audience,
            };
            self.put_import_audience_cluster_in_txn(txn, &cluster)?;
            Ok(Some(rule))
        })
    }

    /// The standing audience the owner chose for a topic's later imports, and the
    /// import reviews that raised it (which the rule never widens); `None` while the
    /// topic has no settled rule.
    pub fn import_audience_rule(
        &self,
        topic: &EntityId,
    ) -> Result<Option<(ImportAudience, Vec<String>)>> {
        let txn = self.store.env.read_txn()?;
        let Some(cluster) = self.import_audience_cluster_in_txn(&txn, topic)? else {
            return Ok(None);
        };
        let ImportAudienceState::Settled {
            seq,
            rule,
            audience,
        } = cluster.state
        else {
            return Ok(None);
        };
        let Some(body) = read_stored_claim_body(&self.store, &txn, &rule)? else {
            return Ok(None);
        };
        if body.predicate != PREDICATE_DISCLOSURE_IMPORT_AUDIENCE
            || body.lifecycle != ClaimLifecycleStatus::Active
            || decode_import_audience_value(&body.value)? != (*topic, audience, seq)
        {
            return Ok(None);
        }
        Ok(Some((audience, cluster.reviews.into_iter().collect())))
    }
}

fn id_value(id: EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

fn decode_id(value: &Value) -> Result<EntityId> {
    let Value::Binary(bytes) = value else {
        return Err(invalid());
    };
    EntityId::from_bytes(bytes.as_slice().try_into().map_err(|_| invalid())?).map_err(|_| invalid())
}

fn invalid() -> Error {
    Error::InvalidClaimBody("disclosure.import_audience value invalid")
}
