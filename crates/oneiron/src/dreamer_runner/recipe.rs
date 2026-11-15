//! Per-vault, owner-admitted workflow skill binding for the Dreamer weave.
//! No recipe instructions or ruler text are embedded in the engine.

use rmpv::Value;

use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{
    DREAMER_WEAVE_RECIPE_ATTEMPT_KIND, DreamerAttemptPayload, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome,
};
use crate::error::{Error, Result};
use crate::skill::{SkillGovernanceTier, SkillLifecycle};
use crate::store::gate_reason::GateReceiptOutcome;
use crate::store::{GateReceipt, PolicyBasis, ReceiptActor};
use crate::{EntityId, TimeRange, Vault};
use oneiron_contracts::RecordedSeconds;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeaveRecipePin {
    pub skill: EntityId,
    pub version: String,
    pub content_hash: String,
    pub subject: EntityId,
    pub evidence: EntityId,
}

fn invalid() -> Error {
    Error::InvalidClaimBody("invalid or unadmitted per-vault weave recipe")
}

impl WeaveRecipePin {
    pub(crate) fn decode(input: &Value) -> Result<Self> {
        let Value::Map(fields) = input else {
            return Err(invalid());
        };
        if fields.len() != 5 {
            return Err(invalid());
        }
        let get = |name: &str| -> Result<&str> {
            fields
                .iter()
                .find_map(|(key, value)| (key.as_str() == Some(name)).then(|| value.as_str()))
                .flatten()
                .ok_or_else(invalid)
        };
        let pin = Self {
            skill: EntityId::from_hex(get("skill")?)?,
            version: get("version")?.to_owned(),
            content_hash: get("content_hash")?.to_owned(),
            subject: EntityId::from_hex(get("subject")?)?,
            evidence: EntityId::from_hex(get("evidence")?)?,
        };
        if pin.version.is_empty()
            || pin.content_hash.len() != 64
            || !pin
                .content_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(invalid());
        }
        Ok(pin)
    }

    pub(crate) fn binding_hash(&self) -> [u8; 32] {
        *blake3::Hasher::new()
            .update(b"oneiron:dreamer:weave-execution-pin:v1")
            .update(self.skill.as_bytes())
            .update(&(self.version.len() as u64).to_be_bytes())
            .update(self.version.as_bytes())
            .update(self.content_hash.as_bytes())
            .update(self.subject.as_bytes())
            .update(self.evidence.as_bytes())
            .finalize()
            .as_bytes()
    }

    fn encode(&self) -> Value {
        Value::Map(vec![
            ("skill".into(), self.skill.to_hex().into()),
            ("version".into(), self.version.clone().into()),
            ("content_hash".into(), self.content_hash.clone().into()),
            ("subject".into(), self.subject.to_hex().into()),
            ("evidence".into(), self.evidence.to_hex().into()),
        ])
    }
}

impl Vault {
    /// An authenticated owner admits an agent-authored recipe and queues a
    /// pinned execution under one transaction. A candidate alone never runs.
    pub fn admit_and_enqueue_weave_recipe(
        &self,
        owner: &AuthenticatedOwner,
        skill: EntityId,
        subject: EntityId,
        evidence: EntityId,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
            if policy.is_fail_closed() {
                return Err(invalid());
            }
            if !crate::vault::live_entity_row_in_txn(&self.store, txn, &subject)?.is_live()
                || !crate::vault::live_entity_row_in_txn(&self.store, txn, &evidence)?.is_live()
            {
                return Err(Error::EntityNotFound);
            }
            let mut record = self.read_skill_record_in_txn(txn, &skill)?;
            if record.lifecycle_status != SkillLifecycle::Candidate
                || record.approval_status != crate::ClaimApprovalStatus::Proposed
                || record.source != crate::ClaimSource::Generated
            {
                return Err(invalid());
            }
            let hash = record.content_hash.ok_or_else(invalid)?;
            let package = self
                .runtime_skill_package_in_txn(txn, &skill, &record)?
                .ok_or_else(invalid)?;
            if !package
                .files
                .iter()
                .any(|file| file.path == "SKILL.md" && !file.content.is_empty())
            {
                return Err(invalid());
            }
            record.governance_tier = Some(SkillGovernanceTier::Standard);
            record.lifecycle_status = SkillLifecycle::Active;
            record.approval_status = crate::ClaimApprovalStatus::Approved;
            self.put_skill_record_in_txn(
                txn,
                &skill,
                &record,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )?;
            let pin = WeaveRecipePin {
                skill,
                version: record.version,
                content_hash: hash.to_hex(),
                subject,
                evidence,
            };
            let mut decision = GateReceipt::new(
                GateReceiptOutcome::Allow,
                "dreamer_recipe",
                "gate.dreamer.recipe_admitted",
                ReceiptActor::human(actor),
                blake3::Hasher::new()
                    .update(b"oneiron:dreamer:weave-ruler-decision:v1")
                    .update(skill.as_bytes())
                    .update(hash.as_bytes())
                    .update(subject.as_bytes())
                    .update(evidence.as_bytes())
                    .finalize()
                    .as_bytes()
                    .to_vec(),
                PolicyBasis::frontier(policy.read_frontier_hash()?),
            );
            decision.decided_at = Some(RecordedSeconds::from_secs(now));
            self.store.record_gate_receipt_in_txn(txn, decision)?;
            // Hash the full scoped binding so a second evidence slice
            // cannot collide or silently
            // reuse another attempt, without truncating any ref.
            let run_key = format!(
                "weave:{}",
                blake3::Hasher::new()
                    .update(b"oneiron:dreamer:weave-run:v1")
                    .update(skill.as_bytes())
                    .update(hash.as_bytes())
                    .update(subject.as_bytes())
                    .update(evidence.as_bytes())
                    .finalize()
                    .to_hex()
            );
            let store = DreamerRunnerStore::new(self);
            store.enqueue_kind_in_txn(
                txn,
                DREAMER_WEAVE_RECIPE_ATTEMPT_KIND,
                DreamerAttemptPayload {
                    attempt_type: DREAMER_WEAVE_RECIPE_ATTEMPT_KIND.into(),
                    input: pin.encode(),
                    parent_attempt: None,
                },
                Some(run_key.clone()),
                Some(run_key),
                now,
            )
        })
    }
}
