//! Executor-specific callable outcomes over the shared skill Beta posterior.

use super::codec::{decode_value, encode_value, invalid, map_entry};
use super::ledger::receipt_manifest_names_skill;
use super::posterior::SkillReliabilityPosterior;
use super::provenance::skill_reliability_prior;
use crate::Vault;
use crate::attempt_queue::{AttemptQueue, AttemptRecord, AttemptState, ManifestKind};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::skill::SkillRole;
use crate::skill_attribution::{AttributionVerdict, attribution_judgments};
use rmpv::Value;
use sha2::{Digest, Sha256};

const PREFIX: &[u8] = b"skill_reliability:executor:v1:";
const INVOCATION_PREFIX: &[u8] = b"skill_reliability:call_invocation:v1:";

fn invocation_key(skill: &EntityId, receipt: &str) -> Vec<u8> {
    let mut key = INVOCATION_PREFIX.to_vec();
    key.extend_from_slice(skill.as_bytes());
    key.extend_from_slice(receipt.as_bytes());
    key
}

/// The callable door alone writes this lease-bound invocation witness. The
/// first write proves execution began; the second proves its return contract
/// passed. A pack manifest by itself never proves either fact.
pub(crate) fn record_callable_invocation(
    vault: &Vault,
    leased: &AttemptRecord,
    skill: &EntityId,
    executor: &str,
    version: &str,
    result: Option<&str>,
) -> Result<()> {
    let succeeded = result.is_some();
    let receipt = crate::receipt::attempt_pack_receipt_id(&leased.id);
    let _ = key(skill, executor, &receipt)?;
    let binding = invocation_key(skill, &receipt);
    vault.with_write_txn(|txn| {
        let current = AttemptQueue::new(vault)
            .get_in_txn(txn, leased.id)?
            .ok_or(Error::EntityNotFound)?;
        let record = vault.read_skill_record_in_txn(txn, skill)?;
        if current.state != AttemptState::Leased
            || current.lease_owner.is_none()
            || current.lease_owner != leased.lease_owner
            || current.attempt_count != leased.attempt_count
            || !current.manifest().iter().any(|entry| {
                entry.kind == ManifestKind::Skill
                    && entry.reference == record.skill_id
                    && entry.version == version
            })
        {
            return Err(invalid(
                "callable invocation requires its live lease and loaded revision",
            ));
        }
        if record.role != SkillRole::Callable || record.version != version {
            return Err(invalid("callable invocation revision moved"));
        }
        if let Some(raw) = vault.store.vault_meta.get(txn, &binding)? {
            let prior = decode_value(&raw)?;
            if map_entry(&prior, "executor").and_then(Value::as_str) != Some(executor)
                || map_entry(&prior, "version").and_then(Value::as_str) != Some(version)
            {
                return Err(invalid(
                    "callable receipt is already bound to another executor or revision",
                ));
            }
            if !succeeded || map_entry(&prior, "success").and_then(Value::as_bool) == Some(true) {
                return Ok(());
            }
        } else if succeeded {
            return Err(invalid("callable success has no started invocation"));
        }
        let encoded = encode_value(&Value::Map(vec![
            (Value::from("executor"), Value::from(executor)),
            (Value::from("version"), Value::from(version)),
            (Value::from("success"), Value::Boolean(succeeded)),
            (
                Value::from("resultDigest"),
                result.map_or(Value::Nil, |text| {
                    Value::from(bytes_to_hex_lower(&Sha256::digest(text.as_bytes())))
                }),
            ),
        ]))?;
        vault.store.vault_meta.put(txn, &binding, &encoded)?;
        Ok(())
    })
}

fn key(skill: &EntityId, executor: &str, receipt: &str) -> Result<Vec<u8>> {
    if executor.trim().is_empty()
        || executor.len() > 256
        || receipt.is_empty()
        || receipt.len() > 1024
    {
        return Err(invalid(
            "executor and receipt must be bounded non-empty identifiers",
        ));
    }
    let mut key = PREFIX.to_vec();
    key.extend_from_slice(skill.as_bytes());
    key.extend_from_slice(&(executor.len() as u16).to_be_bytes());
    key.extend_from_slice(executor.as_bytes());
    key.extend_from_slice(receipt.as_bytes());
    Ok(key)
}

/// Attribute a judged callable outcome only after its terminal receipt exists.
/// A win needs a completed receipt with no routed defect; a loss needs a
/// persisted skill-defect judgment. A receipt binds to one executor for this
/// skill so one attempt cannot be counted under two model identities.
pub fn record_skill_executor_outcome(
    vault: &Vault,
    skill: &EntityId,
    executor: &str,
    receipt_ref: &str,
    win: bool,
) -> Result<()> {
    let record = vault
        .get_skill_record(skill)?
        .ok_or(Error::EntityNotFound)?;
    if record.role != SkillRole::Callable {
        return Err(invalid("executor outcome requires a callable skill"));
    }
    let receipt = crate::receipt::attempt_pack_receipt(vault, receipt_ref)?.ok_or(invalid(
        "executor outcome requires a terminal attempt receipt",
    ))?;
    if receipt.pack_manifest_skills().is_none() || !receipt_manifest_names_skill(&receipt, &record)
    {
        return Err(invalid(
            "executor outcome requires the callable revision in its pack manifest",
        ));
    }
    let defect = attribution_judgments(vault)?.iter().any(|judgment| {
        judgment.verdict == AttributionVerdict::SkillDefect
            && judgment.subject == *skill
            && judgment
                .evidence_receipts
                .iter()
                .any(|cited| cited == receipt_ref)
    });
    if (win && (receipt.outcome != "completed" || defect)) || (!win && !defect) {
        return Err(invalid(
            "executor outcome lacks matching completed or routed-defect evidence",
        ));
    }
    let key = key(skill, executor, receipt_ref)?;
    let witness_key = invocation_key(skill, receipt_ref);
    let value = encode_value(&Value::Map(vec![(Value::from("win"), Value::Boolean(win))]))?;
    vault.with_write_txn(|txn| {
        let raw = vault
            .store
            .vault_meta
            .get(txn, &witness_key)?
            .ok_or(invalid(
                "executor outcome requires a witnessed callable invocation",
            ))?;
        let witness = decode_value(&raw)?;
        if map_entry(&witness, "executor").and_then(Value::as_str) != Some(executor)
            || map_entry(&witness, "version").and_then(Value::as_str)
                != Some(record.version.as_str())
            || (win
                && (map_entry(&witness, "success").and_then(Value::as_bool) != Some(true)
                    || map_entry(&witness, "resultDigest")
                        .and_then(Value::as_str)
                        .is_none()))
        {
            return Err(invalid(
                "executor outcome disagrees with the callable invocation",
            ));
        }
        if let Some(previous) = vault.store.vault_meta.get(txn, &key)? {
            let prior = decode_value(&previous)?;
            let was_win = map_entry(&prior, "win")
                .and_then(Value::as_bool)
                .ok_or(invalid("executor outcome is missing its result"))?;
            // A skill defect outranks an earlier win, never the reverse.
            if !was_win && win {
                return Ok(());
            }
        }
        vault.store.vault_meta.put(txn, &key, &value)?;
        Ok(())
    })
}

/// Pair-specific posterior; an executor swap starts at the provenance prior,
/// never inherits the previous model's observations.
pub fn skill_executor_reliability_posterior(
    vault: &Vault,
    skill: &EntityId,
    executor: &str,
) -> Result<SkillReliabilityPosterior> {
    let record = vault
        .get_skill_record(skill)?
        .ok_or(Error::EntityNotFound)?;
    if record.role != SkillRole::Callable {
        return Err(invalid("executor posterior requires a callable skill"));
    }
    let prefix = key(skill, executor, "prefix")?;
    let prefix = &prefix[..prefix.len() - "prefix".len()];
    let mut posterior = skill_reliability_prior(vault, skill)?;
    let txn = vault.store.env.read_txn()?;
    for row in vault.store.vault_meta.prefix_iter(&txn, prefix)? {
        let (_, raw) = row?;
        let value = decode_value(&raw)?;
        let win = map_entry(&value, "win")
            .and_then(Value::as_bool)
            .ok_or(invalid("executor outcome is missing its result"))?;
        posterior.apply(win);
    }
    Ok(posterior)
}
