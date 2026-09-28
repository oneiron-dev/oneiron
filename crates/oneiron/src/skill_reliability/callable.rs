//! Callable invocation witnesses. A callable's reliability pair is the
//! executor that actually ran it under the caller's lease; its outcomes land
//! in the shared outcome ledger and project through the same per-executor arm
//! as every other skill.

use std::collections::BTreeMap;

use rmpv::Value;
use sha2::{Digest, Sha256};

use super::codec::{decode_value, encode_value, invalid, map_entry, map_str};
use super::ledger::{
    ATTEMPT_OUTCOME_COMPLETED, receipt_manifest_names_skill, record_outcome_in_txn,
};
use super::projector::project_skill_reliability_for_executor;
use super::read::validate_executor;
use crate::Vault;
use crate::attempt_queue::{AttemptQueue, AttemptRecord, AttemptState, ManifestKind};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::skill::SkillRole;

/// One caller step's invocation witness: the MessagePack map [`encode_value`] spells. Key: the
/// [`invocation_prefix`] bytes, then the step seq (u64be).
const INVOCATIONS: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::SKILL_RELIABILITY_CALL_INVOCATION);

fn invocation_prefix(skill: &EntityId, receipt: &str) -> Result<Vec<u8>> {
    let length = u16::try_from(receipt.len())
        .ok()
        .filter(|length| *length > 0 && *length <= 1024)
        .ok_or(invalid("callable receipt must be a bounded identifier"))?;
    let mut key = skill.as_bytes().to_vec();
    key.extend_from_slice(&length.to_be_bytes());
    key.extend_from_slice(receipt.as_bytes());
    Ok(key)
}

/// The callable door alone writes this lease-bound invocation witness, one
/// per caller step. The first write proves execution began; the second proves
/// its return contract passed. A pack manifest by itself never proves either
/// fact, and a step already bound to one executor cannot be re-credited to
/// another.
pub(crate) fn record_callable_invocation(
    vault: &Vault,
    leased: &AttemptRecord,
    skill: &EntityId,
    executor: &str,
    version: &str,
    seq: u64,
    result: Option<&str>,
) -> Result<()> {
    validate_executor(executor)?;
    let succeeded = result.is_some();
    let receipt = crate::receipt::attempt_pack_receipt_id(&leased.id);
    let mut binding = invocation_prefix(skill, &receipt)?;
    binding.extend_from_slice(&seq.to_be_bytes());
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
        if let Some(raw) = INVOCATIONS.get(&vault.store, txn, &binding)? {
            let prior = decode_value(&raw)?;
            if map_str(&prior, "executor") != Some(executor)
                || map_str(&prior, "version") != Some(version)
            {
                return Err(invalid(
                    "callable step is already bound to another executor or revision",
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
        INVOCATIONS.put(&vault.store, txn, &binding, &encoded)?;
        Ok(())
    })
}

/// Applies an already-routed receipt outcome to every executor that invoked
/// this callable revision under that attempt. A win credits only executors
/// whose invocation returned within its contract; a routed defect charges
/// every executor that ran it. A tier-1 listing or a pack load without an
/// invocation is not pair evidence. Non-callable subjects are left to the
/// shared receipt-executor path.
pub(crate) fn project_callable_receipt_outcome(
    vault: &Vault,
    skill: &EntityId,
    receipt_ref: &str,
    win: bool,
    at: u64,
) -> Result<()> {
    let Some(record) = vault.get_skill_record(skill)? else {
        return Ok(());
    };
    if record.role != SkillRole::Callable {
        return Ok(());
    }
    let grounded = crate::receipt::attempt_pack_receipt(vault, receipt_ref)?
        .filter(|receipt| receipt_manifest_names_skill(receipt, &record));
    let Some(receipt) = grounded else {
        // Same line as the shared doors: an ungrounded win is refused; an
        // ungrounded routed loss is skipped rather than fatal to the pass.
        return if win {
            Err(invalid("callable win cites a receipt that never loaded it"))
        } else {
            Ok(())
        };
    };
    if win && receipt.outcome != ATTEMPT_OUTCOME_COMPLETED {
        return Err(invalid(
            "a contributing win requires a completed attempt receipt",
        ));
    }
    let prefix = invocation_prefix(skill, receipt_ref)?;
    let credited = vault.with_write_txn(|txn| {
        let mut executors = BTreeMap::<String, bool>::new();
        for row in INVOCATIONS.iter_from(&vault.store, txn, &prefix)? {
            let (_, raw) = row?;
            let witness = decode_value(&raw)?;
            if map_str(&witness, "version") != Some(record.version.as_str()) {
                continue;
            }
            let executor = map_str(&witness, "executor")
                .ok_or(invalid("callable invocation lacks executor"))?;
            let success = map_entry(&witness, "success")
                .and_then(Value::as_bool)
                .ok_or(invalid("callable invocation lacks result state"))?;
            *executors.entry(executor.to_owned()).or_default() |= success;
        }
        let credited: Vec<String> = executors
            .into_iter()
            .filter(|(_, succeeded)| !win || *succeeded)
            .map(|(executor, _)| executor)
            .collect();
        for executor in &credited {
            record_outcome_in_txn(
                vault,
                txn,
                skill,
                Some(executor.as_str()),
                receipt_ref,
                win,
                at,
            )?;
        }
        Ok(credited)
    })?;
    for executor in credited {
        project_skill_reliability_for_executor(vault, skill, &executor, at)?;
    }
    Ok(())
}
