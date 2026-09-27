//! Atomic, idempotent human TASK notification for one landed policy change.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::PolicyApprovalCeiling;
use crate::memory::{MemoryError, facade_provenance, verify_actor_binding_in_txn};
use crate::registry::ENTITY_TYPE_TASK;

use super::create_spec::{TaskCreateRateLimit, TaskCreateSpec};
use super::create_validation::{task_body_in_txn, validate_task_create_in};
use super::rate_limit::{record_task_create, task_actor_ceiling};
use super::verb_kind::{TaskAssignee, TaskKind};

const INDEX_PREFIX: &[u8] = b"task.policy_change_followup.v1:";

#[derive(Serialize, Deserialize)]
struct FollowupIndex {
    task_ref: EntityId,
    author: EntityId,
    recipient: EntityId,
    receipt_id: String,
}

fn index_key(receipt_id: &str, recipient: EntityId) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(INDEX_PREFIX);
    hash.update(&(receipt_id.len() as u64).to_be_bytes());
    hash.update(receipt_id.as_bytes());
    hash.update(recipient.as_bytes());
    [INDEX_PREFIX, hash.finalize().as_bytes()].concat()
}

fn task_error(error: MemoryError) -> Error {
    Error::InvalidConfig(format!("human follow-up TASK refused: {}", error.message))
}

/// One recipient-owned digest TASK binds every receipt in the batch. The
/// sorted receipt set is part of both the idempotency index and the TASK spec.
pub(crate) fn enqueue_policy_change_digest_followup_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    sender: EntityId,
    recipient: EntityId,
    receipts: &[String],
    now: u64,
) -> Result<EntityId> {
    if receipts.is_empty() || receipts.iter().any(|r| r.is_empty()) {
        return Err(Error::InvalidConfig("empty policy digest".into()));
    }
    let mut sorted = receipts.to_vec();
    sorted.sort();
    sorted.dedup();
    let mut hash = blake3::Hasher::new();
    hash.update(b"policy:recipient-digest:v1");
    hash.update(recipient.as_bytes());
    for receipt in &sorted {
        hash.update(&(receipt.len() as u64).to_be_bytes());
        hash.update(receipt.as_bytes());
    }
    let id = format!("digest:{}", hash.finalize().to_hex());
    let spec = Value::Map(vec![(
        Value::from("source_receipt_refs"),
        Value::Array(sorted.into_iter().map(Value::from).collect()),
    )]);
    enqueue_followup_in_txn(vault, txn, sender, recipient, &id, spec, now)
}

/// Mints a standard, human-assigned TASK and its local follow-up cursor inside
/// the caller's policy-write transaction. No decision ASK, realization job or
/// outbound send is created here. A repeated `(receipt_id, recipient)` returns
/// the same TASK; a different author for that pair is refused.
///
/// The caller must establish that `author` is the authenticated author of the
/// landed policy row and call this only when that row lands. Merely passing an
/// author id does not prove the row's provenance or policy holder authority.
/// The human actor type and Auto task-create ceiling are rechecked here against
/// transaction state; root ownership is deliberately not required, so a valid
/// Admin/Delegate policy holder may author the notice.
pub(crate) fn enqueue_policy_change_followup_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    author: EntityId,
    recipient: EntityId,
    receipt_id: &str,
    now: u64,
) -> Result<EntityId> {
    enqueue_followup_in_txn(
        vault,
        txn,
        author,
        recipient,
        receipt_id,
        Value::Map(vec![(
            Value::from("source_receipt_ref"),
            Value::from(receipt_id),
        )]),
        now,
    )
}

fn enqueue_followup_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    author: EntityId,
    recipient: EntityId,
    receipt_id: &str,
    task_spec: Value,
    now: u64,
) -> Result<EntityId> {
    if receipt_id.is_empty()
        || receipt_id.len() > 512
        || receipt_id.trim() != receipt_id
        || receipt_id.contains('\0')
    {
        return Err(Error::InvalidConfig(
            "invalid policy change receipt id".into(),
        ));
    }
    verify_actor_binding_in_txn(vault, &*txn, author, EdgeActorClass::Human).map_err(task_error)?;
    let memory = vault.memory(author, EdgeActorClass::Human);
    let key = index_key(receipt_id, recipient);
    if let Some(raw) = vault.store.vault_meta.get(&*txn, &key)? {
        let index: FollowupIndex = rmp_serde::from_slice(&raw)
            .map_err(|_| Error::CorruptedIndex("policy change follow-up index"))?;
        if index.author != author || index.recipient != recipient || index.receipt_id != receipt_id
        {
            return Err(Error::CorruptedIndex("policy change follow-up index"));
        }
        if vault.get_entity_type_in_txn(&*txn, &index.task_ref)? != Some(ENTITY_TYPE_TASK) {
            return Err(Error::CorruptedIndex(
                "policy change follow-up TASK missing",
            ));
        }
        let body = task_body_in_txn(vault, &*txn, index.task_ref).map_err(task_error)?;
        if body.task_kind() != TaskKind::Standard
            || body.owner_ref != author.to_hex()
            || body.assignee
                != Some(TaskAssignee::Human {
                    actor_ref: recipient,
                })
            || body.spec != task_spec
        {
            return Err(Error::CorruptedIndex(
                "policy change follow-up TASK mismatch",
            ));
        }
        crate::human_task::register_human_followup_in_txn(
            vault,
            txn,
            index.task_ref,
            recipient,
            now,
        )?;
        return Ok(index.task_ref);
    }
    if task_actor_ceiling(vault, &*txn, author, EdgeActorClass::Human).map_err(task_error)?
        != PolicyApprovalCeiling::Auto
    {
        return Err(Error::InvalidConfig(
            "follow-up author lacks Auto task-create ceiling".into(),
        ));
    }
    let spec = TaskCreateSpec::new(task_spec, None, Some(author), Some(now))
        .with_kind(TaskKind::Standard)
        .with_assignee(TaskAssignee::Human {
            actor_ref: recipient,
        });
    let validated = validate_task_create_in(vault, &*txn, &spec, now).map_err(task_error)?;
    // The normal human TASK route checks an existing PERSON, active contact and
    // channel, including opt-out vetoes. Never degrade to Dreamer or a proposal.
    crate::human_task::resolve_native_human_route_in(vault, &*txn, recipient)
        .map_err(|error| Error::InvalidConfig(format!("human follow-up route refused: {error}")))?;
    record_task_create(
        vault,
        txn,
        author,
        vault.store.clock.now_recorded_at(),
        TaskCreateRateLimit::default(),
    )?;
    let task_ref = memory
        .mint_task_in_txn(
            txn,
            &validated,
            None,
            author,
            &facade_provenance("tasks.create"),
            now,
        )
        .map_err(task_error)?;
    memory
        .route_created_task_in_txn(txn, task_ref, &validated, now)
        .map_err(task_error)?;
    let index = FollowupIndex {
        task_ref,
        author,
        recipient,
        receipt_id: receipt_id.to_owned(),
    };
    let raw = rmp_serde::to_vec_named(&index)
        .map_err(|_| Error::InvariantViolation("policy follow-up index encoding"))?;
    vault.store.vault_meta.put(txn, &key, &raw)?;
    Ok(task_ref)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel_identity::{
        ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityState,
        SelfHeldShape,
    };
    use crate::comm::resolve_or_create_comm_party;
    use crate::config::VaultConfig;
    use crate::counterparty_contact::CounterpartyContactRecord;
    use crate::human_task::{HumanFollowupStage, human_followup_record};
    use crate::registry::ENTITY_TYPE_PERSON;
    use crate::temporal::TimeRange;

    const NOW: u64 = 1_772_600_000;

    fn fixture() -> (tempfile::TempDir, Vault, EntityId, EntityId) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        let author = EntityId::from_bytes([0xe1; 16]).expect("author id");
        vault
            .put_entity(
                &author,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"author",
            )
            .expect("author");
        let recipient =
            resolve_or_create_comm_party(&vault, "recipient@example.test").expect("comm person");
        let face = EntityId::from_bytes([0x7c; 16]).expect("face id");
        vault
            .create_channel_identity(
                &face,
                &ChannelIdentity::requested(
                    "email",
                    "sender@example.test",
                    SelfHeldShape::DedicatedAddress,
                    ChannelIdentityBinding::vault(1),
                    NOW,
                ),
            )
            .expect("create identity");
        vault
            .transition_channel_identity(
                &face,
                ChannelIdentityState::PendingFulfillment,
                Some(ChannelIdentityFulfillment::Api),
                NOW,
                None,
            )
            .expect("fulfill identity");
        vault
            .transition_channel_identity(&face, ChannelIdentityState::Active, None, NOW, None)
            .expect("activate identity");
        vault
            .create_counterparty_contact(
                &EntityId::from_bytes([0x7d; 16]).expect("contact id"),
                &CounterpartyContactRecord::user_introduction(face, "recipient@example.test", NOW)
                    .expect("contact"),
            )
            .expect("create contact");
        (dir, vault, author, recipient)
    }

    #[test]
    fn one_receipt_mints_one_human_task_and_cursor_without_a_worker() -> Result<()> {
        let (_dir, vault, author, recipient) = fixture();
        let before = vault.entities_by_type(ENTITY_TYPE_TASK)?;
        let task = vault.with_write_txn(|txn| {
            let first = enqueue_policy_change_followup_in_txn(
                &vault,
                txn,
                author,
                recipient,
                "receipt:1",
                NOW,
            )?;
            let replay = enqueue_policy_change_followup_in_txn(
                &vault,
                txn,
                author,
                recipient,
                "receipt:1",
                NOW + 1,
            )?;
            assert_eq!(first, replay);
            Ok(first)
        })?;
        let cursor = human_followup_record(&vault, task)?.expect("follow-up cursor");
        assert_eq!(cursor.assignee_ref, recipient);
        assert_eq!(cursor.stage, HumanFollowupStage::Tracking);
        let after = vault.entities_by_type(ENTITY_TYPE_TASK)?;
        assert!(!before.contains(&task));
        assert!(after.contains(&task));
        // Human routing may mint a separate delivery TASK; only one task may
        // carry this policy receipt as its source.
        let txn = vault.store.env.read_txn()?;
        let body = task_body_in_txn(&vault, &txn, task).map_err(task_error)?;
        assert_eq!(
            body.spec,
            Value::Map(vec![(
                Value::from("source_receipt_ref"),
                Value::from("receipt:1"),
            )])
        );
        drop(txn);
        assert!(
            crate::attempt_queue::AttemptQueue::new(&vault)
                .list()?
                .iter()
                .all(|attempt| attempt.task_ref.as_deref() != Some(task.to_hex().as_str()))
        );
        Ok(())
    }

    #[test]
    fn unreachable_recipient_rolls_back_without_a_task() -> Result<()> {
        let (_dir, vault, author, _recipient) = fixture();
        let unknown = EntityId::from_bytes([0x39; 16])?;
        vault.put_entity(
            &unknown,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"unreachable",
        )?;
        assert!(
            vault
                .with_write_txn(|txn| enqueue_policy_change_followup_in_txn(
                    &vault,
                    txn,
                    author,
                    unknown,
                    "receipt:2",
                    NOW,
                ))
                .is_err()
        );
        assert!(vault.entities_by_type(ENTITY_TYPE_TASK)?.is_empty());
        Ok(())
    }
}
