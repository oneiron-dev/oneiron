use crate::edge::EdgeActorClass;
use crate::task_verb::{TaskAssignee, TaskCreateSpec};
use crate::{EntityId, Result, Vault};
use crate::{TimeRange, VaultConfig};
use rmpv::Value;
use std::future::Future;

#[test]
fn owners_share_exact_inbox_and_saved_query_membership_with_backfill() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owners = [EntityId::now(), EntityId::now()];
    let mut tasks = vec![Vec::new(), Vec::new()];
    for (index, owner) in owners.iter().enumerate() {
        vault.put_entity(
            owner,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )?;
        for _ in 0..index + 1 {
            let receipt = vault
                .memory(*owner, EdgeActorClass::Human)
                .tasks_create(
                    &TaskCreateSpec::new(Value::from("indexed"), None, None, Some(100))
                        .with_assignee(TaskAssignee::Peer { actor_ref: *owner }),
                )
                .expect("create");
            tasks[index].push(receipt.task_ref.expect("task"));
        }
        tasks[index].sort();
        assert_eq!(vault.tasks_by_owner(*owner, None, 10)?, tasks[index]);
        assert_eq!(vault.agent_inbox_tasks(*owner, None, 10)?, tasks[index]);
    }
    // Simulate a pre-index vault: the facts and edges stay intact.
    vault.with_write_txn(|txn| {
        let keys = vault
            .store
            .vault_meta
            .iter(txn)?
            .filter_map(|entry| match entry {
                Ok((key, _))
                    if key.starts_with(b"tasks.by_owner")
                        || key.starts_with(b"tasks.owner_fact") =>
                {
                    Some(Ok(key.to_vec()))
                }
                Err(e) => Some(Err(e)),
                _ => None,
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for key in keys {
            vault.store.vault_meta.delete(txn, &key)?;
        }
        Ok(())
    })?;
    vault.backfill_tasks_by_owner()?;
    for (owner, expected) in owners.iter().zip(&tasks) {
        assert_eq!(vault.tasks_by_owner(*owner, None, 10)?, *expected);
    }
    use crate::saved_query::*;
    let filter =
        parse_filter_ast(&serde_json::json!({"op": "task_owner", "owner": owners[0].to_hex()}))?;
    let definition = SavedQueryDefinition {
        schema_version: SAVED_QUERY_SCHEMA_VERSION,
        owner_actor: owners[0],
        scope: QueryScope::default(),
        definition_version: 1,
        filter,
        matcher: MatcherSpec::Hard {
            expression: FilterAst::All { terms: vec![] },
        },
        eval: EvalPolicy {
            mode: EvalMode::Manual,
            max_entities_per_wake: 10,
            max_judges_per_wake: 0,
        },
        lifecycle: SavedQueryLifecycle::Active,
    };
    let grants = QueryScope::default();
    let evaluator = SavedQueryEvaluator {
        vault: &vault,
        owner_grants: &grants,
        judge: None,
    };
    for (index, rows) in tasks.iter().enumerate() {
        for task in rows {
            let request = EvaluationRequest {
                query_ref: EntityId::now(),
                campaign_ref: EntityId::now(),
                entity_ref: *task,
                definition: &definition,
                cause: MembershipCause::DataChange,
                valid_at: 100,
                detected_at: 100,
            };
            let future = evaluator.evaluate_entity(&request);
            let std::task::Poll::Ready(result) = std::pin::pin!(future)
                .as_mut()
                .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
            else {
                panic!("hard matcher must not suspend");
            };
            let result = result?;
            assert_eq!(result.decision.verdict == MatchVerdict::Match, index == 0);
        }
    }
    assert!(
        vault
            .tasks_by_owner(owners[0], Some(tasks[0][0]), 10)?
            .is_empty()
    );
    vault.delete_entity(&tasks[0][0])?;
    assert!(vault.tasks_by_owner(owners[0], None, 10)?.is_empty());
    Ok(())
}
