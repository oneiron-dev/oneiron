use super::*;
use crate::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};
use crate::edge::EdgeActorClass;
use crate::{EntityId, TimeRange, Vault, VaultConfig};
use rmpv::Value;

#[test]
fn overlapping_declarations_serialize_queue_claims_but_disjoint_tasks_run() -> crate::Result<()> {
    for kind_scoped in [false, true] {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), VaultConfig::default())?;
        let holder = EntityId::now();
        vault.put_entity(
            &holder,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"holder",
        )?;
        let mut tasks = Vec::new();
        for _ in 0..3 {
            tasks.push(
                vault
                    .memory(holder, EdgeActorClass::Human)
                    .tasks_create(&TaskCreateSpec::new(
                        Value::from("lease work"),
                        None,
                        None,
                        Some(100),
                    ))
                    .expect("create")
                    .task_ref
                    .unwrap(),
            );
        }
        let symbols = ["repo/src::symbol".to_owned()].into();
        assert!(matches!(
            vault.declare_symbols(tasks[0], holder, symbols, 10, 100)?,
            SymbolLeaseOutcome::Granted(_)
        ));
        assert!(
            matches!(vault.declare_symbols(tasks[1], holder, ["repo/src::symbol".to_owned()].into(), 10, 100)?,
            SymbolLeaseOutcome::Waiting { blockers, .. } if blockers == vec![tasks[0]])
        );
        vault.declare_symbols(
            tasks[2],
            holder,
            ["repo/src::other".to_owned()].into(),
            10,
            100,
        )?;
        let queue = AttemptQueue::new(&vault);
        let claim = |now| {
            let input = ClaimAttempt {
                lease_owner: "symbol-worker".to_owned(),
                now,
            };
            if kind_scoped {
                queue.claim_kind(super::consts::TASK_REALIZE_ATTEMPT_KIND, input)
            } else {
                queue.claim(input)
            }
        };
        for task in [tasks[0], tasks[2]] {
            let ClaimOutcome::Claimed(record) = claim(100)? else {
                panic!("ready task");
            };
            assert_eq!(record.task_ref.as_deref(), Some(task.to_hex().as_str()));
        }
        assert!(matches!(claim(100)?, ClaimOutcome::Empty));
        assert!(vault.release_symbols(tasks[0], EntityId::now()).is_err());
        if kind_scoped {
            vault.release_symbols(tasks[0], holder)?;
        } else {
            assert!(vault.expire_symbol_leases(110)?.contains(&tasks[0]));
        }
        let ClaimOutcome::Claimed(record) = claim(110)? else {
            panic!("released waiter");
        };
        assert_eq!(record.task_ref.as_deref(), Some(tasks[1].to_hex().as_str()));
        assert_eq!(vault.renew_symbols(tasks[1], holder, 115)?.expires_at, 125);
    }
    Ok(())
}
