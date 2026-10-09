use super::*;

fn usage(input: u64, output: u64) -> LlmUsage {
    let mut usage = LlmUsage::zero();
    usage.input.total = input;
    usage.output.total = output;
    usage
}

#[test]
fn same_textual_ids_from_independent_guards_are_not_authority() {
    let table = BudgetPolicyTable::from_rows(vec![actor_row(0x64, Some(6), Some(100))]);
    for policy_aware in [false, true] {
        let make_guard = || {
            if policy_aware {
                BudgetGuard::with_policy_table(
                    "same-attempt",
                    100,
                    10,
                    BudgetExhaustionPolicy::Suspend,
                    policy_test_actor(0x64),
                    &table,
                )
            } else {
                BudgetGuard::with_reserve_units(
                    "same-attempt",
                    100,
                    10,
                    BudgetExhaustionPolicy::Suspend,
                )
            }
        };
        let guard = make_guard();
        let foreign = make_guard();
        let local = guard.admit().unwrap().lease;
        let other = foreign.admit().unwrap().lease;
        assert_eq!(local.id(), other.id());
        assert_ne!(local, other);
        let leases = std::collections::HashSet::from([local.clone(), local.clone(), other.clone()]);
        assert_eq!(leases.len(), 2);
        for lease in [&other, &BudgetLease::for_test(local.id())] {
            assert!(matches!(
                guard.settle_per_call(lease, &usage(90, 9)),
                Err(BudgetDenied::LeaseInvalid)
            ));
            assert_eq!(guard.read().used_units, 0);
            assert_eq!(guard.read().reserved_units, 10);
            assert!(matches!(
                guard.settle_absolute(lease, 99),
                Err(BudgetDenied::LeaseInvalid)
            ));
            assert_eq!(guard.read().used_units, 0);
            assert_eq!(guard.read().reserved_units, 10);
            assert!(matches!(
                guard.settle_terminal(lease, &usage(90, 9)),
                Err(BudgetDenied::LeaseInvalid)
            ));
            assert_eq!(guard.read().used_units, 0);
            assert_eq!(guard.read().reserved_units, 10);
            assert!(matches!(
                guard.abort(lease),
                Err(BudgetDenied::LeaseInvalid)
            ));
            assert_eq!(guard.read().used_units, 0);
            assert_eq!(guard.read().reserved_units, 10);
        }
        assert_eq!(foreign.read().used_units, 0);
        assert_eq!(foreign.read().reserved_units, 10);
        guard.settle_per_call(&local, &usage(3, 4)).unwrap();
        assert_eq!(guard.read().used_units, 7);
        assert_eq!(guard.read().reserved_units, 0);
        // A settled record must not turn foreign settlement into a duplicate no-op.
        assert!(matches!(
            guard.settle_per_call(&other, &usage(3, 4)),
            Err(BudgetDenied::LeaseInvalid)
        ));
        assert!(matches!(
            guard.settle_absolute(&other, 7),
            Err(BudgetDenied::LeaseInvalid)
        ));
        assert_eq!(guard.read().used_units, 7);
        assert_eq!(guard.read().reserved_units, 0);
        foreign.abort(&other).unwrap();
        assert_eq!(foreign.read().used_units, 0);
        assert_eq!(foreign.read().reserved_units, 0);
    }
}
