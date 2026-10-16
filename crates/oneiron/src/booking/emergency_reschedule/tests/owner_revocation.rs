use super::*;

#[test]
fn revoked_owner_cannot_persist_plans_or_replay_a_pending_pick_at_outbound_gate() {
    // `executable` roots the vault under the test host and binds the owner.
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    let mut sink = spy(&vault, &plan);
    let item = execute(&vault, &plan, &mut sink, NOW).unwrap();
    sink.fail_channel = Some("calendar");
    assert!(
        counterparty_pick(
            &vault,
            &item.actions[1],
            &calendars(),
            &consumer(&vault, NOW + 1),
            &mut sink
        )
        .is_err()
    );
    let pending = checkpoint(&vault, &plan).unwrap();
    vault
        .revoke_host_actor_for_test(&crate::test_util::test_host_issuer())
        .unwrap();
    let before = (meta(&vault), entities(&vault));
    assert!(
        plan_item(
            &vault,
            &plan.request,
            plan.booking.clone(),
            &calendars(),
            NOW
        )
        .is_err()
    );
    assert_eq!((meta(&vault), entities(&vault)), before);
    let count = sink.calls.len();
    let error = super::super::execution::dispatch_item_effect(
        &vault,
        &pending,
        super::super::execution::EmergencyEffect::Pick,
        &mut sink,
        NOW + 2,
    )
    .unwrap_err();
    assert_eq!(
        crate::memory::booking_error(error).code,
        crate::memory::MEMORY_CODE_FORBIDDEN
    );
    assert_eq!(sink.calls.len(), count);
    assert!(
        vault.get_entity_type(&id(OWNER)).unwrap().is_some(),
        "revocation, not deletion"
    );
}
