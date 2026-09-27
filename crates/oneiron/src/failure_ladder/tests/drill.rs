//! Retrospective owner drill-in binds the caller, group, trace and receipt.
use super::*;
use crate::attempt_queue::{ManifestEntry, ManifestKind};
use crate::error::{Error, GateError};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::store::GateDecisionId;

fn person(vault: &Vault, seed: u8) -> Result<crate::consent::AuthenticatedOwner> {
    let id = test_id(seed);
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"human",
    )?;
    vault.authenticate_owner(id, &id.to_hex(), true, GateDecisionId::now())
}

#[test]
fn owner_drills_from_group_to_own_traces_and_receipts_without_consent_while_non_owner_is_denied()
-> Result<()> {
    let (_dir, vault) = open_vault();
    let (_other_dir, other) = open_vault();
    let owner_id = vault.ensure_embedded_owner_actor().expect("seed owner");
    let other_owner_id = other.ensure_embedded_owner_actor().expect("seed owner");
    assert_eq!(owner_id, other_owner_id);
    let owner =
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;
    let non_owner = person(&vault, 0xb4)?;
    // A proof from another vault, even for the same owner actor id, cannot
    // cross the vault boundary.
    let foreign_owner = other.authenticate_owner(
        other_owner_id,
        &other_owner_id.to_hex(),
        true,
        GateDecisionId::now(),
    )?;
    let agent = put_scope_agent(&vault, 0xb5, "custom.trace")?;
    let leased = leased_dispatch(&vault, agent, 10)?;
    AttemptQueue::new(&vault).append_manifest_entry(
        leased.id,
        ManifestEntry::new(ManifestKind::Skill, "skill.trace", "1", 11),
    )?;
    let FailureLadderOutcome::Human(surface) = FailureLadder::new(&vault).handle_attempt_failure(
        failure_input(&leased, indeterminate(), 20),
        policy_with(agent, 3, FailureEscalationMode::Human),
    )?
    else {
        panic!("expected surfaced failure");
    };
    assert_eq!(surface.failed_attempt.id, leased.id);
    let class = FailureSignalClass::TaskFailure;
    vault.record_custom_agent_failure(leased.id, class)?;
    let group = vault.custom_agent_failure_groups()?.remove(0);
    assert_eq!(group.class, class);
    assert_eq!(group.member_refs, vec![leased.id]);
    let drill = vault.drill_custom_agent_failure(&owner, group.class, group.member_refs[0])?;
    assert_eq!(drill.trace.id, leased.id);
    assert_eq!(drill.trace.state, AttemptState::Failed);
    assert_eq!(drill.trace.run_id.as_deref(), Some(RUN_ID));
    assert_eq!(
        drill.receipt_refs,
        vec![crate::receipt::attempt_pack_receipt_id(&leased.id)]
    );
    assert!(
        crate::receipt::attempt_pack_receipt(&vault, &drill.receipt_refs[0])?.is_some(),
        "drill must not invent a dangling receipt ref"
    );
    assert!(
        vault
            .drill_custom_agent_failure(&owner, FailureSignalClass::MemoryMiss, leased.id,)
            .is_err(),
        "a caller cannot use a class from a different group"
    );
    assert!(
        other
            .drill_custom_agent_failure(&foreign_owner, class, leased.id)
            .is_err(),
        "the attempt lives only in the first vault"
    );
    assert!(matches!(
        vault.drill_custom_agent_failure(&foreign_owner, class, leased.id),
        Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_)))
    ));
    // An authenticated human in this vault is not automatically its owner.
    assert!(matches!(
        vault.drill_custom_agent_failure(&non_owner, class, leased.id),
        Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_)))
    ));
    Ok(())
}
