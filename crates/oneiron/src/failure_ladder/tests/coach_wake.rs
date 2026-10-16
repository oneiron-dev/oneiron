//! The default policy's Auto escalation wakes the Coach (owner ruling
//! 2026-10-16), not a reserved slot that enqueues nothing.
use super::*;

#[test]
fn default_policy_wakes_one_coach_stamped_heal_per_case() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let policy = auto_policy(agent_ref);
    let rows = transient_chain(&vault, agent_ref, &policy, 2)?;
    let outcome = FailureLadder::new(&vault)
        .handle_attempt_failure(failure_input(&rows[2], transient(), 60), policy)?;
    let case = healer_case(&outcome);

    let heals: Vec<_> = AttemptQueue::new(&vault)
        .list()?
        .into_iter()
        .filter(|row| row.kind == "coach.heal")
        .collect();
    assert_eq!(heals.len(), 1, "the transient limit wakes the Coach");
    let payload = crate::dreamer_runner::decode_dreamer_attempt_payload(&heals[0].payload)?;
    assert_eq!(payload.input.as_str(), Some(case.case_ref.as_str()));
    assert_eq!(payload.parent_attempt, Some(rows[2].id));
    let stamp = vault
        .dreamer_attempt_authority(heals[0].id)?
        .expect("the heal carries a stamp");
    let coach = crate::codebase::entity_id_from_hash_material(b"oneiron.coach.authority.v1", &[])?;
    assert_eq!(stamp.actor, coach);
    assert_ne!(stamp.actor, vault.dreamer_authority()?.entity_ref());
    Ok(())
}
