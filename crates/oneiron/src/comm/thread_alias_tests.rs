use super::*;
use crate::channel_identity::{ChannelIdentity, ChannelIdentityBinding, SelfHeldShape};
use crate::thread_passport::{ThreadPassportInput, canonical_message_id};

fn seed_threads(vault: &Vault) -> (EntityId, String, String) {
    let identity = entity(0x61);
    vault
        .create_channel_identity(
            &identity,
            &ChannelIdentity::requested(
                "email",
                "agent@x",
                SelfHeldShape::DedicatedAddress,
                ChannelIdentityBinding::agent(entity(0x51)),
                1,
            ),
        )
        .unwrap();
    let record = |message| {
        vault
            .record_thread_passport(ThreadPassportInput::new(
                identity,
                entity(0xA9),
                canonical_message_id(message).unwrap(),
                1,
            ))
            .unwrap()
    };
    let a = record("a@x");
    let b = record("b@x");
    (identity, a.canonical_thread_ref, b.canonical_thread_ref)
}

fn bridge(vault: &Vault, identity: EntityId) -> String {
    vault
        .record_thread_passport(
            ThreadPassportInput::new(
                identity,
                entity(0xA9),
                canonical_message_id("bridge@x").unwrap(),
                20,
            )
            .with_references(vec![
                canonical_message_id("a@x").unwrap(),
                canonical_message_id("b@x").unwrap(),
            ]),
        )
        .unwrap()
        .canonical_thread_ref
}

#[test]
fn alias_between_pass_snapshot_and_peer_projection_keeps_latest_leave() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    let (identity, a, b) = seed_threads(&vault);
    record_comm_thread_event(&vault, &a, "party@x", true, 10)?;
    record_comm_thread_event(&vault, &b, "party@x", false, 30)?;
    let join = thread_event_id(&vault, &a, true, 10)?;
    let leave = thread_event_id(&vault, &b, false, 30)?;
    let stale_pass = snapshot_pass_index(&vault)?;
    let canonical = bridge(&vault, identity);
    let peer = snapshot_pass_index(&vault)?;
    project_event(&vault, leave, &peer)?;
    // The stale pass still has TWO raw slot keys and its cursor has not seen
    // the leave. It must re-read that peer boundary under today's alias graph.
    let scans = comm_record_family_scans();
    project_event(&vault, join, &stale_pass)?;
    assert_eq!(
        comm_record_family_scans(),
        scans,
        "reuse the pass index, not a family rescan"
    );
    assert_eq!(
        count_active_thread_member_claims(&vault, &canonical, "party@x")?,
        0
    );
    Ok(())
}

#[test]
fn comm_event_transaction_resolves_alias_and_rolls_back_party_failure() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    let (identity, a, b) = seed_threads(&vault);
    let canonical = bridge(&vault, identity);
    let losing = if canonical == a { b } else { a };
    let before = snapshot_pass_index(&vault)?.pending_event_ids();
    assert!(vault.join_thread_party(&losing, "", true, 30).is_err());
    assert_eq!(snapshot_pass_index(&vault)?.pending_event_ids(), before);
    // Both the public comm door and the passport wrapper use the same write
    // transaction for canonical lookup, party creation and event insertion.
    record_comm_thread_event(&vault, &losing, "direct@x", true, 31)?;
    vault.join_thread_party(&losing, "wrapped@x", true, 32)?;
    for at in [31, 32] {
        thread_event_id(&vault, &canonical, true, at)?;
    }
    Ok(())
}

#[test]
fn pending_event_keeps_its_source_key_in_the_derived_claim_after_bridge() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    let (identity, a, b) = seed_threads(&vault);
    let losing = a.max(b);
    record_comm_thread_event(&vault, &losing, "party@x", true, 10)?;
    let event_id = thread_event_id(&vault, &losing, true, 10)?;
    let party_ref = resolve_party(&vault, "party@x")?.ok_or(CommError::InvalidRecord)?;
    let source_value = CommClaimValue::ThreadMember {
        party_ref,
        thread_ref: losing.clone(),
        occurred_at: 10,
    };
    let expected_id = projected_comm_claim_id(event_id, &source_value)?;
    let canonical = bridge(&vault, identity);
    assert_ne!(canonical, losing);
    run_comm_projector(&vault)?;
    assert_eq!(
        vault.get_claim(&expected_id)?,
        Some(source_value.claim_body())
    );
    assert_eq!(
        count_active_thread_member_claims(&vault, &canonical, "party@x")?,
        1
    );
    assert_eq!(
        count_active_thread_member_claims(&vault, &losing, "party@x")?,
        1
    );
    Ok(())
}

#[test]
fn alias_aware_comm_door_keeps_opaque_non_email_thread_keys() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    let thread = "provider thread 1";
    record_comm_thread_event(&vault, thread, "party@x", true, 10)?;
    run_comm_projector(&vault)?;
    assert_eq!(
        count_active_thread_member_claims(&vault, thread, "party@x")?,
        1
    );
    Ok(())
}
