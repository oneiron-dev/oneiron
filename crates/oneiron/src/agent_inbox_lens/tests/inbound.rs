use super::*;
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape,
};
use crate::surface_event::{
    InboundSurfaceEventInput, SurfaceCounterpartyStamp, SurfaceEventAdmission,
};
use crate::thread_passport::{ThreadPassportInput, canonical_message_id};

#[test]
fn unified_inbox_reads_identity_stamps_membership_drafts_and_updates() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = EntityId::now();
    let identity = EntityId::now();
    let other = EntityId::now();
    for (id, address) in [
        (identity, "resident@example.com"),
        (other, "other@example.com"),
    ] {
        let mut channel = ChannelIdentity::requested(
            "email",
            address,
            SelfHeldShape::DedicatedAddress,
            ChannelIdentityBinding::agent(actor),
            1,
        );
        channel.state = ChannelIdentityState::Active;
        channel.pending_fulfillment = None;
        vault.create_channel_identity(&id, &channel)?;
        let input = InboundSurfaceEventInput::new(
            format!("<{address}>"),
            "email",
            address,
            SurfaceCounterpartyStamp::unknown("sender@example.net"),
            10,
            true,
        )
        .with_payload_ref(format!("payload:{address}"));
        assert!(matches!(
            vault.enqueue_inbound_surface_event(input.clone(), 10)?,
            SurfaceEventAdmission::Accepted(_)
        ));
        assert!(matches!(
            vault.enqueue_inbound_surface_event(input, 11)?,
            SurfaceEventAdmission::Accepted(_)
        ));
    }
    let passport = vault.record_thread_passport(ThreadPassportInput::new(
        identity,
        actor,
        canonical_message_id("<resident@example.com>")?,
        10,
    ))?;
    vault.join_thread_party(
        &passport.canonical_thread_ref,
        "resident@example.com",
        true,
        10,
    )?;
    crate::comm::run_comm_projector(&vault)
        .map_err(|_| Error::InvariantViolation("fixture comm projection"))?;
    let before = vault.thread_passports(&passport.canonical_thread_ref)?;
    let items = vault.agent_inbox_lens(query(Some(identity), 10))?;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].kind, AgentInboxItemKind::Conversation);
    assert_eq!(
        items[0].thread_ref.as_deref(),
        Some(passport.canonical_thread_ref.as_str())
    );
    assert_eq!(
        items[0].payload_ref.as_deref(),
        Some("payload:resident@example.com")
    );
    assert_eq!(vault.agent_inbox_lens(query(Some(identity), 10))?, items);
    assert_eq!(
        vault.thread_passports(&passport.canonical_thread_ref)?,
        before
    );
    assert_eq!(vault.agent_inbox_lens(query(Some(other), 10))?.len(), 1);
    let mut draft = held(identity, "draft", 200, 20);
    draft
        .fields
        .insert("verb".to_owned(), "mail.draft".to_owned());
    persist_send_receipt(
        &vault,
        EntityId::now(),
        draft,
        SendReceiptOutcome::Failed,
        false,
        None,
    )?;
    let page = vault.agent_inbox_lens(query(Some(identity), 1))?;
    assert_eq!(page[0].kind, AgentInboxItemKind::ApprovalRequired);
    let rest = vault.agent_inbox_lens(AgentInboxLensQuery {
        identity_ref: Some(identity),
        limit: 10,
        before: Some((page[0].impact, page[0].occurred_at, page[0].item_id.clone())),
    })?;
    assert_eq!(rest, items);
    Ok(())
}
