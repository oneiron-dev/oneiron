use super::*;
use crate::context_projection::ResolvedContextProjection;

#[test]
fn owner_dial_is_space_local_receipted_and_never_expands_room_or_grants_send() -> crate::Result<()> {
    let (_dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::DraftOnly);
    let identity = request.read_envelope.identity_ref;
    let room = ResolvedContextProjection { memory_sections: vec!["room:claim".to_owned()], ..Default::default() };
    let initial = vault.space_posting_plan(identity, "group:one", room.clone())?;
    assert_eq!(initial.preset, GroupPostingPreset::NamedParticipant);
    let receipt = vault.set_space_posting_preset(identity, "group:one", GroupPostingPreset::OwnerWithApproval, &owner, 10)?;
    assert_eq!(receipt, vault.set_space_posting_preset(identity, "group:one", GroupPostingPreset::OwnerWithApproval, &owner, 11)?);
    let planned = vault.space_posting_plan(identity, "group:one", room.clone())?;
    assert!(planned.policy_risk);
    assert_eq!(planned.room_context, room);
    assert_eq!(planned.preset.mode(), SpacePostingMode::PostAsOwner);
    let bound = planned.needs_owner_consent.expect("dial cannot mint permission");
    assert_eq!(vault.space_posting_plan(identity, "group:two", room.clone())?.preset, GroupPostingPreset::NamedParticipant);
    vault.create_standing_grant(&owner, bound.clone())?;
    assert!(vault.space_posting_plan(identity, "group:one", room.clone())?.needs_owner_consent.is_none());
    // A different preset needs its own exact bound; no silent rung promotion.
    vault.set_space_posting_preset(identity, "group:one", GroupPostingPreset::OwnerDrafts, &owner, 12)?;
    let draft = vault.space_posting_plan(identity, "group:one", room)?;
    assert_eq!(draft.preset.rung(), ChannelIdentityAutonomyRung::DraftOnly);
    assert!(draft.needs_owner_consent.is_some());
    let events = vault.store.gate_decisions(100)?;
    assert!(events.iter().any(|event| event.decision_id == receipt.decision_id && event.actor_ref.as_deref() == Some(owner.actor().to_hex().as_str())));
    Ok(())
}

#[test]
fn bot_only_platform_refuses_owner_presentation_and_keeps_named_default() -> crate::Result<()> {
    let (_dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::DraftOnly);
    let id = EntityId::now();
    let mut identity = vault.get_channel_identity(&request.read_envelope.identity_ref)?.unwrap();
    identity.channel = "telegram".to_owned();
    identity.address_or_handle = "@agent".to_owned();
    // Use the channel's native dedicated-handle shape.
    identity.shape = crate::channel_identity::ChannelIdentityShape::DedicatedHandle;
    vault.create_channel_identity(&id, &identity)?;
    assert!(vault.set_space_posting_preset(id, "group:one", GroupPostingPreset::OwnerWithApproval, &owner, 10).is_err());
    assert_eq!(vault.space_posting_plan(id, "group:one", Default::default())?.preset, GroupPostingPreset::NamedParticipant);
    assert!(crate::outbound::outbound_verb_contract("email", "send").unwrap().params["posting"]["policy_risk"].as_bool().unwrap());
    Ok(())

}
