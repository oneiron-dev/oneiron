use super::*;
use crate::agent_inbox_lens::{AgentInboxItemKind, AgentInboxLensQuery};
use crate::thread_passport::canonical_message_id;

#[test]
fn cc_intake_is_atomic_idempotent_and_hands_the_thread_to_propose_confirm() -> Result<()> {
    struct Coordinator;
    impl SurfaceEventDispatcher for Coordinator {
        fn dispatch(
            &self,
            request: SurfaceEventDispatchRequest<'_>,
        ) -> SurfaceEventDispatchDisposition {
            assert_eq!(request.route, SurfaceEventDispatchRoute::ProposeConfirm);
            assert!(
                request
                    .thread_ref
                    .is_some_and(|thread| thread.starts_with("mail:v1:"))
            );
            assert!(request.event.claims_not_instructions);
            SurfaceEventDispatchDisposition::Complete
        }
    }
    let (_dir, vault) = test_vault();
    let identity_ref = entity(0x61);
    let agent = entity(0x51);
    vault.create_channel_identity(
        &identity_ref,
        &identity("cc@example.com", agent, ChannelIdentityState::Active),
    )?;
    let input = input(
        "cc@example.com",
        SurfaceCounterpartyStamp::unknown("guest@example.net"),
    );
    let landed =
        vault.enqueue_cc_agent_email(input.clone(), "<message@example.net>", &[], None, 20)?;
    let thread = landed.thread.unwrap().canonical_thread_ref;
    let SurfaceEventAdmission::Accepted(ack) = landed.admission else {
        panic!("admitted")
    };
    assert!(!ack.replayed);
    let repeated =
        vault.enqueue_cc_agent_email(input.clone(), "<message@example.net>", &[], None, 21)?;
    let SurfaceEventAdmission::Accepted(replay) = repeated.admission else {
        panic!("replay")
    };
    assert!(replay.replayed);
    assert_eq!(replay.attempt_ref, ack.attempt_ref);
    assert!(
        vault
            .enqueue_cc_agent_email(input, "<different@example.net>", &[], None, 22)
            .is_err()
    );
    assert!(
        vault
            .thread_passport(
                &identity_ref,
                &canonical_message_id("<different@example.net>")?
            )?
            .is_none()
    );
    let items = vault.agent_inbox_lens(AgentInboxLensQuery {
        identity_ref: Some(identity_ref),
        limit: 10,
        before: None,
    })?;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].kind, AgentInboxItemKind::Conversation);
    assert_eq!(items[0].thread_ref.as_deref(), Some(thread.as_str()));
    assert_eq!(items[0].actor_ref, agent);
    assert!(matches!(
        vault.dispatch_next_surface_event("coordinator", 23, &Coordinator)?,
        SurfaceEventWorkerOutcome::Completed(_)
    ));
    assert!(matches!(
        vault.dispatch_next_surface_event("coordinator", 24, &Coordinator)?,
        SurfaceEventWorkerOutcome::Empty
    ));
    Ok(())
}
