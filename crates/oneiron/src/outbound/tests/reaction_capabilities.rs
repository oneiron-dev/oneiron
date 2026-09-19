//! Reaction discovery must distinguish provider support from message support.
use super::*;

#[test]
fn reaction_capabilities_match_provider_doors() {
    let (_dir, vault) = temp_vault();
    for connector in ["line", "imessage_mfb", "email", "linkedin"] {
        let manifest = outbound_capability_manifest(connector).unwrap();
        assert_eq!(
            manifest.reaction_vocabulary,
            OutboundReactionVocabulary::Unsupported
        );
        let error = outbound_verb_contract(connector, "react").unwrap_err();
        assert!(error.connector_known());
        assert_eq!(error.verb(), Some("react"));
        assert!(!error.recovery_suggestions().is_empty());
        let intent = OutboundIntent::from_trigger(
            OutboundIntentDraft::new("reaction-test", "react", connector, "message:target"),
            OutboundIntentTrigger::agent_immediate("session:reaction"),
        );
        let request = OutboundDispatchRequest::new(
            "outbound:unsupported-reaction",
            "intent:unsupported-reaction",
            intent,
            OutboundDispatchActor::agent(entity(0xCD)),
            OutboundDispatchGate::allow_when_policy_grants(),
            10,
            OutboundDeliveryWindowDecision::DeliverNow,
        );
        let mut executor = RecordingExecutor::default();
        let OutboundDispatchError::UnsupportedCapability(error) = vault
            .dispatch_outbound_intent(request, &mut executor)
            .expect_err("unsupported tapback")
        else {
            panic!("expected typed capability refusal")
        };
        assert_eq!(error.connector(), connector);
        assert_eq!(error.verb(), Some("react"));
        assert!(executor.calls.is_empty());
    }
    let bridge = outbound_capability_manifest("imessage_bridge").unwrap();
    assert_eq!(
        bridge.reaction_vocabulary,
        OutboundReactionVocabulary::Tapback {
            glyphs: &["❤️", "👍", "👎", "😂", "‼️", "❓"],
        }
    );
    assert_eq!(
        outbound_capability_manifest("in_app")
            .unwrap()
            .reaction_vocabulary,
        OutboundReactionVocabulary::Unicode { max_scalars: 64 }
    );
    for connector in ["imessage_bridge", "in_app", "telegram", "slack", "discord"] {
        assert_eq!(
            outbound_verb_contract(connector, "react")
                .unwrap()
                .delivery_semantics
                .kind,
            OutboundDeliverySemanticsKind::ReactionTarget
        );
    }
}
