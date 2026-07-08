use super::*;
use crate::genui::GrantMintIntentScope;

fn intent(scope: GrantMintIntentScope) -> GrantMintIntent {
    GrantMintIntent {
        principal_ref: "owner".to_owned(),
        origin_component_id: "ask-1".to_owned(),
        origin_action_id: "escalate_always_this_verb_class".to_owned(),
        origin_receipt_ref: Some("gate:ask".to_owned()),
        scope,
    }
}

#[test]
fn standing_outbound_grant_codec_round_trips_active_grant() -> Result<()> {
    let grant = StandingOutboundGrant::from_grant_mint_intent(
        &intent(GrantMintIntentScope::VerbClass {
            verb_class: "send".to_owned(),
        }),
        10,
        vec![0xA5; 32],
        [0xB6; 32],
    )?;

    let encoded = encode_standing_outbound_grant_body(&grant)?;
    validate_standing_outbound_grant_body_bytes(&encoded)?;
    let decoded = decode_standing_outbound_grant_body(&encoded)?;

    assert_eq!(decoded, grant);
    assert_eq!(decoded.scope.dial_label(), "always_this_verb_class");
    assert!(decoded.revoked_at.is_none());
    assert!(decoded.last_used_at.is_none());
    Ok(())
}

#[test]
fn standing_outbound_grant_revoke_and_touch_validate_lifecycle() -> Result<()> {
    let grant = StandingOutboundGrant::from_grant_mint_intent(
        &intent(GrantMintIntentScope::Channel {
            channel: "line".to_owned(),
        }),
        10,
        vec![0xA5],
        [0xB6; 32],
    )?;

    let touched = grant.clone().touched(12)?;
    assert_eq!(touched.last_used_at, Some(12));
    let revoked = grant.revoked(20)?;
    assert_eq!(revoked.status, StandingOutboundGrantStatus::Revoked);
    assert_eq!(revoked.revoked_at, Some(20));
    assert!(!revoked.is_active_under_policy(&[0xB6; 32]));
    Ok(())
}

#[test]
fn standing_outbound_grant_scope_matching_is_narrow() {
    let contact = StandingOutboundGrantScope::Contact {
        contact_ref: "contact:yuki".to_owned(),
    };
    assert!(contact.matches_effect("send", "line", Some("contact:yuki"), None));
    assert!(!contact.matches_effect("send", "line", Some("ren"), None));
    assert!(!contact.matches_effect("send", "line", Some("slack:yuki"), None));

    let channel = StandingOutboundGrantScope::Channel {
        channel: "line".to_owned(),
    };
    assert!(channel.matches_effect("send", "line", None, None));
    assert!(!channel.matches_effect("provision", "line", None, None));
    assert!(!channel.matches_effect("send", "email", None, None));

    let brief = StandingOutboundGrantScope::BriefVerbClass {
        brief_ref: "brief:party".to_owned(),
        verb_class: "send".to_owned(),
    };
    assert!(brief.matches_effect("send", "line", None, Some("brief:party")));
    assert!(!brief.matches_effect("react", "line", None, Some("brief:party")));
    assert!(!brief.matches_effect("send", "line", None, Some("party")));
    assert!(!brief.matches_effect("send", "line", None, Some("brief:other")));
}

#[test]
fn standing_outbound_grant_rejects_non_standing_intent_scopes() {
    let just_once = StandingOutboundGrant::from_grant_mint_intent(
        &intent(GrantMintIntentScope::JustOnce {
            effect_ref: Some("effect:send-1".to_owned()),
        }),
        10,
        vec![0xA5],
        [0xB6; 32],
    )
    .expect_err("one-shot consent is not a standing grant scope");
    assert_eq!(just_once.kind(), crate::ErrorKind::InvalidOutboundGrantBody);

    let exact_bundle = StandingOutboundGrant::from_grant_mint_intent(
        &intent(GrantMintIntentScope::BundleExactSends {
            send_refs: vec!["send-1".to_owned()],
        }),
        10,
        vec![0xA5],
        [0xB6; 32],
    )
    .expect_err("exact send bundles are not standing grant scopes");
    assert_eq!(
        exact_bundle.kind(),
        crate::ErrorKind::InvalidOutboundGrantBody
    );
}

#[test]
fn standing_outbound_grant_decode_fails_closed_for_malformed_bodies() {
    let err = decode_standing_outbound_grant_body(b"not-msgpack")
        .expect_err("malformed body must fail closed");
    assert_eq!(err.kind(), crate::ErrorKind::InvalidOutboundGrantBody);
}

#[test]
fn standing_outbound_grant_schema_has_no_auto_expiry_field() {
    assert!(!OUTBOUND_GRANT_BODY_KEYS.contains(&"expires_at"));
    assert!(!OUTBOUND_GRANT_BODY_KEYS.contains(&"ttl"));
}
