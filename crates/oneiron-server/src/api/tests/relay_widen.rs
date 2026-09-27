//! Route-level separation: proposal is inert, and only the human holder's host-bound slip lands it.
use super::*;
use ed25519_dalek::Signer;
use oneiron::{
    authority::HostSlipIssuer,
    consent::{ActionClass, ActionEnvelope, ActorBound, GrantBound},
    registry::ENTITY_TYPE_PERSON,
};

#[tokio::test]
async fn remote_proposal_cannot_land_widen_but_host_bound_holder_can_once() {
    let (_dir, server) = auth_test_server();
    let vault = server.vault();
    let owner = oneiron::EntityId::now();
    let agent = oneiron::EntityId::now();
    for id in [owner, agent] {
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"person",
            )
            .unwrap();
    }
    let agent_recipe = format!(
        "scope=propose_action_widen;principal_ref={};actor_class=agent",
        agent.to_hex()
    );
    let (agent_slip, agent_key) = slip_credentials::credential(&server, &agent_recipe);
    let challenge = b"widen-proposal";
    let signature = agent_key.sign(&agent_slip.binding_transcript(challenge).unwrap());
    let issuer = HostSlipIssuer::from_secret(b"secret").unwrap();
    let proof = vault
        .verify_capability_slip(
            &issuer.public_key(),
            &agent_slip,
            challenge,
            &signature.to_bytes(),
        )
        .unwrap();
    let bound = GrantBound::action(
        ActorBound::new(agent.to_hex()).unwrap(),
        ActionClass::new("claim.put").unwrap(),
        ActionEnvelope::new(["world:home".to_owned()]).unwrap(),
    )
    .unwrap();
    let proposal = vault
        .propose_action_widen(
            &proof,
            bound.clone(),
            &owner.to_hex(),
            vault.now_recorded_at() + 300,
        )
        .unwrap();
    assert!(
        vault
            .consent_grant(&bound.digest().to_hex())
            .unwrap()
            .is_none()
    );
    let delta = proposal
        .canonical_delta
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let payload = json!({"proposal_ref":proposal.proposal_ref,"expected_delta":delta});
    let path = "/v1/core/consent/widen/accept";
    // A logged propose-only principal has identity, but no holder authority.
    let (status, _) = route_json(
        server.clone(),
        core_request_with_authz("POST", path, test_bearer(&agent_recipe), Some(&payload)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // A bare host root is not a human holder action either.
    let (status, _) = route_json(
        server.clone(),
        core_request_with_authz("POST", path, owner_bearer(), Some(&payload)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Both local stdio/keychain and remote HTTP carry the same logged,
    // holder-bound instrument. The transport gives no extra authority.
    let holder_recipe = format!(
        "scope=core:auth;principal_ref={};actor_class=human",
        owner.to_hex()
    );
    let mut first =
        core_request_with_authz("POST", path, test_bearer(&holder_recipe), Some(&payload));
    first
        .headers_mut()
        .insert("idempotency-key", "widen-once".parse().unwrap());
    let (status, body) = route_json(server.clone(), first).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["grant_ref"], bound.digest().to_hex());
    assert_eq!(body["decision_id"].as_str().unwrap().len(), 32);
    assert!(
        vault
            .consent_grant(&bound.digest().to_hex())
            .unwrap()
            .unwrap()
            .is_active()
    );
    let mut replay =
        core_request_with_authz("POST", path, test_bearer(&holder_recipe), Some(&payload));
    replay
        .headers_mut()
        .insert("idempotency-key", "widen-once".parse().unwrap());
    let (status, _) = route_json(server.clone(), replay).await;
    assert_eq!(status, StatusCode::CONFLICT);
    // An unrelated human credential cannot replay a different holder's proposal.
    let other = oneiron::EntityId::now();
    vault
        .put_entity(
            &other,
            ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"other",
        )
        .unwrap();
    let other_recipe = format!(
        "scope=core:auth;principal_ref={};actor_class=human",
        other.to_hex()
    );
    let (status, _) = route_json(
        server,
        core_request_with_authz("POST", path, test_bearer(&other_recipe), Some(&payload)),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}
