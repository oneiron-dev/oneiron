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
    // A different human can hold core:auth, but cannot land this owner's
    // exact proposal or mint its grant.
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
        server.clone(),
        core_request_with_authz("POST", path, test_bearer(&other_recipe), Some(&payload)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        vault
            .consent_grant(&bound.digest().to_hex())
            .unwrap()
            .is_none()
    );
    // HTTP authority follows the logged holder-bound instrument, not the
    // caller's ability to reach the server over a network.
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

    // The encoder itself refuses out-of-model requests; the route accepts
    // every delta that this existing structural model can produce.
    assert!(
        ActionEnvelope::new(
            (0..=oneiron::consent::MAX_ENVELOPE_SELECTORS).map(|i| format!("world:{i:03}"))
        )
        .is_err()
    );
    assert!(ActionEnvelope::new(["x".repeat(oneiron::consent::MAX_CONSENT_REF_LEN + 1)]).is_err());
    // Every structurally valid frozen delta can land, not just deltas below
    // the old 4 KiB decoded route limit. Exercise the selector ceiling too.
    for count in [9, oneiron::consent::MAX_ENVELOPE_SELECTORS] {
        let selectors = (0..count).map(|index| format!("world:{index:03}:{}", "x".repeat(502)));
        let large = GrantBound::action(
            ActorBound::new(agent.to_hex()).unwrap(),
            ActionClass::new("claim.put").unwrap(),
            ActionEnvelope::new(selectors).unwrap(),
        )
        .unwrap();
        let proposal = vault
            .propose_action_widen(
                &proof,
                large.clone(),
                &owner.to_hex(),
                vault.now_recorded_at() + 300,
            )
            .unwrap();
        assert!(proposal.canonical_delta.len() > 4096);
        let delta = proposal
            .canonical_delta
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let body = json!({"proposal_ref":proposal.proposal_ref,"expected_delta":delta});
        let (status, response) = route_json(
            server.clone(),
            core_request_with_authz("POST", path, test_bearer(&holder_recipe), Some(&body)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["grant_ref"], large.digest().to_hex());
        assert!(
            vault
                .consent_grant(&large.digest().to_hex())
                .unwrap()
                .unwrap()
                .is_active()
        );
    }
}

#[tokio::test]
async fn managed_host_account_holder_lands_once_but_host_root_and_other_account_cannot() {
    use crate::managed::{ManagedState, WakeLedger, build_managed_app};
    use axum::body::{Body, to_bytes};
    use oneiron_vault_contract::{
        DEK_LEN, ManagedWidenAction, TOKEN_LEN, TokenHex, read_credentials, write_credentials,
    };
    use tower::ServiceExt;

    let (dir, mut server) = auth_test_server();
    let issuer = HostSlipIssuer::from_secret(b"secret").unwrap();
    server.vault().ensure_host_root_slip(&issuer).unwrap();
    Arc::get_mut(&mut server).unwrap().managed_issuer = Some(issuer);
    let vault = server.vault();
    let owner = oneiron::EntityId::now();
    let agent = oneiron::EntityId::now();
    let other = oneiron::EntityId::now();
    for actor in [owner, agent, other] {
        vault
            .put_entity(
                &actor,
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
    let (slip, key) = slip_credentials::credential(&server, &agent_recipe);
    let proof = vault
        .verify_capability_slip(
            &server.managed_issuer.as_ref().unwrap().public_key(),
            &slip,
            b"managed-widen",
            &key.sign(&slip.binding_transcript(b"managed-widen").unwrap())
                .to_bytes(),
        )
        .unwrap();
    let bound = GrantBound::action(
        ActorBound::new(agent.to_hex()).unwrap(),
        ActionClass::new("claim.put").unwrap(),
        ActionEnvelope::new(["world:managed".to_owned()]).unwrap(),
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
    let delta = proposal
        .canonical_delta
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let payload = json!({"proposal_ref":proposal.proposal_ref,"expected_delta":delta}).to_string();
    let token = [0x62; TOKEN_LEN];
    let mut frame = Vec::new();
    write_credentials(&mut frame, &[0x71; DEK_LEN], &token).unwrap();
    let credentials = read_credentials(&frame[..]).unwrap();
    let ledger = WakeLedger::load(
        vault.clone(),
        "managed-test".into(),
        dir.path().join("supervisor.sock"),
        &credentials,
    )
    .unwrap();
    let state = Arc::new(ManagedState::new(
        "managed-test".into(),
        server.clone(),
        ledger,
    ));
    let app = build_managed_app(server.clone(), state);
    let token = TokenHex::from_token(&token);
    let send = |action: Option<ManagedWidenAction>| {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/core/consent/widen/accept")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, "Bearer spoofed-human");
        if let Some(action) = action {
            builder = builder.header(
                "x-oneiron-managed-widen-action",
                serde_json::to_string(&action).unwrap(),
            );
        }
        builder.body(Body::from(payload.clone())).unwrap()
    };
    let unsigned = app.clone().oneshot(send(None)).await.unwrap();
    assert_eq!(unsigned.status(), StatusCode::FORBIDDEN);
    let other_action = ManagedWidenAction::sign_after_account_auth(
        &token,
        "managed-test",
        &other.to_hex(),
        payload.as_bytes(),
    );
    assert_eq!(
        app.clone()
            .oneshot(send(Some(other_action)))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let mut tampered = ManagedWidenAction::sign_after_account_auth(
        &token,
        "managed-test",
        &owner.to_hex(),
        payload.as_bytes(),
    );
    tampered.mac.replace_range(..1, "0");
    if tampered.mac.starts_with('0') {
        tampered.mac.replace_range(..1, "1");
    }
    assert_eq!(
        app.clone()
            .oneshot(send(Some(tampered)))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(
        vault
            .consent_grant(&bound.digest().to_hex())
            .unwrap()
            .is_none()
    );
    let owner_action = ManagedWidenAction::sign_after_account_auth(
        &token,
        "managed-test",
        &owner.to_hex(),
        payload.as_bytes(),
    );
    let response = app
        .clone()
        .oneshot(send(Some(owner_action.clone())))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body["grant_ref"], bound.digest().to_hex());
    assert_eq!(body["decision_id"].as_str().unwrap().len(), 32);
    assert!(
        vault
            .consent_grant(&bound.digest().to_hex())
            .unwrap()
            .unwrap()
            .is_active()
    );
    assert_eq!(
        app.oneshot(send(Some(owner_action)))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
}

/// A local stdio leg contributes a JSON line, not bearer identity. This test
/// source represents a Keychain-held logged token and holder signing key;
/// both reach the production holder verifier through the existing binder.
async fn local_stdio_json(
    server: Arc<SyncServer>,
    keychain: &crate::test_credentials::TestKeychainCredentialSource,
    frame: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    use std::io::BufRead;
    let input = format!("{frame}\n");
    let mut line = String::new();
    std::io::BufReader::new(input.as_bytes())
        .read_line(&mut line)
        .unwrap();
    let frame: serde_json::Value = serde_json::from_str(&line).unwrap();
    let request = core_request_with_authz(
        frame["method"].as_str().unwrap(),
        frame["path"].as_str().unwrap(),
        "Bearer untrusted-stdio-identity".into(),
        frame.get("body"),
    );
    let request = keychain.bind(&server, request);
    route_json(server, request).await
}

#[tokio::test]
async fn local_stdio_keychain_source_obeys_remote_read_propose_and_holder_widen_rules() {
    let (_dir, server) = auth_test_server();
    let vault = server.vault();
    let owner = oneiron::EntityId::now();
    let agent = oneiron::EntityId::now();
    for actor in [owner, agent] {
        vault
            .put_entity(
                &actor,
                ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"person",
            )
            .unwrap();
    }
    let agent_recipe = format!(
        "scope=core:read,core:propose,propose_action_widen;principal_ref={};actor_class=agent",
        agent.to_hex(),
    );
    let agent_keychain =
        crate::test_credentials::TestKeychainCredentialSource::from_recipe(&server, &agent_recipe);
    // The owner grants this principal its subject read. As with OAuth, login
    // without this grant is not read/proposal authority.
    vault
        .install_foreign_grant_for_test(&agent.to_hex())
        .unwrap();
    let (status, _) = local_stdio_json(
        server.clone(),
        &agent_keychain,
        json!({"method":"GET","path":"/v1/core/conversations"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, proposed) = local_stdio_json(
        server.clone(),
        &agent_keychain,
        json!({"method":"POST","path":"/v1/core/propose","body":{
            "subject":agent.to_hex(), "predicate":"profile.name", "value":"local"
        }}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{proposed}");
    let claim = vault
        .get_claim(&oneiron::EntityId::from_hex(proposed["id"].as_str().unwrap()).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(claim.approval, oneiron::ClaimApprovalStatus::Proposed);

    let bound = GrantBound::action(
        ActorBound::new(agent.to_hex()).unwrap(),
        ActionClass::new("claim.put").unwrap(),
        ActionEnvelope::new(["world:home".to_owned()]).unwrap(),
    )
    .unwrap();
    let proposal = vault
        .propose_action_widen(
            &agent_keychain.verified_for_proposal(&server),
            bound.clone(),
            &owner.to_hex(),
            vault.now_recorded_at() + 300,
        )
        .unwrap();
    let delta = proposal
        .canonical_delta
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let frame = json!({"method":"POST","path":"/v1/core/consent/widen/accept", "body":{
        "proposal_ref": proposal.proposal_ref, "expected_delta":delta
    }});
    let (status, _) = local_stdio_json(server.clone(), &agent_keychain, frame.clone()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        vault
            .consent_grant(&bound.digest().to_hex())
            .unwrap()
            .is_none()
    );
    let holder_recipe = format!(
        "scope=core:auth;principal_ref={};actor_class=human",
        owner.to_hex()
    );
    let holder_keychain =
        crate::test_credentials::TestKeychainCredentialSource::from_recipe(&server, &holder_recipe);
    let (status, receipt) = local_stdio_json(server.clone(), &holder_keychain, frame.clone()).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["grant_ref"], bound.digest().to_hex());
    assert_eq!(receipt["decision_id"].as_str().unwrap().len(), 32);
    let (status, _) = local_stdio_json(server, &holder_keychain, frame).await;
    assert_eq!(status, StatusCode::CONFLICT);
}
