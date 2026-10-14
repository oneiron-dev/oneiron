//! World privacy P1 through the server: the owner's answer at the pairing
//! ceremony decides whether a machine is the owner's, and a request names its
//! machine only with a proof bound to that same request.
use super::owner_routes::{owner_recipe, refused_recipes};
use super::*;
use axum::Json;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MACHINE_PROOF_HEADER,
    MachineEncryptionKey, PeerMachine, machine_connection_transcript,
    machine_profile_proof_transcript, machine_proof_header_value, pairing_binding_transcript,
};
use serde_json::json;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn vault_id(server: &SyncServer) -> [u8; 32] {
    server.vault().authority_fold().unwrap().vault_id.unwrap()
}

fn link(answer: Option<&str>) -> Value {
    let mut payload = json!({"scope": oneiron::federation::Scope::top(), "lifetime_secs": 600});
    if let Some(answer) = answer {
        payload["machine"] = json!(answer);
    }
    payload
}

/// The joining machine's half of the ceremony: a holder proof for the slip
/// and, when `enrol` is set, the machine's own enrolment signed by `machine_key`.
fn redemption(
    server: &SyncServer,
    code: &str,
    machine: oneiron::EntityId,
    machine_key: &SigningKey,
    enrol: bool,
) -> Value {
    let holder = SigningKey::from_bytes(&[71; 32]);
    let holder_ref = server
        .vault()
        .ensure_embedded_owner_actor()
        .unwrap()
        .to_hex();
    let binding_key = holder.verifying_key().to_bytes();
    let transcript = pairing_binding_transcript(code, &binding_key, &holder_ref).unwrap();
    let mut body = json!({"code": code, "holder_ref": holder_ref, "binding_key": hex(&binding_key),
        "signature": hex(&holder.sign(&transcript).to_bytes())});
    if enrol {
        let vault_id = vault_id(server);
        let encryption_key = MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: vec![5; MACHINE_ENCRYPTION_KEY_LEN],
        };
        let key = machine_key.verifying_key().to_bytes();
        let proof = machine_key.sign(&machine_profile_proof_transcript(
            &vault_id,
            machine,
            &key,
            &encryption_key,
        ));
        body["machine"] = json!({
            "vault_id": hex(&vault_id),
            "machine": machine.to_hex(),
            "machine_key": hex(&key),
            "encryption_suite": MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            "encryption_key": base64::engine::general_purpose::STANDARD.encode(&encryption_key.key),
            "machine_proof": hex(&proof.to_bytes()),
        });
    }
    body
}

async fn pair(
    server: &Arc<SyncServer>,
    answer: Option<&str>,
    machine: oneiron::EntityId,
    key: &SigningKey,
    enrol: bool,
) -> StatusCode {
    let (status, body) = route_json(
        server.clone(),
        core_request_with_authz(
            "POST",
            "/v1/core/pairing/links",
            owner_recipe(server),
            Some(&link(answer)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let code = body["code"].as_str().unwrap();
    let redeem = redemption(server, code, machine, key, enrol);
    route_json(
        server.clone(),
        json_request("POST", "/v1/core/pairing/redeem", redeem),
    )
    .await
    .0
}

fn mine(server: &SyncServer, machine: oneiron::EntityId) -> Option<bool> {
    server
        .vault()
        .authority_fold()
        .unwrap()
        .machine(machine)
        .map(oneiron::authority::FoldedMachine::is_mine)
}

#[tokio::test]
async fn the_owners_answer_at_pairing_decides_mine() {
    let (_dir, server) = auth_test_server();
    // Only the owner, in person, answers for a machine.
    for recipe in refused_recipes(&server) {
        let (status, _) = route_json(
            server.clone(),
            core_request_with_authz(
                "POST",
                "/v1/core/pairing/links",
                recipe,
                Some(&link(Some("yours"))),
            ),
        )
        .await;
        assert!(status.is_client_error(), "{status}");
    }
    for (index, (answer, owners)) in [("yours", true), ("work_school", false), ("rented", false)]
        .into_iter()
        .enumerate()
    {
        let machine = oneiron::EntityId::now();
        let key = SigningKey::from_bytes(&[80 + index as u8; 32]);
        assert_eq!(
            pair(&server, Some(answer), machine, &key, true).await,
            StatusCode::OK
        );
        assert_eq!(mine(&server, machine), Some(owners), "{answer}");
    }
    // A machine link enrols its machine or nothing, and a plain link enrols none.
    let machine = oneiron::EntityId::now();
    let key = SigningKey::from_bytes(&[90; 32]);
    assert_eq!(
        pair(&server, Some("yours"), machine, &key, false).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        pair(&server, None, machine, &key, true).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(mine(&server, machine), None);
}

async fn probe(axum::Extension(machine): axum::Extension<PeerMachine>) -> Json<Value> {
    Json(match machine {
        PeerMachine::Proven(id) => json!(id.to_hex()),
        PeerMachine::Unknown => Value::Null,
    })
}

/// Sends one bound request through the binding door; `machine` signs a
/// machine header over that request's own proof when given.
async fn probed(
    server: &Arc<SyncServer>,
    machine: Option<(oneiron::EntityId, &SigningKey)>,
    lifted: Option<&axum::http::HeaderValue>,
) -> (Value, Option<axum::http::HeaderValue>) {
    let request = core_request_with_authz("GET", "/probe", owner_recipe(server), None);
    let mut request = slip_credentials::bind_request(server, request);
    let token = request.headers()[AUTHORIZATION]
        .to_str()
        .unwrap()
        .strip_prefix("Bearer ")
        .unwrap()
        .to_owned();
    let proof: Value =
        serde_json::from_str(request.headers()["x-oneiron-binding"].to_str().unwrap()).unwrap();
    let mut sent = None;
    if let Some((machine, key)) = machine {
        let transcript = machine_connection_transcript(
            &vault_id(server),
            machine,
            &token,
            proof["timestamp"].as_u64().unwrap(),
            proof["nonce"].as_str().unwrap(),
        );
        let value: axum::http::HeaderValue =
            machine_proof_header_value(machine, &key.sign(&transcript).to_bytes())
                .parse()
                .unwrap();
        request
            .headers_mut()
            .insert(MACHINE_PROOF_HEADER, value.clone());
        sent = Some(value);
    }
    if let Some(value) = lifted {
        request
            .headers_mut()
            .insert(MACHINE_PROOF_HEADER, value.clone());
    }
    let router = axum::Router::new()
        .route("/probe", axum::routing::get(probe))
        .layer(axum::middleware::from_fn_with_state(
            server.clone(),
            crate::auth::admit_http_binding,
        ));
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (serde_json::from_slice(&body).unwrap(), sent)
}

#[tokio::test]
async fn a_request_names_its_machine_only_with_its_own_proof() {
    let (_dir, server) = auth_test_server();
    let machine = oneiron::EntityId::now();
    let key = SigningKey::from_bytes(&[91; 32]);
    assert_eq!(
        pair(&server, Some("yours"), machine, &key, true).await,
        StatusCode::OK
    );

    // No proof: an unknown destination, whoever the actor is.
    assert_eq!(probed(&server, None, None).await.0, Value::Null);
    // The machine's install key over this request's own slip proof.
    let (named, header) = probed(&server, Some((machine, &key)), None).await;
    assert_eq!(named, json!(machine.to_hex()));
    // The same header lifted onto another request proves nothing.
    assert_eq!(probed(&server, None, header.as_ref()).await.0, Value::Null);
    // Another key cannot name the machine, nor can a machine never enrolled.
    let stranger = SigningKey::from_bytes(&[92; 32]);
    assert_eq!(
        probed(&server, Some((machine, &stranger)), None).await.0,
        Value::Null
    );
    assert_eq!(
        probed(&server, Some((oneiron::EntityId::now(), &key)), None)
            .await
            .0,
        Value::Null
    );
}
