//! `/v1/owner`: one owner door, receipted acts, whole-batch and whole-run consent.
use super::*;
use crate::owner::schedule::OwnerHost;
use oneiron::registry::ENTITY_TYPE_PERSON;

/// The vault's embedded owner, holding an unattenuated human slip.
fn owner_recipe(server: &SyncServer) -> String {
    let owner = server.vault().ensure_embedded_owner_actor().unwrap();
    test_bearer(&format!(
        "principal_ref={};actor_class=human",
        owner.to_hex()
    ))
}

fn person(server: &SyncServer, body: &[u8]) -> oneiron::EntityId {
    let id = oneiron::EntityId::now();
    server
        .vault()
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            body,
        )
        .unwrap();
    id
}

/// Every credential that is not the live human owner's own full slip.
fn refused_recipes(server: &SyncServer) -> Vec<String> {
    let owner = server
        .vault()
        .ensure_embedded_owner_actor()
        .unwrap()
        .to_hex();
    let stranger = person(server, b"another person").to_hex();
    vec![
        // Another authenticated human is not an owner.
        test_bearer(&format!("principal_ref={stranger};actor_class=human")),
        // The owner's identity on an agent-class slip.
        test_bearer(&format!(
            "jti=owner-as-agent;principal_ref={owner};actor_class=agent"
        )),
        // The owner's slip attenuated to read and write.
        test_bearer(&format!(
            "jti=owner-narrow;principal_ref={owner};actor_class=human;scope=core:read,core:write"
        )),
        // The host root is not a human owner.
        owner_bearer(),
    ]
}

async fn call(
    server: &Arc<SyncServer>,
    method: &str,
    path: &str,
    authorization: String,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    route_json(
        server.clone(),
        core_request_with_authz(method, path, authorization, body),
    )
    .await
}

#[tokio::test]
async fn secret_scan_switch_is_owner_only_and_receipted() {
    let (_dir, server) = auth_test_server();
    let off = json!({ "mode": "off" });
    for recipe in refused_recipes(&server) {
        let (status, _) = call(&server, "POST", "/v1/owner/secret-scan", recipe, Some(&off)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    assert_eq!(
        server.vault().secret_scan_mode().unwrap(),
        oneiron::policy_model::SecretScanMode::On
    );
    assert!(server.vault().secret_scan_change_log().unwrap().is_empty());

    let owner = owner_recipe(&server);
    let (status, receipt) = call(
        &server,
        "POST",
        "/v1/owner/secret-scan",
        owner.clone(),
        Some(&off),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["mode"], "off");
    assert_eq!(receipt["previous"], "on");
    assert_eq!(receipt["revision"], 1);
    let (status, state) = call(&server, "GET", "/v1/owner/secret-scan", owner, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(state["mode"], "off");
    assert_eq!(state["changes"].as_array().unwrap().len(), 1);
    assert_eq!(
        server.vault().secret_scan_mode().unwrap(),
        oneiron::policy_model::SecretScanMode::Off
    );
}

#[tokio::test]
async fn import_preview_approve_and_decline_act_on_the_exact_batch() {
    let (_dir, server) = auth_test_server();
    let owner = owner_recipe(&server);
    let subject = person(&server, b"imported subject").to_hex();
    let batch = |value: &str| {
        json!({
            "source_id": "okf",
            "claims": [
                { "subject": subject, "source_record_id": "concept-1", "predicate": "profile.name",
                  "value": value, "occurred": { "start": 1, "end": 1 }, "learned_at": 2 },
                { "subject": subject, "source_record_id": "concept-2", "predicate": "profile.name",
                  "value": "Ada L.", "occurred": { "start": 1, "end": 1 }, "learned_at": 2 },
            ]
        })
    };
    let claim_ids = |preview: &Value| -> Vec<oneiron::EntityId> {
        preview["batch"]["claims"]
            .as_array()
            .unwrap()
            .iter()
            .map(|claim| oneiron::EntityId::from_hex(claim["claim_id"].as_str().unwrap()).unwrap())
            .collect()
    };
    for recipe in refused_recipes(&server) {
        let (status, _) = call(
            &server,
            "POST",
            "/v1/owner/imports/preview",
            recipe,
            Some(&batch("Ada")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    // Decline: one receipt, nothing admitted.
    let (status, declined_preview) = call(
        &server,
        "POST",
        "/v1/owner/imports/preview",
        owner.clone(),
        Some(&batch("Ada")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{declined_preview}");
    assert_eq!(declined_preview["claims"], 2);
    let decision =
        json!({ "batch": declined_preview["batch"], "digest": declined_preview["digest"] });
    let (status, declined) = call(
        &server,
        "POST",
        "/v1/owner/imports/decline",
        owner.clone(),
        Some(&decision),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{declined}");
    assert_eq!(declined["admitted"], 0);
    // A declined batch takes no second decision, decline or approve.
    for route in ["/v1/owner/imports/decline", "/v1/owner/imports/approve"] {
        let (status, body) = call(&server, "POST", route, owner.clone(), Some(&decision)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{route}: {body}");
        assert_eq!(
            error_envelope(&body)["details"]["state"],
            "already_decided",
            "{body}"
        );
    }
    for id in claim_ids(&declined_preview) {
        assert!(server.vault().get_raw(&id).unwrap().is_none());
    }

    // A batch changed after preview is refused whole.
    let (_, preview) = call(
        &server,
        "POST",
        "/v1/owner/imports/preview",
        owner.clone(),
        Some(&batch("Ada")),
    )
    .await;
    let mut changed = preview["batch"].clone();
    changed["claims"][0]["value"] = json!("Eve");
    let (status, _) = call(
        &server,
        "POST",
        "/v1/owner/imports/approve",
        owner.clone(),
        Some(&json!({ "batch": changed, "digest": preview["digest"] })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    for id in claim_ids(&preview) {
        assert!(server.vault().get_raw(&id).unwrap().is_none());
    }

    // Approve admits every claim of the previewed batch, once.
    let decision = json!({ "batch": preview["batch"], "digest": preview["digest"] });
    let (status, approved) = call(
        &server,
        "POST",
        "/v1/owner/imports/approve",
        owner.clone(),
        Some(&decision),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(approved["approval"], "approved");
    for id in claim_ids(&preview) {
        let claim = server.vault().get_claim(&id).unwrap().unwrap();
        assert_eq!(claim.approval, oneiron::ClaimApprovalStatus::Approved);
    }
    // An approved batch takes no second decision either; the approval stands.
    for route in ["/v1/owner/imports/approve", "/v1/owner/imports/decline"] {
        let (status, body) = call(&server, "POST", route, owner.clone(), Some(&decision)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{route}: {body}");
        assert_eq!(
            error_envelope(&body)["details"]["state"],
            "already_decided",
            "{body}"
        );
    }
    for id in claim_ids(&preview) {
        let claim = server.vault().get_claim(&id).unwrap().unwrap();
        assert_eq!(claim.approval, oneiron::ClaimApprovalStatus::Approved);
    }
}

#[tokio::test]
async fn agent_run_is_approved_or_declined_whole_through_the_route() {
    let (_dir, server) = auth_test_server();
    let owner = owner_recipe(&server);
    let vault = server.vault();
    let agent = oneiron::EntityId::now();
    let approved_run = "owner-route-run-approve";
    let declined_run = "owner-route-run-decline";
    let approve_ids = [
        vault
            .park_run_proposal_for_test(approved_run, agent, oneiron::EntityId::now(), "one")
            .unwrap(),
        vault
            .park_run_proposal_for_test(approved_run, agent, oneiron::EntityId::now(), "two")
            .unwrap(),
    ];
    let decline_id = vault
        .park_run_proposal_for_test(declined_run, agent, oneiron::EntityId::now(), "three")
        .unwrap();

    let (status, pending) = call(&server, "GET", "/v1/owner/runs", owner.clone(), None).await;
    assert_eq!(status, StatusCode::OK, "{pending}");
    assert_eq!(pending[0]["run_id"], approved_run);
    assert_eq!(pending[0]["pending"], 2);

    let review_path = format!("/v1/owner/runs/review?run_id={approved_run}");
    for recipe in refused_recipes(&server) {
        let (status, _) = call(&server, "GET", &review_path, recipe, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (status, review) = call(&server, "GET", &review_path, owner.clone(), None).await;
    assert_eq!(status, StatusCode::OK, "{review}");
    assert_eq!(review["proposals"].as_array().unwrap().len(), 2);

    let decide = json!({ "run_id": approved_run, "bundle_id": review["bundle_id"] });
    for recipe in refused_recipes(&server) {
        let (status, _) = call(
            &server,
            "POST",
            "/v1/owner/runs/approve",
            recipe,
            Some(&decide),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (status, resolved) = call(
        &server,
        "POST",
        "/v1/owner/runs/approve",
        owner.clone(),
        Some(&decide),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resolved}");
    assert_eq!(resolved["action"], "approve");
    for id in approve_ids {
        assert_eq!(
            vault.get_claim(&id).unwrap().unwrap().approval,
            oneiron::ClaimApprovalStatus::Approved
        );
    }

    let review_path = format!("/v1/owner/runs/review?run_id={declined_run}");
    let (_, review) = call(&server, "GET", &review_path, owner.clone(), None).await;
    let stale = json!({ "run_id": declined_run, "bundle_id": "00".repeat(32) });
    let (status, _) = call(
        &server,
        "POST",
        "/v1/owner/runs/decline",
        owner.clone(),
        Some(&stale),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a bundle id the owner never reviewed"
    );
    let decide = json!({ "run_id": declined_run, "bundle_id": review["bundle_id"] });
    let (status, resolved) = call(
        &server,
        "POST",
        "/v1/owner/runs/decline",
        owner,
        Some(&decide),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resolved}");
    assert_eq!(resolved["action"], "decline");
    assert_eq!(
        vault.get_claim(&decline_id).unwrap().unwrap().approval,
        oneiron::ClaimApprovalStatus::Rejected
    );
}

/// `auth_test_server` with the vault path and a backup plan, as `serve` builds it.
fn owner_host_server() -> (tempfile::TempDir, tempfile::TempDir, Arc<SyncServer>) {
    let dir = tempfile::tempdir().unwrap();
    let backups = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let host = OwnerHost {
        vault_path: dir.path().to_path_buf(),
        vault_config: oneiron::VaultConfig::device(),
        backups: crate::owner::backup::BackupPlan::new(dir.path(), backups.path().to_path_buf(), 2),
        every: None,
        backup_lock: std::sync::Mutex::new(()),
    };
    let config = SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    };
    let server = SyncServer::new(vault, config)
        .unwrap()
        .with_owner_host(host);
    (dir, backups, Arc::new(server))
}

#[tokio::test]
async fn owner_backup_rehearse_and_status_through_the_route() {
    let (_dir, _backups, server) = owner_host_server();
    let owner = owner_recipe(&server);
    for recipe in refused_recipes(&server) {
        let (status, _) = call(&server, "POST", "/v1/owner/backups", recipe, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let kept = person(&server, b"in the backup");
    let (status, taken) = call(&server, "POST", "/v1/owner/backups", owner.clone(), None).await;
    assert_eq!(status, StatusCode::OK, "{taken}");
    let later = person(&server, b"after the backup");
    let (status, rehearsal) = call(
        &server,
        "POST",
        "/v1/owner/backups/rehearse",
        owner.clone(),
        Some(&json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{rehearsal}");
    assert_eq!(rehearsal["verified"], true);
    assert_eq!(rehearsal["checkpoint_id"], taken["checkpoint_id"]);
    assert_eq!(rehearsal["kept"], false);
    // The live vault is untouched by a rehearsal.
    assert!(server.vault().get(&kept).unwrap().is_some());
    assert!(server.vault().get(&later).unwrap().is_some());

    let (status, location) = call(&server, "GET", "/v1/owner/status", owner, None).await;
    assert_eq!(status, StatusCode::OK, "{location}");
    assert_eq!(location["backups"]["count"], 1);
    assert_eq!(location["backups"]["last"]["file"], taken["backup"]["file"]);
    assert_eq!(location["secret_scan"], "on");
    assert!(location["disk_bytes"].as_u64().unwrap() > 0);
}
