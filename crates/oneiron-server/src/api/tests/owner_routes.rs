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

/// A request the owner door admitted, then a revocation of its slip commits
/// while the act waits for the writer: every queued act is refused in its
/// own transaction and lands no receipt and no change.
#[tokio::test]
async fn an_owner_act_queued_behind_a_slip_revocation_commits_nothing() {
    use crate::owner::{OwnerError, imports, runs};
    let (_dir, server) = auth_test_server();
    let vault = server.vault();
    let owner_id = vault.ensure_embedded_owner_actor().unwrap();
    let recipe = format!("principal_ref={};actor_class=human", owner_id.to_hex());
    let request = slip_credentials::bind_request(
        &server,
        core_request_with_authz("POST", "/v1/owner/secret-scan", test_bearer(&recipe), None),
    );
    let auth = CoreAuth::from_headers(request.headers(), &server.config, vault.as_ref()).unwrap();

    // What the queued acts would decide: an import batch and a parked run.
    let unbound = vault
        .authenticate_owner(
            owner_id,
            &owner_id.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .unwrap();
    let subject = person(&server, b"imported subject").to_hex();
    let batch: imports::ImportBatch = serde_json::from_value(json!({
        "source_id": "okf",
        "claims": [{ "subject": subject, "source_record_id": "concept-1",
                     "predicate": "profile.name", "value": "Ada",
                     "occurred": { "start": 1, "end": 1 }, "learned_at": 2 }]
    }))
    .unwrap();
    let preview = imports::preview(vault, &unbound, batch).unwrap();
    let run = "owner-route-run-revoked";
    let proposal = vault
        .park_run_proposal_for_test(
            run,
            oneiron::EntityId::now(),
            oneiron::EntityId::now(),
            "one",
        )
        .unwrap();
    let bundle_id = runs::review(vault, &unbound, runs::RunName::Id(run))
        .unwrap()
        .bundle_id;

    // Admitted at the door, then revoked before any act reaches the writer.
    let admitted = crate::api::owner_routes::owner(&auth, &server).expect("the owner is admitted");
    let (slip, _) = slip_credentials::credential(&server, &recipe);
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(
        server.config.auth_secret.as_deref().unwrap().as_bytes(),
    )
    .unwrap();
    vault
        .revoke_capability_slip(&issuer, slip.claims.slip_id)
        .unwrap();

    let refused = |error: oneiron::Error| {
        assert_eq!(
            error.kind(),
            oneiron::ErrorKind::ConsentOwnerNotAuthenticated,
            "{error}"
        );
    };
    let refused_owner = |error: OwnerError| match error {
        OwnerError::Engine(error) => refused(*error),
        other => panic!("refused for another reason: {other}"),
    };
    refused(
        vault
            .set_secret_scan_mode(
                &admitted,
                oneiron::policy_model::SecretScanMode::Off,
                vault.now_recorded_at(),
            )
            .unwrap_err(),
    );
    assert_eq!(
        vault.secret_scan_mode().unwrap(),
        oneiron::policy_model::SecretScanMode::On
    );
    assert!(vault.secret_scan_change_log().unwrap().is_empty());

    refused_owner(imports::approve(vault, &admitted, &preview.batch, &preview.digest).unwrap_err());
    refused_owner(imports::decline(vault, &admitted, &preview.batch, &preview.digest).unwrap_err());
    for claim in &preview.batch.claims {
        let id = oneiron::EntityId::from_hex(claim.claim_id.as_deref().unwrap()).unwrap();
        assert!(vault.get_raw(&id).unwrap().is_none(), "nothing admitted");
    }
    // The batch's one decision is still open for the owner's live slip.
    imports::decline(vault, &unbound, &preview.batch, &preview.digest).unwrap();

    for action in [
        oneiron::run_tree::GateConsentBundleAction::Approve,
        oneiron::run_tree::GateConsentBundleAction::Decline,
    ] {
        let run = runs::RunName::Id(run);
        refused_owner(runs::resolve(vault, &admitted, run, &bundle_id, action).unwrap_err());
    }
    assert_eq!(
        vault.get_claim(&proposal).unwrap().unwrap().approval,
        oneiron::ClaimApprovalStatus::Proposed
    );
    assert_eq!(runs::pending(vault).unwrap()[0].run_id, run);
}

/// Review serves a stored proposal through the release redaction even with
/// the ingest scan off, and approving the reviewed bundle id still acts on
/// the stored, unredacted proposal. (`owner::runs::tests` covers the CLI.)
#[tokio::test]
async fn run_review_redacts_stored_credentials_with_the_scan_off() {
    let (_dir, server) = auth_test_server();
    let owner = owner_recipe(&server);
    let vault = server.vault();
    let (status, _) = call(
        &server,
        "POST",
        "/v1/owner/secret-scan",
        owner.clone(),
        Some(&json!({ "mode": "off" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB";
    let run = "owner-route-run-secrets";
    let agent = oneiron::EntityId::now();
    let values = [
        rmpv::Value::from(format!("my token is {token}")),
        rmpv::Value::Map(vec![
            (
                rmpv::Value::from("password"),
                rmpv::Value::from("hunter2-hunter2"),
            ),
            (rmpv::Value::from("label"), rmpv::Value::from("kept")),
        ]),
        rmpv::Value::Binary(token.as_bytes().to_vec()),
        rmpv::Value::Ext(7, token.as_bytes().to_vec()),
    ];
    let ids: Vec<_> = values
        .iter()
        .map(|value| {
            vault
                .park_run_proposal_for_test(run, agent, oneiron::EntityId::now(), value.clone())
                .unwrap()
        })
        .collect();
    // A proposer chooses its predicate too: a valid one can end in a token.
    let predicate_token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
    let predicate = format!("core.opinion.{predicate_token}");
    let named = vault
        .park_run_proposal_with_predicate_for_test(
            run,
            agent,
            oneiron::EntityId::now(),
            &predicate,
            "an innocuous value",
        )
        .unwrap();
    let leaks = |review: &Value| {
        let text = review.to_string();
        let hex: String = token.bytes().map(|byte| format!("{byte:02x}")).collect();
        text.contains(token)
            || text.contains("hunter2")
            || text.contains(&hex)
            || text.contains(predicate_token)
    };

    let path = format!("/v1/owner/runs/review?run_id={run}");
    let (status, review) = call(&server, "GET", &path, owner.clone(), None).await;
    assert_eq!(status, StatusCode::OK, "{review}");
    assert_eq!(
        review["proposals"].as_array().unwrap().len(),
        values.len() + 1
    );
    assert!(!leaks(&review), "{review}");
    assert!(
        review.to_string().contains("kept"),
        "safe fields stay: {review}"
    );

    let decide = json!({ "run_id": run, "bundle_id": review["bundle_id"] });
    let (status, resolved) = call(
        &server,
        "POST",
        "/v1/owner/runs/approve",
        owner,
        Some(&decide),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resolved}");
    for (id, value) in ids.iter().zip(&values) {
        let stored = vault.get_claim(id).unwrap().unwrap();
        assert_eq!(stored.approval, oneiron::ClaimApprovalStatus::Approved);
        assert_eq!(&stored.value, value, "the stored proposal is unchanged");
    }
    let stored = vault.get_claim(&named).unwrap().unwrap();
    assert_eq!(stored.approval, oneiron::ClaimApprovalStatus::Approved);
    assert_eq!(
        stored.predicate, predicate,
        "the stored predicate is unchanged"
    );
}

/// #1307 review: a run id is any text, another run's `run_ref` among it.
/// The run with that id is reviewed and decided by it, the other run by its
/// `run_ref`, and neither name selects the other run.
#[tokio::test]
async fn a_run_id_that_is_another_runs_ref_names_its_own_run() {
    let (_dir, server) = auth_test_server();
    let owner = owner_recipe(&server);
    let vault = server.vault();
    let first = vault
        .park_run_proposal_for_test(
            "owner-route-run-first",
            oneiron::EntityId::now(),
            oneiron::EntityId::now(),
            "the first run's",
        )
        .unwrap();
    let (status, listing) = call(&server, "GET", "/v1/owner/runs", owner.clone(), None).await;
    assert_eq!(status, StatusCode::OK, "{listing}");
    let first_ref = listing[0]["run_ref"].as_str().unwrap().to_owned();
    let second = vault
        .park_run_proposal_for_test(
            &first_ref,
            oneiron::EntityId::now(),
            oneiron::EntityId::now(),
            "the second run's",
        )
        .unwrap();
    let proposal = |review: &Value| review["proposals"][0]["claim_id"].clone();

    let path = format!("/v1/owner/runs/review?run_id={first_ref}");
    let (status, by_id) = call(&server, "GET", &path, owner.clone(), None).await;
    assert_eq!(status, StatusCode::OK, "{by_id}");
    assert_eq!(proposal(&by_id), second.to_hex(), "{by_id}");
    let path = format!("/v1/owner/runs/review?run_ref={first_ref}");
    let (status, by_ref) = call(&server, "GET", &path, owner.clone(), None).await;
    assert_eq!(status, StatusCode::OK, "{by_ref}");
    assert_eq!(proposal(&by_ref), first.to_hex(), "{by_ref}");
    let both = format!("/v1/owner/runs/review?run_id={first_ref}&run_ref={first_ref}");
    let (status, _) = call(&server, "GET", &both, owner.clone(), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let decide = json!({ "run_id": first_ref, "bundle_id": by_id["bundle_id"] });
    let (status, resolved) = call(
        &server,
        "POST",
        "/v1/owner/runs/approve",
        owner,
        Some(&decide),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resolved}");
    let approval = |id| vault.get_claim(&id).unwrap().unwrap().approval;
    assert_eq!(approval(second), oneiron::ClaimApprovalStatus::Approved);
    assert_eq!(approval(first), oneiron::ClaimApprovalStatus::Proposed);
}

/// SOL-9A-2-R2 F2: a backup the owner door admitted, then queued behind a
/// revocation of its slip, writes nothing and prunes nothing.
#[tokio::test]
async fn a_backup_queued_behind_a_slip_revocation_takes_and_prunes_nothing() {
    use crate::owner::OwnerError;
    let (_dir, _backups, server) = owner_host_server();
    let vault = server.vault();
    let host = Arc::clone(server.owner_host.as_ref().unwrap());
    let owner_id = vault.ensure_embedded_owner_actor().unwrap();
    let recipe = format!("principal_ref={};actor_class=human", owner_id.to_hex());
    let request = slip_credentials::bind_request(
        &server,
        core_request_with_authz("POST", "/v1/owner/backups", test_bearer(&recipe), None),
    );
    let auth = CoreAuth::from_headers(request.headers(), &server.config, vault.as_ref()).unwrap();
    let admitted = crate::api::owner_routes::owner(&auth, &server).expect("the owner is admitted");
    // keep = 2: two backups, so a third would prune the first.
    for _ in 0..2 {
        host.take(vault, Some(&admitted)).unwrap();
    }
    let before = crate::owner::backup::list(&host.backups).unwrap();

    let (slip, _) = slip_credentials::credential(&server, &recipe);
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(
        server.config.auth_secret.as_deref().unwrap().as_bytes(),
    )
    .unwrap();
    vault
        .revoke_capability_slip(&issuer, slip.claims.slip_id)
        .unwrap();
    match host.take(vault, Some(&admitted)) {
        Err(OwnerError::Engine(error)) => assert_eq!(
            error.kind(),
            oneiron::ErrorKind::ConsentOwnerNotAuthenticated,
            "{error}"
        ),
        other => panic!("the queued backup must be refused: {other:?}"),
    }
    assert_eq!(crate::owner::backup::list(&host.backups).unwrap(), before);
    let partials = std::fs::read_dir(&host.backups.dir)
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".partial")
        })
        .count();
    assert_eq!(partials, 0, "no partial file is left behind");
}

/// ASTRA-9A-2-R2 F1: a run id is free text its proposer chose. A
/// credential-shaped one is never served by the listing, review or receipt,
/// and the run is still reviewed and approved through its `run_ref`.
#[tokio::test]
async fn a_credential_shaped_run_id_is_never_served_and_its_ref_decides_the_run() {
    let (_dir, server) = auth_test_server();
    let owner = owner_recipe(&server);
    let vault = server.vault();
    let (status, _) = call(
        &server,
        "POST",
        "/v1/owner/secret-scan",
        owner.clone(),
        Some(&json!({ "mode": "off" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let run = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
    let proposal = vault
        .park_run_proposal_for_test(
            run,
            oneiron::EntityId::now(),
            oneiron::EntityId::now(),
            "an innocuous value",
        )
        .unwrap();

    let (status, listing) = call(&server, "GET", "/v1/owner/runs", owner.clone(), None).await;
    assert_eq!(status, StatusCode::OK, "{listing}");
    assert!(!listing.to_string().contains(run), "{listing}");
    let run_ref = listing[0]["run_ref"].as_str().unwrap().to_owned();

    let path = format!("/v1/owner/runs/review?run_ref={run_ref}");
    let (status, review) = call(&server, "GET", &path, owner.clone(), None).await;
    assert_eq!(status, StatusCode::OK, "{review}");
    assert!(!review.to_string().contains(run), "{review}");

    let decide = json!({ "run_ref": run_ref, "bundle_id": review["bundle_id"] });
    let (status, resolved) = call(
        &server,
        "POST",
        "/v1/owner/runs/approve",
        owner,
        Some(&decide),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resolved}");
    assert!(!resolved.to_string().contains(run), "{resolved}");
    assert_eq!(
        vault.get_claim(&proposal).unwrap().unwrap().approval,
        oneiron::ClaimApprovalStatus::Approved
    );
}
