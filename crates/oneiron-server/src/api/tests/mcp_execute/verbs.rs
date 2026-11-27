//! Caller-code verb behaviors through `execute` (FIX EXECUTE-CALLER-CODE): a held write (d),
//! supersede on the real engine (e), the ai grant refusal (f), secret handles (g), bound
//! verbs (h), masked reads (i), and the Foreign HTTP door (j).

use super::super::mcp_quickjs::factory;
use super::*;

/// Proves (d): a `vault.remember` that proposes shows its call as `held` with its reason
/// codes, and `vault.writes.pending` lists it.
#[tokio::test]
async fn a_held_write_shows_as_held_and_lists_in_pending() {
    let seatless = seatless_server();
    let proposer = seeded_test_entity_id(0x0024_6651);
    let subject = seeded_test_entity_id(0x0024_6652);
    let credential = "execute-held-credential";
    // Propose-only as `token agent` mints it: the slip reads and proposes and holds no
    // write, and the actor's live ceiling is `proposed`. Writes under it are held,
    // deterministically (a bare Human credential would land them).
    seatless
        .vault
        .put_entity(
            &proposer,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"propose-only actor",
        )
        .unwrap();
    seed_subject(&seatless.vault, subject, proposer);
    let vault_wide = crate::mcp::McpConnectorScope::vault_wide();
    pair_mcp_credential(
        &seatless.server,
        credential,
        proposer,
        oneiron::EdgeActorClass::Human,
        &vault_wide,
    );
    let mut verbs = oneiron::federation::Scope::top();
    verbs.verbs = oneiron::federation::ScopeAxis::Some(
        ["core:read".to_owned(), "core:propose".to_owned()].into(),
    );
    let token = attenuate_mcp_credential(
        &seatless.server,
        credential,
        oneiron::authority::SlipCaveat {
            scope: Some(verbs),
            ..Default::default()
        },
    );
    seatless
        .server
        .mcp_registry
        .lock()
        .await
        .register(
            &token,
            crate::mcp::McpConnectorActorRecord::new(
                proposer,
                oneiron::EdgeActorClass::Human,
                vault_wide,
            ),
        )
        .unwrap();
    let owner = seatless.vault.ensure_embedded_owner_actor().unwrap();
    oneiron::conversation_dag::test_support::put_test_policy_manifest(
        &seatless.vault,
        oneiron::write_envelope::WriteActor::new(owner, oneiron::edge::EdgeActorClass::Human),
        seeded_test_entity_id(0x0024_6653),
        &json!({
            "schema_version": "1.2", "pack_id": "held-write-runs", "pack_version": "v1",
            "min_engine_version": "0.0.0",
            "defaults": { "criticality": "normal", "sensitivity": "normal" },
            "rules": [],
            "actor_ceilings": [{ "actor_class": "human", "actor_ref": proposer.to_hex(),
                "ceiling": "proposed" }],
        }),
    )
    .unwrap();
    assert!(
        seatless
            .vault
            .gate_actor_ceiling_is_proposed("human", &proposer.to_hex())
            .unwrap(),
        "fixture check: the proposer's live ceiling is `proposed`"
    );
    let code = format!(
        r#"return await vault.remember({{subject_ref: "{hex}", predicate: "test.execute_held", value: {{note: "held for review"}}, confidence: 0.9, source: "observed"}});"#,
        hex = subject.to_hex()
    );
    let body = execute(
        &seatless.server,
        credential,
        "held",
        &code,
        Some("d-held-run"),
    )
    .await;
    let answered = structured(&body);
    assert_eq!(answered["status"], "complete", "{body:?}");
    assert_eq!(answered["result"]["approval"], "proposed", "{body:?}");
    let call = call_entry(&answered["calls"], "vault.remember");
    assert_eq!(call["outcome"], "held", "{body:?}");
    assert!(
        call["reason_codes"]
            .as_array()
            .is_some_and(|codes| !codes.is_empty()),
        "{body:?}"
    );

    let pending = execute(
        &seatless.server,
        credential,
        "pending",
        r#"return await vault.writes.pending({limit: 10});"#,
        Some("d-pending-run"),
    )
    .await;
    let listed = structured(&pending);
    assert_eq!(listed["status"], "complete", "{pending:?}");
    // The held claim's own row, found by its predicate, is the pending entry's claim.
    let held = seatless
        .vault
        .entities_by_type(oneiron::registry::ENTITY_TYPE_CLAIM)
        .expect("list claims")
        .into_iter()
        .find_map(|id| {
            let stored = seatless.vault.get_claim(&id).expect("read claim")?;
            (stored.predicate == "test.execute_held").then_some(id)
        })
        .expect("the held claim is stored");
    assert!(
        listed["result"].to_string().contains(&held.to_hex()),
        "{pending:?}"
    );
}

/// Proves (e, T3a on the real engine): one run records six claims on one subject with
/// predicates experiment.run_result.d1a ... d6a; a second run remembers a corrected value
/// for d3a on the same subject and predicate: its call carries `superseded_short_id`, and
/// six claims stand on the subject.
#[tokio::test]
async fn caller_runs_record_six_claims_and_supersede_the_corrected_one() {
    let seatless = seatless_server();
    let actor = seeded_test_entity_id(0x0024_6661);
    let subject = seeded_test_entity_id(0x0024_6662);
    let credential = "execute-t3a-credential";
    register_mcp_actor(
        &seatless.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    seed_subject(&seatless.vault, subject, actor);
    seed_auto_ceiling(&seatless.vault, actor, seeded_test_entity_id(0x0024_6643));
    let hex = subject.to_hex();
    let mut six = String::from("const out = [];");
    for n in 1..=6 {
        six.push_str(&format!(
            r#"out.push(await vault.remember({{subject_ref: "{hex}", predicate: "experiment.run_result.d{n}a", value: {{run: "d{n}a", v: 1}}, confidence: 0.9, source: "observed"}}));"#,
        ));
    }
    six.push_str("return out;");
    let first = execute(&seatless.server, credential, "six", &six, Some("e-t3a-six")).await;
    let answered = structured(&first);
    assert_eq!(answered["status"], "complete", "{first:?}");
    assert_eq!(
        answered["calls"].as_array().map(Vec::len),
        Some(6),
        "{first:?}"
    );
    let d3a = answered["result"][2]["claim_short_id"]
        .as_str()
        .expect("d3a short id")
        .to_owned();

    let fix = format!(
        r#"return await vault.remember({{subject_ref: "{hex}", predicate: "experiment.run_result.d3a", value: {{run: "d3a", v: 2, corrected: true}}, confidence: 0.95, source: "observed"}});"#,
    );
    let second = execute(&seatless.server, credential, "fix", &fix, Some("e-t3a-fix")).await;
    let corrected = structured(&second);
    assert_eq!(corrected["status"], "complete", "{second:?}");
    let call = call_entry(&corrected["calls"], "vault.remember");
    assert_eq!(call["superseded_short_id"], json!(d3a), "{second:?}");

    // Six claims stand: the corrected d3a is active, its original superseded.
    let mut active = 0;
    let mut rows = 0;
    let mut saw_corrected = false;
    let mut saw_original = false;
    for id in seatless
        .vault
        .entities_by_type(oneiron::registry::ENTITY_TYPE_CLAIM)
        .expect("list claims")
    {
        let Some(body) = seatless.vault.get_claim(&id).expect("read claim") else {
            continue;
        };
        if body.subject != oneiron::ClaimSubject::Entity(subject) {
            continue;
        }
        rows += 1;
        if body.lifecycle == oneiron::ClaimLifecycleStatus::Active {
            active += 1;
        }
        if body.predicate == "experiment.run_result.d3a" {
            let value = format!("{:?}", body.value);
            if body.lifecycle == oneiron::ClaimLifecycleStatus::Active {
                assert!(
                    value.contains("corrected"),
                    "the active d3a is the correction: {value}"
                );
                saw_corrected = true;
            } else {
                assert_eq!(
                    body.lifecycle,
                    oneiron::ClaimLifecycleStatus::Superseded,
                    "the original d3a is superseded"
                );
                assert!(!value.contains("corrected"), "the original stands: {value}");
                saw_original = true;
            }
        }
    }
    assert_eq!(rows, 7, "seven rows: six plus the correction");
    assert_eq!(active, 6, "six claims stand");
    assert!(saw_corrected && saw_original);
}

/// Proves (f, FIX EXECUTE-CALLER-CODE, PR B's rule end to end): `ai.image` from caller
/// code under a credential with no ai.* Grant is refused, naming the exact grant it needs.
#[tokio::test]
async fn caller_code_ai_image_without_a_grant_is_refused_naming_the_grant() {
    let seatless = seatless_server();
    let actor = seeded_test_entity_id(0x0024_6671);
    let credential = "execute-ai-credential";
    register_mcp_actor(
        &seatless.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    let body = execute(
        &seatless.server,
        credential,
        "image",
        r#"return await ai.image({prompt: "a heron lantern by the north gate"});"#,
        Some("f-ai-run"),
    )
    .await;
    let refused = structured(&body);
    assert_eq!(refused["status"], "error", "{body:?}");
    assert_eq!(refused["error"]["code"], "facade_error", "{body:?}");
    assert_eq!(refused["error"]["verb"], "ai.image", "{body:?}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("ai.image"),
        "the refusal names the grant it needs: {body:?}"
    );
    assert!(
        refused["error"]["reason_codes"]
            .as_array()
            .is_some_and(|codes| codes.contains(&json!("grant_required.ai.image"))),
        "{body:?}"
    );
    let call = call_entry(&refused["calls"], "ai.image");
    assert_eq!(call["outcome"], "refused", "{body:?}");
    assert_eq!(call["code"], "facade_error", "{body:?}");
    assert!(
        call["reason_codes"]
            .as_array()
            .is_some_and(|codes| codes.contains(&json!("grant_required.ai.image"))),
        "{body:?}"
    );
}

/// Proves (g, Engine ruling CALLER-CODE-OWNER-SIGHT = A): an agent credential's caller-code
/// `vault.hydrate` of a record holding a lifted secret gets the handle, not the value.
#[tokio::test]
async fn agent_hydrate_of_a_lifted_secret_gets_the_handle_not_the_value() {
    const SECRET: &str = "tok-9f2c7a1e-lighthouse-secret";
    let seatless = seatless_server();
    let writer = seeded_test_entity_id(0x0024_6681);
    let agent = seeded_test_entity_id(0x0024_6682);
    let claim = seeded_test_entity_id(0x0024_6683);
    register_mcp_actor(
        &seatless.server,
        "execute-secret-writer",
        writer,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    register_mcp_actor(
        &seatless.server,
        "execute-secret-agent",
        agent,
        oneiron::EdgeActorClass::Agent,
    )
    .await;
    put_actor_read_grant(&seatless.vault, writer, None);
    put_actor_read_grant(&seatless.vault, agent, None);
    seed_auto_ceiling(&seatless.vault, writer, seeded_test_entity_id(0x0024_6684));
    // The record holding the secret: a claim whose credential-named value the secret scan
    // (on by default) lifts into custody.
    let seed = format!(
        r#"return await vault.remember({{id: "{id}", subject_ref: "{writer}", predicate: "test.lifted_secret", value: {{token: "{secret}", note: "the lighthouse keeper's token"}}, confidence: 0.9, source: "observed"}});"#,
        id = claim.to_hex(),
        writer = writer.to_hex(),
        secret = SECRET
    );
    let seeded = execute(
        &seatless.server,
        "execute-secret-writer",
        "seed",
        &seed,
        Some("g-seed-run"),
    )
    .await;
    assert_eq!(structured(&seeded)["status"], "complete", "{seeded:?}");
    // Fixture self-check: the stored row no longer carries the plaintext, so the scan
    // lifted it; a failure here is the fixture, not the product.
    let stored = seatless
        .vault
        .get_claim(&claim)
        .expect("read claim")
        .expect("claim stored");
    assert!(
        !format!("{:?}", stored.value).contains(SECRET),
        "the scan lifted the secret"
    );
    let body = execute(
        &seatless.server,
        "execute-secret-agent",
        "hydrate",
        &format!(
            r#"return await vault.hydrate({{refs: ["{id}"]}});"#,
            id = claim.to_hex()
        ),
        Some("g-hydrate-run"),
    )
    .await;
    let answered = structured(&body);
    assert_eq!(answered["status"], "complete", "{body:?}");
    let text = answered["result"].to_string();
    assert!(!text.contains(SECRET), "no value: {text}");
    assert!(
        text.contains("[secret "),
        "the handle stands for it: {text}"
    );
}

/// Proves (h, the exact-name rule through the dispatcher): a connector bound to `self.fold`
/// (beside the `execute` entry tool, which bound-tool admission also names) passes its
/// `self.fold` call and is refused `self.folds`.
#[tokio::test]
async fn connector_bound_to_self_fold_passes_it_and_is_refused_self_folds() {
    let seatless = seatless_server();
    let actor = seeded_test_entity_id(0x0024_6691);
    register_bound_verb_mcp_actor(
        &seatless.server,
        "execute-fold-credential",
        actor,
        &["execute", "self.fold"],
    )
    .await;
    let body = execute(
        &seatless.server,
        "execute-fold-credential",
        "fold",
        r#"let fold_outcome; let folds_seen;
try { const r = await self.fold([0, 0]); fold_outcome = "ok:" + JSON.stringify(r).slice(0, 80); }
catch (e) { fold_outcome = "threw:" + String(e).slice(0, 200); }
try { await self.folds({}); folds_seen = "unexpected-ok"; }
catch (e) { folds_seen = String(e); }
return {fold_outcome, folds_seen};"#,
        Some("h-fold-run"),
    )
    .await;
    let answered = structured(&body);
    assert_eq!(answered["status"], "complete", "{body:?}");
    let folds_seen = answered["result"]["folds_seen"]
        .as_str()
        .expect("folds answer");
    assert!(
        folds_seen.contains("mcp_verb_not_bound"),
        "self.folds is refused: {folds_seen}"
    );
    let fold_outcome = answered["result"]["fold_outcome"]
        .as_str()
        .expect("fold answer");
    assert!(
        fold_outcome.starts_with("ok:"),
        "self.fold passes its binding: {fold_outcome}"
    );
    for expected in [
        "\"fold\":\"f1\"",
        "\"from\":0",
        "\"through\":0",
        "\"pending\":true",
    ] {
        assert!(
            fold_outcome.contains(expected),
            "self.fold marks f1 pending: {fold_outcome}"
        );
    }
    assert!(
        !answered["calls"].as_array().expect("calls").is_empty(),
        "{body:?}"
    );
}

/// Proves (i): formatted `vault.recall` and `self.focus.refresh` are open to caller code
/// and come back masked for an agent credential (#10576 is on this HEAD; #10578 lands with
/// main and the lane re-checks refresh masking then).
#[tokio::test]
async fn caller_code_formatted_recall_and_focus_refresh_come_back_masked() {
    const SECRET: &str = "tok-9f2c7a1e-lantern-secret";
    let seatless = seatless_server();
    let writer = seeded_test_entity_id(0x0024_66a1);
    let agent = seeded_test_entity_id(0x0024_66a2);
    register_mcp_actor(
        &seatless.server,
        "execute-mask-writer",
        writer,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    register_mcp_actor(
        &seatless.server,
        "execute-mask-agent",
        agent,
        oneiron::EdgeActorClass::Agent,
    )
    .await;
    put_actor_read_grant(&seatless.vault, writer, None);
    put_actor_read_grant(&seatless.vault, agent, None);
    seed_auto_ceiling(&seatless.vault, writer, seeded_test_entity_id(0x0024_66a3));
    // The masked content: a claim the formatted recall finds, holding a lifted secret.
    let seed = format!(
        r#"return await vault.remember({{subject_ref: "{writer}", predicate: "test.masked_recall", value: {{token: "{secret}", note: "the lighthouse keeper's token"}}, confidence: 0.9, source: "observed"}});"#,
        writer = writer.to_hex(),
        secret = SECRET
    );
    let seeded = execute(
        &seatless.server,
        "execute-mask-writer",
        "seed",
        &seed,
        Some("i-seed-run"),
    )
    .await;
    assert_eq!(structured(&seeded)["status"], "complete", "{seeded:?}");
    let stored = seatless
        .vault
        .entities_by_type(oneiron::registry::ENTITY_TYPE_CLAIM)
        .expect("list claims")
        .into_iter()
        .find_map(|id| {
            let stored = seatless.vault.get_claim(&id).expect("read claim")?;
            (stored.predicate == "test.masked_recall").then_some(stored)
        })
        .expect("the masked claim is stored");
    assert!(
        !format!("{:?}", stored.value).contains(SECRET),
        "the scan lifted the secret"
    );

    let recalled = execute(
        &seatless.server,
        "execute-mask-agent",
        "recall",
        r#"return await vault.recall({query: "lighthouse keeper", limit: 5, format: "md"});"#,
        Some("i-recall-run"),
    )
    .await;
    let pack = structured(&recalled);
    assert_eq!(pack["status"], "complete", "{recalled:?}");
    let text = pack["result"].to_string();
    assert!(!text.contains(SECRET), "no value: {text}");
    assert!(
        text.contains("[secret "),
        "the handle stands for it: {text}"
    );

    let refreshed = execute(
        &seatless.server,
        "execute-mask-agent",
        "refresh",
        r#"return await self.focus.refresh({});"#,
        Some("i-refresh-run"),
    )
    .await;
    let frame = structured(&refreshed);
    assert_eq!(frame["status"], "complete", "{refreshed:?}");
    assert!(
        !frame["result"].to_string().contains(SECRET),
        "the frame withholds it: {refreshed:?}"
    );
}

/// Proves (j): the Foreign HTTP door POST /v1/core/facade/execute_code still answers: the
/// row keeps its facade door while leaving MCP.
#[tokio::test]
async fn foreign_http_execute_code_door_still_answers() {
    // Deterministic canary: no isolating backend, so source `1 + 1` reaches the Foreign
    // worker past admission and fails closed with the tier's exact refusal.
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    crate::test_credentials::install_fixture_keystore(&vault, b"secret");
    assert!(
        vault
            .install_sandbox_backends(Arc::new(oneiron::code_sandbox::microvm::NoSandboxBackends,))
            .is_ok(),
        "first backend install wins"
    );
    let provider = crate::mcp::McpQuickJsProvider::for_caller_source(Arc::new(factory())).unwrap();
    let server = Arc::new(
        SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                auth_secret: Some("secret".to_owned()),
                ..Default::default()
            },
        )
        .unwrap()
        .with_mcp_quickjs_provider(provider, crate::mcp::CodeRunLimits::default()),
    );
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let credential = test_bearer(&format!(
        "scope=core:read,core:write;principal_ref={};actor_class=human",
        owner.to_hex()
    ));
    let (status, body) = route_json(
        server.clone(),
        core_request_with_authz(
            "POST",
            "/v1/core/facade/execute_code",
            credential,
            Some(&json!({ "source": "1 + 1" })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body:?}");
    assert_eq!(body["error"]["code"], json!("BAD_REQUEST"), "{body:?}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("no microVM backend is available for guest tier `foreign`"),
        "{body:?}"
    );
    // Control: a verb that names nothing answers 404, so the door above is real.
    let (missing_status, _) = route_json(
        server.clone(),
        core_request_with_authz(
            "POST",
            "/v1/core/facade/definitely.not.a.verb",
            owner_bearer(),
            None,
        ),
    )
    .await;
    assert_eq!(missing_status, StatusCode::NOT_FOUND);
}
