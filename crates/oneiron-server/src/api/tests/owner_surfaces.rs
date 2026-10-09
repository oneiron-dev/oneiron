//! `/v1/owner` surfaces wired from built engine doors: cleanup review,
//! persona export, off-record sessions, the Graph-FS read, feedback and pack
//! drift.
use super::owner_routes::{call, owner_recipe, person, refused_recipes};
use super::*;
use oneiron::attempt_queue::AttemptId;
use oneiron::{ClaimSource, EntityId, TimeRange};

fn extraction_person(server: &SyncServer, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    assert!(
        server
            .vault()
            .put_extraction_minted_person(
                &id,
                ClaimSource::Generated,
                TimeRange { start: 1, end: 1 },
                1,
                body
            )
            .unwrap()
    );
    id
}

fn hexes(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap().to_owned())
        .collect()
}

/// ARCH-0073 propose-first: the cleanup job's proposal waits for the owner,
/// accepting archives what is still empty, restoring brings the same record
/// back, and the automatic posture stays refused while its teeth are open.
#[tokio::test]
async fn cleanup_proposals_wait_for_the_owner_and_archive_stays_restorable() {
    let (_dir, server) = auth_test_server();
    let owner = owner_recipe(&server);
    let husk = extraction_person(&server, b"a person nobody mentions again").to_hex();
    let run = oneiron::vault_cleanup::run_vault_cleanup(server.vault(), &AttemptId::now()).unwrap();
    let proposal = run
        .proposal
        .expect("propose-first opens a proposal")
        .to_hex();
    assert!(run.archived.is_empty());

    let decide = json!({ "proposal": proposal });
    for recipe in refused_recipes(&server) {
        let (status, _) = call(&server, "GET", "/v1/owner/cleanup", recipe.clone(), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = call(
            &server,
            "POST",
            "/v1/owner/cleanup/accept",
            recipe,
            Some(&decide),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (status, review) = call(&server, "GET", "/v1/owner/cleanup", owner.clone(), None).await;
    assert_eq!(status, StatusCode::OK, "{review}");
    assert_eq!(review["posture"], "propose_first");
    assert_eq!(review["task_retention_days"], 90);
    assert_eq!(review["proposals"].as_array().unwrap().len(), 1);
    assert_eq!(review["proposals"][0]["id"], proposal);
    assert!(
        review["proposals"][0]["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|candidate| candidate["entity"] == husk
                && candidate["kind"] == "claimless_extraction_person")
    );
    assert!(review["archived"].as_array().unwrap().is_empty());

    let (status, accepted) = call(
        &server,
        "POST",
        "/v1/owner/cleanup/accept",
        owner.clone(),
        Some(&decide),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{accepted}");
    assert!(hexes(&accepted["archived"]).contains(&husk));
    let husk_id = EntityId::from_hex(&husk).unwrap();
    assert!(server.vault().archived_entity(&husk_id).unwrap().is_some());
    let (_, review) = call(&server, "GET", "/v1/owner/cleanup", owner.clone(), None).await;
    assert!(review["proposals"].as_array().unwrap().is_empty());
    assert_eq!(review["digests"][0]["decision"], "proposal_accepted");
    assert_eq!(review["digests"][0]["proposal"], proposal);
    assert!(
        review["archived"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["entity"] == husk)
    );
    // An answered proposal is gone; deciding it again changes nothing.
    let (status, again) = call(
        &server,
        "POST",
        "/v1/owner/cleanup/accept",
        owner.clone(),
        Some(&decide),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{again}");

    // Restore brings the same record back.
    let (status, review) = call(
        &server,
        "POST",
        "/v1/owner/cleanup/restore",
        owner.clone(),
        Some(&json!({ "entity": husk })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{review}");
    assert!(server.vault().archived_entity(&husk_id).unwrap().is_none());
    assert!(server.vault().get(&husk_id).unwrap().is_some());

    // Rejecting archives nothing.
    let second = extraction_person(&server, b"another husk");
    let run = oneiron::vault_cleanup::run_vault_cleanup(server.vault(), &AttemptId::now()).unwrap();
    let rejected = json!({ "proposal": run.proposal.unwrap().to_hex() });
    let (status, review) = call(
        &server,
        "POST",
        "/v1/owner/cleanup/reject",
        owner.clone(),
        Some(&rejected),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{review}");
    assert!(review["proposals"].as_array().unwrap().is_empty());
    assert!(server.vault().archived_entity(&second).unwrap().is_none());

    // The automatic arm stays off while ARCH-0066's teeth are open; the
    // retention dial is the owner's.
    let (status, refused) = call(
        &server,
        "POST",
        "/v1/owner/cleanup",
        owner.clone(),
        Some(&json!({ "posture": "auto_with_digest" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    let (status, review) = call(
        &server,
        "POST",
        "/v1/owner/cleanup",
        owner,
        Some(&json!({ "task_retention_days": 30 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{review}");
    assert_eq!(review["posture"], "propose_first");
    assert_eq!(review["task_retention_days"], 30);
}

fn claim_about(server: &SyncServer, subject: EntityId, predicate: &str, text: &str) {
    let mut body = oneiron::ClaimBody::new(
        predicate,
        oneiron::ClaimSubject::Entity(subject),
        rmpv::Value::from(text),
        0.9,
        oneiron::ClaimApprovalStatus::Approved,
        oneiron::ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.salience = Some(0.9);
    body.source = Some(ClaimSource::UserStated);
    server
        .vault()
        .put_claim(
            &EntityId::now(),
            &body,
            TimeRange { start: 10, end: 10 },
            10,
        )
        .unwrap();
}

/// OF-325 mode A: the owner previews the card and strikes a row; the export
/// carries exactly the rows left, in both renders, recorded as granted by the
/// owner. A card that changed since its preview issues nothing.
#[tokio::test]
async fn persona_card_exports_only_what_the_owner_left_after_preview() {
    let (_dir, server) = auth_test_server();
    let owner = owner_recipe(&server);
    let subject = person(&server, b"Ada");
    claim_about(&server, subject, "profile.name", "Ada Lovelace");
    claim_about(
        &server,
        subject,
        "profile.hobby",
        "writes poems about engines",
    );
    let path = format!("/v1/owner/persona?subject={}", subject.to_hex());
    for recipe in refused_recipes(&server) {
        let (status, _) = call(&server, "GET", &path, recipe, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (status, preview) = call(&server, "GET", &path, owner.clone(), None).await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    let hobby = preview["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["text"].as_str().unwrap().contains("poems"))
        .unwrap_or_else(|| panic!("a row for the hobby claim: {preview}"))
        .clone();
    let request = json!({
        "subject": subject.to_hex(),
        "stamp": preview["stamp"],
        "strike": [hobby["row_id"]],
    });
    for recipe in refused_recipes(&server) {
        let (status, _) = call(
            &server,
            "POST",
            "/v1/owner/persona/export",
            recipe,
            Some(&request),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (status, exported) = call(
        &server,
        "POST",
        "/v1/owner/persona/export",
        owner.clone(),
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{exported}");
    assert!(!exported["markdown"].as_str().unwrap().contains("poems"));
    assert!(!exported["memory_pack"].to_string().contains("poems"));
    assert!(
        exported["markdown"]
            .as_str()
            .unwrap()
            .contains("Ada Lovelace")
    );
    assert!(
        exported["struck_row_ids"]
            .as_array()
            .unwrap()
            .contains(&hobby["row_id"])
    );
    let export_id = EntityId::from_hex(exported["export_id"].as_str().unwrap()).unwrap();
    let record = server
        .vault()
        .get_persona_snapshot_export(&export_id)
        .unwrap()
        .expect("the export is recorded");
    assert_eq!(
        record.granted_by,
        server
            .vault()
            .ensure_embedded_owner_actor()
            .unwrap()
            .to_hex()
    );

    // A new claim changes the card: the old preview's stamp issues nothing.
    claim_about(&server, subject, "profile.city", "lives in London");
    let (status, stale) = call(
        &server,
        "POST",
        "/v1/owner/persona/export",
        owner,
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{stale}");
}

fn room_turn(session_ref: &str, text: &str) -> Value {
    json!({
        "session_ref": session_ref,
        "turn": {
            "conversation_ref": "",
            "turn_ref": null,
            "messages": [{
                "id": null,
                "author": "user",
                "message_type": "utterance",
                "content": text,
                "metadata": null,
                "is_visible": true,
                "order": 0,
            }],
            "occurred_at": 100,
        },
    })
}

fn witnessed_turn(receipt: &Value) -> EntityId {
    let turn = receipt["receipt_ref"]
        .as_str()
        .and_then(|reference| reference.strip_prefix("witness:"))
        .unwrap_or_else(|| panic!("a witness receipt: {receipt}"));
    EntityId::from_hex(turn).unwrap()
}

/// ARCH-0052: an off-record room keeps its turns out of the vault; the turn
/// the owner promotes enters through the ordinary write door, and close drops
/// the rest. An anonymous session keeps nothing and cannot be put on record.
#[tokio::test]
async fn off_record_room_keeps_turns_out_until_promoted_and_close_drops_the_rest() {
    let (_dir, server) = auth_test_server();
    let owner = owner_recipe(&server);
    let enter = json!({ "session_ref": "room-1", "mode": "off_record", "backend": "local" });
    for recipe in refused_recipes(&server) {
        let (status, _) = call(
            &server,
            "POST",
            "/v1/owner/off-record",
            recipe,
            Some(&enter),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    assert!(
        server
            .vault()
            .off_record_session("room-1")
            .unwrap()
            .is_none()
    );
    let (status, session) = call(
        &server,
        "POST",
        "/v1/owner/off-record",
        owner.clone(),
        Some(&enter),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert_eq!(session["mode"], "off_record");

    let (status, kept) = call(
        &server,
        "POST",
        "/v1/owner/off-record/witness",
        owner.clone(),
        Some(&room_turn("room-1", "save this one")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{kept}");
    let (status, dropped) = call(
        &server,
        "POST",
        "/v1/owner/off-record/witness",
        owner.clone(),
        Some(&room_turn("room-1", "let this one go")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{dropped}");
    let (kept, dropped) = (witnessed_turn(&kept), witnessed_turn(&dropped));
    // The vault itself holds neither turn while the room is live.
    assert!(server.vault().get(&kept).unwrap().is_none());
    assert!(server.vault().get(&dropped).unwrap().is_none());

    let (status, promoted) = call(
        &server,
        "POST",
        "/v1/owner/off-record/promote",
        owner.clone(),
        Some(&json!({ "session_ref": "room-1", "turn": kept.to_hex() })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{promoted}");
    assert!(hexes(&promoted["replayed"]).contains(&kept.to_hex()));
    assert!(server.vault().get(&kept).unwrap().is_some());

    let close = json!({ "session_ref": "room-1" });
    let (status, closed) = call(
        &server,
        "POST",
        "/v1/owner/off-record/close",
        owner.clone(),
        Some(&close),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{closed}");
    assert_eq!(closed["promoted_turns_kept"], 1);
    assert!(closed["turns_dropped"].as_u64().unwrap() >= 1);
    let (status, _) = call(
        &server,
        "GET",
        "/v1/owner/off-record?session_ref=room-1",
        owner.clone(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(server.vault().get(&kept).unwrap().is_some());
    assert!(server.vault().get(&dropped).unwrap().is_none());

    // Anonymous keeps nothing: it can never be put on record.
    let (status, session) = call(
        &server,
        "POST",
        "/v1/owner/off-record",
        owner.clone(),
        Some(
            &json!({ "session_ref": "room-2", "mode": "anonymous", "backend": "remote_provider" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert_eq!(session["mode"], "anonymous");
    let (status, refused) = call(
        &server,
        "POST",
        "/v1/owner/off-record/mode",
        owner.clone(),
        Some(&json!({ "session_ref": "room-2", "mode": "on_record" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    let (status, _) = call(
        &server,
        "POST",
        "/v1/owner/off-record/close",
        owner,
        Some(&json!({ "session_ref": "room-2" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

/// OF-355: the owner reads the vault as a file tree. Paths resolve lazily,
/// file reads return the stored bytes, and grep searches them.
#[tokio::test]
async fn graph_fs_reads_the_vault_as_a_tree_for_the_owner_only() {
    let (_dir, server) = auth_test_server();
    let owner = owner_recipe(&server);
    let ada = person(&server, b"Ada, who writes about engines").to_hex();
    let ada_id = EntityId::from_hex(&ada).unwrap();
    claim_about(
        &server,
        ada_id,
        "profile.hobby",
        "writes poems about engines",
    );
    // A sealed secret is absent from the tree, and the listing still works.
    let secrets = tempfile::tempdir().unwrap();
    let declared = secrets
        .path()
        .canonicalize()
        .unwrap()
        .join(".secrets/api.key");
    std::fs::create_dir_all(declared.parent().unwrap()).unwrap();
    let custody = {
        use oneiron::secret_custody::{
            CustodyClass, CustodyTier, SECRET_CUSTODY_SCHEMA_VERSION, SecretBinding,
            SecretCustodyFloor, SecretCustodyRecord, SecretCustodyStatus,
        };
        server
            .vault()
            .register_secret(SecretCustodyRecord {
                schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
                name: "graph-fs-secret".to_owned(),
                class: CustodyClass::CustodyPortable,
                device_only: false,
                value_bytes: b"never-in-the-tree".to_vec(),
                status: SecretCustodyStatus::Active,
                registered_at: 1,
                rotated_at: None,
                rotation_generation: 0,
                bindings: vec![SecretBinding {
                    effector: "connector:graph-fs-test".to_owned(),
                    tier_ceiling: CustodyTier::T2LocalRegistered,
                    scopes: vec!["read".to_owned()],
                }],
                manifest_ref: "secrets.toml".to_owned(),
                declared_paths: vec![declared.to_string_lossy().into_owned()],
                policy_floor_snapshot: SecretCustodyFloor::default(),
            })
            .unwrap()
            .to_hex()
    };
    for recipe in refused_recipes(&server) {
        let (status, _) = call(
            &server,
            "GET",
            "/v1/owner/graph-fs?path=/entities",
            recipe,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let read = |query: String| {
        let server = server.clone();
        let owner = owner.clone();
        async move {
            let (status, reply) = call(
                &server,
                "GET",
                &format!("/v1/owner/graph-fs?{query}"),
                owner,
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{query}: {reply}");
            reply["output"].as_str().unwrap().to_owned()
        }
    };
    let root = read("path=/".to_owned()).await;
    for directory in ["worlds", "entities", "claims", "backlinks"] {
        assert!(root.contains(directory), "{root}");
    }
    let entities = read("path=/entities".to_owned()).await;
    assert!(entities.contains(&ada), "{entities}");
    assert!(!entities.contains(&custody), "{entities}");
    // Every other walk passes over it too, and none fails.
    for query in [
        "path=/backlinks",
        "path=/claims/by-time",
        "path=/claims/by-id",
        "path=/claims&by_time=true",
        "path=/&op=find",
    ] {
        let listing = read(query.to_owned()).await;
        assert!(!listing.contains(&custody), "{query}: {listing}");
    }
    // A raw read of it still refuses, and its bytes never leave.
    let (status, raw) = call(
        &server,
        "GET",
        &format!("/v1/owner/graph-fs?path=/entities/{custody}/body&op=cat"),
        owner.clone(),
        None,
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{raw}");
    assert!(!raw.to_string().contains("never-in-the-tree"), "{raw}");
    assert_eq!(
        read(format!("path=/entities/{ada}/body&op=cat"))
            .await
            .trim_end(),
        "Ada, who writes about engines"
    );
    let claims = read(format!("path=/entities/{ada}/claims")).await;
    assert!(!claims.trim().is_empty(), "{claims}");
    let found = read(format!("path=/entities/{ada}/body&op=grep&pattern=engines")).await;
    assert!(found.contains("engines"), "{found}");
    // grep needs something to look for.
    let (status, _) = call(
        &server,
        "GET",
        "/v1/owner/graph-fs?path=/claims&op=grep",
        owner,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

fn feedback_server(endpoint: &str) -> (tempfile::TempDir, Arc<SyncServer>) {
    use crate::feedback_delivery::{FeedbackDeliveryConfig, FeedbackDestination, FeedbackHost};
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            ..Default::default()
        },
    )
    .unwrap()
    .with_feedback(Some(FeedbackHost {
        config: FeedbackDeliveryConfig {
            destination: FeedbackDestination::Collector,
            endpoint: endpoint.to_owned(),
        },
        bearer: None,
    }));
    (dir, Arc::new(server))
}

/// Accepts one request on `listener` and returns its head and body as text.
fn collect_one(listener: std::net::TcpListener) -> std::thread::JoinHandle<String> {
    use std::io::{Read, Write};
    std::thread::spawn(move || {
        listener.set_nonblocking(false).unwrap();
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buf = [0; 4096];
        loop {
            let n = socket.read(&mut buf).unwrap();
            bytes.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&bytes).to_lowercase();
            if let Some(end) = text.find("\r\n\r\n") {
                let length = text[..end]
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .map_or(0, |value| value.trim().parse::<usize>().unwrap());
                if bytes.len() >= end + 4 + length {
                    break;
                }
            }
            assert_ne!(n, 0, "the request ended early");
        }
        write!(
            socket,
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        String::from_utf8_lossy(&bytes).to_lowercase()
    })
}

/// OF-420: the owner previews a bundle with no vault text and sends exactly
/// that bundle to the configured collector. The vault's policy still
/// decides: with no grant for the feedback channel the send is held and
/// nothing leaves; once the owner grants the channel, the previewed bundle
/// arrives. A written note waits for in-vault redaction.
#[tokio::test]
async fn feedback_leaves_only_as_previewed_and_only_where_policy_allows() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}/ingest", listener.local_addr().unwrap());
    let (_dir, server) = feedback_server(&endpoint);
    let owner = owner_recipe(&server);
    let bug = json!({ "category": "bug" });
    for recipe in refused_recipes(&server) {
        let (status, _) = call(
            &server,
            "POST",
            "/v1/owner/feedback/preview",
            recipe,
            Some(&bug),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (status, preview) = call(
        &server,
        "POST",
        "/v1/owner/feedback/preview",
        owner.clone(),
        Some(&bug),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(preview["destination"], endpoint);
    assert_eq!(preview["bundle"]["category"], "bug");
    let send_body = |category: &str, preview: &Value| {
        json!({
            "category": category,
            "digest": preview["digest"],
            "approval": preview["approval"],
            "previewed_at": preview["previewed_at"],
        })
    };

    // A note is refused until the engine redacts in the vault.
    let (status, refused) = call(
        &server,
        "POST",
        "/v1/owner/feedback/preview",
        owner.clone(),
        Some(&json!({ "category": "bug", "note": "the export button hangs" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    // Only the previewed bundle is sent.
    let (status, changed) = call(
        &server,
        "POST",
        "/v1/owner/feedback/send",
        owner.clone(),
        Some(&send_body("papercut", &preview)),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{changed}");

    // No grant for the feedback channel: the gate holds it; nothing leaves.
    let (status, held) = call(
        &server,
        "POST",
        "/v1/owner/feedback/send",
        owner.clone(),
        Some(&send_body("bug", &preview)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{held}");
    assert_eq!(held["outcome"], "held", "{held}");
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));

    // The owner grants sends on the feedback channel.
    let owner_id = server.vault().ensure_embedded_owner_actor().unwrap();
    let mut effect = oneiron::federation::Scope::top();
    effect.verbs = oneiron::federation::ScopeAxis::Some(["effect".to_owned()].into());
    oneiron::conversation_dag::test_support::put_test_policy_manifest(
        server.vault(),
        oneiron::write_envelope::WriteActor::new(owner_id, oneiron::edge::EdgeActorClass::Human),
        EntityId::now(),
        &json!({
            "schema_version": "1.2", "pack_id": "owner-feedback", "pack_version": "v1",
            "min_engine_version": "0.0.0",
            "defaults": { "criticality": "normal", "sensitivity": "normal" },
            "rules": [],
            "actor_ceilings": [{ "actor_class": "human", "actor_ref": owner_id.to_hex(), "ceiling": "auto" }],
            "scoped_grants": [{ "actor_ref": owner_id.to_hex(), "effector": "external:send",
                "scope": effect, "selectors": { "channel": "feedback_collector" } }],
        }),
    )
    .unwrap();
    let wish = json!({ "category": "feature-wish" });
    let (_, preview) = call(
        &server,
        "POST",
        "/v1/owner/feedback/preview",
        owner.clone(),
        Some(&wish),
    )
    .await;
    let digest = preview["digest"].as_str().unwrap().to_owned();
    let collector = collect_one(listener);
    let send = send_body("feature-wish", &preview);
    let (status, sent) = call(
        &server,
        "POST",
        "/v1/owner/feedback/send",
        owner.clone(),
        Some(&send),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    assert_eq!(sent["outcome"], "delivered_to_channel", "{sent}");
    let request = collector.join().unwrap();
    assert!(request.starts_with("post /ingest"), "{request}");
    assert!(
        request.contains(&format!(
            "x-oneiron-bundle-digest: {}",
            digest.to_lowercase()
        )),
        "{request}"
    );
    // The same request a second later is the same send, not a second one:
    // the collector is gone, so a second delivery could not succeed.
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let (status, again) = call(
        &server,
        "POST",
        "/v1/owner/feedback/send",
        owner,
        Some(&send),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["logical_send_ref"], sent["logical_send_ref"]);
    assert_eq!(again["outcome"], "delivered_to_channel", "{again}");
}

/// Two owners of one shared vault preview the same bundle and send it with the
/// same preview second: each approval names its owner, so each send is its
/// own, neither owner can send on the other's preview, and one owner's repeat
/// is still that owner's one send.
#[tokio::test]
async fn two_owners_sending_one_bundle_are_two_sends() {
    use oneiron::federation::{FederationGrantRole, InitialSharedMember};
    // A closed port: a send that tried to deliver would fail, not hang.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/ingest", closed.local_addr().unwrap());
    drop(closed);
    let (_dir, server) = feedback_server(&endpoint);
    let vault = server.vault();
    let first = vault.ensure_embedded_owner_actor().unwrap();
    let second = person(&server, b"the other owner");
    let proof = vault
        .authenticate_owner(
            first,
            &first.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .unwrap();
    let owners = [first, second].map(|member_ref| InitialSharedMember {
        member_ref,
        role: Some(FederationGrantRole::Owner),
    });
    vault
        .initialize_shared_vault(&proof, 42, None, &owners, 1)
        .unwrap();
    let recipes = [
        owner_recipe(&server),
        test_bearer(&format!(
            "principal_ref={};actor_class=human",
            second.to_hex()
        )),
    ];
    let bug = json!({ "category": "bug" });
    let mut previews = Vec::new();
    for recipe in &recipes {
        let (status, preview) = call(
            &server,
            "POST",
            "/v1/owner/feedback/preview",
            recipe.clone(),
            Some(&bug),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        previews.push(preview);
    }
    assert_eq!(previews[0]["digest"], previews[1]["digest"]);
    assert_ne!(previews[0]["approval"], previews[1]["approval"]);
    let previewed_at = previews[0]["previewed_at"].clone();
    let send_body = |preview: &Value| {
        json!({
            "category": "bug",
            "digest": preview["digest"],
            "approval": preview["approval"],
            "previewed_at": previewed_at,
        })
    };
    let mut sent = Vec::new();
    for (recipe, preview) in recipes.iter().zip(&previews) {
        let (status, reply) = call(
            &server,
            "POST",
            "/v1/owner/feedback/send",
            recipe.clone(),
            Some(&send_body(preview)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        sent.push(reply);
    }
    assert_ne!(
        sent[0]["approval_receipt_ref"],
        sent[1]["approval_receipt_ref"]
    );
    assert_ne!(sent[0]["logical_send_ref"], sent[1]["logical_send_ref"]);
    let (status, borrowed) = call(
        &server,
        "POST",
        "/v1/owner/feedback/send",
        recipes[1].clone(),
        Some(&send_body(&previews[0])),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{borrowed}");
    for ((recipe, preview), sent) in recipes.iter().zip(&previews).zip(&sent) {
        let (status, again) = call(
            &server,
            "POST",
            "/v1/owner/feedback/send",
            recipe.clone(),
            Some(&send_body(preview)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(again["logical_send_ref"], sent["logical_send_ref"]);
    }
}

/// ARCH-0059 §4: what the pack-drift ladder did to a saved query reaches the
/// owner.
#[tokio::test]
async fn pack_drift_repairs_reach_the_owner() {
    use oneiron::saved_query::{
        ClaimComparison, CreateSavedQueryRequest, EvalMode, EvalPolicy, FilterAst, MatcherSpec,
        PackDrift, PackMigrationMap, PackPredicateRewrite, QueryScope, SAVED_QUERY_SCHEMA_VERSION,
    };
    let (_dir, server) = auth_test_server();
    let owner = owner_recipe(&server);
    let vault = server.vault();
    oneiron::campaign::register_crm_pack(
        vault,
        107,
        108,
        oneiron::registry::TypeByteFamily::Productivity,
    )
    .unwrap();
    let term = FilterAst::Claim {
        predicate: "profile.seniority".to_owned(),
        cmp: ClaimComparison::Exists,
        value: Value::Null,
    };
    let query = oneiron::saved_query::create_saved_query(
        vault,
        vault.ensure_embedded_owner_actor().unwrap(),
        &CreateSavedQueryRequest {
            schema_version: SAVED_QUERY_SCHEMA_VERSION,
            scope: QueryScope::default(),
            filter: term.clone(),
            matcher: MatcherSpec::Hard { expression: term },
            eval: EvalPolicy {
                mode: EvalMode::Manual,
                max_entities_per_wake: 8,
                max_judges_per_wake: 4,
            },
        },
        10,
    )
    .unwrap();
    let drift = PackDrift {
        from_pack_id: "hr".to_owned(),
        from_version: "1".to_owned(),
        to_pack_id: "hr".to_owned(),
        to_version: "2".to_owned(),
        affected_predicates: vec!["profile.seniority".to_owned()],
    };
    oneiron::saved_query::put_pack_migration_map(
        vault,
        &drift,
        &PackMigrationMap {
            rewrites: [(
                "profile.seniority".to_owned(),
                PackPredicateRewrite::Rename {
                    to: "profile.headcount".to_owned(),
                },
            )]
            .into_iter()
            .collect(),
        },
    )
    .unwrap();
    oneiron::saved_query::repair_pack_drift(vault, query.query_ref, &query.definition, &drift, 100)
        .unwrap();
    for recipe in refused_recipes(&server) {
        let (status, _) = call(&server, "GET", "/v1/owner/pack-drift", recipe, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (status, repairs) = call(&server, "GET", "/v1/owner/pack-drift", owner, None).await;
    assert_eq!(status, StatusCode::OK, "{repairs}");
    let repair = &repairs.as_array().unwrap()[0];
    assert_eq!(repair["query"], query.query_ref.to_hex());
    assert_eq!(repair["pack"], "hr");
    assert_eq!(repair["predicates"], json!(["profile.seniority"]));
    assert!(
        repair["summary"]
            .as_str()
            .unwrap()
            .starts_with("auto-migrated")
    );
}
