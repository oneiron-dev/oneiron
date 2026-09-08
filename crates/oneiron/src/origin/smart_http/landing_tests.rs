//! Landing and attribution tests: unauthenticated push, delete-only pin, secret
//! scan, sync-plane silence, attribution/provenance gates, reopen, replay,
//! observed refs.

use super::tests::{
    CapturingSink, fixture_attribution, git, landed_repo_id, landing_outcome, landing_time,
    narrow_door_effectors, seeded_repo, served_repo, temp_vault,
};
use super::*;
use crate::config::VaultConfig;
use crate::store::Store;

fn sync_plane_rows(vault: &Vault) -> BTreeMap<String, Vec<u8>> {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    vault
        .store
        .sync_state
        .iter(&rtxn)
        .expect("iter sync state")
        .map(|row| {
            let (key, value) = row.expect("sync state row");
            (key.into_owned(), value.to_vec())
        })
        .collect()
}

#[test]
fn smart_http_production_push_rejects_before_git_without_admission() {
    struct UnreadBody;
    impl Read for UnreadBody {
        fn read(&mut self, _bytes: &mut [u8]) -> io::Result<usize> {
            panic!("rejected admission must not start the body pump");
        }
    }
    let (_dir, vault) = temp_vault();
    let (_source, repo_dir, _, _) = served_repo(&vault);
    let mut request = ServeRequest {
        method: "POST".to_owned(),
        path_info: "/demo.git/git-receive-pack".to_owned(),
        query_string: String::new(),
        content_type: Some("application/x-git-receive-pack-request".to_owned()),
        content_length: None,
        content_encoding: None,
        git_protocol: None,
        remote_user: None,
        remote_addr: None,
    };
    let mut sink = CapturingSink::default();
    let before = git(&repo_dir, &["rev-parse", "refs/heads/main"]);
    assert!(
        serve(
            &vault,
            "demo",
            &request,
            DoorSeam::Landed,
            &mut UnreadBody,
            &mut sink
        )
        .is_err()
    );
    request.remote_user = Some(EntityId::now().to_hex());
    for supplied in [
        EntityId::now(),
        fixture_attribution(
            &vault,
            &landing_outcome(&repo_dir, &GitOid::parse_hex(before.clone()).expect("head")),
        )
        .provenance_claim_id,
    ] {
        assert!(
            serve_with_provenance(
                &vault,
                "demo",
                &request,
                DoorSeam::Landed,
                Some(supplied),
                &mut UnreadBody,
                &mut sink
            )
            .is_err(),
            "external evidence is not this request"
        );
    }
    narrow_door_effectors(&vault, Vec::new());
    assert!(matches!(
        serve(
            &vault,
            "demo",
            &request,
            DoorSeam::Landed,
            &mut UnreadBody,
            &mut sink
        ),
        Err(Error::ReceivePackDoorRejected { .. })
    ));
    assert_eq!(sink.status, 0);
    assert_eq!(git(&repo_dir, &["rev-parse", "refs/heads/main"]), before);
    assert!(
        vault
            .origin_publication_rows(None)
            .expect("journal")
            .is_empty()
    );
}

/// The pin names WHICH object store the landing publishes into. A push that
/// only deletes advances no post-image, and reading the pin out of
/// `new_oid` alone is what dropped those pushes: no pin, no handle, no
/// landing, and a mutated repository with no receipt.
#[test]
fn smart_http_delete_only_updates_still_name_a_pin() {
    let advanced = GitOid::parse_hex("a".repeat(40)).expect("post-image oid");
    let decided_against = GitOid::parse_hex("b".repeat(40)).expect("pre-image oid");
    let creation = RefUpdate {
        name: "refs/heads/main".to_owned(),
        old_oid: None,
        new_oid: Some(advanced.clone()),
    };
    let deletion = RefUpdate {
        name: "refs/heads/old".to_owned(),
        old_oid: Some(decided_against.clone()),
        new_oid: None,
    };

    assert_eq!(
        landing_pin(std::slice::from_ref(&deletion)),
        Some(&decided_against),
        "a delete-only push pins the pre-image it was decided against, so it lands"
    );
    let mixed = [deletion, creation];
    assert_eq!(
        landing_pin(&mixed),
        Some(&advanced),
        "a mixed push still pins the post-image it advanced"
    );
    assert_eq!(landing_pin(&[]), None, "nothing proposed pins nothing");
}

#[test]
fn smart_http_landed_door_hook_rejects_secret_shaped_added_lines() {
    let (_dir, vault) = temp_vault();
    let door = CredentialDoorService::new(Arc::clone(&vault));
    let repo = unpinned_repo_ref(Path::new("/tmp/demo.git"));
    let blob = PushedBlob {
        path: "config.env".to_owned(),
        oid: "1".repeat(40),
        added_lines: vec![b"ghp_0123456789abcdefghijklmnopqrstuvwxyz".to_vec()],
    };
    let verdict =
        DoorHook::pre_receive_scan(&door, &repo, std::slice::from_ref(&blob)).expect("scan");
    assert!(
        matches!(verdict, DoorScanVerdict::Rejected { .. }),
        "the landed door's scan is unconditional"
    );
    let clean = scan_through(&NoopDoorHook, &repo, std::slice::from_ref(&blob));
    assert_eq!(
        clean,
        DoorWindowVerdict::Clean,
        "the no-op default is the seam without behavior"
    );
}

#[test]
fn receive_pack_landing_never_writes_sync_plane() {
    let (_vault_dir, vault) = temp_vault();
    let (_repo_dir, root, oid) = seeded_repo();
    let outcome = landing_outcome(&root, &oid);
    let repo = outcome.pinned_repo_ref().expect("pinned repo ref");

    let mut expected = sync_plane_rows(&vault);
    let landing = vault
        .apply_receive_pack_fixture(&repo, &outcome)
        .expect("land receive-pack outcome");
    assert!(
        !landing.replayed,
        "the first landing journals its own record"
    );

    // These LEDGER claims are required. Their generic CLAIM puts create
    // pe:<claim-id> markers in sync_state, not Git replication payloads.
    let records = vault
        .origin_publication_rows(None)
        .expect("publication journal");
    let [record] = records.as_slice() else {
        panic!("one landed ref must have exactly one publication record");
    };
    assert_eq!(record.status, OriginPublicationStatus::Published);
    let source = vault
        .get_claim(&record.provenance_claim_id)
        .expect("read outcome claim")
        .expect("durable outcome claim");
    let operation_id = EntityId::from_hex(
        receive_pack_field(&source, "operation_id")
            .expect("outcome operation")
            .as_str()
            .expect("operation id string"),
    )
    .expect("operation entity id");
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let epoch =
        crate::hnsw::read_embedding_model_epoch(&vault.store, &rtxn).expect("embedding epoch");
    for (id, predicate) in [
        (operation_id, RECEIVE_PACK_ADMISSION_PREDICATE),
        (record.provenance_claim_id, RECEIVE_PACK_OUTCOME_PREDICATE),
        (
            record
                .publication_claim_id
                .expect("durable publication claim id"),
            crate::origin::publication::ORIGIN_PUBLICATION_PREDICATE,
        ),
    ] {
        let claim = vault
            .get_claim_in_txn(&rtxn, &id)
            .expect("read ledger claim")
            .expect("durable ledger claim");
        assert_eq!(claim.predicate, predicate);
        assert_eq!(claim.lifecycle, ClaimLifecycleStatus::Active);
        let body = encode_claim_body(&claim).expect("encode ledger claim");
        assert!(
            expected
                .insert(
                    Store::pending_embedding_marker_key(&id),
                    Store::pending_embedding_marker_token(epoch, &body).to_vec(),
                )
                .is_none(),
            "each new claim must have its own pending-embedding marker"
        );
    }
    drop(rtxn);
    assert_eq!(
        sync_plane_rows(&vault),
        expected,
        "only the ledger claims' versioned hash markers may enter sync_state; \
         no repo object/ref/pack/blob payload or other sync operation may appear"
    );
}

#[test]
fn smart_http_publication_requires_real_attribution_and_durable_provenance() {
    let (_vault_dir, vault) = temp_vault();
    let (_repo_dir, root, oid) = seeded_repo();
    let outcome = landing_outcome(&root, &oid);
    let repo = outcome.pinned_repo_ref().expect("repo");
    assert!(
        vault.apply_receive_pack_update(&repo, &outcome).is_err(),
        "an outcome with no journal cannot invent its actor or provenance"
    );
    let missing = ReceivePackAttribution {
        actor_id: EntityId::now(),
        provenance_claim_id: EntityId::now(),
    };
    assert!(
        vault
            .apply_receive_pack_update_with_attribution(&repo, &outcome, &missing)
            .is_err(),
        "an allocated id is not a durable source claim"
    );
    let attribution = fixture_attribution(&vault, &outcome);
    let source = vault
        .get_claim(&attribution.provenance_claim_id)
        .expect("source")
        .expect("claim");
    let copied_id = EntityId::now();
    vault
        .put_claim(&copied_id, &source, landing_time(), now_secs())
        .expect("generic copied claim");
    let copied = ReceivePackAttribution {
        provenance_claim_id: copied_id,
        ..attribution
    };
    assert!(
        vault
            .apply_receive_pack_update_with_attribution(&repo, &outcome, &copied)
            .is_err(),
        "even a semantically identical claim has no local observer receipt"
    );
    let mut unrelated = source.clone();
    unrelated.predicate = "test.unrelated_source".to_owned();
    let unrelated_id = EntityId::now();
    vault
        .put_claim(&unrelated_id, &unrelated, landing_time(), now_secs())
        .expect("unrelated active claim");
    assert!(
        vault
            .apply_receive_pack_update_with_attribution(
                &repo,
                &outcome,
                &ReceivePackAttribution {
                    provenance_claim_id: unrelated_id,
                    ..attribution
                }
            )
            .is_err()
    );
    let wrong_actor = ReceivePackAttribution {
        actor_id: EntityId::now(),
        ..attribution
    };
    assert!(
        vault
            .apply_receive_pack_update_with_attribution(&repo, &outcome, &wrong_actor)
            .is_err()
    );
    let (_other_dir, other_root, other_oid) = seeded_repo();
    let other = landing_outcome(&other_root, &other_oid);
    assert!(
        vault
            .apply_receive_pack_update_with_attribution(
                &other.pinned_repo_ref().expect("other repo"),
                &other,
                &attribution
            )
            .is_err()
    );
    let mut different_operation = outcome.clone();
    different_operation.ref_updates[0].name = "refs/heads/forged".to_owned();
    assert!(
        vault
            .apply_receive_pack_update_with_attribution(&repo, &different_operation, &attribution)
            .is_err()
    );
    let mut different_intent = outcome.clone();
    different_intent.ref_updates[0].old_oid = Some(oid.clone());
    assert!(
        vault
            .apply_receive_pack_update_with_attribution(&repo, &different_intent, &attribution)
            .is_err()
    );
    let mut different_result = outcome.clone();
    different_result.pack_stats.request_bytes += 1;
    assert!(
        vault
            .apply_receive_pack_update_with_attribution(&repo, &different_result, &attribution)
            .is_err()
    );
    let wire = GitWire::new(&vault).expect("wire");
    let handle = wire.open_repo(repo.clone(), &root).expect("handle");
    let wrong_ref_request = OriginPublicationRequest {
        repo_id: lfs_repo_id(&handle.identity().as_hex()).expect("repo id"),
        repo: handle,
        ref_name: GitRefName::parse_full("refs/heads/forged").expect("ref"),
        expected_old_oid: None,
        new_oid: oid.clone(),
        required_objects: vec![oid],
        required_lfs_oids: Vec::new(),
        actor_id: attribution.actor_id,
        provenance_claim_id: attribution.provenance_claim_id,
        occurred: landing_time(),
        learned_at: now_secs(),
    };
    assert!(
        vault
            .publish_origin_ref(&wire, wrong_ref_request.clone())
            .is_err(),
        "the lower publication door cannot reuse evidence for another ref"
    );
    let mut relabeled = source.clone();
    relabeled.predicate = "test.relabeled_source".to_owned();
    vault
        .put_claim(
            &attribution.provenance_claim_id,
            &relabeled,
            landing_time(),
            now_secs(),
        )
        .expect("generic predicate overwrite fixture");
    assert!(
        vault.publish_origin_ref(&wire, wrong_ref_request).is_err(),
        "rewriting a producer claim predicate cannot evade its source binding"
    );
    let mut forged = source.clone();
    if let Value::Map(fields) = &mut forged.value {
        fields
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("actor_id"))
            .expect("actor field")
            .1 = Value::from(wrong_actor.actor_id.to_hex());
    }
    vault
        .put_claim(
            &attribution.provenance_claim_id,
            &forged,
            landing_time(),
            now_secs(),
        )
        .expect("generic overwrite of claim fixture");
    assert!(
        vault
            .apply_receive_pack_update_with_attribution(&repo, &outcome, &attribution)
            .is_err(),
        "an active rewritten claim no longer matches the original observer receipt"
    );
    let mut inactive = source.clone();
    inactive.lifecycle = crate::claim::ClaimLifecycleStatus::Retracted;
    vault
        .put_claim(
            &attribution.provenance_claim_id,
            &inactive,
            landing_time(),
            now_secs(),
        )
        .expect("retract source fixture");
    assert!(
        vault
            .apply_receive_pack_update_with_attribution(&repo, &outcome, &attribution)
            .is_err()
    );
    vault
        .put_claim(
            &attribution.provenance_claim_id,
            &source,
            landing_time(),
            now_secs(),
        )
        .expect("restore exact source fixture");
    assert!(
        vault
            .origin_publication_rows(None)
            .expect("journal")
            .is_empty(),
        "every bad source is rejected before staging a publication"
    );
    vault
        .apply_receive_pack_update_with_attribution(&repo, &outcome, &attribution)
        .expect("explicit source claim");
    let repo_id = landed_repo_id(&vault, &repo, &root);
    let rows = vault
        .origin_publication_rows(Some(repo_id))
        .expect("journal");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor_id, attribution.actor_id);
    assert_eq!(rows[0].provenance_claim_id, attribution.provenance_claim_id);
    assert!(
        vault
            .get_claim(&rows[0].provenance_claim_id)
            .expect("durable source")
            .is_some()
    );
    assert!(
        vault
            .apply_receive_pack_update(&repo, &outcome)
            .expect("journal-backed replay")
            .replayed
    );
}

#[test]
fn smart_http_receive_pack_evidence_survives_reopen_and_is_not_an_id_only_anchor() {
    let (vault_dir, vault) = temp_vault();
    let (_repo_dir, root, oid) = seeded_repo();
    let outcome = landing_outcome(&root, &oid);
    let attribution = fixture_attribution(&vault, &outcome);
    let repo = outcome.pinned_repo_ref().expect("repo");
    let repo_id = landed_repo_id(&vault, &repo, &root);
    drop(vault);
    let reopened = Vault::open(vault_dir.path(), VaultConfig::default()).expect("reopen");
    reopened
        .validate_receive_pack_attribution(repo_id, &outcome, &attribution)
        .expect("both claims and their atomic local receipts survived");
    let claim = reopened
        .get_claim(&attribution.provenance_claim_id)
        .expect("read")
        .expect("claim");
    let operation = EntityId::from_hex(
        receive_pack_field(&claim, "operation_id")
            .expect("operation")
            .as_str()
            .expect("id"),
    )
    .expect("entity id");
    let mut admission = reopened
        .get_claim(&operation)
        .expect("read admission")
        .expect("admission");
    admission.lifecycle = ClaimLifecycleStatus::Retracted;
    reopened
        .put_claim(&operation, &admission, landing_time(), now_secs())
        .expect("retract fixture");
    assert!(
        reopened
            .apply_receive_pack_update_with_attribution(&repo, &outcome, &attribution)
            .is_err(),
        "an active outcome cannot launder an inactive admission"
    );
    assert!(
        reopened
            .origin_publication_rows(None)
            .expect("journal")
            .is_empty()
    );
}

#[test]
fn smart_http_replayed_receive_pack_outcome_is_a_noop() {
    let (_vault_dir, vault) = temp_vault();
    let (_repo_dir, root, oid) = seeded_repo();
    let outcome = landing_outcome(&root, &oid);
    let repo = outcome.pinned_repo_ref().expect("pinned repo ref");

    let first = vault
        .apply_receive_pack_fixture(&repo, &outcome)
        .expect("first landing");
    let second = vault
        .apply_receive_pack_fixture(&repo, &outcome)
        .expect("replayed landing");
    assert!(!first.replayed);
    assert!(
        second.replayed,
        "a replayed outcome is answered from the durable record"
    );
    assert_eq!(
        first.receipt.record_key, second.receipt.record_key,
        "the replay writes no second record"
    );
}

#[test]
fn smart_http_observed_refs_gate_the_landing() {
    let (_vault_dir, vault) = temp_vault();
    let (_repo_dir, root, oid) = seeded_repo();
    let outcome = landing_outcome(&root, &oid);
    let repo = outcome.pinned_repo_ref().expect("pinned repo ref");

    let applied = refs_already_applied(
        &vault,
        &repo,
        &root,
        &[ObservedRef {
            name: "refs/heads/main".to_owned(),
            oid: Some(oid),
        }],
    )
    .expect("observe refs");
    assert!(applied, "the pushed value is what the repository carries");

    let stale = refs_already_applied(
        &vault,
        &repo,
        &root,
        &[ObservedRef {
            name: "refs/heads/main".to_owned(),
            oid: None,
        }],
    )
    .expect("observe refs");
    assert!(!stale, "an absent expectation does not match a live ref");
}

#[test]
fn smart_http_landing_refuses_an_empty_publication() {
    let (_vault_dir, vault) = temp_vault();
    let (_repo_dir, root, oid) = seeded_repo();
    let mut outcome = landing_outcome(&root, &oid);
    outcome.ref_updates.clear();
    let repo = RepoRef::LocalFolder {
        path: root.to_string_lossy().into_owned(),
        commit: oid.as_str().to_owned(),
    };
    assert!(
        vault.apply_receive_pack_fixture(&repo, &outcome).is_err(),
        "a landing that moves no ref is refused, never receipted"
    );
}
