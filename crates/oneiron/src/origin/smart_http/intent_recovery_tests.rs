//! Crash/recovery contract: pre-outcome crash, declined effects, partial resume,
//! supersede, delete-only, no-hook advertisement, LFS-gated publication.

use super::tests::{
    LANDING_LEARNED_AT, advertise, advertised_refs, commit_file, fixture_attribution,
    fixture_intent, git, hooks_dir, landing_time, pointer_file, pushed_outcome, ref_update,
    seeded_repo, served_repo, temp_vault,
};
use super::*;
use crate::config::VaultConfig;

#[test]
fn receive_pack_crash_before_outcome_recovers_on_noop_retry() {
    let (vault_dir, vault) = temp_vault();
    let (_repo_dir, root, oid) = seeded_repo();
    fixture_intent(
        &vault,
        &root,
        vec![ref_update("refs/heads/recovered", None, Some(&oid))],
    );
    assert!(
        vault
            .origin_publication_ids(None)
            .expect("no publication yet")
            .is_empty()
    );
    let before = vault.receive_pack_intents(&root).expect("intent");
    assert_eq!(before.len(), 1);
    assert!(!before[0].1.refs[0].observed);
    // Backend effect, followed by process loss before finish_serve writes anything.
    git(&root, &["update-ref", "refs/heads/recovered", oid.as_str()]);
    drop(before);
    drop(vault);
    let reopened = Vault::open(vault_dir.path(), VaultConfig::default()).expect("reopen");
    reopened
        .reconcile_receive_pack_operations(&root)
        .expect("no-op retry recovery");
    let rows = reopened.receive_pack_intents(&root).expect("operation");
    assert_eq!(rows[0].1.refs[0].status, ReceivePackRefStatus::Published);
    assert_eq!(
        rows[0].1.transport_bytes, None,
        "no exchange checkpoint survived"
    );
    let source_id = EntityId::from_hex(&rows[0].1.refs[0].outcome_id).expect("source id");
    let source = reopened
        .get_claim(&source_id)
        .expect("source")
        .expect("claim");
    assert_eq!(
        receive_pack_field(&source, "pack_stats").expect("unmeasured counters"),
        &receive_pack_stats_value(PackStats {
            request_bytes: 0,
            response_bytes: 0,
            ref_update_count: 1,
        })
    );
    let ids = reopened.origin_publication_ids(None).expect("ids");
    assert_eq!(ids.len(), 1);
    reopened
        .reconcile_receive_pack_operations(&root)
        .expect("repeated recovery");
    assert_eq!(
        reopened.origin_publication_ids(None).expect("same ids"),
        ids
    );
    let wire = GitWire::new(&reopened).expect("wire");
    let handle = wire
        .open_repo(local_repo_ref(&root, &oid).expect("repo"), &root)
        .expect("handle");
    assert_eq!(
        reopened
            .published_origin_refs(
                &wire,
                lfs_repo_id(&handle.identity().as_hex()).expect("id"),
                &handle,
            )
            .expect("visible")
            .len(),
        1
    );
}

#[test]
fn receive_pack_intent_without_backend_effect_never_advances_a_ref() {
    let (_vault_dir, vault) = temp_vault();
    let (_repo_dir, root, oid) = seeded_repo();
    fixture_intent(
        &vault,
        &root,
        vec![ref_update("refs/heads/declined", None, Some(&oid))],
    );
    vault
        .reconcile_receive_pack_operations(&root)
        .expect("census");
    let rows = vault.receive_pack_intents(&root).expect("operation");
    assert_eq!(rows[0].1.refs[0].status, ReceivePackRefStatus::NotApplied);
    assert!(vault.origin_publication_ids(None).expect("ids").is_empty());
    assert!(git(&root, &["for-each-ref", "refs/heads/declined"]).is_empty());
}

#[test]
fn receive_pack_multiref_partial_publication_resumes_without_rewriting_success() {
    let (vault_dir, vault) = temp_vault();
    let (_repo_dir, root, first) = seeded_repo();
    let second = commit_file(&root, "second.txt", "second\n");
    fixture_intent(
        &vault,
        &root,
        vec![
            ref_update("refs/heads/first", None, Some(&first)),
            ref_update("refs/heads/second", None, Some(&second)),
            ref_update("refs/heads/declined", None, Some(&first)),
        ],
    );
    git(&root, &["update-ref", "refs/heads/first", first.as_str()]);
    git(&root, &["update-ref", "refs/heads/second", second.as_str()]);
    let keep = super::super::publication::origin_keep_ref_name(&second).expect("keep");
    let blocked = root.join(".git").join(format!("{}.lock", keep.as_str()));
    fs::create_dir_all(blocked.parent().expect("parent")).expect("directory");
    fs::write(&blocked, b"blocked keep-ref effect").expect("block second publication");
    vault
        .reconcile_receive_pack_operations(&root)
        .expect("partial result retained");
    let rows = vault.receive_pack_intents(&root).expect("intent");
    assert_eq!(
        rows[0]
            .1
            .refs
            .iter()
            .map(|entry| entry.status)
            .collect::<Vec<_>>(),
        vec![
            ReceivePackRefStatus::Published,
            ReceivePackRefStatus::Pending,
            ReceivePackRefStatus::NotApplied,
        ]
    );
    let first_id = vault.origin_publication_ids(None).expect("first row");
    assert_eq!(first_id.len(), 1);
    let first_claim = vault
        .origin_publication(first_id[0])
        .expect("row")
        .expect("present")
        .publication_claim_id
        .expect("claim");
    let claim_bytes = vault.get_raw(&first_claim).expect("claim bytes");
    drop(rows);
    drop(vault);
    fs::remove_file(blocked).expect("unblock");
    let reopened = Vault::open(vault_dir.path(), VaultConfig::default()).expect("reopen");
    reopened
        .reconcile_receive_pack_operations(&root)
        .expect("resume remaining ref");
    let rows = reopened.receive_pack_intents(&root).expect("operation");
    assert_eq!(rows[0].1.refs[1].status, ReceivePackRefStatus::Published);
    assert_eq!(rows[0].1.refs[2].status, ReceivePackRefStatus::NotApplied);
    assert_eq!(
        reopened.origin_publication_ids(None).expect("rows").len(),
        2
    );
    assert_eq!(
        reopened.get_raw(&first_claim).expect("unchanged claim"),
        claim_bytes
    );
}

#[test]
fn receive_pack_measured_partial_outcome_survives_recovery() {
    let (vault_dir, vault) = temp_vault();
    let (_repo_dir, root, first) = seeded_repo();
    let second = commit_file(&root, "second.txt", "second\n");
    let updates = vec![
        ref_update("refs/heads/pending", None, Some(&first)),
        ref_update("refs/heads/published", None, Some(&second)),
        ref_update("refs/heads/declined", None, Some(&first)),
    ];
    let stamp = DoorAdmissionStamp::from_principal(&EntityId::now().to_hex(), now_secs());
    vault
        .record_receive_pack_admission(&root, &stamp, DoorSeam::Landed)
        .expect("admission");
    let door = DoorWindowReport {
        verdict: DoorWindowVerdict::Clean,
        ref_updates: updates,
        lfs_pointers: Vec::new(),
        quarantine_path: None,
    };
    vault
        .record_receive_pack_intent(&unpinned_repo_ref(&root), &stamp, &door)
        .expect("pre-effect intent");
    git(&root, &["update-ref", "refs/heads/pending", first.as_str()]);
    git(
        &root,
        &["update-ref", "refs/heads/published", second.as_str()],
    );
    let keep = super::super::publication::origin_keep_ref_name(&first).expect("keep");
    let blocked = root.join(".git").join(format!("{}.lock", keep.as_str()));
    fs::create_dir_all(blocked.parent().expect("parent")).expect("directory");
    fs::write(&blocked, b"block first publication").expect("lock");
    let request = ServeRequest {
        method: "POST".to_owned(),
        path_info: "/demo.git/git-receive-pack".to_owned(),
        query_string: String::new(),
        content_type: Some("application/x-git-receive-pack-request".to_owned()),
        content_length: None,
        content_encoding: None,
        git_protocol: None,
        remote_user: Some(stamp.principal_ref().to_owned()),
        remote_addr: None,
    };
    // Synthetic exchange input for this crash-window test. The stock-client
    // fixture separately checks these fields against actual streamed bytes.
    let report = finish_serve(
        &vault,
        &request,
        &root,
        Some(stamp),
        ServeExchange {
            status: 200,
            request_bytes: 1234,
            response_bytes: 567,
            door,
            stderr: String::new(),
        },
    )
    .expect("finish partial exchange");
    assert!(report.landing.is_none(), "not a whole-push success");
    assert_eq!(
        report
            .ref_results
            .iter()
            .map(|entry| entry.status)
            .collect::<Vec<_>>(),
        vec![
            ReceivePackRefStatus::Pending,
            ReceivePackRefStatus::Published,
            ReceivePackRefStatus::NotApplied,
        ]
    );
    let outcome = report.outcome.as_ref().expect("certified ref outcome");
    assert_eq!(outcome.ref_updates.len(), 1, "no aggregate replay token");
    assert_eq!(outcome.ref_updates[0].name, "refs/heads/published");
    assert_eq!(
        outcome.pack_stats,
        PackStats {
            request_bytes: 1234,
            response_bytes: 567,
            ref_update_count: 1,
        }
    );
    let repo = outcome.pinned_repo_ref().expect("repo");
    let replay = vault
        .apply_receive_pack_update(&repo, outcome)
        .expect("exact replay");
    assert!(replay.replayed);
    let rows = vault.receive_pack_intents(&root).expect("checkpoint");
    assert_eq!(rows[0].1.transport_bytes, Some((1234, 567)));
    let pending_id = EntityId::from_hex(&rows[0].1.refs[0].outcome_id).expect("pending source");
    let evidence = vault.get_raw(&pending_id).expect("original evidence");
    assert!(evidence.is_some());
    drop(rows);
    drop(vault);
    fs::remove_file(blocked).expect("unblock");
    let reopened = Vault::open(vault_dir.path(), VaultConfig::default()).expect("reopen");
    reopened
        .reconcile_receive_pack_operations(&root)
        .expect("recover");
    let rows = reopened
        .receive_pack_intents(&root)
        .expect("recovered intent");
    assert_eq!(rows[0].1.transport_bytes, Some((1234, 567)));
    assert_eq!(rows[0].1.refs[0].status, ReceivePackRefStatus::Published);
    assert_eq!(rows[0].1.refs[1].status, ReceivePackRefStatus::Published);
    assert_eq!(rows[0].1.refs[2].status, ReceivePackRefStatus::NotApplied);
    assert_eq!(
        reopened.get_raw(&pending_id).expect("same evidence"),
        evidence
    );
    let source = reopened
        .get_claim(&pending_id)
        .expect("source")
        .expect("claim");
    assert_eq!(
        receive_pack_field(&source, "pack_stats").expect("durable counters"),
        &receive_pack_stats_value(outcome.pack_stats)
    );
    let again = reopened
        .apply_receive_pack_update(&repo, outcome)
        .expect("replay after reopen");
    assert!(again.replayed);
    assert_eq!(again.receipt.record_key, replay.receipt.record_key);
    assert!(git(&root, &["for-each-ref", "refs/heads/declined"]).is_empty());
}

#[test]
fn receive_pack_hook_requires_durable_intent_before_releasing_the_backend() {
    let (_vault_dir, vault) = temp_vault();
    let (_repo_dir, root, oid) = seeded_repo();
    let repo = unpinned_repo_ref(&root);
    for (seam, admitted) in [
        (DoorSeam::Landed, true),
        (DoorSeam::Noop, true),
        (DoorSeam::Landed, false),
    ] {
        let (_hook_root, hooks) = hooks_dir();
        let stamp = DoorAdmissionStamp::from_principal(&EntityId::now().to_hex(), now_secs());
        if admitted {
            vault
                .record_receive_pack_admission(&root, &stamp, seam)
                .expect("admission");
        }
        fs::write(
            hooks.request_path(),
            format!(
                "ref {} {} refs/heads/hook-test\n",
                "0".repeat(40),
                oid.as_str(),
            ),
        )
        .expect("request");
        fs::write(hooks.blobs_path(), b"").expect("empty added-blob stream");
        let report = serve_door_window(
            &vault,
            &repo,
            &hooks,
            &AtomicBool::new(false),
            Instant::now() + DOOR_WINDOW_TIMEOUT,
            DoorWindowContext {
                seam,
                admission: Some(&stamp),
            },
        )
        .expect("window answered");
        let rows = vault.receive_pack_intents(&root).expect("journal");
        let row = rows
            .iter()
            .find(|(_, row)| row.operation_id == stamp.operation_id.to_hex());
        let allowed = admitted && seam == DoorSeam::Landed;
        assert_eq!(report.admitted(), allowed);
        assert_eq!(
            fs::read_to_string(hooks.verdict_path()).expect("verdict") == DOOR_VERDICT_OK,
            allowed
        );
        assert_eq!(
            row.is_some(),
            allowed,
            "no OK can exist without its durable intent"
        );
        if let Some((_, row)) = row {
            assert_eq!(row.refs[0].name, "refs/heads/hook-test");
            assert!(!row.refs[0].observed);
            assert_eq!(row.refs[0].status, ReceivePackRefStatus::Pending);
        }
        assert!(git(&root, &["for-each-ref", "refs/heads/hook-test"]).is_empty());
        assert!(
            vault
                .origin_publication_ids(None)
                .expect("no publication")
                .is_empty()
        );
    }
}

#[test]
fn receive_pack_partial_effect_superseded_before_recovery_is_not_reapplied() {
    let (_vault_dir, vault) = temp_vault();
    let (_repo_dir, root, first) = seeded_repo();
    let later = commit_file(&root, "later.txt", "later\n");
    fixture_intent(
        &vault,
        &root,
        vec![ref_update("refs/heads/pending", None, Some(&first))],
    );
    git(&root, &["update-ref", "refs/heads/pending", first.as_str()]);
    let keep = super::super::publication::origin_keep_ref_name(&first).expect("keep");
    let blocked = root.join(".git").join(format!("{}.lock", keep.as_str()));
    fs::create_dir_all(blocked.parent().expect("parent")).expect("directory");
    fs::write(&blocked, b"block publication").expect("lock");
    vault
        .reconcile_receive_pack_operations(&root)
        .expect("observed but pending");
    let rows = vault.receive_pack_intents(&root).expect("journal");
    assert!(rows[0].1.refs[0].observed);
    assert_eq!(rows[0].1.refs[0].status, ReceivePackRefStatus::Pending);
    git(&root, &["update-ref", "refs/heads/pending", later.as_str()]);
    fs::remove_file(blocked).expect("unlock");
    vault
        .reconcile_receive_pack_operations(&root)
        .expect("do not overwrite later writer");
    let rows = vault.receive_pack_intents(&root).expect("journal");
    assert_eq!(rows[0].1.refs[0].status, ReceivePackRefStatus::Superseded);
    assert!(
        rows[0].1.refs[0].observed,
        "do not erase the earlier partial effect"
    );
    assert_eq!(
        git(&root, &["rev-parse", "refs/heads/pending"]),
        later.as_str()
    );
    assert!(
        vault
            .origin_publication_ids(None)
            .expect("no publication")
            .is_empty()
    );
}

#[test]
fn receive_pack_delete_crash_recovers_operation_without_inventing_an_advance() {
    let (vault_dir, vault) = temp_vault();
    let (_repo_dir, root, oid) = seeded_repo();
    git(&root, &["update-ref", "refs/heads/deleted", oid.as_str()]);
    fixture_intent(
        &vault,
        &root,
        vec![ref_update("refs/heads/deleted", Some(&oid), None)],
    );
    git(&root, &["update-ref", "-d", "refs/heads/deleted"]);
    drop(vault);
    let reopened = Vault::open(vault_dir.path(), VaultConfig::default()).expect("reopen");
    reopened
        .reconcile_receive_pack_operations(&root)
        .expect("recover deletion");
    let rows = reopened.receive_pack_intents(&root).expect("journal");
    assert_eq!(rows[0].1.refs[0].status, ReceivePackRefStatus::Published);
    assert!(rows[0].1.refs[0].observed);
    let evidence_id = EntityId::from_hex(&rows[0].1.refs[0].outcome_id).expect("id");
    let bytes = reopened.get_raw(&evidence_id).expect("evidence");
    assert!(bytes.is_some());
    reopened
        .reconcile_receive_pack_operations(&root)
        .expect("idempotent deletion");
    assert_eq!(
        reopened.get_raw(&evidence_id).expect("evidence unchanged"),
        bytes
    );
    assert!(
        reopened
            .origin_publication_ids(None)
            .expect("no advancing claim")
            .is_empty()
    );
    assert!(git(&root, &["for-each-ref", "refs/heads/deleted"]).is_empty());
}

#[test]
fn receive_pack_no_hook_advertisement_recovers_a_pre_outcome_crash() {
    let (vault_dir, vault) = temp_vault();
    let (_source, repo_dir, _first, oid) = served_repo(&vault);
    fixture_intent(
        &vault,
        &repo_dir,
        vec![ref_update("refs/heads/recovered", None, Some(&oid))],
    );
    git(
        &repo_dir,
        &["update-ref", "refs/heads/recovered", oid.as_str()],
    );
    assert!(
        vault
            .origin_publication_ids(None)
            .expect("before crash")
            .is_empty()
    );
    drop(vault);
    let reopened = Arc::new(Vault::open(vault_dir.path(), VaultConfig::default()).expect("reopen"));
    let response = advertise(&reopened, "git-upload-pack");
    assert!(
        advertised_refs(&response.body)
            .iter()
            .any(|(name, value)| { name == "refs/heads/recovered" && value == oid.as_str() })
    );
    let rows = reopened
        .receive_pack_intents(&repo_dir)
        .expect("recovered journal");
    assert_eq!(rows[0].1.refs[0].status, ReceivePackRefStatus::Published);
    assert_eq!(
        reopened
            .origin_publication_ids(None)
            .expect("one publication")
            .len(),
        1
    );
}

#[test]
fn receive_pack_publication_cannot_omit_lfs_or_add_unobserved_objects() {
    let (_vault_dir, vault) = temp_vault();
    let (_repo_dir, root, base) = seeded_repo();
    let bytes = b"an asset required by the observed pointer";
    let oid = LfsOid::digest(bytes);
    let size = u64::try_from(bytes.len()).expect("size");
    vault
        .put_lfs_object(oid, bytes, landing_time(), LANDING_LEARNED_AT)
        .expect("asset");
    let tip = commit_file(&root, "assets/logo.bin", &pointer_file(oid, size));
    let outcome = pushed_outcome(
        &root,
        vec![ref_update("refs/heads/observed", None, Some(&tip))],
        vec![LfsPushedPointer {
            path: "assets/logo.bin".to_owned(),
            oid,
            size_bytes: size,
        }],
    );
    let attribution = fixture_attribution(&vault, &outcome);
    let wire = GitWire::new(&vault).expect("wire");
    let repo = wire
        .open_repo(outcome.pinned_repo_ref().expect("repo"), &root)
        .expect("handle");
    let mut request = OriginPublicationRequest {
        repo_id: lfs_repo_id(&repo.identity().as_hex()).expect("id"),
        repo,
        ref_name: GitRefName::parse_full("refs/heads/observed").expect("ref"),
        expected_old_oid: None,
        new_oid: tip,
        required_objects: Vec::new(),
        required_lfs_oids: Vec::new(),
        actor_id: attribution.actor_id,
        provenance_claim_id: attribution.provenance_claim_id,
        occurred: landing_time(),
        learned_at: now_secs(),
    };
    assert!(
        vault.publish_origin_ref(&wire, request.clone()).is_err(),
        "LFS omission"
    );
    request.required_lfs_oids = vec![(oid, size)];
    request.required_objects = vec![base];
    assert!(
        vault.publish_origin_ref(&wire, request.clone()).is_err(),
        "unobserved dependency"
    );
    assert!(
        vault
            .origin_publication_ids(None)
            .expect("no prepared rows")
            .is_empty()
    );
    request.required_objects.clear();
    assert_eq!(
        vault
            .publish_origin_ref(&wire, request)
            .expect("exact evidence")
            .record
            .status,
        OriginPublicationStatus::Published
    );
}
