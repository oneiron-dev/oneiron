//! Crash/recovery contract: pre-outcome crash, declined effects, partial resume,
//! supersede, delete-only, no-hook advertisement, LFS-gated publication, and
//! a recovery whose LFS check waited out.

use super::tests::{
    LANDING_LEARNED_AT, RecordingRoom, advertise, advertised_refs, commit_file,
    fixture_attribution, fixture_intent, fixture_intent_with_pointers, git, hooks_dir,
    landing_time, pointer_file, pushed_outcome, ref_update, seeded_repo, served_repo, temp_vault,
    try_advertise,
};
use super::*;
use crate::config::VaultConfig;

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
    // NotApplied settles the push, and its intent goes with it.
    assert_eq!(vault.receive_pack_intent_rows_for_test(&root), 0);
    assert!(vault.origin_publication_ids(None).expect("ids").is_empty());
    assert!(git(&root, &["for-each-ref", "refs/heads/declined"]).is_empty());
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
    let stamp =
        DoorAdmissionStamp::from_principal(EntityId::now(), &EntityId::now().to_hex(), now_secs());
    vault
        .record_receive_pack_admission(&root, &stamp, DoorSeam::Landed)
        .expect("admission");
    let door = DoorWindowReport {
        verdict: DoorWindowVerdict::Clean,
        ref_updates: updates,
        lfs_pointers: Vec::new(),
        ref_lfs_pointers: Vec::new(),
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
    assert_eq!(
        reopened.receive_pack_intent_rows_for_test(&root),
        0,
        "recovery published the last pending ref and settled the push"
    );
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
    match (&again.receipt, &replay.receipt) {
        (ReceivePackCertificate::Wire(again), ReceivePackCertificate::Wire(first)) => {
            assert_eq!(again.record_key, first.record_key);
        }
        other => panic!("a replayed push lands through its wire record: {other:?}"),
    }
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
        let stamp = DoorAdmissionStamp::from_principal(
            EntityId::now(),
            &EntityId::now().to_hex(),
            now_secs(),
        );
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
        fs::write(hooks.history_path(), b"").expect("empty history stream");
        let report = serve_door_window(
            &vault,
            &repo,
            &hooks,
            &AtomicBool::new(false),
            Instant::now() + DOOR_WINDOW_TIMEOUT,
            DoorWindowContext {
                seam,
                admission: Some(&stamp),
                scan: ScanBounds::default(),
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
    assert_eq!(
        vault.receive_pack_intent_rows_for_test(&root),
        0,
        "Superseded settles the push"
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

/// Journal bytes one recovery of a push of `refs` declined creations writes,
/// intent included.
fn declined_push_journal_bytes(refs: usize) -> u64 {
    let (_vault_dir, vault) = temp_vault();
    let (_repo_dir, root, oid) = seeded_repo();
    let updates = (0..refs)
        .map(|index| ref_update(&format!("refs/heads/declined-{index:05}"), None, Some(&oid)))
        .collect();
    let written = || super::intent::JOURNAL_BYTES_WRITTEN.with(std::cell::Cell::get);
    let before = written();
    fixture_intent(&vault, &root, updates);
    vault
        .reconcile_receive_pack_operations(&root)
        .expect("census");
    // Settled, the push is pruned (#1473); every creation was declined, so
    // nothing published.
    assert_eq!(vault.receive_pack_intent_rows_for_test(&root), 0);
    assert!(vault.origin_publication_ids(None).expect("ids").is_empty());
    written() - before
}

/// A push's intent is written once and its progress batch by batch, so the
/// journal bytes a push writes grow linearly in its refs: four times the refs
/// write four times the bytes, not sixteen.
#[test]
fn receive_pack_journal_bytes_grow_linearly_in_the_refs_a_push_names() {
    let small = declined_push_journal_bytes(2_500);
    let large = declined_push_journal_bytes(10_000);
    assert!(
        large * 10 <= small * 4 * 11,
        "2,500 refs wrote {small} bytes, 10,000 wrote {large}"
    );
}

/// Recovery resumes from a push's saved progress: a batch saved as observed
/// before a crash is read back as observed, so a ref another writer moved
/// since is superseded rather than declined, and every other ref publishes.
#[test]
fn receive_pack_recovery_resumes_from_progress_saved_mid_push() {
    let (_vault_dir, vault) = temp_vault();
    let (_repo_dir, root, first) = seeded_repo();
    let later = commit_file(&root, "later.txt", "later\n");
    let refs = ORIGIN_REF_UPDATE_BATCH + 2;
    let names: Vec<String> = (0..refs)
        .map(|index| format!("refs/heads/resumed-{index:03}"))
        .collect();
    fixture_intent(
        &vault,
        &root,
        names
            .iter()
            .map(|name| ref_update(name, None, Some(&first)))
            .collect(),
    );
    for name in &names {
        git(&root, &["update-ref", name, first.as_str()]);
    }
    // The crash came after the first batch's observations were saved and
    // before any of its refs published.
    let (key, mut intent) = vault
        .receive_pack_intents(&root)
        .expect("journal")
        .remove(0);
    for entry in &mut intent.refs[..ORIGIN_REF_UPDATE_BATCH] {
        entry.observed = true;
    }
    vault
        .save_receive_pack_progress(&key, &intent, 0)
        .expect("first batch progress");
    git(&root, &["update-ref", &names[0], later.as_str()]);
    vault
        .reconcile_receive_pack_operations(&root)
        .expect("recover");
    // Settled, the push is pruned with its progress (#1473); the refs it
    // published, and not the one superseded, are the vault's publications.
    assert_eq!(vault.receive_pack_intent_rows_for_test(&root), 0);
    assert_eq!(vault.receive_pack_progress_rows_for_test(&root), 0);
    assert_eq!(published_ref_names(&vault), names[1..].to_vec());
    assert_eq!(git(&root, &["rev-parse", &names[0]]), later.as_str());
}

/// A progress row is applied only as its writer saves it: exactly its own
/// batch of its own intent (review round 3, both F2). A row that runs into the
/// next batch, falls short of its own, or names a batch past the intent is
/// refused, never read as settling a ref.
#[test]
fn receive_pack_progress_rows_of_another_shape_are_refused() {
    let refs = ORIGIN_REF_UPDATE_BATCH + 1;
    let settled = |count: usize| vec![(true, ReceivePackRefStatus::Published); count];
    for (batch, row) in [
        (0, settled(refs)),
        (0, settled(ORIGIN_REF_UPDATE_BATCH - 1)),
        (2, Vec::new()),
    ] {
        let (_vault_dir, vault) = temp_vault();
        let (_repo_dir, root, oid) = seeded_repo();
        let updates = (0..refs)
            .map(|index| ref_update(&format!("refs/heads/shaped-{index:03}"), None, Some(&oid)))
            .collect();
        fixture_intent(&vault, &root, updates);
        let (key, _) = vault
            .receive_pack_intents(&root)
            .expect("journal")
            .remove(0);
        vault
            .put_receive_pack_progress_for_test(&key, batch, row.clone())
            .expect("planted row");
        assert!(
            matches!(
                vault.receive_pack_intents(&root),
                Err(Error::CorruptedIndex("receive-pack progress batch"))
            ),
            "batch {batch} with {} refs",
            row.len()
        );
    }
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
    assert_eq!(
        reopened.receive_pack_intent_rows_for_test(&repo_dir),
        0,
        "the recovered push settled"
    );
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

/// Review r12 narrow (Astra R12n-2, P1): recovery that waited past the
/// host's room to check an LFS object swallowed the error, went on to wait
/// as long again for the next pending ref, and let the exchange answer as if
/// it had recovered, hiding refs whose objects are whole. It now stops at
/// the first such wait and says so; the refs stay Pending, and recovery
/// publishes them once room comes.
#[test]
fn recovery_stops_at_an_lfs_check_that_waited_out_and_leaves_its_refs_pending() {
    let (_vault_dir, vault) = temp_vault();
    let bytes = b"an asset two recovered branches carry".to_vec();
    let oid = LfsOid::digest(&bytes);
    let size = u64::try_from(bytes.len()).expect("size");
    vault
        .put_lfs_object(oid, &bytes, landing_time(), LANDING_LEARNED_AT)
        .expect("asset");
    let (_source, repo_dir, _first, _second) = served_repo(&vault);
    let work = tempfile::tempdir().expect("work tree");
    let served = repo_dir.to_str().expect("utf-8 repo path");
    git(work.path(), &["clone", "--quiet", "--", served, "."]);
    let tip = commit_file(work.path(), "assets/logo.bin", &pointer_file(oid, size));
    let branches = ["refs/heads/one", "refs/heads/two"];
    for branch in branches {
        let target = format!("HEAD:{branch}");
        git(work.path(), &["push", "--quiet", "origin", &target]);
    }
    fixture_intent_with_pointers(
        &vault,
        &repo_dir,
        branches
            .iter()
            .map(|branch| ref_update(branch, None, Some(&tip)))
            .collect(),
        vec![LfsPushedPointer {
            path: "assets/logo.bin".to_owned(),
            oid,
            size_bytes: size,
        }],
    );
    let room = Arc::new(RecordingRoom::default());
    room.waits_run_out.store(true, Ordering::SeqCst);
    vault.set_lfs_read_room(Arc::clone(&room) as Arc<dyn crate::origin::lfs::LfsReadRoom>);

    let (served, _) = try_advertise(&vault, "git-upload-pack");
    assert!(
        matches!(
            served,
            Err(Error::Code(crate::error::CodeError::LfsReadRoomWaitedOut))
        ),
        "the advertisement says its recovery waited out: {served:?}"
    );
    assert_eq!(
        room.asked().len(),
        1,
        "recovery stopped at the first wait that ran out"
    );
    let statuses = |vault: &Vault| {
        vault.receive_pack_intents(&repo_dir).expect("journal")[0]
            .1
            .refs
            .iter()
            .map(|entry| entry.status)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        statuses(&vault),
        vec![ReceivePackRefStatus::Pending; 2],
        "the wait decided nothing"
    );

    room.waits_run_out.store(false, Ordering::SeqCst);
    let refs = advertised_refs(&advertise(&vault, "git-upload-pack").body);
    for branch in branches {
        assert!(
            refs.iter().any(|(name, _)| name == branch),
            "{branch} is published once room comes"
        );
    }
    assert!(
        vault
            .receive_pack_intents(&repo_dir)
            .expect("journal")
            .is_empty(),
        "both refs settled, so no intent is left pending"
    );
}

/// Room for `left` manifest reads, then none; counts the reads it was asked for.
#[derive(Default)]
struct RoomFor {
    left: std::sync::atomic::AtomicUsize,
    asked: std::sync::atomic::AtomicUsize,
}

impl crate::origin::lfs::LfsReadRoom for RoomFor {
    fn hold(&self, _row_bytes: u64) -> Option<Box<dyn std::any::Any + Send>> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        let left = self
            .left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            });
        left.ok()
            .map(|_| Box::new(()) as Box<dyn std::any::Any + Send>)
    }
}

/// Guards for [`three_branch_push`]'s directories.
type PushDirs = (tempfile::TempDir, tempfile::TempDir, tempfile::TempDir);

/// A vault journaling one push of three branches that carry one LFS object,
/// the branches already moved in its repository, with `room` lent to the
/// checks its recovery makes.
fn three_branch_push(room: Arc<RoomFor>) -> (PushDirs, Arc<Vault>, std::path::PathBuf) {
    let (vault_dir, vault) = temp_vault();
    let bytes = b"an asset three recovered branches carry".to_vec();
    let oid = LfsOid::digest(&bytes);
    let size = u64::try_from(bytes.len()).expect("size");
    vault
        .put_lfs_object(oid, &bytes, landing_time(), LANDING_LEARNED_AT)
        .expect("asset");
    let (source, repo_dir, _first, _second) = served_repo(&vault);
    let work = tempfile::tempdir().expect("work tree");
    let served = repo_dir.to_str().expect("utf-8 repo path");
    git(work.path(), &["clone", "--quiet", "--", served, "."]);
    let tip = commit_file(work.path(), "assets/logo.bin", &pointer_file(oid, size));
    let branches = ["refs/heads/one", "refs/heads/two", "refs/heads/three"];
    for branch in branches {
        let target = format!("HEAD:{branch}");
        git(work.path(), &["push", "--quiet", "origin", &target]);
    }
    fixture_intent_with_pointers(
        &vault,
        &repo_dir,
        branches
            .iter()
            .map(|branch| ref_update(branch, None, Some(&tip)))
            .collect(),
        vec![LfsPushedPointer {
            path: "assets/logo.bin".to_owned(),
            oid,
            size_bytes: size,
        }],
    );
    vault.set_lfs_read_room(room as Arc<dyn crate::origin::lfs::LfsReadRoom>);
    ((vault_dir, source, work), vault, repo_dir)
}

/// The ref names the vault published, in order.
fn published_ref_names(vault: &Vault) -> Vec<String> {
    let mut names: Vec<String> = vault
        .origin_publication_ids(None)
        .expect("publications")
        .into_iter()
        .filter_map(|id| vault.origin_publication(id).expect("publication"))
        .filter(|record| record.status == OriginPublicationStatus::Published)
        .map(|record| record.ref_name.as_str().to_owned())
        .collect();
    names.sort();
    names
}

/// Each ref's status, as the journal holds it on disk.
fn journaled_statuses(vault: &Vault, repo_dir: &std::path::Path) -> Vec<ReceivePackRefStatus> {
    vault.receive_pack_intents(repo_dir).expect("journal")[0]
        .1
        .refs
        .iter()
        .map(|entry| entry.status)
        .collect()
}

/// The merge of #1464 into #1468's batched recovery (Engine, 10-15): a
/// recovery whose LFS check waits out after some refs of its batch have
/// published keeps what they published. On disk they read as Published, not
/// observed and Pending, and the next pass finishes the rest under the same
/// outcome ids, ending as a recovery that never waited out does.
#[test]
fn a_batch_that_waits_out_keeps_the_refs_it_published() {
    use ReceivePackRefStatus::{Pending, Published};
    let counted = Arc::new(RoomFor {
        left: usize::MAX.into(),
        ..RoomFor::default()
    });
    let (_dirs, clean, clean_repo) = three_branch_push(Arc::clone(&counted));
    clean
        .reconcile_receive_pack_operations(&clean_repo)
        .expect("a recovery that never waits out");
    let asked = counted.asked.load(Ordering::SeqCst);
    assert!(
        asked > 0 && asked.is_multiple_of(3),
        "{asked} reads for three refs"
    );
    assert_eq!(clean.receive_pack_intent_rows_for_test(&clean_repo), 0);

    // Room for the first two refs' reads only.
    let room = Arc::new(RoomFor {
        left: (asked / 3 * 2).into(),
        ..RoomFor::default()
    });
    let (_dirs, vault, repo_dir) = three_branch_push(Arc::clone(&room));
    let waited = vault.reconcile_receive_pack_operations(&repo_dir);
    assert!(
        matches!(
            waited,
            Err(Error::Code(crate::error::CodeError::LfsReadRoomWaitedOut))
        ),
        "{waited:?}"
    );
    assert_eq!(
        journaled_statuses(&vault, &repo_dir),
        vec![Published, Published, Pending],
        "the refs the batch published are settled on disk"
    );
    assert_eq!(vault.receive_pack_progress_rows_for_test(&repo_dir), 1);

    room.left.store(usize::MAX, Ordering::SeqCst);
    vault
        .reconcile_receive_pack_operations(&repo_dir)
        .expect("the next pass");
    // Settled, the push is pruned with its progress, as the clean run's is,
    // and it published what the clean run did, each once: no ref went out
    // again under a new outcome id.
    assert_eq!(vault.receive_pack_intent_rows_for_test(&repo_dir), 0);
    assert_eq!(vault.receive_pack_progress_rows_for_test(&repo_dir), 0);
    assert_eq!(published_ref_names(&vault), published_ref_names(&clean));
    assert_eq!(
        vault.origin_publication_ids(None).expect("ids").len(),
        clean.origin_publication_ids(None).expect("ids").len()
    );
}
