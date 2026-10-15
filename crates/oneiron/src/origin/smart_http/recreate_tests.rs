//! A ref deleted and pushed again at a tip it was already published at lands
//! on that earlier publication: the push settles, the ref is advertised and
//! fetches, and the move is not published a second time.

use super::tests::{
    PublicationTestOrigin, advertise, advertised_refs, commit_file, git, landing_time,
    pointer_file, seeded_repo, served_repo, temp_vault,
};
use super::*;
use crate::config::VaultConfig;
use crate::git_wire::GitWireRepo;
use crate::origin::publication::OriginPublicationRecord;

const TOPIC: &str = "refs/heads/topic";

fn publications_of(vault: &Vault, name: &str) -> Vec<OriginPublicationRecord> {
    vault
        .origin_publication_rows(None)
        .expect("publication journal")
        .into_iter()
        .filter(|row| row.ref_name.as_str() == name)
        .collect()
}

fn advertised(vault: &Arc<Vault>, service: &str, name: &str) -> Vec<String> {
    advertised_refs(&advertise(vault, service).body)
        .into_iter()
        .filter(|(advertised, _)| advertised == name)
        .map(|(_, oid)| oid)
        .collect()
}

/// An engine publication of `TOPIC` from absent to `tip` in the repository
/// at `root`, read through a handle pinned at `pin`, certifying only `tip`.
fn engine_request(
    vault: &Vault,
    root: &Path,
    pin: &GitOid,
    tip: &GitOid,
) -> (GitWireRepo, OriginPublicationRequest) {
    let wire = GitWire::new(vault).expect("git wire");
    let handle = wire
        .open_repo(local_repo_ref(root, pin).expect("repo ref"), root)
        .expect("handle");
    let request = OriginPublicationRequest {
        repo_id: lfs_repo_id(&handle.identity().as_hex()).expect("repo id"),
        repo: handle.clone(),
        ref_name: GitRefName::parse_full(TOPIC.to_owned()).expect("ref name"),
        expected_old_oid: None,
        new_oid: tip.clone(),
        required_objects: Vec::new(),
        required_lfs_oids: Vec::new(),
        provenance_claim_id: EntityId::now(),
        actor_id: EntityId::now(),
        occurred: landing_time(),
        learned_at: landing_time().start,
    };
    vault
        .put_origin_publication_intent(&request)
        .expect("durable source");
    (handle, request)
}

/// One large file's pointer and bytes: the pointer a push carries at
/// `assets/logo.bin`, a path stored in LFS.
fn large_file() -> (LfsPushedPointer, Vec<u8>) {
    let bytes = b"asset bytes the earlier publication never certified".to_vec();
    let pointer = LfsPushedPointer {
        path: "assets/logo.bin".to_owned(),
        oid: LfsOid::digest(&bytes),
        size_bytes: u64::try_from(bytes.len()).expect("length fits u64"),
    };
    (pointer, bytes)
}

fn fetched(url: &str, name: &str) -> String {
    let client = tempfile::tempdir().expect("stock client");
    git(client.path(), &["init", "--initial-branch=main"]);
    git(client.path(), &["fetch", url, name]);
    git(client.path(), &["rev-parse", "FETCH_HEAD"])
}

/// Push `topic` at A, delete it, push A again: the third push lands on the
/// first one's publication and settles, before and after a reopen.
#[test]
fn a_deleted_ref_pushed_again_at_its_tip_lands_and_settles() {
    let (vault_dir, vault) = temp_vault();
    let (source, repo_dir, first, _second) = served_repo(&vault);
    let origin = PublicationTestOrigin::start(&vault, EntityId::now());
    let url = origin.url();
    let create = format!("{}:{TOPIC}", first.as_str());
    git(source.path(), &["push", &url, &create]);
    let original = publications_of(&vault, TOPIC);
    assert_eq!(original.len(), 1);
    git(source.path(), &["push", &url, &format!(":{TOPIC}")]);
    assert!(
        advertised(&vault, "git-upload-pack", TOPIC).is_empty(),
        "a deleted ref is not advertised"
    );

    git(source.path(), &["push", &url, &create]);
    assert_eq!(
        advertised(&vault, "git-upload-pack", TOPIC),
        vec![first.as_str().to_owned()]
    );
    assert_eq!(fetched(&url, TOPIC), first.as_str());
    assert_eq!(
        publications_of(&vault, TOPIC),
        original,
        "the recreation published nothing new, and the original is unchanged"
    );
    vault
        .reconcile_receive_pack_operations(&repo_dir)
        .expect("reconcile");
    assert_eq!(
        vault.receive_pack_intent_rows_for_test(&repo_dir),
        0,
        "every push settled"
    );

    drop(origin);
    drop(vault);
    let reopened = Arc::new(Vault::open(vault_dir.path(), VaultConfig::default()).expect("reopen"));
    reopened
        .reconcile_receive_pack_operations(&repo_dir)
        .expect("reconcile after reopen");
    assert_eq!(reopened.receive_pack_intent_rows_for_test(&repo_dir), 0);
    assert_eq!(
        advertised(&reopened, "git-upload-pack", TOPIC),
        vec![first.as_str().to_owned()]
    );
}

/// Push `topic` at A, advance it to B, delete it, push A again: the ref is
/// advertised at A, never at the B its slot last named.
#[test]
fn an_older_tip_pushed_again_after_a_deletion_is_advertised() {
    let (_vault_dir, vault) = temp_vault();
    let (source, repo_dir, first, second) = served_repo(&vault);
    let origin = PublicationTestOrigin::start(&vault, EntityId::now());
    let url = origin.url();
    git(
        source.path(),
        &["push", &url, &format!("{}:{TOPIC}", first.as_str())],
    );
    git(
        source.path(),
        &["push", &url, &format!("{}:{TOPIC}", second.as_str())],
    );
    git(source.path(), &["push", &url, &format!(":{TOPIC}")]);

    git(
        source.path(),
        &["push", &url, &format!("{}:{TOPIC}", first.as_str())],
    );
    for service in ["git-upload-pack", "git-receive-pack"] {
        assert_eq!(
            advertised(&vault, service, TOPIC),
            vec![first.as_str().to_owned()],
            "{service} advertises the recreated tip"
        );
    }
    assert_eq!(fetched(&url, TOPIC), first.as_str());
    assert_eq!(publications_of(&vault, TOPIC).len(), 2);
    vault
        .reconcile_receive_pack_operations(&repo_dir)
        .expect("reconcile");
    assert_eq!(vault.receive_pack_intent_rows_for_test(&repo_dir), 0);
}

/// A publication that certified more than a stock push needs, here an
/// independent object: the push that recreates its ref after a deletion asks
/// for a subset of that proof, so it lands on the publication.
#[test]
fn a_recreation_needing_less_than_its_owner_certified_lands() {
    let (_vault_dir, vault) = temp_vault();
    let (source, repo_dir, first, second) = served_repo(&vault);
    let origin = PublicationTestOrigin::start(&vault, EntityId::now());
    let url = origin.url();
    let wire = GitWire::new(&vault).expect("git wire");
    let handle = wire
        .open_repo(
            local_repo_ref(&repo_dir, &second).expect("repo ref"),
            &repo_dir,
        )
        .expect("handle");
    let request = OriginPublicationRequest {
        repo_id: lfs_repo_id(&handle.identity().as_hex()).expect("repo id"),
        repo: handle,
        ref_name: GitRefName::parse_full(TOPIC.to_owned()).expect("ref name"),
        expected_old_oid: None,
        new_oid: first.clone(),
        // Not reachable from the tip: an obligation a stock push never names.
        required_objects: vec![second],
        required_lfs_oids: Vec::new(),
        provenance_claim_id: EntityId::now(),
        actor_id: EntityId::now(),
        occurred: landing_time(),
        learned_at: landing_time().start,
    };
    vault
        .put_origin_publication_intent(&request)
        .expect("durable source");
    let owner = vault
        .publish_origin_ref(&wire, request)
        .expect("the engine publishes topic");
    assert_eq!(owner.record.status, OriginPublicationStatus::Published);
    git(source.path(), &["push", &url, &format!(":{TOPIC}")]);

    git(
        source.path(),
        &["push", &url, &format!("{}:{TOPIC}", first.as_str())],
    );
    assert_eq!(
        advertised(&vault, "git-upload-pack", TOPIC),
        vec![first.as_str().to_owned()]
    );
    assert_eq!(fetched(&url, TOPIC), first.as_str());
    assert_eq!(publications_of(&vault, TOPIC), vec![owner.record]);
    vault
        .reconcile_receive_pack_operations(&repo_dir)
        .expect("reconcile");
    assert_eq!(vault.receive_pack_intent_rows_for_test(&repo_dir), 0);
}

/// A push whose move a `Prepared` publication owns, bringing a large file
/// that publication does not certify, is refused while the hook still
/// blocks the backend: the ref never moves, and the owner stays undecided.
#[test]
fn a_push_needing_more_than_a_prepared_owner_is_refused_before_the_ref_moves() {
    let (_vault_dir, vault) = temp_vault();
    let (source, repo_dir, _first, second) = served_repo(&vault);
    let (pointer, bytes) = large_file();
    vault
        .put_lfs_object(pointer.oid, &bytes, landing_time(), landing_time().start)
        .expect("the large file's bytes are held");
    let tip = commit_file(
        source.path(),
        &pointer.path,
        &pointer_file(pointer.oid, pointer.size_bytes),
    );
    let (_handle, request) = engine_request(&vault, &repo_dir, &second, &tip);
    let wire = GitWire::new(&vault).expect("git wire");
    let owner = vault
        .prepare_origin_publication_for_test(&wire, &request)
        .expect("a Prepared owner of the move, certifying only the tip");
    let origin = PublicationTestOrigin::start(&vault, EntityId::now());
    let pushed = std::process::Command::new("git")
        .current_dir(source.path())
        .args(["push", &origin.url(), &format!("{}:{TOPIC}", tip.as_str())])
        .output()
        .expect("run git push");
    assert!(!pushed.status.success(), "the push is refused");
    assert!(
        git(&repo_dir, &["for-each-ref", TOPIC]).is_empty(),
        "the backend never moved the ref"
    );
    assert_eq!(
        vault
            .origin_publication(owner.publication_id)
            .expect("journal")
            .expect("owner")
            .status,
        OriginPublicationStatus::Prepared
    );
}

/// A push the backend already applied, for a move a `Published` publication
/// made, that needs a large file the publication never certified, ends
/// uncertified and settled, not pending: the consumed move can never certify
/// it.
#[test]
fn an_applied_push_needing_more_than_its_owner_settles_uncertified() {
    let (_vault_dir, vault) = temp_vault();
    let (_repo_dir, root, base) = seeded_repo();
    let (pointer, bytes) = large_file();
    vault
        .put_lfs_object(pointer.oid, &bytes, landing_time(), landing_time().start)
        .expect("the large file's bytes are held");
    let tip = commit_file(
        &root,
        &pointer.path,
        &pointer_file(pointer.oid, pointer.size_bytes),
    );
    git(&root, &["update-ref", "refs/heads/main", base.as_str()]);
    let (_handle, request) = engine_request(&vault, &root, &base, &tip);
    let wire = GitWire::new(&vault).expect("git wire");
    let owner = vault
        .publish_origin_ref(&wire, request)
        .expect("the engine publishes topic, certifying only the tip");
    assert_eq!(owner.record.status, OriginPublicationStatus::Published);

    // The push recreating the same move, already applied by the backend.
    let stamp =
        DoorAdmissionStamp::from_principal(EntityId::now(), &EntityId::now().to_hex(), now_secs());
    vault
        .record_receive_pack_admission(&root, &stamp, DoorSeam::Landed)
        .expect("admission");
    let door = DoorWindowReport {
        verdict: DoorWindowVerdict::Clean,
        ref_updates: vec![RefUpdate {
            name: TOPIC.to_owned(),
            old_oid: None,
            new_oid: Some(tip),
        }],
        lfs_pointers: vec![pointer],
        quarantine_path: None,
    };
    vault
        .record_receive_pack_intent(&unpinned_repo_ref(&root), &stamp, &door)
        .expect("pre-effect durable intent");
    for _ in 0..2 {
        vault
            .reconcile_receive_pack_operations(&root)
            .expect("reconcile");
    }
    assert_eq!(
        vault.receive_pack_intent_rows_for_test(&root),
        0,
        "the push settled uncertified, not pending"
    );
    assert_eq!(publications_of(&vault, TOPIC), vec![owner.record]);
}
