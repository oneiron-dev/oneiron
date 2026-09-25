//! Epoch-bound receive-pack admission, landing and crash recovery.

use super::tests::{
    CapturingSink, advertise, advertised_refs, git, ref_update, served_repo, temp_vault,
};
use super::*;
use crate::config::VaultConfig;
use crate::git_wire::GitWireRepo;
use crate::origin::residence::{OriginAuthorityLease, OriginAuthorityStamp, OriginResidence};
use std::process::{Command, Stdio};

fn epoch_repo(vault: &Vault, root: &Path, pin: &GitOid) -> GitWireRepo {
    GitWire::new(vault)
        .expect("wire")
        .open_repo(local_repo_ref(root, pin).expect("repo ref"), root)
        .expect("repo handle")
}

fn epoch_request(actor: EntityId) -> ServeRequest {
    ServeRequest {
        method: "POST".to_owned(),
        path_info: "/demo.git/git-receive-pack".to_owned(),
        query_string: String::new(),
        content_type: Some("application/x-git-receive-pack-request".to_owned()),
        content_length: None,
        content_encoding: None,
        git_protocol: None,
        remote_user: Some(actor.to_hex()),
        remote_addr: Some("127.0.0.1".to_owned()),
    }
}

fn epoch_intent(
    vault: &Vault,
    root: &Path,
    actor: EntityId,
    lease: &OriginAuthorityLease,
    updates: Vec<RefUpdate>,
) -> EntityId {
    let mut stamp =
        DoorAdmissionStamp::from_principal(EntityId::now(), &actor.to_hex(), now_secs());
    stamp.origin_authority = Some(OriginAuthorityStamp::from_lease(lease));
    vault
        .record_receive_pack_admission(root, &stamp, DoorSeam::Landed)
        .expect("admission");
    let door = DoorWindowReport {
        verdict: DoorWindowVerdict::Clean,
        ref_updates: updates,
        lfs_pointers: Vec::new(),
        quarantine_path: None,
    };
    vault
        .record_receive_pack_intent(&unpinned_repo_ref(root), &stamp, &door)
        .expect("intent");
    stamp.operation_id()
}

fn empty_pack(root: &Path) -> Vec<u8> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["pack-objects", "--stdout"])
        .stdin(Stdio::null())
        .output()
        .expect("empty pack");
    assert!(output.status.success());
    output.stdout
}

fn push_existing_object(root: &Path, oid: &GitOid, name: &str) -> Vec<u8> {
    let command = format!(
        "{} {} {name}\0report-status\n",
        "0".repeat(40),
        oid.as_str()
    );
    let mut bytes = format!("{:04x}{command}0000", command.len() + 4).into_bytes();
    bytes.extend(empty_pack(root));
    bytes
}

#[test]
fn epoch_receive_pack_host_is_not_the_pusher_and_new_authority_lands() {
    let (_vault_dir, vault) = temp_vault();
    let (_source, root, first, tip) = served_repo(&vault);
    let repo = epoch_repo(&vault, &root, &tip);
    let old_host = EntityId::now();
    let new_host = EntityId::now();
    let actor = EntityId::now();
    vault
        .set_origin_authority(&repo, None, OriginResidence::LocalVault, old_host, false)
        .expect("epoch 1");
    let old_lease = vault
        .lease_origin_authority(&repo, old_host)
        .expect("old lease");

    // Even a pusher whose actor id equals the configured host cannot provide
    // host authority through REMOTE_USER. Refusal precedes reading any bytes.
    let request = epoch_request(old_host);
    let bytes = push_existing_object(&root, &first, "refs/heads/rejected");
    let mut body = io::Cursor::new(bytes);
    let mut sink = CapturingSink::default();
    assert!(matches!(
        serve(
            &vault,
            "demo",
            &request,
            DoorSeam::Landed,
            &mut body,
            &mut sink
        ),
        Err(Error::ConcurrentWrite(_))
    ));
    assert_eq!(body.position(), 0);
    assert!(sink.body.is_empty());
    assert!(git(&root, &["for-each-ref", "refs/heads/rejected"]).is_empty());

    vault
        .set_origin_authority(&repo, Some(1), OriginResidence::CloudVault, new_host, false)
        .expect("epoch 2");
    assert!(vault.lease_origin_authority(&repo, old_host).is_err());
    let new_lease = vault
        .lease_origin_authority(&repo, new_host)
        .expect("new lease");
    let request = epoch_request(actor);
    assert!(matches!(
        serve_with_authority(
            &vault,
            "demo",
            &request,
            DoorSeam::Landed,
            &old_lease,
            &mut body,
            &mut sink
        ),
        Err(Error::ConcurrentWrite(_))
    ));
    assert_eq!(body.position(), 0);

    let bytes = push_existing_object(&root, &first, "refs/heads/epoch-two");
    let mut body = io::Cursor::new(bytes);
    let report = serve_with_authority(
        &vault,
        "demo",
        &request,
        DoorSeam::Landed,
        &new_lease,
        &mut body,
        &mut sink,
    )
    .expect("authorized CGI push");
    assert_eq!(report.status, 200);
    assert!(report.landing.is_some());
    assert_eq!(
        report.ref_results,
        vec![ReceivePackRefResult {
            name: "refs/heads/epoch-two".to_owned(),
            status: ReceivePackRefStatus::Published
        }]
    );
    assert_eq!(
        git(&root, &["rev-parse", "refs/heads/epoch-two"]),
        first.as_str()
    );
    let ids = vault.origin_publication_ids(None).expect("publications");
    assert_eq!(ids.len(), 1);
    let row = vault
        .origin_publication(ids[0])
        .expect("row")
        .expect("publication");
    assert_eq!(row.actor_id, actor);
    assert_ne!(row.actor_id, new_host);
    assert_eq!(row.status, OriginPublicationStatus::Published);
    let source = vault
        .get_claim(&row.provenance_claim_id)
        .expect("source")
        .expect("source claim");
    assert_eq!(
        receive_pack_field(&source, "origin_authority").expect("authority"),
        &OriginAuthorityStamp::evidence_value(Some(&OriginAuthorityStamp::from_lease(&new_lease)))
    );
    assert!(
        advertised_refs(&advertise(&vault, "git-upload-pack").body)
            .iter()
            .any(|(name, oid)| name == "refs/heads/epoch-two" && oid == first.as_str())
    );
}

#[test]
fn epoch_receive_pack_mirror_and_other_repo_lease_refuse_before_body() {
    let (_vault_dir, vault) = temp_vault();
    let (_source, root, _first, tip) = served_repo(&vault);
    let repo = epoch_repo(&vault, &root, &tip);
    let host = EntityId::now();
    vault
        .set_origin_authority(&repo, None, OriginResidence::LocalVault, host, false)
        .expect("authority");
    let lease = vault.lease_origin_authority(&repo, host).expect("lease");
    vault
        .set_origin_authority(&repo, Some(1), OriginResidence::CloudVault, host, true)
        .expect("mirror");
    assert!(vault.lease_origin_authority(&repo, host).is_err());
    let request = epoch_request(host);
    let mut body = io::Cursor::new(b"do not read".to_vec());
    let mut sink = CapturingSink::default();
    assert!(matches!(
        serve_with_authority(
            &vault,
            "demo",
            &request,
            DoorSeam::Landed,
            &lease,
            &mut body,
            &mut sink
        ),
        Err(Error::ConcurrentWrite(_))
    ));
    assert_eq!(body.position(), 0);
    assert!(sink.body.is_empty());

    let (_other_dir, other) = temp_vault();
    let (_source2, root2, _first2, tip2) = served_repo(&other);
    let repo2 = epoch_repo(&other, &root2, &tip2);
    other
        .set_origin_authority(&repo2, None, OriginResidence::LocalVault, host, false)
        .expect("other authority");
    // Same host and epoch do not make this a lease for another object store.
    assert!(matches!(
        serve_with_authority(
            &other,
            "demo",
            &request,
            DoorSeam::Landed,
            &lease,
            &mut body,
            &mut sink
        ),
        Err(Error::ConcurrentWrite(_))
    ));
    assert_eq!(body.position(), 0);
    assert_eq!(git(&root, &["rev-parse", "refs/heads/main"]), tip.as_str());
    assert_eq!(
        git(&root2, &["rev-parse", "refs/heads/main"]),
        tip2.as_str()
    );
}

#[test]
fn epoch_cutover_drains_crashed_old_admission_and_cannot_reauthorize_its_source() {
    let (vault_dir, vault) = temp_vault();
    let (_source, root, first, tip) = served_repo(&vault);
    let repo = epoch_repo(&vault, &root, &tip);
    let old_host = EntityId::now();
    let actor = EntityId::now();
    vault
        .set_origin_authority(&repo, None, OriginResidence::LocalVault, old_host, false)
        .expect("epoch 1");
    let lease = vault
        .lease_origin_authority(&repo, old_host)
        .expect("lease");
    epoch_intent(
        &vault,
        &root,
        actor,
        &lease,
        vec![ref_update("refs/heads/recovered", None, Some(&first))],
    );
    git(
        &root,
        &["update-ref", "refs/heads/recovered", first.as_str()],
    );
    assert!(
        vault
            .origin_publication_ids(None)
            .expect("no outcome yet")
            .is_empty()
    );
    drop(vault);

    let reopened = Vault::open(vault_dir.path(), VaultConfig::default()).expect("reopen");
    let new_host = EntityId::now();
    // Recovery still owns epoch 1 until the accepted operation is terminal.
    let authority = reopened
        .set_origin_authority(&repo, Some(1), OriginResidence::CloudVault, new_host, false)
        .expect("drained cutover");
    assert_eq!(authority.epoch, 2);
    let ids = reopened
        .origin_publication_ids(None)
        .expect("recovered publication");
    assert_eq!(ids.len(), 1);
    let row = reopened
        .origin_publication(ids[0])
        .expect("row")
        .expect("publication");
    assert_eq!(row.status, OriginPublicationStatus::Published);
    assert_eq!(row.actor_id, actor);
    let evidence = reopened
        .get_raw(&row.provenance_claim_id)
        .expect("evidence");
    reopened
        .reconcile_receive_pack_operations(&root)
        .expect("terminal epoch 1 stays terminal");
    assert_eq!(
        reopened
            .get_raw(&row.provenance_claim_id)
            .expect("unchanged evidence"),
        evidence
    );

    let wire = GitWire::new(&reopened).expect("wire");
    let current = reopened
        .lease_origin_authority(&repo, new_host)
        .expect("current lease");
    let request = OriginPublicationRequest {
        repo_id: row.repo_id,
        repo,
        ref_name: row.ref_name,
        expected_old_oid: row.expected_old_oid,
        new_oid: row.new_oid,
        required_objects: row.required_objects,
        required_lfs_oids: row.required_lfs_oids,
        provenance_claim_id: row.provenance_claim_id,
        actor_id: row.actor_id,
        occurred: row.occurred,
        learned_at: now_secs(),
    };
    assert!(
        reopened
            .publish_origin_ref_authorized(&wire, request, &current)
            .is_err()
    );
    assert_eq!(
        git(&root, &["rev-parse", "refs/heads/recovered"]),
        first.as_str()
    );
    assert_eq!(
        reopened.origin_publication_ids(None).expect("no new row"),
        ids
    );
}

#[test]
fn epoch_cutover_refuses_pending_prepublication_effect_then_drains() {
    let (_vault_dir, vault) = temp_vault();
    let (source, root, first, tip) = served_repo(&vault);
    let repo = epoch_repo(&vault, &root, &tip);
    let alias_root = source.path().join("linked-authority-admin");
    git(
        &root,
        &[
            "worktree",
            "add",
            "--detach",
            alias_root.to_str().expect("path"),
            tip.as_str(),
        ],
    );
    let admin_repo = epoch_repo(&vault, &alias_root, &tip);
    let host = EntityId::now();
    let next_host = EntityId::now();
    let epoch = vault
        .set_origin_authority(&repo, None, OriginResidence::LocalVault, host, false)
        .expect("epoch 1");
    let lease = vault.lease_origin_authority(&repo, host).expect("lease");
    epoch_intent(
        &vault,
        &root,
        EntityId::now(),
        &lease,
        vec![ref_update("refs/heads/pending", None, Some(&first))],
    );
    git(&root, &["update-ref", "refs/heads/pending", first.as_str()]);
    let keep = crate::origin::publication::origin_keep_ref_name(&first).expect("keep ref");
    let blocked = root.join(format!("{}.lock", keep.as_str()));
    fs::create_dir_all(blocked.parent().expect("parent")).expect("parent directory");
    fs::write(&blocked, b"block before Prepared row").expect("lock");
    assert!(matches!(
        vault.set_origin_authority(
            &admin_repo,
            Some(1),
            OriginResidence::CloudVault,
            next_host,
            false
        ),
        Err(Error::ConcurrentWrite(_))
    ));
    assert_eq!(
        vault.origin_authority(&repo).expect("unchanged epoch"),
        Some(epoch)
    );
    assert!(
        vault
            .origin_publication_ids(None)
            .expect("no Prepared row to count")
            .is_empty()
    );
    assert_eq!(
        git(&root, &["rev-parse", "refs/heads/pending"]),
        first.as_str()
    );
    fs::remove_file(blocked).expect("unblock");
    assert_eq!(
        vault
            .set_origin_authority(
                &admin_repo,
                Some(1),
                OriginResidence::CloudVault,
                next_host,
                false
            )
            .expect("drain before cutover")
            .epoch,
        2
    );
    let ids = vault.origin_publication_ids(None).expect("publication");
    assert_eq!(ids.len(), 1);
    assert_eq!(
        vault
            .origin_publication(ids[0])
            .expect("row")
            .expect("publication")
            .status,
        OriginPublicationStatus::Published
    );
}

#[test]
fn epoch_delete_crash_drains_before_mirror_cutover_and_stale_replay_cannot_delete() {
    let (vault_dir, vault) = temp_vault();
    let (_source, root, first, tip) = served_repo(&vault);
    let repo = epoch_repo(&vault, &root, &tip);
    let host = EntityId::now();
    let actor = EntityId::now();
    vault
        .set_origin_authority(&repo, None, OriginResidence::LocalVault, host, false)
        .expect("epoch 1");
    let lease = vault.lease_origin_authority(&repo, host).expect("lease");
    git(&root, &["update-ref", "refs/heads/deleted", first.as_str()]);
    let update = ref_update("refs/heads/deleted", Some(&first), None);
    epoch_intent(&vault, &root, actor, &lease, vec![update.clone()]);
    git(&root, &["update-ref", "-d", "refs/heads/deleted"]);
    drop(vault);
    let reopened = Vault::open(vault_dir.path(), VaultConfig::default()).expect("reopen");
    reopened
        .set_origin_authority(&repo, Some(1), OriginResidence::CloudVault, host, true)
        .expect("delete drains before mirror");
    assert!(
        reopened
            .origin_publication_ids(None)
            .expect("no advancing publication")
            .is_empty()
    );
    let rows = reopened
        .receive_pack_intents(&root)
        .expect("durable deletion");
    assert_eq!(rows[0].1.refs[0].status, ReceivePackRefStatus::Published);
    let source = EntityId::from_hex(&rows[0].1.refs[0].outcome_id).expect("source");
    git(&root, &["update-ref", "refs/heads/deleted", tip.as_str()]);
    let outcome = ReceivePackOutcome {
        repo_root: root.clone(),
        ref_updates: vec![update],
        lfs_pointers: Vec::new(),
        staged_objects_dir: root.join("objects"),
        pack_stats: PackStats {
            request_bytes: 0,
            response_bytes: 0,
            ref_update_count: 1,
        },
    };
    assert!(matches!(
        reopened.apply_receive_pack_update_with_attribution(
            &outcome.pinned_repo_ref().expect("pin"),
            &outcome,
            &ReceivePackAttribution {
                actor_id: actor,
                provenance_claim_id: source
            }
        ),
        Err(Error::ConcurrentWrite(_))
    ));
    assert_eq!(
        git(&root, &["rev-parse", "refs/heads/deleted"]),
        tip.as_str()
    );
}

#[test]
fn epoch_new_host_cannot_launder_old_observer_evidence_without_an_old_permit() {
    let (_vault_dir, vault) = temp_vault();
    let (_source, root, first, tip) = served_repo(&vault);
    let repo = epoch_repo(&vault, &root, &tip);
    let host = EntityId::now();
    let next_host = EntityId::now();
    let actor = EntityId::now();
    vault
        .set_origin_authority(&repo, None, OriginResidence::LocalVault, host, false)
        .expect("epoch 1");
    let lease = vault.lease_origin_authority(&repo, host).expect("lease");
    let mut stamp =
        DoorAdmissionStamp::from_principal(EntityId::now(), &actor.to_hex(), now_secs());
    stamp.origin_authority = Some(OriginAuthorityStamp::from_lease(&lease));
    vault
        .record_receive_pack_admission(&root, &stamp, DoorSeam::Landed)
        .expect("admission");
    let outcome = ReceivePackOutcome {
        repo_root: root.clone(),
        ref_updates: vec![ref_update("refs/heads/old-evidence", None, Some(&first))],
        lfs_pointers: Vec::new(),
        staged_objects_dir: root.join("objects"),
        pack_stats: PackStats {
            request_bytes: 0,
            response_bytes: 0,
            ref_update_count: 1,
        },
    };
    // Synthetic observer fixture exercises the lower publication door without
    // a receive intent or an existing permit masking its source-epoch check.
    let door = DoorWindowReport {
        verdict: DoorWindowVerdict::Clean,
        ref_updates: outcome.ref_updates.clone(),
        lfs_pointers: Vec::new(),
        quarantine_path: None,
    };
    let attribution = vault
        .record_receive_pack_outcome(&stamp, &door, &outcome, 200)
        .expect("observer evidence");
    vault
        .set_origin_authority(
            &repo,
            Some(1),
            OriginResidence::CloudVault,
            next_host,
            false,
        )
        .expect("epoch 2");
    let lease = vault
        .lease_origin_authority(&repo, next_host)
        .expect("current lease");
    let request = OriginPublicationRequest {
        repo_id: lfs_repo_id(&repo.identity().as_hex()).expect("id"),
        repo,
        ref_name: GitRefName::parse_full("refs/heads/old-evidence").expect("name"),
        expected_old_oid: None,
        new_oid: first.clone(),
        required_objects: vec![first],
        required_lfs_oids: Vec::new(),
        provenance_claim_id: attribution.provenance_claim_id,
        actor_id: actor,
        occurred: TimeRange {
            start: now_secs(),
            end: now_secs(),
        },
        learned_at: now_secs(),
    };
    assert!(matches!(
        vault.publish_origin_ref_authorized(&GitWire::new(&vault).expect("wire"), request, &lease),
        Err(Error::ConcurrentWrite(_))
    ));
    assert!(git(&root, &["for-each-ref", "refs/heads/old-evidence"]).is_empty());
    assert!(
        vault
            .origin_publication_ids(None)
            .expect("no Prepared row")
            .is_empty()
    );
}
