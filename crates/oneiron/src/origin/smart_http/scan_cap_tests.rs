//! No origin scan refuses for how many rows it reads (rule 5): a repository
//! keeps taking pushes, advertisements and fetches past every scan's row, and
//! a settled push leaves no intent row.

use super::tests::{
    PublicationTestOrigin, advertise, commit_file, fixture_intent, git, landed_repo_id,
    pushed_outcome, ref_update, seeded_repo, served_repo, temp_vault,
};
use super::*;
use crate::config::VaultConfig;
use crate::git_wire::GitWireRepo;
use crate::origin::publication::OriginKeepRefKind;
use crate::origin::scan_check::OriginScan;

/// The row each test lowers a scan to; every fixture reads one row past it.
const ROW: u64 = 2;

fn checks_raised(vault: &Vault, scan: OriginScan) -> usize {
    vault
        .origin_scan_checks()
        .expect("origin scan checks")
        .iter()
        .filter(|check| check.scan == scan.code())
        .count()
}

/// `ROW + 1` refs, each at its own commit, published through the landing.
fn publish_refs_past_the_row(vault: &Vault, root: &Path) -> RepoRef {
    let mut updates = Vec::new();
    let mut tip = None;
    for index in 0..=ROW {
        let name = format!("refs/heads/past-{index}");
        let oid = commit_file(root, &format!("past-{index}.txt"), "past\n");
        git(root, &["update-ref", &name, oid.as_str()]);
        updates.push(ref_update(&name, None, Some(&oid)));
        tip = Some(oid);
    }
    let tip = tip.expect("one ref at least");
    for update in updates {
        let outcome = pushed_outcome(root, vec![update], Vec::new());
        let repo = outcome.pinned_repo_ref().expect("pinned repo ref");
        vault
            .apply_receive_pack_fixture(&repo, &outcome)
            .expect("publish one ref");
    }
    local_repo_ref(root, &tip).expect("repo ref")
}

/// A stock client pushes, lists and fetches past every scan's row.
/// Each settled push leaves no intent row, so the journal scan reads pending
/// pushes only, and admission reads no publication history.
#[test]
fn a_repository_keeps_serving_past_every_scan_row() {
    let (_vault_dir, vault) = temp_vault();
    for scan in OriginScan::ALL {
        vault
            .set_origin_scan_threshold(scan, ROW)
            .expect("lower the row");
    }
    let (source, repo_dir, first, second) = served_repo(&vault);
    let origin = PublicationTestOrigin::start(&vault, EntityId::now());
    let url = origin.url();
    git(&repo_dir, &["update-ref", "-d", "refs/heads/main"]);
    git(source.path(), &["push", &url, "refs/heads/main"]);
    let branches: Vec<String> = (0..=ROW).map(|index| format!("branch-{index}")).collect();
    for branch in &branches {
        git(
            source.path(),
            &[
                "push",
                &url,
                &format!("{}:refs/heads/{branch}", first.as_str()),
            ],
        );
    }
    assert_eq!(
        vault.receive_pack_intent_rows_for_test(&repo_dir),
        0,
        "every push settled, so none left its intent"
    );

    let listed = git(source.path(), &["ls-remote", "--heads", &url]);
    assert!(listed.contains(&format!("{}\trefs/heads/main", second.as_str())));
    for branch in &branches {
        assert!(
            listed.contains(&format!("{}\trefs/heads/{branch}", first.as_str())),
            "{branch} is advertised past the visible-ref row"
        );
    }
    let client = tempfile::tempdir().expect("stock client");
    git(client.path(), &["init", "--initial-branch=main"]);
    let last = format!("refs/heads/{}", branches[branches.len() - 1]);
    git(client.path(), &["fetch", &url, &last]);
    assert_eq!(
        git(client.path(), &["rev-parse", "FETCH_HEAD"]),
        first.as_str()
    );

    let repo = local_repo_ref(&repo_dir, &second).expect("pinned repo ref");
    let repo_id = landed_repo_id(&vault, &repo, &repo_dir);
    assert_eq!(
        vault
            .origin_visible_ref_rows(&repo_id)
            .expect("visible slots")
            .len(),
        1 + branches.len(),
        "each published name has its slot"
    );
    assert_eq!(checks_raised(&vault, OriginScan::VisibleRefRows), 1);
    assert_eq!(
        checks_raised(&vault, OriginScan::ReceivePackIntents),
        0,
        "the journal scan read only pending pushes"
    );
    assert_eq!(
        checks_raised(&vault, OriginScan::PublicationRows),
        0,
        "no push read the publication history"
    );
}

/// The door a scan serves through, and what it reads.
enum Door {
    /// Pending intents, as the cutover's drain check reads them.
    Intents,
    /// The diagnostics list of every publication.
    PublicationIds(EntityId),
    /// The advertisement projection.
    Projection(EntityId, GitWireRepo),
    /// The census and its keep-owner sweep.
    Census(EntityId, GitWireRepo),
}

/// The code's own list of origin scans: each serves one row past its
/// threshold row, twice, raises its check once, and refuses nothing.
#[test]
fn no_origin_scan_refuses_for_its_row_count() {
    let mut refused = Vec::new();
    for scan in OriginScan::ALL {
        let (_vault_dir, vault) = temp_vault();
        vault
            .set_origin_scan_threshold(scan, ROW)
            .expect("lower the row");
        let (_repo_dir, root, oid) = seeded_repo();
        let past = usize::try_from(ROW + 1).expect("row fits usize");
        let wire = GitWire::new(&vault).expect("git wire");
        let door = match scan {
            OriginScan::ReceivePackIntents => {
                for index in 0..past {
                    let name = format!("refs/heads/declined-{index}");
                    fixture_intent(&vault, &root, vec![ref_update(&name, None, Some(&oid))]);
                }
                Door::Intents
            }
            OriginScan::PublicationRows => {
                let repo = publish_refs_past_the_row(&vault, &root);
                Door::PublicationIds(landed_repo_id(&vault, &repo, &root))
            }
            OriginScan::VisibleRefRows => {
                let repo = publish_refs_past_the_row(&vault, &root);
                let repo_id = landed_repo_id(&vault, &repo, &root);
                Door::Projection(repo_id, wire.open_repo(repo, &root).expect("handle"))
            }
            OriginScan::KeepOwnerRows => {
                let handle = wire
                    .open_repo(local_repo_ref(&root, &oid).expect("repo ref"), &root)
                    .expect("handle");
                for index in 0..past {
                    let commit = commit_file(&root, &format!("kept-{index}.txt"), "kept\n");
                    vault
                        .pin_origin_object(
                            &wire,
                            &handle,
                            OriginKeepRefKind::Snapshot,
                            &format!("snapshot-{index}"),
                            &commit,
                            now_secs(),
                        )
                        .expect("pin");
                }
                let repo_id = lfs_repo_id(&handle.identity().as_hex()).expect("repo id");
                Door::Census(repo_id, handle)
            }
        };
        for _ in 0..2 {
            let read = match &door {
                Door::Intents => vault.receive_pack_intents(&root).map(|rows| rows.len()),
                Door::PublicationIds(repo_id) => vault
                    .origin_publication_ids(Some(*repo_id))
                    .map(|ids| ids.len()),
                Door::Projection(repo_id, handle) => vault
                    .published_origin_refs(&wire, *repo_id, handle)
                    .map(|refs| refs.len()),
                Door::Census(repo_id, handle) => vault
                    .reconcile_origin_publications(&wire, *repo_id, handle, now_secs())
                    .map(|_| past),
            };
            match read {
                Ok(rows) => assert_eq!(rows, past, "{} read every row", scan.code()),
                Err(error) => refused.push(format!("{}: {error}", scan.code())),
            }
        }
        if refused.is_empty() {
            assert_eq!(
                checks_raised(&vault, scan),
                1,
                "{} raised its check once",
                scan.code()
            );
        }
    }
    assert!(
        refused.is_empty(),
        "scans refused past their row: {refused:?}"
    );
}

/// A settled intent leaves no row; one with a ref still pending keeps its
/// row until that ref settles.
#[test]
fn a_settled_intent_is_pruned_and_a_pending_one_kept() {
    let (_vault_dir, vault) = temp_vault();
    let (_repo_dir, root, oid) = seeded_repo();
    fixture_intent(
        &vault,
        &root,
        vec![
            ref_update("refs/heads/declined", None, Some(&oid)),
            ref_update("refs/heads/pending", None, Some(&oid)),
        ],
    );
    git(&root, &["update-ref", "refs/heads/pending", oid.as_str()]);
    // The publication cannot pin its object, so the ref stays pending.
    let keep = super::super::publication::origin_keep_ref_name(&oid).expect("keep");
    let blocked = root.join(".git").join(format!("{}.lock", keep.as_str()));
    fs::create_dir_all(blocked.parent().expect("parent")).expect("directory");
    fs::write(&blocked, b"block the publication").expect("lock");
    vault
        .reconcile_receive_pack_operations(&root)
        .expect("one ref settles, one stays pending");
    assert_eq!(
        vault.receive_pack_intent_rows_for_test(&root),
        1,
        "a pending intent is never pruned"
    );
    fs::remove_file(blocked).expect("unblock");
    vault
        .reconcile_receive_pack_operations(&root)
        .expect("the last ref settles");
    assert_eq!(vault.receive_pack_intent_rows_for_test(&root), 0);
    assert_eq!(
        git(&root, &["rev-parse", "refs/heads/pending"]),
        oid.as_str()
    );
}

/// A crash between the save that settles an intent and its prune leaves a
/// settled row; the next request after a reopen prunes it, and the
/// repository serves.
#[test]
fn a_settled_row_a_crash_left_is_pruned_on_the_next_request() {
    let (vault_dir, vault) = temp_vault();
    let (_source, repo_dir, first, _second) = served_repo(&vault);
    for index in 0..=ROW {
        let name = format!("refs/heads/crashed-{index}");
        fixture_intent(
            &vault,
            &repo_dir,
            vec![ref_update(&name, None, Some(&first))],
        );
    }
    for (key, mut intent) in vault.receive_pack_intents(&repo_dir).expect("pending") {
        for entry in &mut intent.refs {
            entry.status = ReceivePackRefStatus::NotApplied;
        }
        vault
            .put_receive_pack_intent_for_test(&key, &intent)
            .expect("the settled row the crash left");
    }
    assert_eq!(
        vault.receive_pack_intent_rows_for_test(&repo_dir),
        usize::try_from(ROW + 1).expect("row fits usize")
    );
    drop(vault);
    let reopened = Arc::new(Vault::open(vault_dir.path(), VaultConfig::default()).expect("reopen"));
    reopened
        .set_origin_scan_threshold(OriginScan::ReceivePackIntents, ROW)
        .expect("lower the row");
    assert_eq!(advertise(&reopened, "git-upload-pack").status, 200);
    assert_eq!(
        reopened.receive_pack_intent_rows_for_test(&repo_dir),
        0,
        "the advertisement's reconcile pruned every settled row"
    );
}
