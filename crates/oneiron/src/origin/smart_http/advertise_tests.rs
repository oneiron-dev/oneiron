//! Advertisement gate and stock-client roundtrip tests, plus the LFS
//! attach/detach landing tests and the room their LFS checks take.

use super::tests::{
    CapturingSink, LANDING_LEARNED_AT, PublicationTestOrigin, RecordingRoom, advertise,
    advertised_refs, advertisement_headers, commit_file, fixture_attribution, git, landed_repo_id,
    landing_outcome, landing_time, pointer_file, pushed_outcome, ref_update, seeded_repo,
    served_repo, temp_vault, try_advertise,
};
use super::*;

/// The attachment family is an index of WHICH ref references an object, so
/// a push that moves two refs must not hand one ref's asset to the other.
/// A cartesian attachment would make every branch pushed alongside a
/// pointer a permanent referent of it, and the object would then look
/// referenced by refs whose trees never carried it.
#[test]
fn smart_http_landing_attaches_a_pointer_only_to_the_ref_that_carries_it() {
    let (_vault_dir, vault) = temp_vault();
    let bytes = b"asset bytes exactly one branch carries".to_vec();
    let oid = LfsOid::digest(&bytes);
    let size = u64::try_from(bytes.len()).expect("length fits u64");
    vault
        .put_lfs_object(oid, &bytes, landing_time(), LANDING_LEARNED_AT)
        .expect("the object the pointer names is stored before the push lands");

    let (_repo_dir, root, main_oid) = seeded_repo();
    // The pointer file exists on `assets` and on no other ref.
    git(&root, &["checkout", "-b", "assets"]);
    let assets_oid = commit_file(&root, "assets/logo.bin", &pointer_file(oid, size));

    let outcome = pushed_outcome(
        &root,
        vec![
            ref_update("refs/heads/main", None, Some(&main_oid)),
            ref_update("refs/heads/assets", None, Some(&assets_oid)),
        ],
        vec![LfsPushedPointer {
            path: "assets/logo.bin".to_owned(),
            oid,
            size_bytes: size,
        }],
    );
    let repo = outcome.pinned_repo_ref().expect("pinned repo ref");
    vault
        .apply_receive_pack_fixture(&repo, &outcome)
        .expect("land the push");

    let repo_id = landed_repo_id(&vault, &repo, &root);
    assert_eq!(
        vault
            .lfs_git_ref_objects(repo_id, "refs/heads/assets")
            .expect("read assets rows"),
        vec![oid],
        "the ref whose tree carries the pointer references the object"
    );
    assert!(
        vault
            .lfs_git_ref_objects(repo_id, "refs/heads/main")
            .expect("read main rows")
            .is_empty(),
        "a ref that never carried the pointer gains nothing by travelling with it"
    );

    // Per-ref, not all-or-nothing: the first ref and its attachment survive
    // a later conflict, and the later ref's third-party value is untouched.
    let partial = pushed_outcome(
        &root,
        vec![
            ref_update("refs/heads/partial-assets", None, Some(&assets_oid)),
            ref_update("refs/heads/main", None, Some(&assets_oid)),
        ],
        vec![LfsPushedPointer {
            path: "assets/logo.bin".to_owned(),
            oid,
            size_bytes: size,
        }],
    );
    assert!(vault.apply_receive_pack_fixture(&repo, &partial).is_err());
    assert_eq!(
        vault
            .lfs_git_ref_objects(repo_id, "refs/heads/partial-assets")
            .expect("first ref attachment"),
        vec![oid]
    );
    assert_eq!(
        git(&root, &["rev-parse", "refs/heads/main"]),
        main_oid.as_str()
    );
    assert_eq!(
        git(&root, &["rev-parse", "refs/heads/partial-assets"]),
        assets_oid.as_str()
    );
}

/// Removing a ref removes that ref's rows and nothing else.
///
/// The bytes are the point: two refs referenced this object, so the
/// deletion may not take the object down with the ref, and the surviving
/// ref's own row is still true.
#[test]
fn smart_http_landing_detaches_the_rows_of_a_deleted_ref() {
    let (_vault_dir, vault) = temp_vault();
    let bytes = b"asset bytes two branches share".to_vec();
    let oid = LfsOid::digest(&bytes);
    let size = u64::try_from(bytes.len()).expect("length fits u64");
    vault
        .put_lfs_object(oid, &bytes, landing_time(), LANDING_LEARNED_AT)
        .expect("the object the pointer names is stored before the push lands");

    let (_repo_dir, root, _base_oid) = seeded_repo();
    let carrying = commit_file(&root, "assets/logo.bin", &pointer_file(oid, size));
    // `release` publishes the very commit `main` does, so both refs carry
    // the pointer path and both reference the one object.
    git(&root, &["branch", "release", "refs/heads/main"]);

    let pointer = LfsPushedPointer {
        path: "assets/logo.bin".to_owned(),
        oid,
        size_bytes: size,
    };
    let pushed = pushed_outcome(
        &root,
        vec![
            ref_update("refs/heads/main", None, Some(&carrying)),
            ref_update("refs/heads/release", None, Some(&carrying)),
        ],
        vec![pointer],
    );
    let repo = pushed.pinned_repo_ref().expect("pinned repo ref");
    vault
        .apply_receive_pack_fixture(&repo, &pushed)
        .expect("land the push");
    let repo_id = landed_repo_id(&vault, &repo, &root);
    assert_eq!(
        vault
            .lfs_git_ref_objects(repo_id, "refs/heads/release")
            .expect("read release rows"),
        vec![oid],
        "both refs carry the pointer path, so both reference the object"
    );

    // What the origin's receive-pack already did, which the landing then
    // journals: the ref is observably gone.
    git(
        &root,
        &["update-ref", "-d", "refs/heads/release", carrying.as_str()],
    );
    let deletion = pushed_outcome(
        &root,
        vec![ref_update("refs/heads/release", Some(&carrying), None)],
        Vec::new(),
    );
    let deleted_repo = deletion
        .pinned_repo_ref()
        .expect("a delete-only push still pins its object store");
    vault
        .apply_receive_pack_fixture(&deleted_repo, &deletion)
        .expect("land the deletion");

    assert!(
        vault
            .lfs_git_ref_objects(repo_id, "refs/heads/release")
            .expect("read release rows")
            .is_empty(),
        "the removed ref's rows go with it"
    );
    assert_eq!(
        vault
            .lfs_git_ref_objects(repo_id, "refs/heads/main")
            .expect("read main rows"),
        vec![oid],
        "the ref that still carries the pointer keeps its row"
    );
    assert_eq!(
        vault.get_lfs_object(oid).expect("download"),
        Some(bytes),
        "rows come and go; shared bytes do not"
    );
}

/// One framed pkt-line.
fn pkt(text: &str) -> Vec<u8> {
    let mut framed = format!("{:04x}", text.len() + 4).into_bytes();
    framed.extend_from_slice(text.as_bytes());
    framed
}

/// A stock client sees no head before finalize and fetches actual objects
/// after publication and after recovery of a CAS-before-finalize crash.
#[test]
fn stock_git_publication_roundtrip() {
    let (_vault_dir, vault) = temp_vault();
    let (source, repo_dir, _first, second) = served_repo(&vault);
    let principal = EntityId::now();
    let origin = PublicationTestOrigin::start(&vault, principal);
    let url = origin.url();
    let client = tempfile::tempdir().expect("stock client");
    assert!(git(client.path(), &["ls-remote", "--heads", &url]).is_empty());

    // Raw repository state is not publication authority, including HEAD.
    let adopted = advertised_refs(&advertise(&vault, "git-upload-pack").body);
    assert!(
        !adopted
            .iter()
            .any(|(name, _)| name == "refs/heads/main" || name == "HEAD"),
        "an unpublished repository exposes no head before finalize"
    );

    // The raw head above was deliberately unadvertised. Remove the test
    // fixture head, then let stock Git introduce it through receive-pack.
    git(&repo_dir, &["update-ref", "-d", "refs/heads/main"]);
    git(source.path(), &["push", &url, "refs/heads/main"]);
    let repo = local_repo_ref(&repo_dir, &second).expect("pinned repo ref");
    let rows = vault
        .origin_publication_rows(None)
        .expect("production journal");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor_id, principal);
    let evidence = vault
        .get_claim(&rows[0].provenance_claim_id)
        .expect("source")
        .expect("durable source");
    assert_eq!(evidence.predicate, RECEIVE_PACK_OUTCOME_PREDICATE);
    assert_eq!(
        receive_pack_field(&evidence, "scan").expect("scan"),
        &Value::from("clean")
    );

    let wire = GitWire::new(&vault).expect("git wire");
    let handle = wire
        .open_repo(repo, &repo_dir)
        .expect("open the repository");
    let repo_id = lfs_repo_id(&handle.identity().as_hex()).expect("repo id");
    let published = vault
        .published_origin_refs(&wire, repo_id, &handle)
        .expect("the projection");
    assert_eq!(
        published,
        vec![(
            GitRefName::parse_full("refs/heads/main".to_owned()).expect("ref name"),
            second.clone()
        )],
        "the landing published exactly the head it advanced"
    );

    let served = advertised_refs(&advertise(&vault, "git-upload-pack").body);
    assert!(
        served
            .iter()
            .any(|(name, oid)| name == "refs/heads/main" && oid == second.as_str()),
        "a published head round-trips to a stock client"
    );
    assert!(
        served.iter().any(|(name, _)| name == "HEAD"),
        "the wire furniture a stock client needs is never gated away"
    );
    git(client.path(), &["init", "--initial-branch=main"]);
    git(client.path(), &["fetch", &url, "refs/heads/main"]);
    assert_eq!(
        git(client.path(), &["rev-parse", "FETCH_HEAD"]),
        second.as_str()
    );
    assert_eq!(git(client.path(), &["show", "FETCH_HEAD:NEXT.md"]), "next");

    let recovered_ref = GitRefName::parse_full("refs/heads/recovered").expect("recovered ref");
    let mut recovery_outcome = landing_outcome(&repo_dir, &second);
    recovery_outcome.ref_updates[0].name = recovered_ref.as_str().to_owned();
    let recovery_attribution = fixture_attribution(&vault, &recovery_outcome);
    let ask = OriginPublicationRequest {
        repo_id,
        repo: handle.clone(),
        ref_name: recovered_ref.clone(),
        expected_old_oid: None,
        new_oid: second.clone(),
        required_objects: vec![second.clone()],
        required_lfs_oids: Vec::new(),
        provenance_claim_id: recovery_attribution.provenance_claim_id,
        actor_id: recovery_attribution.actor_id,
        occurred: landing_time(),
        learned_at: now_secs(),
    };
    let prepared = vault
        .prepare_origin_publication_for_test(&wire, &ask)
        .expect("prepare");
    assert_eq!(prepared.status, OriginPublicationStatus::Prepared);
    assert_eq!(
        wire.read_ref(&handle, &recovered_ref)
            .expect("prepared ref"),
        None
    );
    assert!(
        wire.update_ref_cas(&handle, &recovered_ref, None, &second, now_secs())
            .expect("CAS before crash")
            .is_applied()
    );
    assert!(!git(client.path(), &["ls-remote", "--heads", &url]).contains("refs/heads/recovered"));
    let report = vault
        .reconcile_origin_publications(&wire, repo_id, &handle, now_secs())
        .expect("recover publication");
    assert!(report.items.contains(&(
        prepared.publication_id,
        crate::origin::publication::OriginCensusDisposition::FinalizedPublished,
    )));
    let recovered_client = tempfile::tempdir().expect("fresh recovery client");
    git(recovered_client.path(), &["init", "--initial-branch=main"]);
    git(
        recovered_client.path(),
        &["fetch", &url, "refs/heads/recovered"],
    );
    assert_eq!(
        git(recovered_client.path(), &["rev-parse", "FETCH_HEAD"]),
        second.as_str()
    );
    assert_eq!(
        git(recovered_client.path(), &["show", "FETCH_HEAD:NEXT.md"]),
        "next"
    );
}

/// The projection is the authority, and the repository is only ever
/// consulted to DISPROVE it.
#[test]
fn smart_http_advertisement_omits_a_ref_the_projection_disowns() {
    let (_vault_dir, vault) = temp_vault();
    let (_source, repo_dir, first, second) = served_repo(&vault);
    let outcome = landing_outcome(&repo_dir, &second);
    let repo = outcome.pinned_repo_ref().expect("pinned repo ref");
    vault
        .apply_receive_pack_fixture(&repo, &outcome)
        .expect("land the push");

    // The repository moves behind the journal's back, which is exactly the
    // state a half-finished crash or an out-of-band write leaves.
    git(
        &repo_dir,
        &["update-ref", "refs/heads/main", first.as_str()],
    );

    let served = advertised_refs(&advertise(&vault, "git-upload-pack").body);
    assert!(
        !served.iter().any(|(name, _)| name == "refs/heads/main"),
        "a managed ref the projection no longer holds is not advertised"
    );
    assert!(
        !served.iter().any(|(name, _)| name == "HEAD"),
        "HEAD cannot expose the object of a ref the projection disowns"
    );
    assert!(
        served
            .iter()
            .any(|(name, _)| name == ADVERTISED_CAPABILITIES_REF),
        "an empty projection still carries the protocol capabilities"
    );
}

/// Keep-refs are object roots, not content.
#[test]
fn smart_http_advertisement_never_carries_a_keep_ref() {
    let (_vault_dir, vault) = temp_vault();
    let (_source, repo_dir, _first, second) = served_repo(&vault);
    let outcome = landing_outcome(&repo_dir, &second);
    let repo = outcome.pinned_repo_ref().expect("pinned repo ref");
    vault
        .apply_receive_pack_fixture(&repo, &outcome)
        .expect("publish main");
    let keep = format!("{GIT_WIRE_KEEP_REF_PREFIX}object/{}", second.as_str());
    git(&repo_dir, &["update-ref", &keep, second.as_str()]);

    let served = advertised_refs(&advertise(&vault, "git-upload-pack").body);
    assert!(
        !served
            .iter()
            .any(|(name, _)| name.starts_with(GIT_WIRE_KEEP_REF_PREFIX)),
        "an internal object root is never advertised content"
    );
    assert!(
        served
            .iter()
            .any(|(name, oid)| name == "refs/heads/main" && oid == second.as_str()),
        "the refs a client came for are untouched"
    );
}

/// A stock client reads the capabilities off the FIRST ref line, so a
/// gated first line has to hand them on.
#[test]
fn smart_http_advertisement_moves_capabilities_to_the_first_surviving_ref() {
    let (_vault_dir, vault) = temp_vault();
    let (_source, repo_dir, _first, second) = served_repo(&vault);
    let outcome = landing_outcome(&repo_dir, &second);
    let repo = outcome.pinned_repo_ref().expect("pinned repo ref");
    vault
        .apply_receive_pack_fixture(&repo, &outcome)
        .expect("publish main");
    let mut captured = CapturingSink::default();
    let clock = super::exchange_idle::Progress::new();
    let head = second.as_str().to_owned();
    {
        let mut gate = AdvertisedRefGate::new(&vault, &repo_dir, true, &clock, &mut captured);
        gate.begin(200, &advertisement_headers()).expect("begin");
        let body = [
            pkt("# service=git-upload-pack\n"),
            b"0000".to_vec(),
            pkt(&format!(
                "{head} {GIT_WIRE_KEEP_REF_PREFIX}object/{head}\0side-band-64k\n"
            )),
            pkt(&format!("{head} refs/heads/main\n")),
            b"0000".to_vec(),
        ]
        .concat();
        gate.write_chunk(&body).expect("gate the advertisement");
    }

    assert!(
        !captured
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("Content-Length")),
        "a gated body is shorter than the one the backend measured"
    );
    assert_eq!(
        advertised_refs(&captured.body),
        vec![("refs/heads/main".to_owned(), head)],
        "the keep-ref is gone and the ref a client wants remains"
    );
    let text = String::from_utf8_lossy(&captured.body).into_owned();
    assert!(
        text.contains("refs/heads/main\u{0}side-band-64k\n"),
        "the capability suffix moved to the first surviving ref"
    );
}

/// An advertisement whose every ref was gated away is still a legal
/// advertisement.
#[test]
fn smart_http_advertisement_with_no_surviving_ref_still_carries_capabilities() {
    let (_vault_dir, vault) = temp_vault();
    let elsewhere = tempfile::tempdir().expect("tempdir");
    let mut captured = CapturingSink::default();
    let clock = super::exchange_idle::Progress::new();
    let head = "2".repeat(40);
    {
        let mut gate =
            AdvertisedRefGate::new(&vault, elsewhere.path(), true, &clock, &mut captured);
        gate.begin(200, &advertisement_headers()).expect("begin");
        let body = [
            pkt("# service=git-upload-pack\n"),
            b"0000".to_vec(),
            pkt(&format!(
                "{head} {GIT_WIRE_KEEP_REF_PREFIX}object/{head}\0side-band-64k symref=HEAD:refs/heads/main\n"
            )),
            pkt(&format!("{head} refs/heads/main\n")),
            pkt(&format!("{head} HEAD\n")),
            b"0000".to_vec(),
        ]
        .concat();
        gate.write_chunk(&body).expect("gate the advertisement");
    }

    assert_eq!(
        advertised_refs(&captured.body),
        vec![(
            ADVERTISED_CAPABILITIES_REF.to_owned(),
            ADVERTISED_ZERO_OID.to_owned()
        )],
        "git's own spelling for an advertisement with no refs"
    );
    let text = String::from_utf8_lossy(&captured.body).into_owned();
    assert!(
        text.contains("capabilities^{}\u{0}side-band-64k\n"),
        "the capabilities survive the last ref"
    );
    assert!(
        !text.contains("symref=HEAD:"),
        "an unresolved projection cannot leak a raw symbolic ref"
    );
}

/// Review r12 (Astra R12-2, P1): an advertisement, a landing and a redrive
/// each check that every LFS object a published ref needs is readable, and
/// each check reads the object's whole manifest; none took room for it
/// from the host, so a host holding its LFS reads to a room in memory had
/// Git exchanges reading manifests past it. Each check now takes room for
/// its manifest's stored row first and holds it through the check. A wait
/// that runs out fails the exchange instead of hiding a ref that may be
/// whole, and decides no publication.
#[test]
fn availability_checks_take_the_hosts_room_for_each_manifest_they_read() {
    let (_vault_dir, vault) = temp_vault();
    let bytes = b"asset bytes an advertised ref carries".to_vec();
    let oid = LfsOid::digest(&bytes);
    let size = u64::try_from(bytes.len()).expect("length fits u64");
    vault
        .put_lfs_object(oid, &bytes, landing_time(), LANDING_LEARNED_AT)
        .expect("the object the pointer names is stored before the push lands");
    let row = vault
        .lfs_manifest_row_bytes(oid)
        .expect("read the manifest row")
        .expect("a stored object");
    let room = Arc::new(RecordingRoom::default());
    vault.set_lfs_read_room(Arc::clone(&room) as Arc<dyn crate::origin::lfs::LfsReadRoom>);

    let (_source, repo_dir, _first, _second) = served_repo(&vault);
    let work = tempfile::tempdir().expect("work tree");
    let served = repo_dir.to_str().expect("utf-8 repo path");
    git(work.path(), &["clone", "--quiet", "--", served, "."]);
    let assets = commit_file(work.path(), "assets/logo.bin", &pointer_file(oid, size));
    git(
        work.path(),
        &["push", "--quiet", "origin", "HEAD:refs/heads/assets"],
    );
    let pointer = || LfsPushedPointer {
        path: "assets/logo.bin".to_owned(),
        oid,
        size_bytes: size,
    };
    let outcome = pushed_outcome(
        &repo_dir,
        vec![ref_update("refs/heads/assets", None, Some(&assets))],
        vec![pointer()],
    );
    let repo = outcome.pinned_repo_ref().expect("pinned repo ref");
    vault
        .apply_receive_pack_fixture(&repo, &outcome)
        .expect("land the push");
    let landed = room.asked();
    assert!(!landed.is_empty(), "the landing's check took room");

    let refs = advertised_refs(&advertise(&vault, "git-upload-pack").body);
    assert!(
        refs.iter().any(|(name, _)| name == "refs/heads/assets"),
        "the ref whose object was checked is advertised"
    );
    let asked = room.asked();
    assert!(
        asked.len() > landed.len(),
        "the advertisement's check took room"
    );
    assert!(
        asked.iter().all(|asked| *asked == row),
        "each took room by the manifest's stored row"
    );
    assert_eq!(
        room.held.load(Ordering::SeqCst),
        0,
        "each check let its room go when it ended"
    );

    // The host's waits run out from here.
    room.waits_run_out.store(true, Ordering::SeqCst);
    let (served, _) = try_advertise(&vault, "git-upload-pack");
    let error = served.expect_err("an advertisement that cannot check fails");
    assert!(
        error
            .to_string()
            .contains("no room to read an lfs manifest"),
        "it fails for the wait: {error}"
    );
    let more = commit_file(work.path(), "assets/notes.txt", "more\n");
    git(
        work.path(),
        &["push", "--quiet", "origin", "HEAD:refs/heads/more"],
    );
    let outcome = pushed_outcome(
        &repo_dir,
        vec![ref_update("refs/heads/more", None, Some(&more))],
        vec![pointer()],
    );
    let refused = vault
        .apply_receive_pack_fixture(&repo, &outcome)
        .expect_err("a landing that cannot check fails");
    assert!(
        matches!(
            refused,
            Error::Code(crate::error::CodeError::LfsReadRoomWaitedOut)
        ),
        "it fails for the wait: {refused}"
    );
    let repo_id = landed_repo_id(&vault, &repo, &repo_dir);
    let statuses = vault
        .origin_publication_rows(Some(repo_id))
        .expect("publication rows")
        .into_iter()
        .filter(|row| row.ref_name.as_str() == "refs/heads/more")
        .map(|row| row.status)
        .collect::<Vec<_>>();
    assert!(
        statuses
            .iter()
            .all(|status| *status == OriginPublicationStatus::Prepared),
        "the wait decided no publication: {statuses:?}"
    );
}

/// Two branches pushed together carry different large files at one path.
/// Each needs its own file alone: it references only that object, and once
/// the owner deletes the other branch's file it is still advertised and
/// still fetches, while the branch that needed the deleted file is hidden.
#[test]
fn branches_pushed_together_need_only_their_own_large_file_at_a_shared_path() {
    let (_vault_dir, vault) = temp_vault();
    let (source, repo_dir, _first, second) = served_repo(&vault);
    let held = |bytes: &[u8]| {
        let oid = LfsOid::digest(bytes);
        vault
            .put_lfs_object(oid, bytes, landing_time(), LANDING_LEARNED_AT)
            .expect("the large file's bytes are held");
        (oid, u64::try_from(bytes.len()).expect("length fits u64"))
    };
    let (left_oid, left_size) = held(b"the left branch's asset bytes");
    let (right_oid, right_size) = held(b"the right branch's asset bytes, another object");
    let branch = |name: &str, oid: LfsOid, size: u64| {
        git(source.path(), &["checkout", "-b", name, second.as_str()]);
        commit_file(source.path(), "assets/logo.bin", &pointer_file(oid, size))
    };
    let left = branch("left", left_oid, left_size);
    let right = branch("right", right_oid, right_size);
    let origin = PublicationTestOrigin::start(&vault, EntityId::now());
    let url = origin.url();
    git(
        source.path(),
        &[
            "push",
            &url,
            &format!("{}:refs/heads/left", left.as_str()),
            &format!("{}:refs/heads/right", right.as_str()),
        ],
    );
    let repo = local_repo_ref(&repo_dir, &left).expect("repo ref");
    let repo_id = landed_repo_id(&vault, &repo, &repo_dir);
    let references = |name: &str| {
        vault
            .lfs_git_ref_objects(repo_id, name)
            .expect("read ref rows")
    };
    let (left_rows, right_rows) = (
        references("refs/heads/left"),
        references("refs/heads/right"),
    );

    assert!(
        vault
            .delete_lfs_object(right_oid)
            .expect("the owner deletes")
    );
    let advertised = advertised_refs(&advertise(&vault, "git-upload-pack").body);
    assert!(
        advertised.contains(&("refs/heads/left".to_owned(), left.as_str().to_owned())),
        "left needs only its own file: {advertised:?}"
    );
    assert!(
        !advertised
            .iter()
            .any(|(name, _)| name == "refs/heads/right"),
        "right needs the deleted file: {advertised:?}"
    );
    let client = tempfile::tempdir().expect("stock client");
    git(client.path(), &["init", "--initial-branch=main"]);
    git(client.path(), &["fetch", &url, "refs/heads/left"]);
    assert_eq!(
        git(client.path(), &["rev-parse", "FETCH_HEAD"]),
        left.as_str()
    );
    assert_eq!(left_rows, vec![left_oid]);
    assert_eq!(right_rows, vec![right_oid]);
}
