//! Advertisement gate and stock-client roundtrip tests, plus the LFS
//! attach/detach landing tests.

use super::tests::{
    CapturingSink, LANDING_LEARNED_AT, PublicationTestOrigin, advertise, advertised_refs,
    advertisement_headers, commit_file, fixture_attribution, git, landed_repo_id, landing_outcome,
    landing_time, pointer_file, pushed_outcome, ref_update, seeded_repo, served_repo, temp_vault,
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
    let head = second.as_str().to_owned();
    {
        let mut gate = AdvertisedRefGate::new(&vault, &repo_dir, &mut captured);
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
    let head = "2".repeat(40);
    {
        let mut gate = AdvertisedRefGate::new(&vault, elsewhere.path(), &mut captured);
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

/// A response that is not an advertisement is not rewritten.
#[test]
fn smart_http_advertisement_gate_passes_a_non_advertisement_through() {
    let (_vault_dir, vault) = temp_vault();
    let elsewhere = tempfile::tempdir().expect("tempdir");
    let mut captured = CapturingSink::default();
    {
        let mut gate = AdvertisedRefGate::new(&vault, elsewhere.path(), &mut captured);
        gate.begin(404, &[("Content-Type".to_owned(), "text/plain".to_owned())])
            .expect("begin");
        gate.write_chunk(b"Repository not found\n")
            .expect("pass through");
    }
    assert_eq!(captured.status, 404);
    assert_eq!(captured.body, b"Repository not found\n".to_vec());
    assert_eq!(
        captured.headers,
        vec![("Content-Type".to_owned(), "text/plain".to_owned())],
        "a body this gate does not own keeps its framing"
    );
}

/// The wire version is pinned, because v2 puts the ref list where the
/// projection cannot reach it.
#[test]
fn smart_http_serve_never_forwards_a_wire_protocol_version() {
    let request = ServeRequest {
        method: "GET".to_owned(),
        path_info: "/demo.git/info/refs".to_owned(),
        query_string: "service=git-upload-pack".to_owned(),
        content_type: None,
        content_length: None,
        content_encoding: None,
        git_protocol: Some("version=2".to_owned()),
        remote_user: None,
        remote_addr: None,
    };
    assert!(request.is_ref_advertisement());
    assert!(
        !request
            .env_pairs()
            .iter()
            .any(|(key, _)| key == "HTTP_GIT_PROTOCOL"),
        "no served child is ever told to speak protocol v2"
    );

    let dumb = ServeRequest {
        query_string: String::new(),
        ..request
    };
    assert!(
        !dumb.is_ref_advertisement(),
        "a GET with no service is the dumb protocol, which carries no pkt-lines"
    );
}
