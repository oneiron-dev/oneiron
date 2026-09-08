//! Shared test harness: fixtures, temp vault, seeded repos, the capturing sink,
//! and the stock-git test origin.

use std::process::Command as StdCommand;

use super::*;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::config::VaultConfig;
use crate::entity_id::ENTITY_ID_LEN;
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::store::Store;

pub(super) fn fixture_intent(vault: &Vault, root: &Path, updates: Vec<RefUpdate>) -> EntityId {
    let stamp = DoorAdmissionStamp::from_principal(&EntityId::now().to_hex(), now_secs());
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
        .expect("pre-effect durable intent");
    stamp.operation_id
}

// Synthetic observer input for landing/state-machine tests only. The wire
// and server roundtrips below produce this evidence through serve instead.
pub(super) fn fixture_attribution(
    vault: &Vault,
    outcome: &ReceivePackOutcome,
) -> ReceivePackAttribution {
    let stamp = DoorAdmissionStamp::from_principal(&EntityId::now().to_hex(), now_secs());
    vault
        .record_receive_pack_admission(&outcome.repo_root, &stamp, DoorSeam::Landed)
        .expect("fixture admission evidence");
    let door = DoorWindowReport {
        verdict: DoorWindowVerdict::Clean,
        ref_updates: outcome.ref_updates.clone(),
        lfs_pointers: outcome.lfs_pointers.clone(),
        quarantine_path: None,
    };
    vault
        .record_receive_pack_outcome(&stamp, &door, outcome, 200)
        .expect("fixture outcome evidence")
}

impl Vault {
    pub(super) fn apply_receive_pack_fixture(
        &self,
        repo: &RepoRef,
        outcome: &ReceivePackOutcome,
    ) -> Result<ReceivePackLanding> {
        if outcome.ref_updates.is_empty() {
            return Err(serve_failed("receive-pack outcome moved no ref"));
        }
        let wire = GitWire::new(self)?;
        let handle = wire.open_repo(repo.clone(), &outcome.repo_root)?;
        let repo_id = lfs_repo_id(&handle.identity().as_hex())?;
        let existing = self
            .origin_publication_rows(Some(repo_id))?
            .into_iter()
            .find(|row| {
                outcome.ref_updates.iter().any(|update| {
                    row.ref_name.as_str() == update.name
                        && row.expected_old_oid == update.old_oid
                        && Some(&row.new_oid) == update.new_oid.as_ref()
                })
            });
        let attribution = existing.map_or_else(
            || fixture_attribution(self, outcome),
            |row| ReceivePackAttribution {
                actor_id: row.actor_id,
                provenance_claim_id: row.provenance_claim_id,
            },
        );
        self.apply_receive_pack_update_with_attribution(repo, outcome, &attribution)
    }
}

pub(super) fn temp_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, Arc::new(vault))
}

pub(super) fn hooks_dir() -> (tempfile::TempDir, DoorHooksDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let hooks = DoorHooksDir::materialize(dir.path()).expect("materialize door hooks");
    (dir, hooks)
}

pub(super) fn git(repo: &Path, args: &[&str]) -> String {
    let output = StdCommand::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A repository with one commit on `refs/heads/main`.
pub(super) fn seeded_repo() -> (tempfile::TempDir, PathBuf, GitOid) {
    let dir = tempfile::tempdir().expect("repo tempdir");
    let root = dir.path().canonicalize().expect("canonical repo root");
    git(&root, &["init", "--initial-branch=main"]);
    std::fs::write(root.join("README.md"), "base\n").expect("write readme");
    git(&root, &["add", "--", "README.md"]);
    git(
        &root,
        &[
            "-c",
            "user.name=Oneiron",
            "-c",
            "user.email=oneiron@example.invalid",
            "commit",
            "-m",
            "initial",
        ],
    );
    let head = git(&root, &["rev-parse", "--verify", "HEAD"]);
    let oid = GitOid::parse_hex(head).expect("head oid");
    (dir, root, oid)
}

pub(super) fn landing_outcome(root: &Path, oid: &GitOid) -> ReceivePackOutcome {
    ReceivePackOutcome {
        repo_root: root.to_path_buf(),
        ref_updates: vec![RefUpdate {
            name: "refs/heads/main".to_owned(),
            old_oid: None,
            new_oid: Some(oid.clone()),
        }],
        lfs_pointers: Vec::new(),
        staged_objects_dir: root.join(".git").join("objects"),
        pack_stats: PackStats {
            request_bytes: 0,
            response_bytes: 0,
            ref_update_count: 1,
        },
    }
}

/// Narrows the live door dial by landing the one POLICY_MANIFEST row an
/// operator writes in a catastrophe.
///
/// `secret.door.allowed_effectors` is spelled out here rather than imported
/// because it is the OPERATOR-facing name, and this test is about what that
/// operator's row does to the push path. A spelling that drifted from the
/// door's own would leave the dial at its default and fail loudly below.
pub(super) fn narrow_door_effectors(vault: &Vault, effectors: Vec<rmpv::Value>) {
    let rows = vec![(
        rmpv::Value::from("secret.door.allowed_effectors"),
        rmpv::Value::Array(effectors),
    )];
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &rmpv::Value::Map(rows)).expect("encode dial body");

    let id = EntityId::from_bytes([0x51; ENTITY_ID_LEN]).expect("manifest id");
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
    payload.push(ENTITY_TYPE_POLICY_MANIFEST);
    for _ in 0..3 {
        payload.extend_from_slice(&2_u64.to_be_bytes());
    }
    payload.extend_from_slice(&body);

    let mut wtxn = vault.store.env.write_txn().expect("write txn");
    vault
        .store
        .entities
        .put(&mut wtxn, id.as_bytes(), &payload)
        .expect("put manifest");
    let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
    vault
        .store
        .type_index
        .put(&mut wtxn, &type_key, &[])
        .expect("type index row");
    wtxn.commit().expect("commit manifest");
}

pub(super) const LANDING_LEARNED_AT: u64 = 1_700_000_000;

pub(super) fn landing_time() -> TimeRange {
    TimeRange {
        start: LANDING_LEARNED_AT,
        end: LANDING_LEARNED_AT,
    }
}

/// One Git-LFS pointer file, byte for byte as a client writes it.
pub(super) fn pointer_file(oid: LfsOid, size: u64) -> String {
    format!(
        "version https://git-lfs.github.com/spec/v1\noid sha256:{}\nsize {size}\n",
        oid.to_hex()
    )
}

/// Commits one file onto the checked-out branch and returns its commit.
pub(super) fn commit_file(root: &Path, path: &str, contents: &str) -> GitOid {
    let file = root.join(path);
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent).expect("parent directory");
    }
    std::fs::write(&file, contents).expect("write file");
    git(root, &["add", "--", path]);
    git(
        root,
        &[
            "-c",
            "user.name=Oneiron",
            "-c",
            "user.email=oneiron@example.invalid",
            "commit",
            "-m",
            "carry an asset",
        ],
    );
    GitOid::parse_hex(git(root, &["rev-parse", "--verify", "HEAD"])).expect("commit oid")
}

/// The repository key the landing files its attachment rows under.
pub(super) fn landed_repo_id(vault: &Vault, repo: &RepoRef, root: &Path) -> EntityId {
    let wire = GitWire::new(vault).expect("git wire");
    let handle = wire.open_repo(repo.clone(), root).expect("open repo");
    lfs_repo_id(&handle.identity().as_hex()).expect("repo id")
}

pub(super) fn ref_update(
    name: &str,
    old_oid: Option<&GitOid>,
    new_oid: Option<&GitOid>,
) -> RefUpdate {
    RefUpdate {
        name: name.to_owned(),
        old_oid: old_oid.cloned(),
        new_oid: new_oid.cloned(),
    }
}

pub(super) fn pushed_outcome(
    root: &Path,
    ref_updates: Vec<RefUpdate>,
    lfs_pointers: Vec<LfsPushedPointer>,
) -> ReceivePackOutcome {
    ReceivePackOutcome {
        repo_root: root.to_path_buf(),
        pack_stats: PackStats {
            request_bytes: 0,
            response_bytes: 0,
            ref_update_count: ref_updates.len(),
        },
        ref_updates,
        lfs_pointers,
        staged_objects_dir: root.join(".git").join("objects"),
    }
}

/// Collects one serve response without framing it.
#[derive(Default)]
pub(super) struct CapturingSink {
    pub(super) status: u16,
    pub(super) headers: Vec<(String, String)>,
    pub(super) body: Vec<u8>,
}

impl ServeSink for CapturingSink {
    fn begin(&mut self, status: u16, headers: &[(String, String)]) -> io::Result<()> {
        self.status = status;
        self.headers = headers.to_vec();
        Ok(())
    }

    fn write_chunk(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.body.extend_from_slice(bytes);
        Ok(())
    }
}

/// A bare repository under the vault's serving root, with two commits on
/// `main`, and both commit ids.
pub(super) fn served_repo(vault: &Vault) -> (tempfile::TempDir, PathBuf, GitOid, GitOid) {
    let (dir, source, first) = seeded_repo();
    std::fs::write(source.join("NEXT.md"), "next\n").expect("write next");
    git(&source, &["add", "--", "NEXT.md"]);
    git(
        &source,
        &[
            "-c",
            "user.name=Oneiron",
            "-c",
            "user.email=oneiron@example.invalid",
            "commit",
            "-m",
            "second",
        ],
    );
    let head = git(&source, &["rev-parse", "--verify", "HEAD"]);
    let second = GitOid::parse_hex(head).expect("second oid");
    let root = origin_serving_root(vault).expect("serving root");
    let path = source.to_str().expect("utf-8 source path").to_owned();
    git(&root, &["clone", "--bare", "--", path.as_str(), "demo.git"]);
    (dir, root.join("demo.git"), first, second)
}

/// Serves one ref advertisement through the real `git http-backend`.
pub(super) fn advertise(vault: &Arc<Vault>, service: &str) -> CapturingSink {
    let request = ServeRequest {
        method: "GET".to_owned(),
        path_info: "/demo.git/info/refs".to_owned(),
        query_string: format!("service={service}"),
        content_type: None,
        content_length: None,
        content_encoding: None,
        // A stock client asks for v2; the gate declines it so the ref list
        // stays in this response, where it can be projected.
        git_protocol: Some("version=2".to_owned()),
        remote_user: Some("principal:tester".to_owned()),
        remote_addr: None,
    };
    let mut body = io::empty();
    let mut sink = CapturingSink::default();
    serve(
        vault,
        "demo",
        &request,
        DoorSeam::Noop,
        &mut body,
        &mut sink,
    )
    .expect("serve the advertisement");
    sink
}

/// The `(name, oid)` pairs one advertisement body carries.
pub(super) fn advertised_refs(body: &[u8]) -> Vec<(String, String)> {
    let mut carry = body.to_vec();
    let mut section = 0_usize;
    let mut refs = Vec::new();
    while let Some(line) = take_pkt_line(&mut carry).expect("a well-formed pkt-line") {
        match line {
            PktLine::Flush => section += 1,
            PktLine::Data(data) => {
                if section != 1 {
                    continue;
                }
                let text = String::from_utf8_lossy(&data).into_owned();
                let text = text.trim_end_matches('\n');
                let text = text.split('\0').next().unwrap_or_default();
                let mut fields = text.splitn(2, ' ');
                let oid = fields.next().unwrap_or_default().to_owned();
                let name = fields.next().unwrap_or_default().to_owned();
                refs.push((name, oid));
            }
        }
    }
    refs
}

pub(super) fn advertisement_headers() -> Vec<(String, String)> {
    vec![
        (
            "Content-Type".to_owned(),
            "application/x-git-upload-pack-advertisement".to_owned(),
        ),
        ("Content-Length".to_owned(), "512".to_owned()),
    ]
}

/// Test transport with a pre-proved principal. It uses the production
/// landed serve path; server tests below the HTTP adapter prove bearer auth.
pub(super) struct PublicationTestOrigin {
    addr: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl PublicationTestOrigin {
    pub(super) fn start(vault: &Arc<Vault>, principal: EntityId) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("test listener");
        let addr = listener.local_addr().expect("listener address");
        let stop = Arc::new(AtomicBool::new(false));
        let worker = std::thread::spawn({
            let vault = Arc::clone(vault);
            let stop = Arc::clone(&stop);
            move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    serve_publication_test_connection(
                        &vault,
                        principal,
                        stream.expect("test connection"),
                    );
                }
            }
        });
        Self {
            addr,
            stop,
            worker: Some(worker),
        }
    }

    pub(super) fn url(&self) -> String {
        format!("http://{}/demo.git", self.addr)
    }
}

impl Drop for PublicationTestOrigin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(self.addr);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn serve_publication_test_connection(
    vault: &Arc<Vault>,
    principal: EntityId,
    mut stream: std::net::TcpStream,
) {
    use std::io::BufRead;

    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .expect("write timeout");
    let mut reader = io::BufReader::new(stream.try_clone().expect("reader"));
    let mut line = String::new();
    if reader.read_line(&mut line).expect("request line") == 0 {
        return;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().expect("method").to_owned();
    let target = parts.next().expect("target").to_owned();
    let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
    let mut headers = BTreeMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("header");
        if line.trim().is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').expect("header pair");
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    assert!(
        !headers.contains_key("transfer-encoding"),
        "small fetch has a fixed body"
    );
    let length = headers
        .get("content-length")
        .map(|value| value.parse::<u64>().expect("length"));
    let request = ServeRequest {
        method,
        path_info: path.to_owned(),
        query_string: query.to_owned(),
        content_type: headers.get("content-type").cloned(),
        content_length: length,
        content_encoding: headers.get("content-encoding").cloned(),
        git_protocol: headers.get("git-protocol").cloned(),
        remote_user: Some(principal.to_hex()),
        remote_addr: Some("127.0.0.1".to_owned()),
    };
    let mut body = reader.take(length.unwrap_or(0));
    let mut captured = CapturingSink::default();
    let report = serve(
        vault,
        "demo",
        &request,
        DoorSeam::Landed,
        &mut body,
        &mut captured,
    )
    .expect("serve stock client");
    if request.is_receive_pack() {
        let outcome = report.outcome.as_ref().expect("served push outcome");
        // Independent wire counts, not constants copied from the producer.
        assert_eq!(
            outcome.pack_stats.request_bytes,
            length.unwrap_or(0) - body.limit()
        );
        assert!(outcome.pack_stats.request_bytes > 0);
        assert_eq!(
            outcome.pack_stats.response_bytes,
            captured.body.len() as u64
        );
        assert!(outcome.pack_stats.response_bytes > 0);
        assert_eq!(
            outcome.pack_stats.ref_update_count,
            outcome.ref_updates.len()
        );
        let repo = outcome.pinned_repo_ref().expect("replay repo");
        let first = report.landing.as_ref().expect("certified push");
        let replay = vault
            .apply_receive_pack_update(&repo, outcome)
            .expect("the actual served outcome is journal-backed");
        assert!(replay.replayed);
        assert_eq!(replay.receipt.record_key, first.receipt.record_key);
        for field in 0..3 {
            let mut tampered = outcome.clone();
            match field {
                0 => tampered.pack_stats.request_bytes += 1,
                1 => tampered.pack_stats.response_bytes += 1,
                _ => tampered.pack_stats.ref_update_count += 1,
            }
            assert!(vault.apply_receive_pack_update(&repo, &tampered).is_err());
        }
    }
    let mut response = format!("HTTP/1.1 {} OK\r\n", captured.status);
    for (name, value) in captured.headers {
        if !name.eq_ignore_ascii_case("content-length") {
            response.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    response.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        captured.body.len()
    ));
    stream
        .write_all(response.as_bytes())
        .expect("response headers");
    stream.write_all(&captured.body).expect("response body");
}
