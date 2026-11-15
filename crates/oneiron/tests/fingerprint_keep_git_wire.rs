//! K-proof (oracle) for PLAN-UC-04 stage 3.3: the seven git-wire digests keep their bytes.
//!
//! Each git-wire digest now starts its BLAKE3 through the fingerprint crate's K door
//! (`purposes::git_wire`: `CAPABILITY`, `REF_RECORD_KEY`, `STAGE_RECORD_KEY`,
//! `WORKTREE_RECORD_KEY`, `REPO_IDENTITY`, `PLAN_HASH`, `WORKTREE_SCOPE`). The journal stores
//! its rows under the three record keys, each row stores the repo identity and a worktree
//! row its scope, the stage key binds the plan hash, and commit compares a prepared
//! capability with the stored row's. So each must give main's bytes for every value.
//! `base` below holds main's lines at 0ea614455775, copied by range (each range is named above
//! its copy; the generator is `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`)
//! and differing from them only in indentation. The few lines around the copies give them
//! main's names: a journal row read from the same JSON as the head's row, a plan built
//! from the head plan's parts (through the test door `fingerprint_keep_git_wire`), each
//! object write's argv operation and stdin (through the door), and a spool's sealed length
//! and chunks. A field above 4 GiB saturates its u32 length; the fingerprint crate's own
//! test (`fingerprint_rules.rs`) checks that write against a hand-written transcript.
//!
//! The doors build only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_git_wire`.
#![cfg(oneiron_test_support)]

use std::path::{Path, PathBuf};

use oneiron::git_wire::{
    GitCommitRequest, GitObjectKind, GitOid, GitRefExpectation, GitRefName, GitRefPublication,
    GitRetainedObject, GitTreeEntry, GitWireObjectWrite, GitWireOperation, GitWirePlan,
    GitWirePlannedOid, GitWireRepoIdentity,
};
use oneiron::test_doors::fingerprint_keep_git_wire as door;
use oneiron_contracts::fingerprint::{LegacyDigest, LegacyHash, TagMode, purposes};
use oneiron_store::git_wire::plan::{PlannedPublication, hash_publication_target};
use oneiron_store::git_wire::record::{
    StoredGitWireRecord, ref_record_key, stage_record_key, worktree_record_key,
};
use oneiron_store::git_wire::repo::repo_identity_for;
use oneiron_store::git_wire::retained_object::GitSpool;
use serde_json::{Value, json};

// Not formatted, so each copy stays line for line equal to main's. The copies keep main's
// `pub`, which this private module cannot export.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base {
    use std::path::{Path, PathBuf};

    use oneiron::git_wire::{
        GitOid, GitRefExpectation, GitRefPublication, GitWireOperation, GitWirePlannedOid,
        GitWireRepoIdentity, GitWireResult,
    };
    use oneiron::test_doors::fingerprint_keep_git_wire as door;
    use oneiron_base::error::Result;
    use oneiron_store::git_wire::plan::PlannedPublication;
    use oneiron_store::git_wire::retained_object::GitSpool;
    use serde::Deserialize;

// main 0ea614455775: crates/oneiron-store/src/git_wire/config.rs:9-9
pub const GIT_WIRE_DOMAIN: &[u8] = b"oneiron:git-wire:v2";

// main 0ea614455775: crates/oneiron-store/src/git_wire/record.rs:424-428
pub fn hash_field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    hasher.update(&length.to_be_bytes());
    hasher.update(bytes);
}

    /// A publication as a journal row stores it, by main's names.
    #[derive(Deserialize)]
    pub(crate) struct StoredPublication {
        pub(crate) name: String,
        pub(crate) expected: Option<String>,
        pub(crate) next: Option<String>,
    }

    /// An observed ref as a journal row stores it, by main's names.
    #[derive(Deserialize)]
    pub(crate) struct StoredObservedRef {
        pub(crate) name: String,
        pub(crate) oid: Option<String>,
    }

    /// The fields of a journal row the capability hash reads, by main's names.
    #[derive(Deserialize)]
    pub(crate) struct StoredGitWireRecord {
        pub(crate) record_key: [u8; 32],
        pub(crate) repo_identity: [u8; 32],
        pub(crate) operation: String,
        pub(crate) publications: Vec<StoredPublication>,
        pub(crate) observed_before: Vec<StoredObservedRef>,
        pub(crate) keep_refs: Vec<String>,
        pub(crate) worktree_commit: Option<String>,
        pub(crate) worktree_settings_hash: Option<[u8; 32]>,
        pub(crate) started_at: u64,
    }

    impl StoredGitWireRecord {
        pub(crate) fn capability_hash(&self) -> [u8; 32] {
// main 0ea614455775: crates/oneiron-store/src/git_wire/record.rs:105-143
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, GIT_WIRE_DOMAIN);
        hash_field(&mut hasher, b"capability");
        hash_field(&mut hasher, &self.record_key);
        hash_field(&mut hasher, &self.repo_identity);
        hash_field(&mut hasher, self.operation.as_bytes());
        for publication in &self.publications {
            hash_field(&mut hasher, publication.name.as_bytes());
            hash_field(
                &mut hasher,
                publication.expected.as_deref().unwrap_or("*").as_bytes(),
            );
            hash_field(
                &mut hasher,
                publication.next.as_deref().unwrap_or("-").as_bytes(),
            );
        }
        for observed in &self.observed_before {
            hash_field(&mut hasher, observed.name.as_bytes());
            hash_field(
                &mut hasher,
                observed.oid.as_deref().unwrap_or("-").as_bytes(),
            );
        }
        for keep in &self.keep_refs {
            hash_field(&mut hasher, keep.as_bytes());
        }
        hash_field(
            &mut hasher,
            self.worktree_commit.as_deref().unwrap_or("-").as_bytes(),
        );
        hash_field(
            &mut hasher,
            self.worktree_settings_hash
                .as_ref()
                .map_or(b"-".as_slice(), |hash| hash.as_slice()),
        );
        hash_field(&mut hasher, &self.started_at.to_be_bytes());
        *hasher.finalize().as_bytes()
        }
    }

// main 0ea614455775: crates/oneiron-store/src/git_wire/record.rs:249-293
pub fn ref_record_key(
    identity: GitWireRepoIdentity,
    publications: &[GitRefPublication],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, GIT_WIRE_DOMAIN);
    hash_field(&mut hasher, b"ref-effect");
    hash_field(&mut hasher, identity.as_bytes());
    for publication in publications {
        hash_field(&mut hasher, publication.name.as_str().as_bytes());
        match publication.expected() {
            GitRefExpectation::Absent => hash_field(&mut hasher, b"absent"),
            GitRefExpectation::Value(oid) => hash_field(&mut hasher, oid.as_str().as_bytes()),
            GitRefExpectation::Any => hash_field(&mut hasher, b"any"),
        }
        match publication.next() {
            Some(oid) => hash_field(&mut hasher, oid.as_str().as_bytes()),
            None => hash_field(&mut hasher, b"delete"),
        }
    }
    *hasher.finalize().as_bytes()
}

pub fn stage_record_key(identity: GitWireRepoIdentity, plan_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, GIT_WIRE_DOMAIN);
    hash_field(&mut hasher, b"stage");
    hash_field(&mut hasher, identity.as_bytes());
    hash_field(&mut hasher, plan_hash);
    *hasher.finalize().as_bytes()
}

pub fn worktree_record_key(
    identity: GitWireRepoIdentity,
    operation: GitWireOperation,
    scope: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, GIT_WIRE_DOMAIN);
    hash_field(&mut hasher, b"worktree");
    hash_field(&mut hasher, identity.as_bytes());
    hash_field(&mut hasher, operation.as_str().as_bytes());
    hash_field(&mut hasher, scope);
    *hasher.finalize().as_bytes()
}

// main 0ea614455775: crates/oneiron-store/src/git_wire/repo.rs:84-90
pub fn repo_identity_for(common_dir: &Path) -> GitWireRepoIdentity {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, GIT_WIRE_DOMAIN);
    hash_field(&mut hasher, b"repo-identity");
    hash_field(&mut hasher, common_dir.as_os_str().as_encoded_bytes());
    GitWireRepoIdentity(*hasher.finalize().as_bytes())
}

// main 0ea614455775: crates/oneiron-store/src/git_wire/plan.rs:30-45
pub fn hash_publication_target(hasher: &mut blake3::Hasher, publication: &PlannedPublication) {
    match &publication.expected {
        GitRefExpectation::Absent => hash_field(hasher, b"absent"),
        GitRefExpectation::Value(oid) => hash_field(hasher, oid.as_str().as_bytes()),
        GitRefExpectation::Any => hash_field(hasher, b"any"),
    }
    match publication.next {
        Some(GitWirePlannedOid::Written(index)) => {
            hash_field(hasher, format!("written:{index}").as_bytes());
        }
        Some(GitWirePlannedOid::Existing(index)) => {
            hash_field(hasher, format!("existing:{index}").as_bytes());
        }
        None => hash_field(hasher, b"delete"),
    }
}

    /// A spool's sealed file as main's framing reads it: its length, and the head spool
    /// for its chunks.
    pub(crate) struct SpoolFile {
        pub(crate) len: u64,
        pub(crate) spool: GitSpool,
    }

    /// A spool, by main's shape.
    pub(crate) struct Spool(pub(crate) SpoolFile);

    impl Spool {
        pub(crate) fn for_each_chunk(
            &self,
            visit: &mut dyn FnMut(&[u8]) -> Result<()>,
        ) -> Result<()> {
            self.0.spool.for_each_chunk(visit)
        }

        pub(crate) fn hash_framed(&self, hasher: &mut blake3::Hasher) -> Result<()> {
// main 0ea614455775: crates/oneiron-store/src/git_wire/retained_object.rs:203-208
        let length = u32::try_from(self.0.len).unwrap_or(u32::MAX);
        hasher.update(&length.to_be_bytes());
        self.for_each_chunk(&mut |chunk| {
            hasher.update(chunk);
            Ok(())
        })
        }
    }

    /// A retained object: the head write (for its argv) and its spool.
    pub(crate) struct RetainedObject {
        pub(crate) write: oneiron::git_wire::GitWireObjectWrite,
        pub(crate) spool: Spool,
    }

    impl RetainedObject {
        pub(crate) fn spool(&self) -> &Spool {
            &self.spool
        }
    }

    /// An object write, by main's variant name for the one the plan hash tells apart.
    pub(crate) enum GitWireObjectWrite {
        Other(oneiron::git_wire::GitWireObjectWrite),
        Retained(RetainedObject),
    }

    /// What the plan hash reads of a frozen argv.
    pub(crate) struct FrozenGitArgv {
        pub(crate) operation: GitWireOperation,
        pub(crate) stdin: Option<Vec<u8>>,
    }

    impl FrozenGitArgv {
        pub(crate) const fn operation(&self) -> GitWireOperation {
            self.operation
        }

        pub(crate) fn stdin(&self) -> Option<&[u8]> {
            self.stdin.as_deref()
        }
    }

    impl GitWireObjectWrite {
        pub(crate) fn argv(&self) -> GitWireResult<FrozenGitArgv> {
            let write = match self {
                Self::Other(write) => write,
                Self::Retained(object) => &object.write,
            };
            let (operation, stdin) = door::object_argv(write)?;
            Ok(FrozenGitArgv { operation, stdin })
        }
    }

    /// The parts of a plan the plan hash reads, by main's names.
    pub(crate) struct GitWirePlan {
        pub(crate) objects: Vec<GitWireObjectWrite>,
        pub(crate) existing: Vec<GitOid>,
        pub(crate) publications: Vec<PlannedPublication>,
    }

    impl GitWirePlan {
        pub(crate) fn plan_hash(&self) -> GitWireResult<[u8; 32]> {
// main 0ea614455775: crates/oneiron/src/git_wire/plan.rs:163-182
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, GIT_WIRE_DOMAIN);
        hash_field(&mut hasher, b"plan");
        for write in &self.objects {
            let argv = write.argv()?;
            hash_field(&mut hasher, argv.operation().as_str().as_bytes());
            match write {
                // The spool's own sealed bytes, in the same framing.
                GitWireObjectWrite::Retained(object) => object.spool().hash_framed(&mut hasher)?,
                _ => hash_field(&mut hasher, argv.stdin().unwrap_or(&[])),
            }
        }
        for oid in &self.existing {
            hash_field(&mut hasher, oid.as_str().as_bytes());
        }
        for publication in &self.publications {
            hash_field(&mut hasher, publication.name.as_str().as_bytes());
            hash_publication_target(&mut hasher, publication);
        }
        Ok(*hasher.finalize().as_bytes())
        }
    }

// main 0ea614455775: crates/oneiron/src/git_wire/wire_worktree.rs:323-345
fn normalized_path(path: &Path) -> PathBuf {
    if let Ok(resolved) = path.canonicalize() {
        return resolved;
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => match parent.canonicalize() {
            Ok(parent) => parent.join(name),
            Err(_) => path.to_path_buf(),
        },
        _ => path.to_path_buf(),
    }
}

pub(super) fn worktree_scope(path: &Path) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, GIT_WIRE_DOMAIN);
    hash_field(&mut hasher, b"worktree-scope");
    hash_field(
        &mut hasher,
        normalized_path(path).as_os_str().as_encoded_bytes(),
    );
    *hasher.finalize().as_bytes()
}
}

fn oid(seed: u8) -> GitOid {
    GitOid::parse_hex(format!("{seed:02x}").repeat(20)).expect("a 40-hex oid")
}

fn name(full: &str) -> GitRefName {
    GitRefName::parse_full(full).expect("a full ref name")
}

fn hex(seed: u8) -> String {
    oid(seed).as_str().to_owned()
}

/// Identities: all zero, all ones, and a ramp.
fn identities() -> [GitWireRepoIdentity; 3] {
    let mut ramp = [0; 32];
    for (at, byte) in ramp.iter_mut().enumerate() {
        *byte = u8::try_from(at).expect("under 32");
    }
    [
        GitWireRepoIdentity([0; 32]),
        GitWireRepoIdentity([0xff; 32]),
        GitWireRepoIdentity(ramp),
    ]
}

#[test]
fn the_git_wire_purposes_keep_main_s_domain() {
    assert_eq!(oneiron::git_wire::GIT_WIRE_DOMAIN, base::GIT_WIRE_DOMAIN);
    let labels = [
        (purposes::git_wire::CAPABILITY, "capability"),
        (purposes::git_wire::REF_RECORD_KEY, "ref-effect"),
        (purposes::git_wire::STAGE_RECORD_KEY, "stage"),
        (purposes::git_wire::WORKTREE_RECORD_KEY, "worktree"),
        (purposes::git_wire::REPO_IDENTITY, "repo-identity"),
        (purposes::git_wire::PLAN_HASH, "plan"),
        (purposes::git_wire::WORKTREE_SCOPE, "worktree-scope"),
    ];
    for (purpose, label) in labels {
        // The tag is the registry name only: main's hashers start with no tag, and the
        // domain and the label are the first two framed fields.
        assert_eq!(purpose.tag(), format!("oneiron:git-wire:v2:{label}"));
        assert_eq!(purpose.hash(), LegacyHash::Blake3);
        assert_eq!(purpose.tag_mode(), TagMode::NotHashed);
    }
}

/// Publication lists: none; a create; an update and a delete of any value; a delete of a
/// created ref, an update of any value and an update to the same oid.
fn publication_lists() -> Vec<Vec<GitRefPublication>> {
    vec![
        vec![],
        vec![GitRefPublication::update(
            name("refs/heads/main"),
            GitRefExpectation::Absent,
            oid(1),
        )],
        vec![
            GitRefPublication::update(
                name("refs/heads/main"),
                GitRefExpectation::Value(oid(1)),
                oid(2),
            ),
            GitRefPublication::delete(name("refs/tags/v1"), GitRefExpectation::Any),
        ],
        vec![
            GitRefPublication::delete(name("refs/heads/main"), GitRefExpectation::Absent),
            GitRefPublication::update(name("refs/notes/commits"), GitRefExpectation::Any, oid(3)),
            GitRefPublication::update(
                name("refs/heads/a"),
                GitRefExpectation::Value(oid(3)),
                oid(3),
            ),
        ],
    ]
}

#[test]
fn the_record_keys_keep_their_bytes() {
    let mut checked = 0;
    for identity in identities() {
        for publications in publication_lists() {
            assert_eq!(
                ref_record_key(identity, &publications),
                base::ref_record_key(identity, &publications),
                "{identity:?} {publications:?}"
            );
            checked += 1;
        }
        for plan_hash in identities().map(|hash| hash.0) {
            assert_eq!(
                stage_record_key(identity, &plan_hash),
                base::stage_record_key(identity, &plan_hash),
                "{identity:?} {plan_hash:?}"
            );
            checked += 1;
            for operation in [
                GitWireOperation::WorktreeAdd,
                GitWireOperation::WorktreeRemove,
                GitWireOperation::WorktreePrune,
                GitWireOperation::PublishRefs,
            ] {
                assert_eq!(
                    worktree_record_key(identity, operation, &plan_hash),
                    base::worktree_record_key(identity, operation, &plan_hash),
                    "{identity:?} {operation:?} {plan_hash:?}"
                );
                checked += 1;
            }
        }
    }
    // 3 identities x (4 publication lists + 3 plan hashes + 3 scopes x 4 operations).
    assert_eq!(checked, 57);
}

/// A journal row as JSON, with every field the head's row decodes.
fn row(
    keys: u8,
    operation: &str,
    publications: &Value,
    observed: &Value,
    keep: &Value,
    tail: (&Value, &Value, u64),
) -> Value {
    let (commit, settings, started_at) = tail;
    let record_key = [keys; 32];
    let repo_identity = [keys ^ 0xff; 32];
    json!({
        "schema_version": 1,
        "record_key": record_key,
        "repo_identity": repo_identity,
        "operation": operation,
        "state": "prepared",
        "publications": publications,
        "observed_before": observed,
        "observed_after": [],
        "keep_refs": keep,
        "worktree_scope": null,
        "worktree_commit": commit,
        "worktree_settings_hash": settings,
        "failure": null,
        "started_at": started_at,
        "finished_at": null,
    })
}

#[test]
fn the_capability_hash_keeps_its_bytes() {
    // `*` and `-` stand in for a missing value, so a literal `*` or `-` collides with it,
    // as on main.
    let publications = [
        json!([]),
        json!([{ "name": "refs/heads/main", "expected": null, "next": null }]),
        json!([
            { "name": "refs/heads/main", "expected": hex(1), "next": hex(2) },
            { "name": "refs/tags/v1", "expected": "*", "next": "-" },
        ]),
    ];
    let observed = [
        json!([]),
        json!([{ "name": "refs/heads/main", "oid": null }]),
        json!([{ "name": "refs/heads/main", "oid": hex(3) }, { "name": "", "oid": "" }]),
    ];
    let keeps = [json!([]), json!(["refs/oneiron/keep/a"]), json!(["", "x"])];
    let commits = [json!(null), json!(hex(4)), json!("")];
    let settings = [json!(null), json!(vec![7_u8; 32])];
    let mut checked = 0;
    for (at, operation) in ["publish-refs", "", "worktree-add"].into_iter().enumerate() {
        for publications in &publications {
            for observed in &observed {
                for keep in &keeps {
                    for commit in &commits {
                        for settings in &settings {
                            for started_at in [0, 1_700_000_000, u64::MAX] {
                                let keys = u8::try_from(at).expect("three operations");
                                let value = row(
                                    keys,
                                    operation,
                                    publications,
                                    observed,
                                    keep,
                                    (commit, settings, started_at),
                                );
                                let head: StoredGitWireRecord =
                                    serde_json::from_value(value.clone()).expect("a head row");
                                let base: base::StoredGitWireRecord =
                                    serde_json::from_value(value.clone()).expect("a base row");
                                assert_eq!(
                                    head.capability_hash(),
                                    base.capability_hash(),
                                    "{value}"
                                );
                                checked += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    // 3 operations x 3 publication lists x 3 observed lists x 3 keep lists x 3 commits x
    // 2 settings hashes x 3 start times.
    assert_eq!(checked, 1458);
}

#[test]
fn the_repo_identity_keeps_its_bytes() {
    let long = format!("/{}", "a".repeat(300));
    let mut paths: Vec<PathBuf> = [
        "",
        "/",
        "/srv/git/a.git",
        "relative/.git",
        "/ünïcode/路径",
        long.as_str(),
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect();
    #[cfg(unix)]
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt as _;
        paths.push(PathBuf::from(OsStr::from_bytes(b"/tmp/\xff\xfe.git")));
    }
    for path in &paths {
        assert_eq!(
            repo_identity_for(path).0,
            base::repo_identity_for(path).0,
            "{path:?}"
        );
    }
}

#[test]
fn the_publication_target_keeps_its_bytes() {
    let mut checked = 0;
    for expected in [
        GitRefExpectation::Absent,
        GitRefExpectation::Value(oid(5)),
        GitRefExpectation::Any,
    ] {
        for next in [
            None,
            Some(GitWirePlannedOid::Written(0)),
            Some(GitWirePlannedOid::Written(7)),
            Some(GitWirePlannedOid::Existing(0)),
            Some(GitWirePlannedOid::Existing(usize::MAX)),
        ] {
            let publication = PlannedPublication {
                name: name("refs/heads/main"),
                expected: expected.clone(),
                next,
            };
            // Both start with no tag (`TagMode::NotHashed` is a plain BLAKE3 start).
            let mut head = LegacyDigest::new(purposes::git_wire::PLAN_HASH);
            hash_publication_target(&mut head, &publication);
            let mut main = blake3::Hasher::new();
            base::hash_publication_target(&mut main, &publication);
            assert_eq!(
                head.finish(),
                *main.finalize().as_bytes(),
                "{publication:?}"
            );
            checked += 1;
        }
    }
    // 3 expectations x 5 targets. `Any` and the large handles reach no plan through its
    // builders, which refuse them, so they are checked here on the helper itself.
    assert_eq!(checked, 15);
}

fn spool(dir: &Path, bytes: &[u8]) -> GitSpool {
    GitSpool::pump(dir, bytes).expect("a spool")
}

fn retained(dir: &Path, kind: GitObjectKind, bytes: &[u8]) -> GitRetainedObject {
    GitRetainedObject::encoded(kind, spool(dir, bytes))
}

fn commit_request() -> GitCommitRequest {
    GitCommitRequest {
        tree: oid(6),
        parents: vec![oid(7)],
        author_name: "Ada".to_owned(),
        author_email: "ada@example.com".to_owned(),
        authored_at: 1_700_000_000,
        message: b"one\n\ntwo\n".to_vec(),
        extra_headers: vec![],
    }
}

/// Object write lists: none; an empty blob; two blobs, one not UTF-8; a tree and a commit;
/// retained objects of each kind (one empty) around a blob.
fn add_objects(plan: &mut GitWirePlan, list: usize, dir: &Path) {
    match list {
        0 => {}
        1 => {
            plan.write_blob(Vec::new()).expect("a blob");
        }
        2 => {
            plan.write_blob(b"hello\n".to_vec()).expect("a blob");
            plan.write_blob(vec![0, 0xff, 0xfe, b'\n']).expect("a blob");
        }
        3 => {
            plan.write_tree(vec![
                GitTreeEntry {
                    mode: 0o100_644,
                    name: b"a.txt".to_vec(),
                    oid: oid(8),
                },
                GitTreeEntry {
                    mode: 0o40_000,
                    name: b"dir".to_vec(),
                    oid: oid(9),
                },
            ])
            .expect("a tree");
            plan.write_commit(commit_request()).expect("a commit");
        }
        _ => {
            plan.write_retained(retained(dir, GitObjectKind::Blob, b"abc"))
                .expect("a retained blob");
            plan.write_retained(retained(dir, GitObjectKind::Tag, b""))
                .expect("a retained tag");
            plan.write_blob(b"x".to_vec()).expect("a blob");
            plan.write_retained(retained(dir, GitObjectKind::Commit, b"tree 0606\n\nm\n"))
                .expect("a retained commit");
            plan.write_retained(retained(dir, GitObjectKind::Tree, &[0xff; 70]))
                .expect("a retained tree");
        }
    }
}

/// Publication lists: none; a create; an update and a delete; a delete and two creates.
fn add_publications(plan: &mut GitWirePlan, list: usize) {
    let publish = |plan: &mut GitWirePlan, full: &str, expected, target| {
        plan.publish(name(full), expected, target)
            .expect("a publication");
    };
    match list {
        0 => {}
        1 => publish(
            plan,
            "refs/heads/main",
            GitRefExpectation::Absent,
            GitWirePlannedOid::Written(0),
        ),
        2 => {
            publish(
                plan,
                "refs/heads/main",
                GitRefExpectation::Value(oid(1)),
                GitWirePlannedOid::Existing(1),
            );
            plan.unpublish(name("refs/tags/v1"), GitRefExpectation::Absent)
                .expect("a deletion");
        }
        _ => {
            plan.unpublish(name("refs/heads/main"), GitRefExpectation::Value(oid(2)))
                .expect("a deletion");
            publish(
                plan,
                "refs/heads/feature/x",
                GitRefExpectation::Absent,
                GitWirePlannedOid::Written(3),
            );
            publish(
                plan,
                "refs/notes/commits",
                GitRefExpectation::Absent,
                GitWirePlannedOid::Existing(0),
            );
        }
    }
}

/// The head plan's parts under main's names.
fn base_plan(plan: &GitWirePlan) -> base::GitWirePlan {
    let (objects, existing, publications) = door::plan_parts(plan);
    let objects = objects
        .iter()
        .map(|write| match write {
            GitWireObjectWrite::Retained(object) => {
                base::GitWireObjectWrite::Retained(base::RetainedObject {
                    write: write.clone(),
                    spool: base::Spool(base::SpoolFile {
                        len: object.spool().len(),
                        spool: object.spool().clone(),
                    }),
                })
            }
            other => base::GitWireObjectWrite::Other(other.clone()),
        })
        .collect();
    base::GitWirePlan {
        objects,
        existing: existing.to_vec(),
        publications: publications.to_vec(),
    }
}

#[test]
fn the_plan_hash_keeps_its_bytes() {
    let dir = tempfile::tempdir().expect("a spool dir");
    let mut checked = 0;
    for objects in 0..5 {
        for existing in 0..3 {
            for publications in 0..4 {
                let mut plan = GitWirePlan::new();
                add_objects(&mut plan, objects, dir.path());
                for seed in [10, 11].into_iter().take(existing) {
                    plan.existing_object(oid(seed)).expect("an existing object");
                }
                add_publications(&mut plan, publications);
                assert_eq!(
                    door::plan_hash(&plan).expect("a head plan hash"),
                    base_plan(&plan).plan_hash().expect("a base plan hash"),
                    "{plan:?}"
                );
                checked += 1;
            }
        }
    }
    // 5 object lists x 3 existing lists x 4 publication lists.
    assert_eq!(checked, 60);
}

#[test]
fn the_worktree_scope_keeps_its_bytes() {
    let dir = tempfile::tempdir().expect("a worktree dir");
    let real = dir.path().join("real");
    std::fs::create_dir(&real).expect("a real dir");
    let mut paths = vec![
        dir.path().to_path_buf(),
        real.clone(),
        dir.path().join("gone"),
        dir.path().join("gone").join("deeper"),
        PathBuf::from("relative/worktree"),
        PathBuf::new(),
        PathBuf::from("/"),
    ];
    #[cfg(unix)]
    {
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("a symlink");
        paths.push(link.clone());
        paths.push(link.join("gone"));
    }
    for path in &paths {
        assert_eq!(
            door::worktree_scope(path),
            base::worktree_scope(path),
            "{path:?}"
        );
    }
}
