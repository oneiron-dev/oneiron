#![cfg(all(unix, oneiron_test_support))]
//! `oneiron continue --cloud` sends the work's Git-LFS objects (FIX
//! CONTINUE-CLOUD-LFS-OBJECTS-NOT-SENT). The custody landing stores a pointer
//! only once the vault holds the object it names, so the hand-off push sends
//! those objects through the custody repo's own Git-LFS door before its pack.
//!
//! Each case runs the command's real push (`hand_off::push`, through
//! `oneiron_server::test_doors::continue_command::push_hand_off`) against the
//! served app on a loopback port, with the vault owner's holder-bound slip and
//! its seed, as a paired selection holds them: the push proves each request
//! itself, so no proof middleware sits in front of the app. The custody repo
//! `demo` is an empty served repo, and the work is a repo whose hand-off
//! carries a Git-LFS pointer file, its object in the repo's git-lfs store
//! (`.git/lfs/objects/<2>/<2>/<oid>`), as `git lfs` leaves it.
//!
//! - The hand-off lands on its continue ref, and the vault then holds the
//!   object. Before the fix the push sent no object: the landing refused the
//!   pointer, the report named the ref `ng`, the command failed, and the vault
//!   held no object.
//! - A pointer whose object is on neither this machine nor the vault stops
//!   the push before its pack, naming the path and `git lfs fetch`, and the
//!   custody repo gains no ref. Before the fix the pack went and the landing
//!   refused it, with no word of the missing object.
//!
//! Review round 1 of #9882 added four cases; before the fix each fails, as
//! the base's push sends no object:
//! - A local `refs/replace/` entry that reads the pointer's blob as a plain
//!   file hides nothing: the push reads objects as stored, as the pack and
//!   the custody repo's pre-receive do, so the object goes and the hand-off
//!   lands.
//! - A blob of pointer fields padded to 1024 bytes by an `ext-` line is no
//!   pointer to git-lfs, so it lands as a plain file, its named object on
//!   neither side.
//! - An `lfs.storage` path that ends in a space is read byte for byte: the
//!   object stored there goes and the hand-off lands.
//! - An object path holding a FIFO stops the push before its pack, naming
//!   the path, and is never opened to wait on a writer.
//!
//! Review round 2 of #9882 added two cases; before the fix each fails, as
//! the base's push sends no object, and at round 1's head each fails too:
//! - A clone that lacks the continue ref's old commit (another clone pushed
//!   it) lands its hand-off past a pointer that commit already carried,
//!   whose object is on neither side (as one the vault withholds from this
//!   machine is to the batch answer, FIX 8182), and sends the object of the
//!   pointer it adds. Round 1's head diffed from the empty tree and stopped
//!   on the unchanged pointer's missing object; the custody repo diffs from
//!   the old commit and asks nothing of it.
//! - A separate git directory whose name holds a byte that is no UTF-8 is
//!   read byte for byte: the object in its git-lfs store goes and the
//!   hand-off lands. Round 1's head decoded the name and looked for the
//!   object under a path with U+FFFD in it. Linux only: APFS refuses such a
//!   name.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! continue_cloud_lfs_served`. Stock `git` (with `http-backend`) must be on
//! PATH.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use engine_stack::on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::federation::Scope;
use oneiron::origin::lfs::{LFS_POINTER_SIZE_CUTOFF, LfsOid};
use oneiron::origin::smart_http::{ORIGIN_REPO_DIR_SUFFIX, origin_serving_root};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::config::SyncServerConfig;
use oneiron_server::test_doors::continue_command::push_hand_off;
use oneiron_server::{build_app, server::SyncServer};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The custody repo's served name.
const REPO: &str = "demo";
/// The conversation's hand-off ref, as the command names it.
const CONTINUE_REF: &str = "refs/heads/oneiron/continue/0b5e2c1d7a444c399f0e5d2a6b8c9e10";
/// The holder seed byte of the owner's slip.
const OWNER_SEED: u8 = 0x71;
/// The bytes of the work's Git-LFS object.
const OBJECT: &[u8] = b"a model checkpoint the work goes on from\x00\x01\x02\n";
/// The bytes of the Git-LFS object a later hand-off adds.
const ADDED: &[u8] = b"a later checkpoint\x00\x03\x04\n";

/// The served app on a loopback port, the vault behind it, its empty custody
/// repo, and the owner's slip.
struct Served {
    vault: Arc<Vault>,
    /// `http://127.0.0.1:<port>`.
    origin: String,
    /// The custody repo's bare store.
    bare: std::path::PathBuf,
    token: String,
    _serving: ServingTask,
    _vault_dir: tempfile::TempDir,
}

/// The task that serves the app; dropping it stops it.
struct ServingTask(tokio::task::JoinHandle<()>);

impl Drop for ServingTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Served {
    async fn start() -> TestResult<Self> {
        let vault_dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(vault_dir.path(), VaultConfig::device())?);
        let keystore = Arc::new(oneiron_keystore::MemoryKeystore::default());
        vault.install_device_keystore(keystore);
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let owner = vault.ensure_embedded_owner_actor()?;
        oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
        let token = owner_slip(&vault, &issuer, &root, owner)?;
        let serving_root = origin_serving_root(&vault)?;
        let bare_name = format!("{REPO}{ORIGIN_REPO_DIR_SUFFIX}");
        git(
            &serving_root,
            &["init", "--bare", "--initial-branch=main", &bare_name],
        );
        let server = Arc::new(SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("continue-cloud-lfs-served".into()),
                ..Default::default()
            },
        )?);
        let app = build_app(server);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let serving = ServingTask(tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        }));
        Ok(Self {
            vault,
            origin,
            bare: serving_root.join(bare_name),
            token,
            _serving: serving,
            _vault_dir: vault_dir,
        })
    }

    /// Runs the command's push of the work in `dir` to [`CONTINUE_REF`] on
    /// a blocking thread, as the command runs it.
    async fn push(&self, dir: &Path) -> TestResult<Result<String, String>> {
        let (dir, origin, token) = (dir.to_owned(), self.origin.clone(), self.token.clone());
        let seed = hex(&[OWNER_SEED; 32]);
        Ok(tokio::task::spawn_blocking(move || {
            push_hand_off(
                &dir,
                &origin,
                REPO,
                (token.as_str(), seed.as_str()),
                CONTINUE_REF,
            )
        })
        .await?)
    }

    /// The commit the custody repo's bare store holds on [`CONTINUE_REF`].
    fn landed(&self) -> Option<String> {
        let output = git_output(
            &self.bare,
            &["rev-parse", "--verify", "--quiet", CONTINUE_REF],
        );
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }
}

/// The owner's slip, holder-bound to the key of [`OWNER_SEED`], as a paired
/// selection holds it.
fn owner_slip(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    root: &CapabilitySlip,
    owner: EntityId,
) -> TestResult<String> {
    let key = SigningKey::from_bytes(&[OWNER_SEED; 32]);
    let mut claims = root.claims.clone();
    claims.parent_id = None;
    claims.slip_id = [OWNER_SEED; 32];
    claims.holder_ref = owner.to_hex();
    claims.binding_key = key.verifying_key().to_bytes();
    claims.actor_class = Some("human".to_owned());
    claims.scope = Scope::top();
    Ok(vault.mint_capability_slip(issuer, claims)?.to_token()?)
}

/// A work repo with one commit and, untracked, a Git-LFS pointer file
/// `assets/model.bin` for [`OBJECT`]; with `stored`, the object sits in the
/// repo's git-lfs store. Answers the object's id.
fn work_repo(dir: &Path, stored: bool) -> TestResult<LfsOid> {
    git(dir, &["init", "--initial-branch=main"]);
    git(dir, &["config", "user.name", "Oneiron"]);
    git(dir, &["config", "user.email", "oneiron@example.invalid"]);
    std::fs::write(dir.join("README.md"), "outside work\n")?;
    git(dir, &["add", "--", "README.md"]);
    git(dir, &["commit", "-m", "first"]);
    let store = dir.join(".git/lfs");
    pointer_file(
        dir,
        "assets/model.bin",
        OBJECT,
        stored.then_some(store.as_path()),
    )
}

/// Writes a Git-LFS pointer file for `object` at `path` in the work repo
/// `dir`, and with `store`, the object into that git-lfs store
/// (`<store>/objects/<2>/<2>/<oid>`), as `git lfs` leaves it. Answers the
/// object's id.
fn pointer_file(dir: &Path, path: &str, object: &[u8], store: Option<&Path>) -> TestResult<LfsOid> {
    let oid = LfsOid::digest(object);
    let hex = oid.to_hex();
    let file = dir.join(path);
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        &file,
        format!(
            // testkit-lint: allow(network) the pointer grammar's version line names a URI; nothing fetches it.
            "version https://git-lfs.github.com/spec/v1\noid sha256:{hex}\nsize {}\n",
            object.len()
        ),
    )?;
    if let Some(store) = store {
        let objects = store.join("objects").join(&hex[..2]).join(&hex[2..4]);
        std::fs::create_dir_all(&objects)?;
        std::fs::write(objects.join(&hex), object)?;
    }
    Ok(oid)
}

fn size() -> u64 {
    size_of(OBJECT)
}

fn size_of(object: &[u8]) -> u64 {
    u64::try_from(object.len()).expect("the object's length fits u64")
}

#[test]
fn the_hand_off_sends_its_lfs_objects_and_lands() -> TestResult {
    on_engine_stack(|| async {
        let served = Served::start().await?;
        let work = tempfile::tempdir()?;
        let oid = work_repo(work.path(), true)?;
        assert!(
            !served.vault.has_lfs_object(oid, size())?,
            "the vault starts without the object"
        );

        let pushed = served.push(work.path()).await?;

        let commit = pushed.map_err(|error| format!("the push fails: {error}"))?;
        assert_eq!(
            served.landed().as_deref(),
            Some(commit.as_str()),
            "the hand-off lands on its continue ref"
        );
        assert!(
            served.vault.has_lfs_object(oid, size())?,
            "the vault holds the work's Git-LFS object"
        );
        Ok(())
    })
}

#[test]
fn an_object_on_neither_side_stops_the_push_before_its_pack() -> TestResult {
    on_engine_stack(|| async {
        let served = Served::start().await?;
        let work = tempfile::tempdir()?;
        let oid = work_repo(work.path(), false)?;

        let pushed = served.push(work.path()).await?;

        let error = pushed.expect_err("the push fails");
        assert!(
            error.contains("assets/model.bin") && error.contains("git lfs fetch"),
            "the error names the path and how to fetch the object: {error}"
        );
        assert_eq!(served.landed(), None, "the custody repo gains no ref");
        assert!(
            !served.vault.has_lfs_object(oid, size())?,
            "the vault holds no object"
        );
        Ok(())
    })
}

#[test]
fn a_local_replace_ref_of_the_pointer_blob_still_sends_its_object() -> TestResult {
    on_engine_stack(|| async {
        let served = Served::start().await?;
        let work = tempfile::tempdir()?;
        let oid = work_repo(work.path(), true)?;
        // Locally, the pointer's blob reads as a plain file.
        let pointer = git(
            work.path(),
            &["hash-object", "-w", "--", "assets/model.bin"],
        );
        std::fs::write(work.path().join("plain.txt"), "a plain file\n")?;
        let stand_in = git(work.path(), &["hash-object", "-w", "--", "plain.txt"]);
        std::fs::remove_file(work.path().join("plain.txt"))?;
        git(
            work.path(),
            &["replace", pointer.as_str(), stand_in.as_str()],
        );

        let pushed = served.push(work.path()).await?;

        let commit = pushed.map_err(|error| format!("the push fails: {error}"))?;
        assert_eq!(
            served.landed().as_deref(),
            Some(commit.as_str()),
            "the hand-off lands on its continue ref"
        );
        assert!(
            served.vault.has_lfs_object(oid, size())?,
            "the vault holds the work's Git-LFS object"
        );
        Ok(())
    })
}

#[test]
fn pointer_fields_padded_to_the_cutoff_land_as_a_plain_file() -> TestResult {
    on_engine_stack(|| async {
        let served = Served::start().await?;
        let work = tempfile::tempdir()?;
        let oid = work_repo(work.path(), false)?;
        let file = work.path().join("assets/model.bin");
        let pointer = std::fs::read_to_string(&file)?;
        let (version, fields) = pointer
            .split_once('\n')
            .ok_or("the pointer starts with its version line")?;
        let ext = "ext-0-pad ";
        let cutoff = usize::try_from(LFS_POINTER_SIZE_CUTOFF)?;
        let pad = "x".repeat(cutoff - pointer.len() - ext.len() - 1);
        let padded = format!("{version}\n{ext}{pad}\n{fields}");
        assert_eq!(padded.len(), cutoff, "the blob is exactly the cutoff long");
        std::fs::write(&file, padded)?;

        let pushed = served.push(work.path()).await?;

        let commit = pushed.map_err(|error| format!("the push fails: {error}"))?;
        assert_eq!(
            served.landed().as_deref(),
            Some(commit.as_str()),
            "the hand-off lands on its continue ref"
        );
        assert!(
            !served.vault.has_lfs_object(oid, size())?,
            "nothing asked for the object the blob names"
        );
        Ok(())
    })
}

#[test]
fn an_lfs_storage_path_ending_in_a_space_is_read_as_written() -> TestResult {
    on_engine_stack(|| async {
        let served = Served::start().await?;
        let work = tempfile::tempdir()?;
        let oid = work_repo(work.path(), false)?;
        git(work.path(), &["config", "lfs.storage", "media "]);
        let hex = oid.to_hex();
        let store = work
            .path()
            .join(".git/media /objects")
            .join(&hex[..2])
            .join(&hex[2..4]);
        std::fs::create_dir_all(&store)?;
        std::fs::write(store.join(&hex), OBJECT)?;

        let pushed = served.push(work.path()).await?;

        let commit = pushed.map_err(|error| format!("the push fails: {error}"))?;
        assert_eq!(
            served.landed().as_deref(),
            Some(commit.as_str()),
            "the hand-off lands on its continue ref"
        );
        assert!(
            served.vault.has_lfs_object(oid, size())?,
            "the vault holds the work's Git-LFS object"
        );
        Ok(())
    })
}

#[test]
fn a_fifo_at_the_object_path_stops_the_push_before_its_pack() -> TestResult {
    on_engine_stack(|| async {
        let served = Served::start().await?;
        let work = tempfile::tempdir()?;
        let oid = work_repo(work.path(), false)?;
        let hex = oid.to_hex();
        let store = work
            .path()
            .join(".git/lfs/objects")
            .join(&hex[..2])
            .join(&hex[2..4]);
        std::fs::create_dir_all(&store)?;
        let made = Command::new("mkfifo").arg(store.join(&hex)).status()?;
        assert!(made.success(), "mkfifo makes the FIFO");

        let pushed = served.push(work.path()).await?;

        let error = pushed.expect_err("the push fails");
        assert!(
            error.contains("assets/model.bin") && error.contains("not a regular file"),
            "the error names the path and why its object cannot go: {error}"
        );
        assert_eq!(served.landed(), None, "the custody repo gains no ref");
        assert!(
            !served.vault.has_lfs_object(oid, size())?,
            "the vault holds no object"
        );
        Ok(())
    })
}

#[test]
fn a_clone_lacking_the_old_hand_off_lands_past_its_unchanged_pointer() -> TestResult {
    on_engine_stack(|| async {
        let served = Served::start().await?;
        // The old hand-off, which another clone pushed: its pointer's object
        // is on neither side. It goes into the custody store as is.
        let first = tempfile::tempdir()?;
        let unchanged = work_repo(first.path(), false)?;
        git(first.path(), &["add", "-A"]);
        git(first.path(), &["commit", "-m", "the old hand-off"]);
        let old = git(first.path(), &["rev-parse", "HEAD"]);
        let first_dir = first.path().to_str().ok_or("the temp dir is UTF-8")?;
        let refspec = format!("+refs/heads/main:{CONTINUE_REF}");
        git(
            &served.bare,
            &["fetch", "--no-tags", first_dir, refspec.as_str()],
        );
        assert_eq!(
            served.landed().as_deref(),
            Some(old.as_str()),
            "the custody repo holds the old hand-off"
        );
        // This clone never fetched it: the same pointer, an edited plain
        // file, and a pointer it adds, whose object is here.
        let work = tempfile::tempdir()?;
        work_repo(work.path(), false)?;
        std::fs::write(work.path().join("README.md"), "outside work, edited\n")?;
        let store = work.path().join(".git/lfs");
        let added = pointer_file(
            work.path(),
            "assets/added.bin",
            ADDED,
            Some(store.as_path()),
        )?;
        assert!(
            !git_output(work.path(), &["cat-file", "-e", old.as_str()])
                .status
                .success(),
            "this clone lacks the old hand-off"
        );

        let pushed = served.push(work.path()).await?;

        let commit = pushed.map_err(|error| format!("the push fails: {error}"))?;
        assert_eq!(
            served.landed().as_deref(),
            Some(commit.as_str()),
            "the hand-off lands on its continue ref"
        );
        assert!(
            served.vault.has_lfs_object(added, size_of(ADDED))?,
            "the vault holds the object of the pointer the hand-off adds"
        );
        assert!(
            !served.vault.has_lfs_object(unchanged, size())?,
            "nothing sent the unchanged pointer's object"
        );
        Ok(())
    })
}

#[cfg(target_os = "linux")]
#[test]
fn a_git_directory_named_with_a_byte_that_is_no_utf8_is_read_as_written() -> TestResult {
    use std::os::unix::ffi::OsStrExt as _;

    on_engine_stack(|| async {
        let served = Served::start().await?;
        let work = tempfile::tempdir()?;
        let tree = work.path().join("tree");
        let git_dir = work
            .path()
            .join(std::ffi::OsStr::from_bytes(b"git-\xff-dir"));
        let made = Command::new("git")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(["init", "--initial-branch=main", "--separate-git-dir"])
            .arg(&git_dir)
            .arg(&tree)
            .status()?;
        assert!(
            made.success(),
            "git init makes the work tree and its git directory"
        );
        let oid = work_repo(&tree, false)?;
        let store = git_dir.join("lfs");
        pointer_file(&tree, "assets/model.bin", OBJECT, Some(store.as_path()))?;

        let pushed = served.push(&tree).await?;

        let commit = pushed.map_err(|error| format!("the push fails: {error}"))?;
        assert_eq!(
            served.landed().as_deref(),
            Some(commit.as_str()),
            "the hand-off lands on its continue ref"
        );
        assert!(
            served.vault.has_lfs_object(oid, size())?,
            "the vault holds the work's Git-LFS object"
        );
        Ok(())
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn git_output(cwd: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .current_dir(cwd)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(args)
        .output()
        .expect("run git")
}

fn git(cwd: &Path, args: &[&str]) -> String {
    let output = git_output(cwd, args);
    assert!(
        output.status.success(),
        "git {args:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}
