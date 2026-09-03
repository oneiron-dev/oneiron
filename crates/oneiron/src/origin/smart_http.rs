//! Git smart-HTTP serving over the vault (ARCH-0068 Phase A, ONE-1908).
//!
//! One subprocess model and one only: `git http-backend`. There is no gitoxide
//! serving engine here and no per-request upload-pack/receive-pack split — the
//! CGI backend is the whole wire, and every invocation is built from a frozen
//! argv and a closed environment.
//!
//! # The serve invariants this module carries
//!
//! - **Frozen argv / scoped env (RC6).** [`ServeCommand`] is built once and
//!   never mutated. Its argv always carries `-c core.hooksPath=<door-owned
//!   dir>` ahead of the verb, so no repository-supplied hook can ever run:
//!   `core.hooksPath` is a git *config key*, not an environment variable, and
//!   `git -c` reaches every git child a git child spawns.
//! - **Closed environment.** The child is spawned after `env_clear`, with
//!   exactly [`SERVE_BASE_ENV_KEYS`] plus the typed CGI request keys in
//!   [`SERVE_REQUEST_ENV_KEYS`]. Nothing is inherited from the ambient
//!   environment except `PATH`, and `GIT_HTTP_EXPORT_ALL=1` is the export pin.
//! - **Quarantine.** The vetted `pre-receive` hook decides while the received
//!   objects still sit under `GIT_QUARANTINE_PATH`, so a rejected push leaves
//!   refs unmoved and the objects unreachable — rejected before objects become
//!   durable. The hook enumerates every added or modified blob from the RAW
//!   diff and hands the door those blobs WHOLE, length-framed: no text patch is
//!   parsed, so binary bytes cannot slip past a patch grammar, and an
//!   extraction the origin cannot read whole is a refusal rather than an empty
//!   scan.
//! - **Single writer (RA2).** A receive-pack holds the repository coordinator —
//!   the same advisory lock in the git common directory that
//!   [`crate::Vault::apply_repo_mutation`] and every GitWire ref effect take —
//!   across its WHOLE mutation window: it is acquired before the backend is
//!   spawned and released after the landing is journaled, so the ref mutation,
//!   the quarantine migration and the journaled advance cannot interleave with
//!   a queued repo mutation. The advance is journaled through GitWire's
//!   transactional publication. Repo refs and objects ride the git wire;
//!   nothing here writes the sync plane.
//! - **Receipts and replay.** Every landing produces a [`GitWireReceipt`]. The
//!   durable record is keyed by the exact publication, so a replayed outcome is
//!   answered from the record instead of re-running git, and no second record
//!   is written.
//!
//! # What this module deliberately does not do
//!
//! It mints no origin credential (Edge #2). The single thing it asks the
//! secret stack is the catastrophe dial's verdict on the `door:receive-pack`
//! effector, because a dial that cannot shut the push door shuts nothing that
//! matters — it READS that dial and mints nothing from it. It buffers no
//! request or response body, adds no size cap and no rate cap, and expands no
//! gix feature. `git_wire.rs` and `credential_door.rs` are consumed read-only;
//! this module owns neither.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::Vault;
use crate::codebase::RepoRef;
use crate::credential_door::{
    CredentialDoorError, CredentialDoorService, DOOR_RECEIVE_PACK_EFFECTOR, DoorCredential,
    DoorScanVerdict, PushedBlob,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{
    GitOid, GitRefExpectation, GitRefName, GitRefPublication, GitWire, GitWireCommitOutcome,
    GitWireProcessEnv, GitWireReceipt, lock_repository,
};

/// Directory under the vault root that holds the served bare repositories.
/// It is the `GIT_PROJECT_ROOT` of every serve invocation.
pub const ORIGIN_SERVING_ROOT_NAME: &str = "origin";

/// Directory under the vault root that holds the per-request door-owned hook
/// directories. Deliberately OUTSIDE the serving root: a hook directory is
/// never addressable as a repository.
pub const ORIGIN_DOOR_ROOT_NAME: &str = "origin-door";

/// Suffix of a served bare repository directory.
pub const ORIGIN_REPO_DIR_SUFFIX: &str = ".git";

/// The closed serve baseline. Exactly these keys, and nothing else, form the
/// non-request half of the child environment.
pub const SERVE_BASE_ENV_KEYS: [&str; 4] =
    ["GIT_DIR", "GIT_HTTP_EXPORT_ALL", "GIT_PROJECT_ROOT", "PATH"];

/// The closed CGI request half of the child environment. Every value is
/// constructed from the typed [`ServeRequest`]; none is read from the ambient
/// environment.
///
/// These are exactly the request-scoped names `git http-backend` reads:
/// `HTTP_CONTENT_ENCODING` (a stock client gzips its RPC bodies) and
/// `HTTP_GIT_PROTOCOL` (the negotiated wire version) carry their CGI spelling,
/// because that is the spelling the backend looks for.
pub const SERVE_REQUEST_ENV_KEYS: [&str; 9] = [
    "CONTENT_LENGTH",
    "CONTENT_TYPE",
    "HTTP_CONTENT_ENCODING",
    "HTTP_GIT_PROTOCOL",
    "PATH_INFO",
    "QUERY_STRING",
    "REMOTE_ADDR",
    "REMOTE_USER",
    "REQUEST_METHOD",
];

/// The one vetted hook the door-owned directory contains.
pub const DOOR_PRE_RECEIVE_HOOK_NAME: &str = "pre-receive";

/// Longest repository name the origin will resolve.
pub const ORIGIN_MAX_REPO_NAME_BYTES: usize = 100;

/// Bound on the CGI header block. This bounds a protocol preamble, not a body:
/// request and response bodies stream unbounded and unbuffered.
const SERVE_MAX_CGI_HEADER_BYTES: usize = 64 * 1024;

/// Streaming chunk size for both directions.
const SERVE_STREAM_CHUNK_BYTES: usize = 64 * 1024;

/// Bound on the captured child stderr used for diagnostics only.
const SERVE_MAX_STDERR_BYTES: usize = 16 * 1024;

/// How often the door window looks for the hook's request.
const DOOR_WINDOW_POLL: Duration = Duration::from_millis(2);

/// How long the door window waits for a hook that never arrives before failing
/// closed. A push whose door window cannot complete is refused, never admitted.
pub const DOOR_WINDOW_TIMEOUT: Duration = Duration::from_secs(300);

/// The verdict line the vetted hook accepts as an admission.
const DOOR_VERDICT_OK: &str = "ok";

/// The vetted `pre-receive` hook.
///
/// It is the ONLY executable the door-owned directory carries, and it is the
/// only hook any serve invocation can reach. It enumerates the pushed blobs
/// with git plumbing *inside the quarantine window*, hands them to the door
/// through the request file, and blocks on the verdict. Every failure path
/// exits non-zero: a door that cannot answer refuses the push.
///
/// The enumeration is the RAW diff, never a text patch. `--raw` names every
/// added or modified entry with its post-image oid whether or not the entry has
/// a printable patch, and each named blob is emitted WHOLE and length-framed,
/// so binary content, NUL-carrying content and content whose lines begin with
/// `+` all reach the door as the exact bytes the push would make durable. A
/// blob the hook cannot size or read ends the push right here, under `set -e`,
/// while the objects are still quarantined.
const DOOR_PRE_RECEIVE_HOOK: &str = r#"#!/bin/sh
# Vetted door hook (ONE-1908). Repository-supplied hooks never run: every serve
# invocation pins core.hooksPath in argv to this door-owned directory.
#
# This runs inside git's quarantine window: the received objects are still under
# GIT_QUARANTINE_PATH, so a non-zero exit leaves refs unmoved and the objects
# unreachable.
#
# The blob stream is length-framed: "blob <oid> <bytes> <path>\n" followed by
# exactly <bytes> raw bytes. Framing rather than patch text is what makes the
# extraction total -- there is no line shape a blob can carry that hides it.
set -eu
dir=${0%/*}
req="$dir/pre-receive.request"
part="$dir/pre-receive.request.part"
blobs="$dir/pre-receive.blobs"
blobspart="$dir/pre-receive.blobs.part"
entries="$dir/pre-receive.entries"
verdict="$dir/pre-receive.verdict"
tab=$(printf '\t')
: > "$part"
: > "$blobspart"
printf 'quarantine %s\n' "${GIT_QUARANTINE_PATH-}" >> "$part"
empty=$(git hash-object -t tree /dev/null)
while read -r old new ref; do
	printf 'ref %s %s %s\n' "$old" "$new" "$ref" >> "$part"
	case "$new" in
		*[!0]*) ;;
		*) continue ;;
	esac
	case "$old" in
		*[!0]*) base=$old ;;
		*) base=$empty ;;
	esac
	# Written to a file, never piped: a diff-tree that fails must fail the
	# hook, and the left-hand side of a pipeline cannot do that in POSIX sh.
	git diff-tree -r --raw --no-abbrev --no-commit-id --diff-filter=AMT \
		"$base" "$new" > "$entries"
	# ":<srcmode> <dstmode> <srcoid> <dstoid> <status><tab><path>"
	while IFS= read -r entry; do
		meta=${entry%%"$tab"*}
		path=${entry#*"$tab"}
		set -- $meta
		mode=$2
		oid=$4
		# A gitlink names a commit in another repository: this push makes no
		# bytes of it durable here, and there is no blob to read.
		case "$mode" in
			160000) continue ;;
		esac
		case "$oid" in
			*[!0]*) ;;
			*) continue ;;
		esac
		size=$(git cat-file -s "$oid")
		printf 'blob %s %s %s\n' "$oid" "$size" "$path" >> "$blobspart"
		git cat-file blob "$oid" >> "$blobspart"
	done < "$entries"
done
printf 'end\n' >> "$part"
rm -f "$entries"
mv -f "$blobspart" "$blobs"
mv -f "$part" "$req"
waited=0
while [ ! -f "$verdict" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 120000 ]; then
		echo "oneiron door: verdict window closed without an answer" >&2
		exit 1
	fi
	sleep 0.005 2>/dev/null || sleep 1
done
answer=$(cat "$verdict")
if [ "$answer" = "ok" ]; then
	exit 0
fi
printf '%s\n' "$answer" >&2
exit 1
"#;

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn serve_failed(reason: impl Into<String>) -> Error {
    Error::GitHttpServeFailed {
        reason: reason.into(),
    }
}

/// Carries a door refusal out through the crate error surface without ever
/// carrying a secret: the door's messages name paths and reason codes only.
fn door_refused(error: &CredentialDoorError) -> Error {
    Error::ReceivePackDoorRejected {
        reason: error.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

/// Validates a repository name from the route.
///
/// Closed shape: ASCII alphanumerics, `.`, `_`, `-`, never leading `.`, never
/// a path component of its own. The serve invocation's `PATH_INFO` is built
/// from the validated name, so no request can address anything but a
/// repository directory directly under the serving root.
pub fn validate_repo_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > ORIGIN_MAX_REPO_NAME_BYTES {
        return Err(Error::GitHttpInvalidRepoName(
            "origin repo name must be non-empty and at most 100 bytes",
        ));
    }
    if name.starts_with('.') {
        return Err(Error::GitHttpInvalidRepoName(
            "origin repo name must not start with a dot",
        ));
    }
    let shaped = name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if !shaped {
        return Err(Error::GitHttpInvalidRepoName(
            "origin repo name must be [A-Za-z0-9._-]",
        ));
    }
    Ok(())
}

/// The serving root of one vault: the `GIT_PROJECT_ROOT` of every invocation.
pub fn origin_serving_root(vault: &Vault) -> Result<PathBuf> {
    let root = vault.store.env.path().join(ORIGIN_SERVING_ROOT_NAME);
    fs::create_dir_all(&root)?;
    Ok(root.canonicalize()?)
}

/// The per-request door root. Never inside the serving root, so it is never
/// addressable as a repository.
fn origin_door_root(vault: &Vault) -> Result<PathBuf> {
    let root = vault.store.env.path().join(ORIGIN_DOOR_ROOT_NAME);
    fs::create_dir_all(&root)?;
    Ok(root.canonicalize()?)
}

/// Resolves an existing served repository directory.
///
/// Phase A serves; it does not create. A name that resolves to nothing is a
/// miss, never an implicit `git init`.
pub fn origin_repo_dir(vault: &Vault, repo_name: &str) -> Result<PathBuf> {
    validate_repo_name(repo_name)?;
    let root = origin_serving_root(vault)?;
    let dir = root.join(format!("{repo_name}{ORIGIN_REPO_DIR_SUFFIX}"));
    if !dir.is_dir() {
        return Err(Error::GitHttpRepoNotFound {
            repo: repo_name.to_owned(),
        });
    }
    let dir = dir.canonicalize()?;
    if !dir.starts_with(&root) {
        return Err(Error::GitHttpInvalidRepoName(
            "origin repo path escapes the serving root",
        ));
    }
    Ok(dir)
}

// ---------------------------------------------------------------------------
// The door seam
// ---------------------------------------------------------------------------

/// A derived admission record — NOT an identity type and NOT a credential
/// store.
///
/// It is minted from the canonical [`DoorCredential`] when a capability slip is
/// presented, and otherwise from the registered principal the transport already
/// proved. There is no `DoorActor` anywhere in this surface: nothing here mints
/// a second identity, and the stamp holds no token material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoorAdmissionStamp {
    principal_ref: String,
    credential_fingerprint: Option<String>,
    method: &'static str,
    admitted_at: u64,
}

impl DoorAdmissionStamp {
    /// The admission a transport-proved principal carries when Phase A presents
    /// no capability slip (Edge #2: the serving plane mints no origin
    /// credential and gates on nothing in the secret stack).
    fn from_principal(principal_ref: &str, admitted_at: u64) -> Self {
        Self {
            principal_ref: principal_ref.to_owned(),
            credential_fingerprint: None,
            method: "bearer+registered-principal",
            admitted_at,
        }
    }

    /// The admission a presented slip carries, fingerprinted from the canonical
    /// credential's own identifiers. The fingerprint is a digest, never the
    /// slip: `DoorCredential` holds no token material to begin with.
    fn from_credential(credential: &DoorCredential, principal_ref: &str, admitted_at: u64) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron:origin:door-admission:v1");
        hasher.update(credential.slip_id().as_bytes());
        hasher.update(b"\x00");
        hasher.update(credential.holder_ref().as_bytes());
        Self {
            principal_ref: principal_ref.to_owned(),
            credential_fingerprint: Some(hasher.finalize().to_hex().to_string()),
            method: "door-credential+registered-principal",
            admitted_at,
        }
    }

    /// The registered principal this admission was stamped for.
    #[must_use]
    pub fn principal_ref(&self) -> &str {
        &self.principal_ref
    }

    /// The canonical credential fingerprint, when a slip was presented.
    #[must_use]
    pub fn credential_fingerprint(&self) -> Option<&str> {
        self.credential_fingerprint.as_deref()
    }

    /// How the admission was established.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        self.method
    }

    /// When the admission was stamped, in unix seconds.
    #[must_use]
    pub const fn admitted_at(&self) -> u64 {
        self.admitted_at
    }
}

/// The door seam — always present.
///
/// Crate-visible on purpose: its methods name the canonical door types, which
/// `credential_door.rs` publishes to this crate and to no one else. The
/// transport reaches the seam through [`serve`], never by holding a door type.
pub(crate) trait DoorHook: Send + Sync {
    /// Admits an authenticated receive-pack.
    ///
    /// `presented` is the capability slip the caller carried, or `None` in
    /// Phase A, where the serving plane presents none. `peer_addr` is transport
    /// context, never an authorization input: a loopback push is admitted
    /// exactly like any other push.
    fn admit_receive_pack(
        &self,
        presented: Option<&DoorCredential>,
        principal_ref: &str,
        repo: &RepoRef,
        peer_addr: IpAddr,
        now: u64,
    ) -> Result<DoorAdmissionStamp>;

    /// The pre-receive verdict over a push's added lines, taken while the
    /// objects are still quarantined.
    fn pre_receive_scan(&self, repo: &RepoRef, blobs: &[PushedBlob]) -> Result<DoorScanVerdict>;
}

/// The seam's no-op default: it stamps the admission the transport already
/// proved and returns a clean verdict. It scans nothing and refuses nothing, so
/// the seam is present without adding behavior.
pub(crate) struct NoopDoorHook;

impl DoorHook for NoopDoorHook {
    fn admit_receive_pack(
        &self,
        presented: Option<&DoorCredential>,
        principal_ref: &str,
        _repo: &RepoRef,
        _peer_addr: IpAddr,
        now: u64,
    ) -> Result<DoorAdmissionStamp> {
        Ok(match presented {
            Some(credential) => DoorAdmissionStamp::from_credential(credential, principal_ref, now),
            None => DoorAdmissionStamp::from_principal(principal_ref, now),
        })
    }

    fn pre_receive_scan(&self, _repo: &RepoRef, _blobs: &[PushedBlob]) -> Result<DoorScanVerdict> {
        Ok(DoorScanVerdict::Clean)
    }
}

/// The wiring block onto the landed credential door.
///
/// Both legs delegate; neither restates a door rule. A presented slip is
/// evaluated by the door's own `authenticate_receive_pack` before any stamp
/// exists, the catastrophe dial is the door's own resolved policy either way,
/// and the scan is the door's unconditional call.
impl DoorHook for CredentialDoorService {
    fn admit_receive_pack(
        &self,
        presented: Option<&DoorCredential>,
        principal_ref: &str,
        repo: &RepoRef,
        peer_addr: IpAddr,
        now: u64,
    ) -> Result<DoorAdmissionStamp> {
        let Some(credential) = presented else {
            // Phase A presents no slip. The door has nothing to evaluate, so it
            // stamps the registered principal the transport proved instead of
            // pretending a credential was checked — the stamp carries no
            // fingerprint, and that absence is the honest record.
            //
            // The catastrophe dial is not part of that evaluation, so it is
            // consulted here on its own. Receive-pack is a door effector like
            // any other, and reaching the dial ONLY through
            // `authenticate_receive_pack` would leave it unreachable on exactly
            // the path that carries no slip — which is every production push.
            // An operator who empties `secret.door.allowed_effectors` would
            // then close every lease and injection downstream while leaving the
            // push door itself wide open.
            admit_receive_pack_effector(self)?;
            return Ok(DoorAdmissionStamp::from_principal(principal_ref, now));
        };
        self.authenticate_receive_pack(Some(credential), repo, peer_addr)
            .map_err(|error| door_refused(&error))?;
        Ok(DoorAdmissionStamp::from_credential(
            credential,
            principal_ref,
            now,
        ))
    }

    fn pre_receive_scan(&self, repo: &RepoRef, blobs: &[PushedBlob]) -> Result<DoorScanVerdict> {
        // Inherent before trait: this dispatches to the door's own
        // `CredentialDoorService::pre_receive_scan`, which is the unconditional
        // scan. The seam carries the verdict; it never restates the rule.
        self.pre_receive_scan(repo, blobs)
            .map_err(|error| door_refused(&error))
    }
}

/// The catastrophe dial's verdict on the receive-pack effector, asked WITHOUT a
/// credential.
///
/// It restates no door rule and reads no door internal. The dial is resolved by
/// the door's own [`CredentialDoorService::door_policy`] and admitted by the
/// door's own `DoorPolicy::admits_effector` — the same two steps
/// [`CredentialDoorService::authenticate_receive_pack`] takes before it
/// evaluates a slip, and the refusal it raises is that same call's
/// `LeaseScopeRefused` with that same wording. What differs is only the way in:
/// no slip is required to reach it, because Phase A presents none and the dial
/// was never a statement about a credential.
///
/// Fail-closed in both directions. A dial that cannot be RESOLVED is a refusal
/// too: a push admitted because nobody could read the dial is a push nobody
/// checked.
fn admit_receive_pack_effector(door: &CredentialDoorService) -> Result<()> {
    let policy = door.door_policy().map_err(|error| door_refused(&error))?;
    if policy.admits_effector(DOOR_RECEIVE_PACK_EFFECTOR) {
        return Ok(());
    }
    Err(door_refused(&CredentialDoorError::LeaseScopeRefused {
        effector: DOOR_RECEIVE_PACK_EFFECTOR.to_owned(),
        reason: "not a door effector the resolved dial admits",
    }))
}

/// Which door implementation a serve invocation binds.
///
/// Both arms are real. `Noop` is the seam's always-present no-op default;
/// `Landed` binds the credential door that ships in this vault.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DoorSeam {
    /// The no-op default: the seam is present, the verdict is always clean.
    Noop,
    /// The landed credential door: its pre-receive scan is unconditional.
    /// This is what a serve invocation binds unless something names otherwise.
    #[default]
    Landed,
}

// ---------------------------------------------------------------------------
// The frozen serve invocation
// ---------------------------------------------------------------------------

/// One CGI request, as typed fields. Every environment value the child sees
/// beyond the closed baseline is built from exactly these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeRequest {
    /// `GET` or `POST`.
    pub method: String,
    /// The path under `GIT_PROJECT_ROOT`, e.g. `/demo.git/info/refs`.
    pub path_info: String,
    /// The raw query string, without the leading `?`.
    pub query_string: String,
    /// The request's content type, when it carries a body.
    pub content_type: Option<String>,
    /// The request's declared length. `None` streams to EOF (chunked upload).
    pub content_length: Option<u64>,
    /// The body's content encoding. A stock client gzips its RPC bodies, and
    /// the backend inflates them only when it is told they are gzipped.
    pub content_encoding: Option<String>,
    /// The negotiated wire protocol version, when the client sent one.
    pub git_protocol: Option<String>,
    /// The registered principal this request authenticated as. It becomes the
    /// reflog identity of anything the push lands.
    pub remote_user: Option<String>,
    /// The peer address, when the transport knows it. Never an authorization
    /// input.
    pub remote_addr: Option<String>,
}

impl ServeRequest {
    /// Whether this request drives `git-receive-pack` — the only shape that
    /// opens a door window and lands refs.
    #[must_use]
    pub fn is_receive_pack(&self) -> bool {
        self.path_info.ends_with("/git-receive-pack")
    }

    fn env_pairs(&self) -> Vec<(String, String)> {
        let mut pairs = vec![
            ("REQUEST_METHOD".to_owned(), self.method.clone()),
            ("PATH_INFO".to_owned(), self.path_info.clone()),
            ("QUERY_STRING".to_owned(), self.query_string.clone()),
        ];
        if let Some(content_type) = &self.content_type {
            pairs.push(("CONTENT_TYPE".to_owned(), content_type.clone()));
        }
        if let Some(length) = self.content_length {
            pairs.push(("CONTENT_LENGTH".to_owned(), length.to_string()));
        }
        if let Some(encoding) = &self.content_encoding {
            pairs.push(("HTTP_CONTENT_ENCODING".to_owned(), encoding.clone()));
        }
        if let Some(protocol) = &self.git_protocol {
            pairs.push(("HTTP_GIT_PROTOCOL".to_owned(), protocol.clone()));
        }
        if let Some(user) = &self.remote_user {
            pairs.push(("REMOTE_USER".to_owned(), user.clone()));
        }
        if let Some(addr) = &self.remote_addr {
            pairs.push(("REMOTE_ADDR".to_owned(), addr.clone()));
        }
        pairs
    }
}

/// The frozen serve invocation: one argv and one closed environment baseline,
/// both fixed at build time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeCommand {
    argv: Vec<String>,
    env: BTreeMap<String, String>,
}

impl ServeCommand {
    /// Builds the one serve invocation: `git -c core.hooksPath=<door dir>
    /// http-backend`, with the pinned git executable as argv[0].
    ///
    /// `core.hooksPath` travels in argv rather than the environment because it
    /// is a git config key; `git -c` gives it command-line precedence and
    /// carries it to every git child the backend spawns, so no repository-local
    /// `hooksPath` and no repository-supplied hook can displace the door's.
    pub fn http_backend(
        repo_dir: &Path,
        project_root: &Path,
        door_hooks_dir: &Path,
    ) -> Result<Self> {
        let process_env = GitWireProcessEnv::capture()?;
        let hooks = door_hooks_dir
            .to_str()
            .ok_or_else(|| serve_failed("door hooks path must be UTF-8"))?;
        let argv = vec![
            path_arg(process_env.git_binary())?,
            "-c".to_owned(),
            format!("core.hooksPath={hooks}"),
            "http-backend".to_owned(),
        ];
        let mut env = BTreeMap::new();
        env.insert("GIT_DIR".to_owned(), path_arg(repo_dir)?);
        env.insert("GIT_PROJECT_ROOT".to_owned(), path_arg(project_root)?);
        env.insert("GIT_HTTP_EXPORT_ALL".to_owned(), "1".to_owned());
        env.insert("PATH".to_owned(), inherited_path());
        Ok(Self { argv, env })
    }

    /// The frozen argv.
    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    /// The closed environment baseline.
    #[must_use]
    pub const fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    /// The exact environment one child receives: the closed baseline plus the
    /// typed CGI request keys. Nothing else reaches the child, because the
    /// spawn clears the ambient environment first.
    #[must_use]
    pub fn child_env(&self, request: &ServeRequest) -> BTreeMap<String, String> {
        let mut env = self.env.clone();
        env.extend(request.env_pairs());
        env
    }

    /// Spawns the backend with piped stdio and a cleared environment.
    pub fn spawn(&self, request: &ServeRequest) -> Result<ServeChild> {
        let mut command = Command::new(&self.argv[0]);
        command
            .args(&self.argv[1..])
            .env_clear()
            .envs(self.child_env(request))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| serve_failed("git http-backend stdin was not piped"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| serve_failed("git http-backend stdout was not piped"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| serve_failed("git http-backend stderr was not piped"))?;
        Ok(ServeChild {
            child,
            stdin: Some(stdin),
            stdout: Some(stdout),
            stderr: Some(stderr),
        })
    }
}

fn path_arg(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| serve_failed("serve path must be UTF-8"))
}

/// `PATH` is the one inherited value, matching the GitWire baseline. Every
/// other environment key the child sees is assigned, never inherited.
fn inherited_path() -> String {
    std::env::var_os("PATH")
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// One running `git http-backend`.
#[derive(Debug)]
pub struct ServeChild {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
}

impl ServeChild {
    /// Takes the request-body sink.
    pub fn take_stdin(&mut self) -> Result<ChildStdin> {
        self.stdin
            .take()
            .ok_or_else(|| serve_failed("git http-backend stdin was already taken"))
    }

    /// Takes the response source.
    pub fn take_stdout(&mut self) -> Result<ChildStdout> {
        self.stdout
            .take()
            .ok_or_else(|| serve_failed("git http-backend stdout was already taken"))
    }

    /// Takes the diagnostic stream.
    pub fn take_stderr(&mut self) -> Result<ChildStderr> {
        self.stderr
            .take()
            .ok_or_else(|| serve_failed("git http-backend stderr was already taken"))
    }

    /// Reaps the child and reports whether it exited cleanly.
    pub fn wait(&mut self) -> Result<bool> {
        Ok(self.child.wait()?.success())
    }

    /// Ends a child whose request could not be completed.
    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// The door-owned hook directory
// ---------------------------------------------------------------------------

/// One per-request directory that `core.hooksPath` points at.
///
/// It is created by the origin, holds exactly one vetted `pre-receive` script,
/// and is removed when the request ends. A repository can neither add to it nor
/// redirect away from it.
#[derive(Debug)]
pub struct DoorHooksDir {
    path: PathBuf,
}

impl DoorHooksDir {
    /// Materializes a fresh door-owned directory under `root`.
    pub fn materialize(root: &Path) -> Result<Self> {
        let path = root.join(EntityId::now().to_hex());
        fs::create_dir_all(&path)?;
        let hook = path.join(DOOR_PRE_RECEIVE_HOOK_NAME);
        fs::write(&hook, DOOR_PRE_RECEIVE_HOOK.as_bytes())?;
        set_executable(&hook)?;
        Ok(Self {
            path: path.canonicalize()?,
        })
    }

    /// The directory every serve invocation pins in argv.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn request_path(&self) -> PathBuf {
        self.path.join("pre-receive.request")
    }

    /// The length-framed blob stream the hook emits, moved into place before
    /// the request file it announces.
    fn blobs_path(&self) -> PathBuf {
        self.path.join("pre-receive.blobs")
    }

    fn verdict_path(&self) -> PathBuf {
        self.path.join("pre-receive.verdict")
    }

    /// Publishes the verdict the blocked hook is waiting on. The write is
    /// rename-atomic, so the hook can never read half an answer.
    fn publish_verdict(&self, verdict: &str) -> Result<()> {
        let staged = self.path.join("pre-receive.verdict.part");
        fs::write(&staged, verdict.as_bytes())?;
        fs::rename(&staged, self.verdict_path())?;
        Ok(())
    }
}

impl Drop for DoorHooksDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// The door window
// ---------------------------------------------------------------------------

/// What the door answered while the objects were quarantined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoorWindowVerdict {
    /// The hook never ran: the request moved no ref.
    NotInvoked,
    /// Every added line scanned, nothing matched.
    Clean,
    /// The push was refused. Each reason names one offending path and its
    /// detector code; no matched line and no value bytes ever appear here.
    Rejected {
        /// One printable reason per offending blob.
        reasons: Vec<String>,
    },
}

/// The transport's record of one door window. A projection for the serving
/// layer — it carries no door type and no credential material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoorWindowReport {
    /// The door's answer.
    pub verdict: DoorWindowVerdict,
    /// The ref updates the push proposed, as the hook saw them.
    pub ref_updates: Vec<RefUpdate>,
    /// The quarantine the objects sat in while the door decided.
    pub quarantine_path: Option<PathBuf>,
}

impl DoorWindowReport {
    fn not_invoked() -> Self {
        Self {
            verdict: DoorWindowVerdict::NotInvoked,
            ref_updates: Vec::new(),
            quarantine_path: None,
        }
    }

    /// Whether the door admitted the push.
    #[must_use]
    pub fn admitted(&self) -> bool {
        matches!(self.verdict, DoorWindowVerdict::Clean)
    }
}

struct DoorWindowRequest {
    quarantine_path: Option<PathBuf>,
    ref_updates: Vec<RefUpdate>,
}

/// Services one door window: waits for the vetted hook, scans the quarantined
/// blobs, and publishes the verdict the hook is blocked on.
///
/// Fail-closed on every axis. A window that times out, a request that cannot be
/// parsed, and a scan that cannot run all publish a refusal, so the hook exits
/// non-zero and the objects never leave quarantine.
fn serve_door_window(
    vault: &Arc<Vault>,
    repo: &RepoRef,
    hooks: &DoorHooksDir,
    finished: &AtomicBool,
    deadline: Instant,
    seam: DoorSeam,
) -> Result<DoorWindowReport> {
    let request_path = hooks.request_path();
    loop {
        if request_path.is_file() {
            break;
        }
        if finished.load(Ordering::SeqCst) {
            return Ok(DoorWindowReport::not_invoked());
        }
        if Instant::now() >= deadline {
            hooks.publish_verdict("oneiron door: window closed without a request")?;
            return Ok(DoorWindowReport {
                verdict: DoorWindowVerdict::Rejected {
                    reasons: vec!["door window closed without a request".to_owned()],
                },
                ref_updates: Vec::new(),
                quarantine_path: None,
            });
        }
        std::thread::sleep(DOOR_WINDOW_POLL);
    }

    // Everything past the request file is fail-closed and ANSWERED: a request
    // that cannot be parsed and an extraction that cannot be read whole are
    // both unscanned bytes, so they become a published refusal rather than an
    // empty scan — and rather than an unanswered hook left blocking.
    let (ref_updates, quarantine_path, verdict) = match door_window_inputs(&request_path, hooks) {
        Ok((request, blobs)) => {
            let verdict = match seam {
                DoorSeam::Noop => scan_through(&NoopDoorHook, repo, &blobs),
                DoorSeam::Landed => {
                    scan_through(&CredentialDoorService::new(Arc::clone(vault)), repo, &blobs)
                }
            };
            (request.ref_updates, request.quarantine_path, verdict)
        }
        Err(error) => (
            Vec::new(),
            None,
            DoorWindowVerdict::Rejected {
                reasons: vec![error.to_string()],
            },
        ),
    };
    hooks.publish_verdict(&verdict_line(&verdict))?;
    Ok(DoorWindowReport {
        verdict,
        ref_updates,
        quarantine_path,
    })
}

/// Reads what the hook left behind: the ref list it decided over, and the
/// complete blob stream it framed. Both are required — the blob stream is moved
/// into place BEFORE the request file that announces it, so a readable request
/// with an unreadable extraction is a fault, never an empty push.
fn door_window_inputs(
    request_path: &Path,
    hooks: &DoorHooksDir,
) -> Result<(DoorWindowRequest, Vec<PushedBlob>)> {
    let request = parse_door_request(&fs::read(request_path)?)?;
    let blobs = parse_pushed_blobs(&fs::read(hooks.blobs_path())?)?;
    Ok((request, blobs))
}

/// Runs one bound door through the seam. A scan that cannot run is a refusal,
/// never a pass: the error arm becomes a rejection, not a clean verdict.
fn scan_through(hook: &dyn DoorHook, repo: &RepoRef, blobs: &[PushedBlob]) -> DoorWindowVerdict {
    match hook.pre_receive_scan(repo, blobs) {
        Ok(DoorScanVerdict::Clean) => DoorWindowVerdict::Clean,
        Ok(DoorScanVerdict::Rejected { proposals }) => DoorWindowVerdict::Rejected {
            reasons: proposals
                .iter()
                .map(|proposal| format!("{}: {}", proposal.path, proposal.reason))
                .collect(),
        },
        Err(error) => DoorWindowVerdict::Rejected {
            reasons: vec![error.to_string()],
        },
    }
}

fn verdict_line(verdict: &DoorWindowVerdict) -> String {
    match verdict {
        DoorWindowVerdict::Clean => DOOR_VERDICT_OK.to_owned(),
        DoorWindowVerdict::NotInvoked => "oneiron door: no request".to_owned(),
        DoorWindowVerdict::Rejected { reasons } => {
            format!("oneiron door refused this push: {}", reasons.join("; "))
        }
    }
}

fn parse_door_request(bytes: &[u8]) -> Result<DoorWindowRequest> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| serve_failed("door request must be UTF-8".to_owned()))?;
    let mut quarantine_path = None;
    let mut ref_updates = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("quarantine ") {
            if !rest.is_empty() {
                quarantine_path = Some(PathBuf::from(rest));
            }
        } else if let Some(rest) = line.strip_prefix("ref ") {
            ref_updates.push(parse_ref_update(rest)?);
        }
    }
    Ok(DoorWindowRequest {
        quarantine_path,
        ref_updates,
    })
}

fn parse_ref_update(line: &str) -> Result<RefUpdate> {
    let mut parts = line.split(' ');
    let old = parts
        .next()
        .ok_or_else(|| serve_failed("door request ref line has no old oid"))?;
    let new = parts
        .next()
        .ok_or_else(|| serve_failed("door request ref line has no new oid"))?;
    let name = parts
        .next()
        .ok_or_else(|| serve_failed("door request ref line has no ref name"))?;
    Ok(RefUpdate {
        name: name.to_owned(),
        old_oid: parse_optional_oid(old)?,
        new_oid: parse_optional_oid(new)?,
    })
}

/// The all-zero oid is git's "absent", and the canonical [`GitOid`] refuses it
/// by construction, so absence is `None` and never a second oid type.
fn parse_optional_oid(value: &str) -> Result<Option<GitOid>> {
    if value.bytes().all(|byte| byte == b'0') {
        return Ok(None);
    }
    Ok(Some(GitOid::parse_hex(value.to_ascii_lowercase())?))
}

/// Reads the length-framed blob stream the vetted hook emitted inside the
/// quarantine window.
///
/// One record is `blob <oid> <bytes> <path>\n` followed by exactly `<bytes>`
/// raw bytes. There is no patch grammar here on purpose: the framing is what
/// makes the extraction TOTAL. Every added or modified blob the raw diff named
/// is present with its complete post-image content, so a binary blob, a blob
/// carrying NUL, and a line beginning `++` or `+++ b/...` are all just bytes —
/// none of them can look like a header and none of them can go unscanned.
///
/// The door is handed the blob's whole content, one line per element, because
/// the entire post-image of an added or modified blob is what the push would
/// make durable. Content the door cannot scan (binary, invalid UTF-8) is the
/// door's own rejection, and a stream this function cannot read whole is a
/// refusal at the window — never a silently empty scan.
fn parse_pushed_blobs(framed: &[u8]) -> Result<Vec<PushedBlob>> {
    let mut blobs = Vec::new();
    let mut cursor = 0_usize;
    while cursor < framed.len() {
        let end = framed[cursor..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|at| cursor + at)
            .ok_or_else(|| serve_failed("door blob stream ends inside a record header"))?;
        let header = std::str::from_utf8(&framed[cursor..end])
            .map_err(|_| serve_failed("door blob record header must be UTF-8"))?;
        let (oid, len, path) = parse_blob_record_header(header)?;
        let start = end + 1;
        let stop = start
            .checked_add(len)
            .filter(|stop| *stop <= framed.len())
            .ok_or_else(|| serve_failed("door blob record is truncated"))?;
        blobs.push(PushedBlob {
            path,
            oid,
            added_lines: content_lines(&framed[start..stop]),
        });
        cursor = stop;
    }
    Ok(blobs)
}

/// `blob <oid> <bytes> <path>` — the path is last because it is the one field
/// that may carry spaces; the three before it are fixed and are validated here.
fn parse_blob_record_header(header: &str) -> Result<(String, usize, String)> {
    let mut fields = header.splitn(4, ' ');
    let unshaped = || serve_failed("door blob record header is not `blob <oid> <bytes> <path>`");
    if fields.next() != Some("blob") {
        return Err(unshaped());
    }
    let oid = fields.next().ok_or_else(unshaped)?;
    let len = fields.next().ok_or_else(unshaped)?;
    let path = fields.next().ok_or_else(unshaped)?;
    if oid.is_empty() || !oid.bytes().all(|byte| byte.is_ascii_hexdigit()) || path.is_empty() {
        return Err(unshaped());
    }
    let len = len
        .parse::<usize>()
        .map_err(|_| serve_failed("door blob record declares an unparsable length"))?;
    Ok((oid.to_owned(), len, path.to_owned()))
}

/// One blob's bytes as lines, split on `\n` with no line reshaped: a trailing
/// newline ends the last line rather than adding an empty one, and CR, NUL and
/// every other byte survive untouched into the door's hands.
fn content_lines(content: &[u8]) -> Vec<Vec<u8>> {
    if content.is_empty() {
        return Vec::new();
    }
    let trimmed = content.strip_suffix(b"\n").unwrap_or(content);
    trimmed
        .split(|byte| *byte == b'\n')
        .map(<[u8]>::to_vec)
        .collect()
}

// ---------------------------------------------------------------------------
// The landing
// ---------------------------------------------------------------------------

/// A ref and the value the origin observed for it. The oid is the canonical
/// [`GitOid`]; this module mints no origin-local object identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedRef {
    /// The full `refs/...` name.
    pub name: String,
    /// The observed value, absent when the ref does not exist.
    pub oid: Option<GitOid>,
}

/// One ref move a push proposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    /// The full `refs/...` name.
    pub name: String,
    /// The value the push was decided against; absent for a creation.
    pub old_oid: Option<GitOid>,
    /// The value the ref moves to; absent for a deletion.
    pub new_oid: Option<GitOid>,
}

impl RefUpdate {
    fn publication(&self) -> Result<GitRefPublication> {
        let name = GitRefName::parse_full(self.name.clone())?;
        let expected = match &self.old_oid {
            Some(oid) => GitRefExpectation::Value(oid.clone()),
            None => GitRefExpectation::Absent,
        };
        Ok(match &self.new_oid {
            Some(next) => GitRefPublication::update(name, expected, next.clone()),
            None => GitRefPublication::delete(name, expected),
        })
    }
}

/// What one push moved, counted rather than buffered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PackStats {
    /// Request bytes streamed into the backend.
    pub request_bytes: u64,
    /// Response bytes streamed back out.
    pub response_bytes: u64,
    /// How many refs the push proposed to move.
    pub ref_update_count: usize,
}

/// What the subprocess left behind for the single-writer landing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivePackOutcome {
    /// The served repository directory.
    pub repo_root: PathBuf,
    /// The ref moves the push proposed, as the door window saw them.
    pub ref_updates: Vec<RefUpdate>,
    /// Where the objects live after the quarantine migrated.
    pub staged_objects_dir: PathBuf,
    /// Byte and ref counters for the request.
    pub pack_stats: PackStats,
}

impl ReceivePackOutcome {
    /// The repo_ref this landing publishes against, pinned to a commit this
    /// object store carries.
    ///
    /// The pin cannot be chosen before the push: a repository receiving its
    /// first push holds no commit at all, and [`GitWire::open_repo`] proves the
    /// pin is present in the object store before it hands out a handle. Which
    /// commit is chosen is `landing_pin`'s rule, and a delete-only push has one
    /// because a deletion unlinks a name rather than removing an object.
    pub fn pinned_repo_ref(&self) -> Result<RepoRef> {
        let commit = landing_pin(&self.ref_updates)
            .ok_or_else(|| serve_failed("receive-pack outcome moved no ref"))?;
        local_repo_ref(&self.repo_root, commit)
    }
}

/// The commit a receive-pack landing pins its repo_ref to.
///
/// The pin's whole job is to name WHICH object store this landing publishes
/// into — [`GitWire::open_repo`] proves the pinned commit is present there
/// before it hands out a handle. It is never a statement about what the push
/// did; the publications carry that.
///
/// So the post-image comes first: an advancing push pins something it just made
/// durable. A push that only DELETES refs advances no post-image at all, and
/// reading the pin out of `new_oid` alone is what silently dropped delete-only
/// pushes on the floor — no pin, no handle, no landing, and a mutated
/// repository with no receipt. The pre-image the deletion was decided against
/// is still in that store (deleting a ref unlinks a name; it does not remove an
/// object, and the repository coordinator is held across this whole window), so
/// it names the same store just as well.
fn landing_pin(updates: &[RefUpdate]) -> Option<&GitOid> {
    updates
        .iter()
        .find_map(|update| update.new_oid.as_ref())
        .or_else(|| updates.iter().find_map(|update| update.old_oid.as_ref()))
}

fn local_repo_ref(repo_root: &Path, commit: &GitOid) -> Result<RepoRef> {
    let path = path_arg(repo_root)?;
    RepoRef::parse(&format!("local:{path}#{}", commit.as_str()))
}

/// The durable record of one landing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivePackLanding {
    /// The journaled receipt of the ref advance.
    pub receipt: GitWireReceipt,
    /// Whether a durable terminal record answered without re-running git.
    pub replayed: bool,
}

/// Whether the repository already carries every observed value.
///
/// The observed-ref check is what makes a replayed outcome a no-op: a landing
/// whose refs already match publishes nothing new.
pub fn refs_already_applied(
    vault: &Vault,
    repo: &RepoRef,
    repo_root: &Path,
    refs: &[ObservedRef],
) -> Result<bool> {
    if refs.is_empty() {
        return Ok(true);
    }
    let wire = GitWire::new(vault)?;
    let handle = wire.open_repo(repo.clone(), repo_root)?;
    let names = refs
        .iter()
        .map(|entry| GitRefName::parse_full(entry.name.clone()))
        .collect::<Result<Vec<_>>>()?;
    let observed = wire.read_refs(&handle, &names)?;
    Ok(refs
        .iter()
        .zip(observed)
        .all(|(wanted, seen)| wanted.oid == seen.oid && wanted.name == seen.name.as_str()))
}

impl Vault {
    /// Lands one receive-pack outcome through the single-writer path.
    ///
    /// Crate-local inherent impl: it lives HERE, and `vault.rs` is never
    /// edited.
    ///
    /// The whole landing runs under the repository coordinator — the advisory
    /// lock in the git common directory that every queued repo mutation and
    /// every GitWire ref effect also take — so the origin's receive-pack is the
    /// single writer and no queued mutation can interleave with it. Served
    /// through [`serve`] the guard is already held for the whole mutation
    /// window and this acquisition is the re-entrant depth bump; called
    /// directly (a replay, a recovery) it is the acquisition itself. Either way
    /// the landing never runs without it.
    ///
    /// The ref advance is journaled through GitWire's transactional
    /// publication, which is the crash-window protocol for refs: a durable
    /// intent exists before the effect is claimed, the postcondition is
    /// re-verified against the repository, object availability is proved
    /// *whole* before any ref is certified, and `GitWire::recover` finishes any
    /// record a crash left `Prepared`. Nothing here writes the sync plane.
    pub fn apply_receive_pack_update(
        &self,
        repo: &RepoRef,
        outcome: &ReceivePackOutcome,
    ) -> Result<ReceivePackLanding> {
        let publications = outcome
            .ref_updates
            .iter()
            .map(RefUpdate::publication)
            .collect::<Result<Vec<_>>>()?;
        if publications.is_empty() {
            return Err(serve_failed("receive-pack outcome moved no ref"));
        }
        let wire = GitWire::new(self)?;
        let handle = wire.open_repo(repo.clone(), &outcome.repo_root)?;
        let _guard = lock_repository(handle.common_dir())?;
        match wire.publish_refs(&handle, publications, now_secs())? {
            GitWireCommitOutcome::Applied(receipt) => Ok(ReceivePackLanding {
                receipt,
                replayed: false,
            }),
            GitWireCommitOutcome::Replayed(receipt) => Ok(ReceivePackLanding {
                receipt,
                replayed: true,
            }),
            GitWireCommitOutcome::Rejected { reason, .. } => {
                Err(Error::ReceivePackLandingRefused {
                    reason: format!("{reason:?}"),
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Serving one request
// ---------------------------------------------------------------------------

/// Where a serve invocation writes its response.
///
/// The transport owns framing; this module owns the wire. Bodies pass through
/// chunk by chunk and are never buffered whole.
pub trait ServeSink {
    /// Announces the response status and headers the CGI backend produced.
    fn begin(&mut self, status: u16, headers: &[(String, String)]) -> io::Result<()>;

    /// Streams one response chunk.
    fn write_chunk(&mut self, bytes: &[u8]) -> io::Result<()>;
}

/// What one serve invocation did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeReport {
    /// The status the backend produced.
    pub status: u16,
    /// The admission stamped for a receive-pack, when one ran.
    pub admission: Option<DoorAdmissionStamp>,
    /// The door window, when one opened.
    pub door: DoorWindowReport,
    /// What the push left behind, when refs moved.
    pub outcome: Option<ReceivePackOutcome>,
    /// The journaled landing, when one happened.
    pub landing: Option<ReceivePackLanding>,
}

/// Serves one git smart-HTTP request against a vault-hosted repository.
///
/// Exactly one `git http-backend` child runs per request. The request body
/// streams into its stdin while the response streams out of its stdout, and a
/// receive-pack additionally opens the door window and lands its refs.
///
/// # The receive-pack mutation window (RA2)
///
/// A receive-pack takes the repository coordinator BEFORE the backend is
/// spawned and holds it until the landing is journaled, because the mutation
/// window is not the landing alone: `git receive-pack` moves refs and migrates
/// the quarantined objects inside the exchange. Taking the coordinator
/// afterwards would leave exactly that window open to a concurrent
/// [`crate::Vault::apply_repo_mutation`] or GitWire ref effect, which is the
/// interleaving single-writer forbids.
///
/// It cannot deadlock the worker:
///
/// - The coordinator is re-entrant on one thread, and the landing runs on THIS
///   thread, so [`Vault::apply_receive_pack_update`]'s own acquisition of the
///   same key is a depth bump rather than a second wait.
/// - No thread this function spawns takes it: the body pump, the stderr drain
///   and the door window do not, and the door's scan reads the vault store
///   only.
/// - The `git http-backend` child takes git's own lockfiles, never this
///   advisory lock, so the process holding the coordinator is never waiting on
///   a process that wants it.
///
/// Streaming is unchanged: the wait happens before the exchange begins, so no
/// request is admitted and then stalled mid-body.
pub fn serve(
    vault: &Arc<Vault>,
    repo_name: &str,
    request: &ServeRequest,
    seam: DoorSeam,
    body: &mut (dyn Read + Send),
    sink: &mut dyn ServeSink,
) -> Result<ServeReport> {
    let repo_dir = origin_repo_dir(vault, repo_name)?;
    let project_root = origin_serving_root(vault)?;
    let hooks = DoorHooksDir::materialize(&origin_door_root(vault)?)?;
    let command = ServeCommand::http_backend(&repo_dir, &project_root, hooks.path())?;
    let admission = stamp_admission(vault, request, &repo_dir, seam)?;
    let coordinator = if request.is_receive_pack() {
        Some(lock_repository(&repo_common_dir(&repo_dir)?)?)
    } else {
        // A fetch and an advertisement mutate nothing, so neither queues behind
        // a push and neither delays one.
        None
    };
    let mut child = command.spawn(request)?;
    let exchange = run_exchange(
        vault, request, seam, &repo_dir, &hooks, &mut child, body, sink,
    );
    let exchange = match exchange {
        Ok(exchange) => exchange,
        Err(error) => {
            child.kill();
            return Err(error);
        }
    };
    let succeeded = child.wait()?;
    if !succeeded {
        return Err(serve_failed(format!(
            "git http-backend exited with a failure: {}",
            exchange.stderr
        )));
    }
    let report = finish_serve(vault, request, &repo_dir, admission, exchange);
    // Held to here on purpose: the ref mutation, the quarantine migration and
    // the journaled advance are one window, and it closes here.
    drop(coordinator);
    report
}

/// The git common directory that backs a served repository's refs and objects —
/// the key the repository coordinator is taken on.
///
/// A served repository IS a git directory: every serve invocation runs with
/// `GIT_DIR=<repo_dir>`, so git's own rule applies unchanged — the common
/// directory is the `commondir` pointer when one exists and the git directory
/// itself otherwise. Canonicalized, that is the same path
/// [`GitWire::open_repo`] resolves for the same directory, which is what makes
/// this guard and the landing's guard the SAME guard rather than two locks.
fn repo_common_dir(repo_dir: &Path) -> Result<PathBuf> {
    let pointer = repo_dir.join("commondir");
    let common = match fs::read_to_string(&pointer) {
        Ok(text) => {
            let named = PathBuf::from(text.trim_end_matches(['\r', '\n']));
            if named.is_absolute() {
                named
            } else {
                repo_dir.join(named)
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => repo_dir.to_path_buf(),
        Err(error) => return Err(Error::Io(error)),
    };
    Ok(common.canonicalize()?)
}

/// Stamps the admission before any subprocess exists.
///
/// The transport has already proved a registered principal and a write scope by
/// the time this runs; the door derives its record from that (and from a
/// presented slip, when Phase B starts presenting one). `peer_addr` is passed
/// through unread on purpose — the door's own contract is that "localhost"
/// describes a route and never a principal.
///
/// This is also where the landed door's catastrophe dial reaches the push: the
/// `Landed` seam admits the `door:receive-pack` effector here, with no slip
/// required, so an operator-narrowed effector set closes the push path BEFORE
/// the backend is spawned and before a single pushed byte is read. The `Noop`
/// seam refuses nothing, which is its whole contract.
fn stamp_admission(
    vault: &Arc<Vault>,
    request: &ServeRequest,
    repo_dir: &Path,
    seam: DoorSeam,
) -> Result<Option<DoorAdmissionStamp>> {
    if !request.is_receive_pack() {
        return Ok(None);
    }
    let principal_ref = request
        .remote_user
        .as_deref()
        .ok_or_else(|| serve_failed("receive-pack requires a registered principal"))?;
    let repo = unpinned_repo_ref(repo_dir);
    let peer_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let now = now_secs();
    let stamp = match seam {
        DoorSeam::Noop => {
            NoopDoorHook.admit_receive_pack(None, principal_ref, &repo, peer_addr, now)?
        }
        DoorSeam::Landed => CredentialDoorService::new(Arc::clone(vault)).admit_receive_pack(
            None,
            principal_ref,
            &repo,
            peer_addr,
            now,
        )?,
    };
    Ok(Some(stamp))
}

/// A repo_ref that names the repository before any commit is pinned to it.
///
/// The door reads only the repository's name from it, and the door window runs
/// before the pushed objects leave quarantine, so there is nothing to pin yet.
fn unpinned_repo_ref(repo_dir: &Path) -> RepoRef {
    RepoRef::LocalFolder {
        path: repo_dir.to_string_lossy().into_owned(),
        commit: "0".repeat(40),
    }
}

struct ServeExchange {
    status: u16,
    request_bytes: u64,
    response_bytes: u64,
    door: DoorWindowReport,
    stderr: String,
}

#[allow(clippy::too_many_arguments)]
fn run_exchange(
    vault: &Arc<Vault>,
    request: &ServeRequest,
    seam: DoorSeam,
    repo_dir: &Path,
    hooks: &DoorHooksDir,
    child: &mut ServeChild,
    body: &mut (dyn Read + Send),
    sink: &mut dyn ServeSink,
) -> Result<ServeExchange> {
    let stdin = child.take_stdin()?;
    let stdout = child.take_stdout()?;
    let stderr = child.take_stderr()?;
    let finished = AtomicBool::new(false);
    let repo = unpinned_repo_ref(repo_dir);
    let deadline = Instant::now() + DOOR_WINDOW_TIMEOUT;
    let receive_pack = request.is_receive_pack();

    std::thread::scope(|scope| {
        let pump = scope.spawn(move || pump_request_body(body, stdin));
        let drain = scope.spawn(move || drain_stderr(stderr));
        let door = receive_pack.then(|| {
            scope.spawn(|| serve_door_window(vault, &repo, hooks, &finished, deadline, seam))
        });
        let streamed = stream_response(stdout, sink);
        finished.store(true, Ordering::SeqCst);
        let (status, response_bytes) = streamed?;
        let request_bytes = join_thread(pump.join())?;
        let stderr = drain.join().unwrap_or_default();
        let door = match door {
            Some(handle) => join_thread(handle.join())?,
            None => DoorWindowReport::not_invoked(),
        };
        Ok(ServeExchange {
            status,
            request_bytes,
            response_bytes,
            door,
            stderr,
        })
    })
}

fn join_thread<T>(joined: std::thread::Result<Result<T>>) -> Result<T> {
    match joined {
        Ok(result) => result,
        Err(_) => Err(serve_failed("a serve worker panicked")),
    }
}

/// Streams the request body into the backend. Nothing is buffered whole: the
/// body moves one chunk at a time and stdin closes on the last one.
fn pump_request_body(body: &mut (dyn Read + Send), mut stdin: ChildStdin) -> Result<u64> {
    let mut buffer = vec![0_u8; SERVE_STREAM_CHUNK_BYTES];
    let mut total = 0_u64;
    loop {
        let read = match body.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Error::Io(error)),
        };
        // A backend that closed its input first is not a request failure: the
        // response it already produced is the answer.
        if stdin.write_all(&buffer[..read]).is_err() {
            break;
        }
        total = total.saturating_add(read as u64);
    }
    let _ = stdin.flush();
    drop(stdin);
    Ok(total)
}

/// Drains the backend's diagnostics for the failure message, and only for
/// that. A diagnostic that cannot be read is not a request failure, so this
/// reports what it got rather than an error.
fn drain_stderr(mut stderr: ChildStderr) -> String {
    let mut captured = Vec::new();
    let mut buffer = vec![0_u8; SERVE_STREAM_CHUNK_BYTES];
    loop {
        match stderr.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                if captured.len() < SERVE_MAX_STDERR_BYTES {
                    let room = SERVE_MAX_STDERR_BYTES - captured.len();
                    captured.extend_from_slice(&buffer[..read.min(room)]);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&captured).into_owned()
}

/// Parses the CGI header block, then streams the body through untouched.
fn stream_response(mut stdout: ChildStdout, sink: &mut dyn ServeSink) -> Result<(u16, u64)> {
    let (status, headers, mut carry) = read_cgi_headers(&mut stdout)?;
    sink.begin(status, &headers)?;
    let mut total = 0_u64;
    if !carry.is_empty() {
        sink.write_chunk(&carry)?;
        total = total.saturating_add(carry.len() as u64);
        carry.clear();
    }
    let mut buffer = vec![0_u8; SERVE_STREAM_CHUNK_BYTES];
    loop {
        match stdout.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                sink.write_chunk(&buffer[..read])?;
                total = total.saturating_add(read as u64);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Error::Io(error)),
        }
    }
    Ok((status, total))
}

type CgiHeaderBlock = (u16, Vec<(String, String)>, Vec<u8>);

fn read_cgi_headers(stdout: &mut ChildStdout) -> Result<CgiHeaderBlock> {
    let mut raw = Vec::new();
    let mut buffer = vec![0_u8; SERVE_STREAM_CHUNK_BYTES];
    let split = loop {
        if let Some(split) = header_terminator(&raw) {
            break split;
        }
        if raw.len() > SERVE_MAX_CGI_HEADER_BYTES {
            return Err(serve_failed(
                "git http-backend produced an oversized header",
            ));
        }
        match stdout.read(&mut buffer) {
            Ok(0) => {
                return Err(serve_failed(
                    "git http-backend produced no CGI header block",
                ));
            }
            Ok(read) => raw.extend_from_slice(&buffer[..read]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Error::Io(error)),
        }
    };
    let body = raw.split_off(split.1);
    raw.truncate(split.0);
    let (status, headers) = parse_cgi_headers(&raw)?;
    Ok((status, headers, body))
}

/// Returns `(header_end, body_start)` for whichever terminator the backend used.
fn header_terminator(raw: &[u8]) -> Option<(usize, usize)> {
    let crlf = find_subsequence(raw, b"\r\n\r\n").map(|at| (at, at + 4));
    let lf = find_subsequence(raw, b"\n\n").map(|at| (at, at + 2));
    match (crlf, lf) {
        (Some(crlf), Some(lf)) if lf.0 < crlf.0 => Some(lf),
        (Some(crlf), _) => Some(crlf),
        (None, found) => found,
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse_cgi_headers(raw: &[u8]) -> Result<(u16, Vec<(String, String)>)> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| serve_failed("git http-backend CGI headers must be UTF-8"))?;
    let mut status = 200_u16;
    let mut headers = Vec::new();
    for line in text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("Status") {
            status = value
                .split(' ')
                .next()
                .and_then(|code| code.parse::<u16>().ok())
                .ok_or_else(|| serve_failed("git http-backend produced an unparsable status"))?;
            continue;
        }
        headers.push((name.to_owned(), value.to_owned()));
    }
    Ok((status, headers))
}

/// Narrows the door window's proposed updates to the ones the repository
/// actually carries now.
///
/// The landing journals what the origin's receive-pack DID; it is never an
/// independent writer. A ref the backend declined after the door window (a
/// non-fast-forward, a per-ref refusal) is observably unmoved, so it is
/// dropped here instead of being published by the origin behind git's back.
///
/// A deletion is narrowed by that same one comparison rather than by a second
/// rule: its `new_oid` is `None`, so it survives exactly when the ref is
/// observably ABSENT, and a delete the backend declined is dropped like any
/// other unrealized move. Deletions are a real outcome and are journaled like
/// any other — a delete-only push mutates the repository, so it owes a receipt.
fn realized_updates(
    vault: &Vault,
    repo_dir: &Path,
    proposed: &[RefUpdate],
) -> Result<Vec<RefUpdate>> {
    let Some(pin) = landing_pin(proposed) else {
        // No proposed ref carries a value in either direction, so there is no
        // commit that names this object store and nothing to journal.
        return Ok(Vec::new());
    };
    let repo = local_repo_ref(repo_dir, pin)?;
    let wire = GitWire::new(vault)?;
    let handle = wire.open_repo(repo, repo_dir)?;
    let names = proposed
        .iter()
        .map(|update| GitRefName::parse_full(update.name.clone()))
        .collect::<Result<Vec<_>>>()?;
    let observed = wire.read_refs(&handle, &names)?;
    Ok(proposed
        .iter()
        .zip(observed)
        .filter_map(|(update, seen)| (update.new_oid == seen.oid).then(|| update.clone()))
        .collect())
}

fn finish_serve(
    vault: &Arc<Vault>,
    request: &ServeRequest,
    repo_dir: &Path,
    admission: Option<DoorAdmissionStamp>,
    exchange: ServeExchange,
) -> Result<ServeReport> {
    let mut report = ServeReport {
        status: exchange.status,
        admission,
        door: exchange.door,
        outcome: None,
        landing: None,
    };
    if !request.is_receive_pack() || !report.door.admitted() {
        return Ok(report);
    }
    let moved = realized_updates(vault, repo_dir, &report.door.ref_updates)?;
    if moved.is_empty() {
        return Ok(report);
    }
    let outcome = ReceivePackOutcome {
        repo_root: repo_dir.to_path_buf(),
        pack_stats: PackStats {
            request_bytes: exchange.request_bytes,
            response_bytes: exchange.response_bytes,
            ref_update_count: moved.len(),
        },
        ref_updates: moved,
        staged_objects_dir: repo_dir.join("objects"),
    };
    let repo = outcome.pinned_repo_ref()?;
    let landing = vault.apply_receive_pack_update(&repo, &outcome)?;
    report.outcome = Some(outcome);
    report.landing = Some(landing);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::ENTITY_METADATA_HEADER_LEN;
    use crate::config::VaultConfig;
    use crate::entity_id::ENTITY_ID_LEN;
    use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
    use crate::store::Store;
    use std::process::Command as StdCommand;

    fn temp_vault() -> (tempfile::TempDir, Arc<Vault>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        (dir, Arc::new(vault))
    }

    fn hooks_dir() -> (tempfile::TempDir, DoorHooksDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let hooks = DoorHooksDir::materialize(dir.path()).expect("materialize door hooks");
        (dir, hooks)
    }

    fn git(repo: &Path, args: &[&str]) -> String {
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
    fn seeded_repo() -> (tempfile::TempDir, PathBuf, GitOid) {
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

    fn landing_outcome(root: &Path, oid: &GitOid) -> ReceivePackOutcome {
        ReceivePackOutcome {
            repo_root: root.to_path_buf(),
            ref_updates: vec![RefUpdate {
                name: "refs/heads/main".to_owned(),
                old_oid: None,
                new_oid: Some(oid.clone()),
            }],
            staged_objects_dir: root.join(".git").join("objects"),
            pack_stats: PackStats {
                request_bytes: 0,
                response_bytes: 0,
                ref_update_count: 1,
            },
        }
    }

    fn sync_plane_rows(vault: &Vault) -> usize {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        vault
            .store
            .sync_state
            .iter(&rtxn)
            .expect("iter sync state")
            .count()
    }

    #[test]
    fn smart_http_serve_command_env_allowlist_is_closed() {
        let (root, hooks) = hooks_dir();
        let repo = root.path().join("demo.git");
        std::fs::create_dir_all(&repo).expect("repo dir");
        let command = ServeCommand::http_backend(&repo, root.path(), hooks.path())
            .expect("build serve command");

        let base = command.env().keys().cloned().collect::<Vec<_>>();
        assert_eq!(base, SERVE_BASE_ENV_KEYS.to_vec(), "closed serve baseline");
        assert_eq!(
            command.env().get("GIT_HTTP_EXPORT_ALL").map(String::as_str),
            Some("1"),
            "export pin"
        );

        let request = ServeRequest {
            method: "POST".to_owned(),
            path_info: "/demo.git/git-receive-pack".to_owned(),
            query_string: String::new(),
            content_type: Some("application/x-git-receive-pack-request".to_owned()),
            content_length: Some(7),
            content_encoding: Some("gzip".to_owned()),
            git_protocol: Some("version=2".to_owned()),
            remote_user: Some("principal:tester".to_owned()),
            remote_addr: None,
        };
        let child_env = command.child_env(&request);
        for key in child_env.keys() {
            let known = SERVE_BASE_ENV_KEYS.contains(&key.as_str())
                || SERVE_REQUEST_ENV_KEYS.contains(&key.as_str());
            assert!(known, "unexpected serve environment key {key}");
        }
        assert!(
            !child_env.contains_key("GIT_CONFIG_PARAMETERS"),
            "the config policy travels in argv, never in the environment"
        );
    }

    #[test]
    fn smart_http_serve_command_argv_pins_door_hooks_path() {
        let (root, hooks) = hooks_dir();
        let repo = root.path().join("demo.git");
        std::fs::create_dir_all(&repo).expect("repo dir");
        let command = ServeCommand::http_backend(&repo, root.path(), hooks.path())
            .expect("build serve command");

        let argv = command.argv();
        assert_eq!(argv[1], "-c", "the config pair leads the verb");
        assert_eq!(
            argv[2],
            format!("core.hooksPath={}", hooks.path().display()),
            "every serve invocation pins the door-owned hooks path"
        );
        assert_eq!(argv[3], "http-backend", "exactly one subprocess model");
        assert_eq!(argv.len(), 4, "the argv is frozen");
    }

    #[test]
    fn smart_http_door_hooks_dir_carries_only_the_vetted_hook() {
        let (_root, hooks) = hooks_dir();
        let entries = std::fs::read_dir(hooks.path())
            .expect("read hooks dir")
            .map(|entry| entry.expect("dir entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1, "one hook, nothing else");
        assert_eq!(entries[0], DOOR_PRE_RECEIVE_HOOK_NAME);
    }

    /// Frames one record the way the vetted hook does.
    fn blob_record(oid: &str, path: &str, content: &[u8]) -> Vec<u8> {
        let mut record = format!("blob {oid} {} {path}\n", content.len()).into_bytes();
        record.extend_from_slice(content);
        record
    }

    #[test]
    fn smart_http_framed_blobs_reach_the_door_whatever_their_bytes_look_like() {
        // Two entries a text patch could never carry past the door: added lines
        // that begin with `++` and `+++ b/...` (a patch grammar would read the
        // second as a file header and drop the first), and a blob whose bytes
        // are binary (a patch carries `Binary files ... differ` and no content
        // at all).
        let text = b"++ let token = \"value\";\n+++ b/decoy\n";
        let binary = [0x89_u8, 0x50, 0x00, 0x01, 0x02];
        let mut framed = blob_record(&"1".repeat(40), "app.rs", text);
        framed.extend_from_slice(&blob_record(&"2".repeat(40), "a dir/logo.png", &binary));

        let blobs = parse_pushed_blobs(&framed).expect("framed records parse");
        assert_eq!(blobs.len(), 2, "every enumerated entry reaches the door");
        assert_eq!(blobs[0].path, "app.rs");
        assert_eq!(
            blobs[0].oid,
            "1".repeat(40),
            "the post-image oid is what the push would make durable"
        );
        assert_eq!(
            blobs[0].added_lines,
            vec![
                b"++ let token = \"value\";".to_vec(),
                b"+++ b/decoy".to_vec()
            ],
            "no line is dropped and no line is reshaped"
        );
        assert_eq!(
            blobs[1].path, "a dir/logo.png",
            "the path field runs to the end of the header, spaces and all"
        );
        assert!(
            blobs[1].added_lines.iter().any(|line| line.contains(&0)),
            "binary bytes reach the door, which is what refuses them"
        );
    }

    #[test]
    fn smart_http_unreadable_blob_stream_is_an_error_never_an_empty_scan() {
        let oid = "1".repeat(40);
        for unusable in [
            format!("blob {oid} 99 app.rs\nshort"),
            format!("blob {oid} 4 app.rs"),
            format!("blob {oid} four app.rs\n"),
            format!("blob {oid} 0 \n"),
            format!("patch {oid} 0 app.rs\n"),
        ] {
            assert!(
                parse_pushed_blobs(unusable.as_bytes()).is_err(),
                "a stream not readable whole is refused, never scanned: {unusable:?}"
            );
        }
        assert!(
            parse_pushed_blobs(b"")
                .expect("an empty stream parses")
                .is_empty(),
            "a push that added no blob enumerates nothing"
        );
    }

    #[test]
    fn smart_http_receive_pack_coordinator_is_the_repositorys_common_dir() {
        let (_vault_dir, vault) = temp_vault();
        let (_source_dir, source, oid) = seeded_repo();
        // A bare repository is the shape the origin serves: GIT_DIR is the
        // repository directory itself.
        let dir = tempfile::tempdir().expect("bare tempdir");
        let source_arg = source.to_string_lossy().into_owned();
        git(
            dir.path(),
            &["clone", "--bare", "--", &source_arg, "demo.git"],
        );
        let bare = dir
            .path()
            .join("demo.git")
            .canonicalize()
            .expect("canonical bare repo");

        let repo = local_repo_ref(&bare, &oid).expect("pinned repo ref");
        let wire = GitWire::new(&vault).expect("git wire");
        let handle = wire.open_repo(repo, &bare).expect("open bare repo");
        assert_eq!(
            repo_common_dir(&bare).expect("coordinator key"),
            handle.common_dir(),
            "the coordinator the serve window takes is the coordinator the landing takes"
        );
    }

    #[test]
    fn smart_http_door_request_parses_creations_and_deletions() {
        let zero = "0".repeat(40);
        let oid = "a".repeat(40);
        let raw = format!(
            "quarantine /tmp/quarantine\nref {zero} {oid} refs/heads/main\nref {oid} {zero} refs/heads/old\nend\n"
        );
        let request = parse_door_request(raw.as_bytes()).expect("parse door request");
        assert_eq!(
            request.quarantine_path,
            Some(PathBuf::from("/tmp/quarantine"))
        );
        assert_eq!(request.ref_updates.len(), 2);
        assert!(
            request.ref_updates[0].old_oid.is_none(),
            "the null oid is absence, never a second oid type"
        );
        assert!(request.ref_updates[1].new_oid.is_none());
    }

    #[test]
    fn smart_http_repo_names_are_closed() {
        assert!(validate_repo_name("demo").is_ok());
        assert!(validate_repo_name("demo.core-1_x").is_ok());
        assert!(validate_repo_name("").is_err());
        assert!(validate_repo_name(".door").is_err());
        assert!(validate_repo_name("a/b").is_err());
        assert!(validate_repo_name("../escape").is_err());
    }

    #[test]
    fn smart_http_noop_door_hook_stamps_without_a_credential() {
        let repo = unpinned_repo_ref(Path::new("/tmp/demo.git"));
        let stamp = NoopDoorHook
            .admit_receive_pack(
                None,
                "principal:tester",
                &repo,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                7,
            )
            .expect("noop admission");
        assert_eq!(stamp.principal_ref(), "principal:tester");
        assert_eq!(stamp.method(), "bearer+registered-principal");
        assert!(
            stamp.credential_fingerprint().is_none(),
            "Phase A presents no slip, and the stamp says so"
        );
        assert!(
            matches!(
                NoopDoorHook.pre_receive_scan(&repo, &[]),
                Ok(DoorScanVerdict::Clean)
            ),
            "the no-op default adds no behavior"
        );
    }

    #[test]
    fn smart_http_landed_door_hook_refuses_an_unauthorized_slip() {
        let (_dir, vault) = temp_vault();
        let door = CredentialDoorService::new(Arc::clone(&vault));
        let repo = unpinned_repo_ref(Path::new("/tmp/demo.git"));
        // A slip that was never narrowed authorizes nothing: the wiring block
        // delegates to the door's own evaluator rather than restating it.
        let credential = DoorCredential::verified("slip-1", "principal:tester", 1, 10_000);
        let refused = DoorHook::admit_receive_pack(
            &door,
            Some(&credential),
            "principal:tester",
            &repo,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            10,
        );
        assert!(
            matches!(refused, Err(Error::ReceivePackDoorRejected { .. })),
            "an unnarrowed slip is refused at the door, not at the transport"
        );
    }

    /// Narrows the live door dial by landing the one POLICY_MANIFEST row an
    /// operator writes in a catastrophe.
    ///
    /// `secret.door.allowed_effectors` is spelled out here rather than imported
    /// because it is the OPERATOR-facing name, and this test is about what that
    /// operator's row does to the push path. A spelling that drifted from the
    /// door's own would leave the dial at its default and fail loudly below.
    fn narrow_door_effectors(vault: &Vault, effectors: Vec<rmpv::Value>) {
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

    /// The catastrophe dial must reach the path that carries NO slip.
    ///
    /// Every production push is that path: Phase A presents no capability slip
    /// by design, so a receive-pack gate reachable only through a presented
    /// credential is a gate no push ever passes through. An operator who empties
    /// `secret.door.allowed_effectors` would then shut every lease and injection
    /// downstream of the door while leaving the push door itself open.
    #[test]
    fn smart_http_narrowed_dial_shuts_the_push_door_with_no_slip_presented() {
        let (_dir, vault) = temp_vault();
        let repo_dir = Path::new("/tmp/demo.git");
        let request = ServeRequest {
            method: "POST".to_owned(),
            path_info: "/demo.git/git-receive-pack".to_owned(),
            query_string: String::new(),
            content_type: Some("application/x-git-receive-pack-request".to_owned()),
            content_length: None,
            content_encoding: None,
            git_protocol: None,
            remote_user: Some("principal:tester".to_owned()),
            remote_addr: Some("127.0.0.1".to_owned()),
        };

        let admitted = stamp_admission(&vault, &request, repo_dir, DoorSeam::Landed)
            .expect("the default dial admits the push door")
            .expect("a receive-pack stamps an admission");
        assert!(
            admitted.credential_fingerprint().is_none(),
            "no slip was presented, and the stamp says so"
        );

        narrow_door_effectors(&vault, Vec::new());
        assert!(
            matches!(
                stamp_admission(&vault, &request, repo_dir, DoorSeam::Landed),
                Err(Error::ReceivePackDoorRejected { .. })
            ),
            "an emptied effector set closes the push path itself, not only what is downstream"
        );
        // Refused HERE is refused before anything exists to refuse it at:
        // `stamp_admission` runs ahead of the coordinator and ahead of the
        // backend, so no pushed byte is ever read.
        assert!(
            DoorHook::admit_receive_pack(
                &CredentialDoorService::new(Arc::clone(&vault)),
                None,
                "principal:tester",
                &unpinned_repo_ref(repo_dir),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                10,
            )
            .is_err(),
            "the seam itself carries the gate, not just this one caller"
        );
        assert!(
            stamp_admission(&vault, &request, repo_dir, DoorSeam::Noop).is_ok(),
            "the no-op seam refuses nothing, which is its whole contract"
        );
    }

    /// The pin names WHICH object store the landing publishes into. A push that
    /// only deletes advances no post-image, and reading the pin out of
    /// `new_oid` alone is what dropped those pushes: no pin, no handle, no
    /// landing, and a mutated repository with no receipt.
    #[test]
    fn smart_http_delete_only_updates_still_name_a_pin() {
        let advanced = GitOid::parse_hex("a".repeat(40)).expect("post-image oid");
        let decided_against = GitOid::parse_hex("b".repeat(40)).expect("pre-image oid");
        let creation = RefUpdate {
            name: "refs/heads/main".to_owned(),
            old_oid: None,
            new_oid: Some(advanced.clone()),
        };
        let deletion = RefUpdate {
            name: "refs/heads/old".to_owned(),
            old_oid: Some(decided_against.clone()),
            new_oid: None,
        };

        assert_eq!(
            landing_pin(std::slice::from_ref(&deletion)),
            Some(&decided_against),
            "a delete-only push pins the pre-image it was decided against, so it lands"
        );
        let mixed = [deletion, creation];
        assert_eq!(
            landing_pin(&mixed),
            Some(&advanced),
            "a mixed push still pins the post-image it advanced"
        );
        assert_eq!(landing_pin(&[]), None, "nothing proposed pins nothing");
    }

    #[test]
    fn smart_http_landed_door_hook_rejects_secret_shaped_added_lines() {
        let (_dir, vault) = temp_vault();
        let door = CredentialDoorService::new(Arc::clone(&vault));
        let repo = unpinned_repo_ref(Path::new("/tmp/demo.git"));
        let blob = PushedBlob {
            path: "config.env".to_owned(),
            oid: "1".repeat(40),
            added_lines: vec![b"ghp_0123456789abcdefghijklmnopqrstuvwxyz".to_vec()],
        };
        let verdict =
            DoorHook::pre_receive_scan(&door, &repo, std::slice::from_ref(&blob)).expect("scan");
        assert!(
            matches!(verdict, DoorScanVerdict::Rejected { .. }),
            "the landed door's scan is unconditional"
        );
        let clean = scan_through(&NoopDoorHook, &repo, std::slice::from_ref(&blob));
        assert_eq!(
            clean,
            DoorWindowVerdict::Clean,
            "the no-op default is the seam without behavior"
        );
    }

    #[test]
    fn receive_pack_landing_never_writes_sync_plane() {
        let (_vault_dir, vault) = temp_vault();
        let (_repo_dir, root, oid) = seeded_repo();
        let outcome = landing_outcome(&root, &oid);
        let repo = outcome.pinned_repo_ref().expect("pinned repo ref");

        let before = sync_plane_rows(&vault);
        let landing = vault
            .apply_receive_pack_update(&repo, &outcome)
            .expect("land receive-pack outcome");
        assert!(
            !landing.replayed,
            "the first landing journals its own record"
        );
        assert_eq!(
            sync_plane_rows(&vault),
            before,
            "repo refs ride the git wire; repo bytes never enter the sync plane"
        );
    }

    #[test]
    fn smart_http_replayed_receive_pack_outcome_is_a_noop() {
        let (_vault_dir, vault) = temp_vault();
        let (_repo_dir, root, oid) = seeded_repo();
        let outcome = landing_outcome(&root, &oid);
        let repo = outcome.pinned_repo_ref().expect("pinned repo ref");

        let first = vault
            .apply_receive_pack_update(&repo, &outcome)
            .expect("first landing");
        let second = vault
            .apply_receive_pack_update(&repo, &outcome)
            .expect("replayed landing");
        assert!(!first.replayed);
        assert!(
            second.replayed,
            "a replayed outcome is answered from the durable record"
        );
        assert_eq!(
            first.receipt.record_key, second.receipt.record_key,
            "the replay writes no second record"
        );
    }

    #[test]
    fn smart_http_observed_refs_gate_the_landing() {
        let (_vault_dir, vault) = temp_vault();
        let (_repo_dir, root, oid) = seeded_repo();
        let outcome = landing_outcome(&root, &oid);
        let repo = outcome.pinned_repo_ref().expect("pinned repo ref");

        let applied = refs_already_applied(
            &vault,
            &repo,
            &root,
            &[ObservedRef {
                name: "refs/heads/main".to_owned(),
                oid: Some(oid),
            }],
        )
        .expect("observe refs");
        assert!(applied, "the pushed value is what the repository carries");

        let stale = refs_already_applied(
            &vault,
            &repo,
            &root,
            &[ObservedRef {
                name: "refs/heads/main".to_owned(),
                oid: None,
            }],
        )
        .expect("observe refs");
        assert!(!stale, "an absent expectation does not match a live ref");
    }

    #[test]
    fn smart_http_landing_refuses_an_empty_publication() {
        let (_vault_dir, vault) = temp_vault();
        let (_repo_dir, root, oid) = seeded_repo();
        let mut outcome = landing_outcome(&root, &oid);
        outcome.ref_updates.clear();
        let repo = RepoRef::LocalFolder {
            path: root.to_string_lossy().into_owned(),
            commit: oid.as_str().to_owned(),
        };
        assert!(
            vault.apply_receive_pack_update(&repo, &outcome).is_err(),
            "a landing that moves no ref is refused, never receipted"
        );
    }
}
