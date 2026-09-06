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
//! - **No substituted bytes.** Replacement-object lookup is OFF on every git the
//!   serve path runs: `GIT_NO_REPLACE_OBJECTS` is part of the closed baseline
//!   (an environment variable reaches every git a git spawns) and the vetted
//!   hook additionally passes `--no-replace-objects` to each of its own git
//!   children. A push that proposes a `refs/replace/*` name is refused in the
//!   door window on top of that, so no replacement can be planted through this
//!   wire at all. Without both, a planted `refs/replace/<oid>` would make the
//!   door's scan read benign substitute bytes while the original object is what
//!   the push makes durable.
//! - **Only journalable refs move.** The door window refuses a push whose
//!   proposed names the landing could not journal — names outside the GitWire
//!   ref grammar, a name proposed twice, or a batch larger than the GitWire
//!   publication bound — WHILE the objects are still quarantined. The landing's
//!   own parse is the last line of defence, not the first: discovering an
//!   unpublishable name after `git receive-pack` has moved refs would leave a
//!   mutated repository with no receipt.
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
use std::collections::btree_map::Entry;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::Vault;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, encode_claim_body,
};
use crate::codebase::RepoRef;
use crate::credential_door::{
    CredentialDoorError, CredentialDoorService, DOOR_RECEIVE_PACK_EFFECTOR, DoorCredential,
    DoorScanVerdict, PushedBlob,
};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{
    GIT_WIRE_KEEP_REF_PREFIX, GitOid, GitRefExpectation, GitRefName, GitRefPublication,
    GitTreeEntry, GitWire, GitWireCommitOutcome, GitWireProcessEnv, GitWireReceipt, GitWireRepo,
    lock_repository,
};
use crate::origin::lfs::{
    DefaultRepositoryLargeLfsPathPolicy, LfsAdmission, LfsOid, LfsPointerIntent, LfsPushedPointer,
    lfs_repo_id,
};
use crate::origin::publication::{
    OriginPublicationReceipt, OriginPublicationRequest, OriginPublicationStatus,
};
use crate::temporal::TimeRange;
use rmpv::Value;

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
///
/// `GIT_NO_REPLACE_OBJECTS` is in the baseline rather than in argv because it
/// has to reach git children this process never spawns: `http-backend` spawns
/// `receive-pack`, which spawns the door hook, which spawns the plumbing that
/// reads the pushed bytes. An environment variable travels that whole chain,
/// and a replacement lookup anywhere in it would show the scan bytes other than
/// the ones the push makes durable.
pub const SERVE_BASE_ENV_KEYS: [&str; 5] = [
    "GIT_DIR",
    "GIT_HTTP_EXPORT_ALL",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_PROJECT_ROOT",
    "PATH",
];

/// The closed CGI request half of the child environment. Every value is
/// constructed from the typed [`ServeRequest`]; none is read from the ambient
/// environment.
///
/// These are exactly the request-scoped names `git http-backend` reads:
/// `HTTP_CONTENT_ENCODING` (a stock client gzips its RPC bodies) and
/// `HTTP_GIT_PROTOCOL` (the negotiated wire version) carry their CGI spelling,
/// because that is the spelling the backend looks for.
///
/// The allowlist is what a served child MAY be given, not what it is always
/// given: `HTTP_GIT_PROTOCOL` is currently never emitted, because the ref
/// advertisement is gated by the publication projection and protocol v2 moves
/// the ref list somewhere that projection cannot reach.
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

/// The most ref moves one push may propose.
///
/// It mirrors GitWire's publication bound, because the landing publishes what
/// the push moved through exactly one publication set: a batch the landing
/// could not carry is refused BEFORE `git receive-pack` moves anything, rather
/// than discovered after the refs are already elsewhere.
pub const ORIGIN_MAX_REF_UPDATES: usize = 64;

/// The ref namespace this origin never lets a push write.
///
/// A `refs/replace/<oid>` entry rewrites what every later object lookup in this
/// repository sees. The door scans the bytes a push makes durable, so a push
/// that could plant a replacement is a push that could aim the next scan at
/// bytes nobody is landing.
pub const ORIGIN_REFUSED_REF_PREFIX: &str = "refs/replace/";

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

/// How much of a refused ref name a refusal echoes back to the client. A
/// diagnostic names the ref; it never becomes a channel of its own.
const DOOR_REFUSAL_NAME_CHARS: usize = 100;

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
#
# Every git below reads TRUE object bytes: replacement lookup is disabled by the
# exported GIT_NO_REPLACE_OBJECTS (which reaches any git a git spawns) and again
# by --no-replace-objects in each argv. A planted refs/replace/<oid> would
# otherwise hand this scan a benign substitute while the original object is what
# the push makes durable.
set -eu
GIT_NO_REPLACE_OBJECTS=1
export GIT_NO_REPLACE_OBJECTS
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
empty=$(git --no-replace-objects hash-object -t tree /dev/null)
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
	git --no-replace-objects diff-tree -r --raw --no-abbrev --no-commit-id \
		--diff-filter=AMT "$base" "$new" > "$entries"
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
		size=$(git --no-replace-objects cat-file -s "$oid")
		printf 'blob %s %s %s\n' "$oid" "$size" "$path" >> "$blobspart"
		git --no-replace-objects cat-file blob "$oid" >> "$blobspart"
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
    operation_id: EntityId,
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
            operation_id: EntityId::now(),
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
            operation_id: EntityId::now(),
        }
    }

    /// The request identity. After `serve` admits the request, this also names
    /// its durable admission claim. Allocating this id alone is not evidence.
    #[must_use]
    pub const fn operation_id(&self) -> EntityId {
        self.operation_id
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

    /// Whether this request is the smart-HTTP ref advertisement.
    ///
    /// This is the ONE response that carries a ref list, and therefore the one
    /// response [`Vault::published_origin_refs`] gates.
    #[must_use]
    pub fn is_ref_advertisement(&self) -> bool {
        self.method.eq_ignore_ascii_case("GET")
            && self.path_info.ends_with("/info/refs")
            && self.advertised_service().is_some()
    }

    /// The service a smart advertisement names, if this request is one.
    ///
    /// A `GET /info/refs` with no `service=` is the DUMB protocol: it serves a
    /// file, not a pkt-line ref list, and nothing here touches it.
    fn advertised_service(&self) -> Option<&'static str> {
        self.query_string.split('&').find_map(|pair| match pair {
            "service=git-upload-pack" => Some("git-upload-pack"),
            "service=git-receive-pack" => Some("git-receive-pack"),
            _ => None,
        })
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
        // `HTTP_GIT_PROTOCOL` is deliberately NOT forwarded, so every served
        // exchange speaks the v0/v1 wire.
        //
        // Protocol v2 moves the ref list out of this response and into an
        // `ls-refs` command inside the RPC body, where it is interleaved with
        // negotiation and cannot be projected through
        // [`Vault::published_origin_refs`]. Advertising v2 and then gating
        // nothing would publish heads this vault has not proved; advertising
        // v2 and gating the GET would leave the client asking `ls-refs` for a
        // list nobody filtered. Declining the version is the only answer that
        // keeps "every advertised ref is a published ref" true, and a stock
        // client that asked for v2 falls back to v0 on its own.
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
        // Reaches receive-pack, the door hook, and every git either of them
        // spawns: the whole serve path reads true object bytes, never a
        // replacement's.
        env.insert("GIT_NO_REPLACE_OBJECTS".to_owned(), "1".to_owned());
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
    /// detector code, or one proposed ref name this origin will not land; no
    /// matched line and no value bytes ever appear here.
    Rejected {
        /// One printable reason per offending blob or refused ref.
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
    /// The Git-LFS pointers this push newly introduced, paired with the
    /// repository paths that carry them.
    ///
    /// The pairing is knowable HERE and nowhere later: the vetted hook framed
    /// every added or modified blob together with its path, and once the
    /// quarantine migrates that association is gone. Carrying it forward is
    /// what lets the landing decide about a pointer instead of guessing.
    pub lfs_pointers: Vec<LfsPushedPointer>,
    /// The quarantine the objects sat in while the door decided.
    pub quarantine_path: Option<PathBuf>,
}

impl DoorWindowReport {
    fn not_invoked() -> Self {
        Self {
            verdict: DoorWindowVerdict::NotInvoked,
            ref_updates: Vec::new(),
            lfs_pointers: Vec::new(),
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
                lfs_pointers: Vec::new(),
                quarantine_path: None,
            });
        }
        std::thread::sleep(DOOR_WINDOW_POLL);
    }

    // Everything past the request file is fail-closed and ANSWERED: a request
    // that cannot be parsed and an extraction that cannot be read whole are
    // both unscanned bytes, so they become a published refusal rather than an
    // empty scan — and rather than an unanswered hook left blocking.
    let (ref_updates, lfs_pointers, quarantine_path, verdict) =
        match door_window_inputs(&request_path, hooks) {
            Ok((request, blobs)) => {
                // The name rule decides FIRST, and it decides here rather than
                // at the landing: this is the last moment at which refusing
                // costs nothing, because the hook is still blocked and the
                // backend has moved no ref. A push whose names the landing
                // could not journal is refused whole; nothing about a legal
                // batch changes.
                let unlandable = unlandable_ref_reasons(&request.ref_updates);
                let verdict = if unlandable.is_empty() {
                    match seam {
                        DoorSeam::Noop => scan_through(&NoopDoorHook, repo, &blobs),
                        DoorSeam::Landed => scan_through(
                            &CredentialDoorService::new(Arc::clone(vault)),
                            repo,
                            &blobs,
                        ),
                    }
                } else {
                    DoorWindowVerdict::Rejected {
                        reasons: unlandable,
                    }
                };
                (
                    request.ref_updates,
                    lfs_pushed_pointers(&blobs),
                    request.quarantine_path,
                    verdict,
                )
            }
            Err(error) => (
                Vec::new(),
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
        lfs_pointers,
        quarantine_path,
    })
}

/// The Git-LFS pointers a push newly introduced.
///
/// Reads only what the door was already handed. No git child runs, no object
/// is re-read, and a blob that is not a pointer is simply not one: the
/// grammar decides, never a size.
fn lfs_pushed_pointers(blobs: &[PushedBlob]) -> Vec<LfsPushedPointer> {
    blobs
        .iter()
        .filter_map(|blob| LfsPushedPointer::from_pointer_lines(&blob.path, &blob.added_lines))
        .collect()
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

/// Why this push cannot be landed, one reason per offending name, empty when
/// every proposed move is one the landing can journal.
///
/// This is the pre-move half of the landing's own rule. `RefUpdate::publication`
/// and `realized_updates` both parse these names with [`GitRefName::parse_full`]
/// and both collect WHOLE, so a single name outside the GitWire grammar turns
/// the landing into an error — and by then `git receive-pack` has moved the
/// refs, leaving a mutated repository with no receipt. Deciding here, while the
/// hook is still blocked and the objects are still quarantined, is what keeps
/// "git moved it" and "the origin journaled it" the same set.
///
/// Every rule below is one the landing enforces anyway; none of them narrows
/// what a legal push may do:
///
/// - `refs/replace/*` is refused outright (see [`ORIGIN_REFUSED_REF_PREFIX`]):
///   the landing would publish it, and what it publishes is a rewrite of what
///   every later scan of this repository reads.
/// - A name outside the GitWire ref grammar is refused, because
///   [`GitRefName::parse_full`] is what the landing must parse it with.
/// - A name proposed twice and a batch past [`ORIGIN_MAX_REF_UPDATES`] are
///   refused, because GitWire's publication set rejects both.
fn unlandable_ref_reasons(updates: &[RefUpdate]) -> Vec<String> {
    let mut reasons = Vec::new();
    if updates.len() > ORIGIN_MAX_REF_UPDATES {
        reasons.push(format!(
            "a push may propose at most {ORIGIN_MAX_REF_UPDATES} ref moves; this one proposes {}",
            updates.len()
        ));
    }
    for (index, update) in updates.iter().enumerate() {
        let name = printable_ref_name(&update.name);
        if update.name.starts_with(ORIGIN_REFUSED_REF_PREFIX) {
            reasons.push(format!(
                "{name}: this origin never serves a replacement ref"
            ));
        } else if GitRefName::parse_full(update.name.clone()).is_err() {
            reasons.push(format!("{name}: not a ref name this origin can journal"));
        } else if updates[..index]
            .iter()
            .any(|earlier| earlier.name == update.name)
        {
            reasons.push(format!("{name}: proposed twice in one push"));
        }
    }
    reasons
}

/// The offending name as it may appear in a refusal the client will read.
///
/// A refusal names the ref and nothing else — no pushed byte and no value ever
/// reaches this string. The name itself is client-supplied, so it is bounded
/// and stripped of anything that is not printable ASCII before it is echoed.
fn printable_ref_name(name: &str) -> String {
    let mut printable = name
        .chars()
        .take(DOOR_REFUSAL_NAME_CHARS)
        .map(|character| {
            if character.is_ascii_graphic() || character == ' ' {
                character
            } else {
                '?'
            }
        })
        .collect::<String>();
    if name.chars().nth(DOOR_REFUSAL_NAME_CHARS).is_some() {
        printable.push_str("...");
    }
    printable
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
    // The name is the LAST field, so a line with a fourth one describes a name
    // this parse would truncate — and a truncated name is a name the door would
    // decide while git moved a different one. Git's own ref grammar has no
    // space in it, so this is a fault, and a fault here is a refusal.
    if parts.next().is_some() {
        return Err(serve_failed("door request ref line has a spaced ref name"));
    }
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
    /// The Git-LFS pointers this push newly introduced, as the door window
    /// framed them. Empty for every push that introduced none, which is every
    /// push that does not use LFS.
    pub lfs_pointers: Vec<LfsPushedPointer>,
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

// These claims describe transport admission and observation, NOT publication
// or a credential evaluation that Phase A never performed. The local receipt
// is atomic with the generic claim write and is not sync/export authority:
// copied or caller-written claim bodies alone cannot impersonate this observer.
pub(super) const RECEIVE_PACK_ADMISSION_PREDICATE: &str = "repo.receive_pack_admission";
pub(super) const RECEIVE_PACK_OUTCOME_PREDICATE: &str = "repo.receive_pack_outcome";
const RECEIVE_PACK_EVIDENCE_PREFIX: &[u8] = b"origin:receive_pack_evidence:v1:";

fn receive_pack_evidence_key(id: EntityId) -> Vec<u8> {
    let mut key = RECEIVE_PACK_EVIDENCE_PREFIX.to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}

fn receive_pack_fields(fields: Vec<(&str, Value)>) -> Value {
    Value::Map(
        fields
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}

fn receive_pack_field<'a>(body: &'a ClaimBody, key: &str) -> Result<&'a Value> {
    body.value
        .as_map()
        .and_then(|fields| {
            fields
                .iter()
                .find(|(name, _)| name.as_str() == Some(key))
                .map(|(_, value)| value)
        })
        .ok_or_else(|| receive_pack_provenance_refused("missing evidence field"))
}

fn receive_pack_provenance_refused(reason: &str) -> Error {
    Error::ReceivePackLandingRefused {
        reason: format!("receive-pack provenance: {reason}"),
    }
}

fn receive_pack_updates_value(updates: &[RefUpdate]) -> Value {
    Value::Array(
        updates
            .iter()
            .map(|update| {
                Value::Array(vec![
                    Value::from(update.name.clone()),
                    update
                        .old_oid
                        .as_ref()
                        .map_or(Value::Nil, |oid| Value::from(oid.as_str())),
                    update
                        .new_oid
                        .as_ref()
                        .map_or(Value::Nil, |oid| Value::from(oid.as_str())),
                ])
            })
            .collect(),
    )
}

fn receive_pack_lfs_value(pointers: &[LfsPushedPointer]) -> Value {
    Value::Array(
        pointers
            .iter()
            .map(|pointer| {
                Value::Array(vec![
                    Value::from(pointer.path.clone()),
                    Value::from(pointer.oid.to_hex()),
                    Value::from(pointer.size_bytes),
                ])
            })
            .collect(),
    )
}

fn receive_pack_stats_value(stats: PackStats) -> Value {
    Value::Array(vec![
        Value::from(stats.request_bytes),
        Value::from(stats.response_bytes),
        Value::from(stats.ref_update_count as u64),
    ])
}

fn receive_pack_claim(subject: ClaimSubject, predicate: &str, value: Value) -> ClaimBody {
    let mut body = ClaimBody::new(
        predicate,
        subject,
        value,
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    // Only public repository operation metadata, as in repo.publication. No
    // bearer, credential bytes, blob contents, or scanner matches are retained.
    body.scope = Some(receive_pack_fields(vec![(
        "sensitivity",
        Value::from("public"),
    )]));
    body
}

impl Vault {
    fn put_receive_pack_evidence(&self, id: EntityId, body: &ClaimBody, at: u64) -> Result<()> {
        let encoded = encode_claim_body(body)?;
        let key = receive_pack_evidence_key(id);
        self.with_write_txn(|wtxn| {
            if self.store.entities.get(wtxn, id.as_bytes())?.is_some()
                || self.store.vault_meta.get(wtxn, &key)?.is_some()
            {
                return Err(receive_pack_provenance_refused(
                    "evidence id already exists",
                ));
            }
            self.put_claim_in_txn(wtxn, &id, body, TimeRange { start: at, end: at }, at)?;
            self.store.vault_meta.put(wtxn, &key, &encoded)?;
            Ok(())
        })
    }

    fn receive_pack_evidence_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: EntityId,
        predicate: &str,
    ) -> Result<ClaimBody> {
        let body = self
            .get_claim_in_txn(rtxn, &id)?
            .ok_or_else(|| receive_pack_provenance_refused("claim is absent"))?;
        let key = receive_pack_evidence_key(id);
        let receipt =
            self.store.vault_meta.get(rtxn, &key)?.ok_or_else(|| {
                receive_pack_provenance_refused("not a locally observed operation")
            })?;
        let receipt: &[u8] = receipt.as_ref();
        if body.predicate != predicate
            || body.lifecycle != ClaimLifecycleStatus::Active
            || receipt != encode_claim_body(&body)?.as_slice()
        {
            return Err(receive_pack_provenance_refused(
                "claim does not match its producer receipt",
            ));
        }
        Ok(body)
    }

    fn record_receive_pack_admission(
        &self,
        repo_dir: &Path,
        stamp: &DoorAdmissionStamp,
        seam: DoorSeam,
    ) -> Result<()> {
        // Preserve the explicit no-op transport seam, but never describe it
        // as landed policy or scanning evidence. The authenticated server pins
        // Landed; the seam is not selected by any request field or claim id.
        let (door_seam, effector_check) = match seam {
            DoorSeam::Landed => ("landed", "admitted"),
            DoorSeam::Noop => ("noop", "not_performed"),
        };
        let actor = EntityId::from_hex(stamp.principal_ref())
            .map_err(|_| receive_pack_provenance_refused("principal is not an entity id"))?;
        let body = receive_pack_claim(
            ClaimSubject::Edge {
                source: stamp.operation_id,
                kind: EdgeKind::PartOf,
                target: actor,
            },
            RECEIVE_PACK_ADMISSION_PREDICATE,
            receive_pack_fields(vec![
                ("schema_version", Value::from(1)),
                ("operation_id", Value::from(stamp.operation_id.to_hex())),
                ("actor_id", Value::from(actor.to_hex())),
                (
                    "repo_root",
                    Value::from(path_arg(&repo_dir.canonicalize()?)?),
                ),
                ("operation", Value::from("git-receive-pack")),
                ("method", Value::from(stamp.method())),
                (
                    "credential_presented",
                    Value::from(stamp.credential_fingerprint().is_some()),
                ),
                ("door_seam", Value::from(door_seam)),
                ("effector", Value::from(DOOR_RECEIVE_PACK_EFFECTOR)),
                ("effector_check", Value::from(effector_check)),
                ("admitted_at", Value::from(stamp.admitted_at())),
            ]),
        );
        self.put_receive_pack_evidence(stamp.operation_id, &body, stamp.admitted_at())
    }

    // Only finish_serve calls this production producer, after the single
    // backend has exited, the door window admitted the intent and live refs
    // narrowed it to observed results under the repository lock. An explicit
    // Noop transport never claims the landed scanner ran.
    fn record_receive_pack_outcome(
        &self,
        stamp: &DoorAdmissionStamp,
        door: &DoorWindowReport,
        outcome: &ReceivePackOutcome,
        status: u16,
    ) -> Result<ReceivePackAttribution> {
        if !door.admitted()
            || outcome.lfs_pointers != door.lfs_pointers
            || !outcome
                .ref_updates
                .iter()
                .all(|update| door.ref_updates.contains(update))
        {
            return Err(receive_pack_provenance_refused(
                "scan did not admit this intent",
            ));
        }
        let wire = GitWire::new(self)?;
        let repo = wire.open_repo(outcome.pinned_repo_ref()?, &outcome.repo_root)?;
        let repo_id = lfs_repo_id(&repo.identity().as_hex())?;
        let actor = EntityId::from_hex(stamp.principal_ref())
            .map_err(|_| receive_pack_provenance_refused("principal is not an entity id"))?;
        let admission = {
            let rtxn = self.store.env.read_txn()?;
            self.receive_pack_evidence_in_txn(
                &rtxn,
                stamp.operation_id,
                RECEIVE_PACK_ADMISSION_PREDICATE,
            )?
        };
        let scan = match receive_pack_field(&admission, "door_seam")?.as_str() {
            Some("landed") => "clean",
            Some("noop") => "not_performed",
            _ => {
                return Err(receive_pack_provenance_refused(
                    "unknown admitted door seam",
                ));
            }
        };
        let id = EntityId::now();
        let body = receive_pack_claim(
            ClaimSubject::Edge {
                source: actor,
                kind: EdgeKind::PartOf,
                target: repo_id,
            },
            RECEIVE_PACK_OUTCOME_PREDICATE,
            receive_pack_fields(vec![
                ("schema_version", Value::from(1)),
                ("operation_id", Value::from(stamp.operation_id.to_hex())),
                ("actor_id", Value::from(actor.to_hex())),
                ("repo_id", Value::from(repo_id.to_hex())),
                (
                    "repo_root",
                    Value::from(path_arg(&outcome.repo_root.canonicalize()?)?),
                ),
                ("operation", Value::from("git-receive-pack")),
                (
                    "intent_updates",
                    receive_pack_updates_value(&door.ref_updates),
                ),
                (
                    "realized_updates",
                    receive_pack_updates_value(&outcome.ref_updates),
                ),
                (
                    "lfs_pointers",
                    receive_pack_lfs_value(&outcome.lfs_pointers),
                ),
                ("pack_stats", receive_pack_stats_value(outcome.pack_stats)),
                (
                    "staged_objects_dir",
                    Value::from(path_arg(&outcome.staged_objects_dir)?),
                ),
                ("scan", Value::from(scan)),
                ("backend_exited_successfully", Value::from(true)),
                ("http_status", Value::from(status)),
                ("observed_at", Value::from(now_secs())),
            ]),
        );
        self.put_receive_pack_evidence(id, &body, now_secs())?;
        let attribution = ReceivePackAttribution {
            actor_id: actor,
            provenance_claim_id: id,
        };
        self.validate_receive_pack_attribution(repo_id, outcome, &attribution)?;
        Ok(attribution)
    }

    fn receive_pack_source(
        &self,
        repo_id: EntityId,
        repo_root: &Path,
        attribution: &ReceivePackAttribution,
    ) -> Result<ClaimBody> {
        let rtxn = self.store.env.read_txn()?;
        let body = self.receive_pack_evidence_in_txn(
            &rtxn,
            attribution.provenance_claim_id,
            RECEIVE_PACK_OUTCOME_PREDICATE,
        )?;
        let operation = receive_pack_field(&body, "operation_id")?
            .as_str()
            .and_then(|id| EntityId::from_hex(id).ok())
            .ok_or_else(|| receive_pack_provenance_refused("invalid operation identity"))?;
        let admission =
            self.receive_pack_evidence_in_txn(&rtxn, operation, RECEIVE_PACK_ADMISSION_PREDICATE)?;
        let actor = attribution.actor_id;
        let root = Value::from(path_arg(&repo_root.canonicalize()?)?);
        let observation_matches_seam = matches!(
            (
                receive_pack_field(&admission, "door_seam")?.as_str(),
                receive_pack_field(&admission, "effector_check")?.as_str(),
                receive_pack_field(&body, "scan")?.as_str()
            ),
            (Some("landed"), Some("admitted"), Some("clean"))
                | (Some("noop"), Some("not_performed"), Some("not_performed"))
        );
        if body.subject
            != (ClaimSubject::Edge {
                source: actor,
                kind: EdgeKind::PartOf,
                target: repo_id,
            })
            || admission.subject
                != (ClaimSubject::Edge {
                    source: operation,
                    kind: EdgeKind::PartOf,
                    target: actor,
                })
            || receive_pack_field(&body, "repo_id")? != &Value::from(repo_id.to_hex())
            || receive_pack_field(&body, "actor_id")? != &Value::from(actor.to_hex())
            || receive_pack_field(&admission, "actor_id")? != &Value::from(actor.to_hex())
            || receive_pack_field(&admission, "operation_id")? != &Value::from(operation.to_hex())
            || receive_pack_field(&body, "repo_root")? != &root
            || receive_pack_field(&admission, "repo_root")? != &root
            || receive_pack_field(&body, "operation")? != &Value::from("git-receive-pack")
            || receive_pack_field(&admission, "operation")? != &Value::from("git-receive-pack")
            || !observation_matches_seam
        {
            return Err(receive_pack_provenance_refused(
                "actor, repository or operation does not match",
            ));
        }
        Ok(body)
    }

    fn validate_receive_pack_attribution(
        &self,
        repo_id: EntityId,
        outcome: &ReceivePackOutcome,
        attribution: &ReceivePackAttribution,
    ) -> Result<()> {
        let body = self.receive_pack_source(repo_id, &outcome.repo_root, attribution)?;
        if receive_pack_field(&body, "realized_updates")?
            != &receive_pack_updates_value(&outcome.ref_updates)
            || receive_pack_field(&body, "lfs_pointers")?
                != &receive_pack_lfs_value(&outcome.lfs_pointers)
            || receive_pack_field(&body, "pack_stats")?
                != &receive_pack_stats_value(outcome.pack_stats)
            || receive_pack_field(&body, "staged_objects_dir")?
                != &Value::from(path_arg(&outcome.staged_objects_dir)?)
        {
            return Err(receive_pack_provenance_refused(
                "outcome does not match the observed operation",
            ));
        }
        Ok(())
    }

    pub(super) fn has_receive_pack_evidence(&self, id: EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        Ok(self
            .store
            .vault_meta
            .get(&rtxn, &receive_pack_evidence_key(id))?
            .is_some())
    }

    /// The publication door must not let a receive-pack source certify some
    /// other ref triple, actor or repository through a lower-level caller.
    pub(super) fn validate_receive_pack_publication(
        &self,
        request: &OriginPublicationRequest,
    ) -> Result<()> {
        let attribution = ReceivePackAttribution {
            actor_id: request.actor_id,
            provenance_claim_id: request.provenance_claim_id,
        };
        let body =
            self.receive_pack_source(request.repo_id, request.repo.repo_root(), &attribution)?;
        let update = RefUpdate {
            name: request.ref_name.as_str().to_owned(),
            old_oid: request.expected_old_oid.clone(),
            new_oid: Some(request.new_oid.clone()),
        };
        let expected = receive_pack_updates_value(&[update]);
        if !receive_pack_field(&body, "realized_updates")?
            .as_array()
            .is_some_and(|updates| {
                expected
                    .as_array()
                    .is_some_and(|wanted| updates.contains(&wanted[0]))
            })
        {
            return Err(receive_pack_provenance_refused(
                "ref triple was not observed in this operation",
            ));
        }
        Ok(())
    }
}

/// Attribution from the durable receive-pack observer. The landing verifies
/// the local producer receipt and the actor/repository/operation binding.
#[derive(Debug, Clone, Copy)]
pub struct ReceivePackAttribution {
    /// Server-derived authenticated principal, not an origin-local stand-in.
    pub actor_id: EntityId,
    /// Durable observed-outcome claim written by this module's serve path.
    /// Landing reads it; caller-supplied active claims are not source proof.
    pub provenance_claim_id: EntityId,
}

/// The durable record of one landing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivePackLanding {
    /// The first certified ref's receipt. A multi-ref landing is not atomic;
    /// success means every ref certified, but failure never rolls earlier refs back.
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
    /// Replays a receive-pack outcome through the single-writer path.
    ///
    /// New advancing publications require
    /// [`Vault::apply_receive_pack_update_with_attribution`]. This outcome-only
    /// door recovers attribution from an existing journal row or refuses.
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
    /// The ref advance is journaled through the origin publication protocol,
    /// which is the crash-window protocol for refs: a durable intent exists
    /// before the effect is claimed, the postcondition is re-verified against
    /// the repository, object availability is proved *whole* before any ref is
    /// certified, and the census finishes any record a crash left `Prepared`.
    /// Nothing here writes the sync plane.
    ///
    /// # Why an advance and a deletion take different routes
    ///
    /// An advance PUBLISHES: it makes a new head visible, so it owes the
    /// availability proof, the claim, and the visible-ref row that
    /// [`Vault::published_origin_refs`] projects. It therefore runs through
    /// [`Vault::publish_origin_ref`], one publication per ref, and a
    /// publication the protocol refuses refuses the landing.
    ///
    /// A deletion publishes nothing. It withdraws a name, needs no object to
    /// be present (deleting a ref unlinks a name rather than removing an
    /// object), and mints no visibility — so it stays on the plain journaled
    /// ref path. Routing it through the publication protocol would demand an
    /// availability proof for a head that is being retired.
    ///
    /// # LFS pointer admission
    ///
    /// The admission runs HERE rather than at the transport, so a replay and a
    /// recovery pass through it exactly as a served push does — a gate a caller
    /// can route around is not a gate. It is the one place that knows both the
    /// proven repository identity and the pointers the door framed.
    pub fn apply_receive_pack_update(
        &self,
        repo: &RepoRef,
        outcome: &ReceivePackOutcome,
    ) -> Result<ReceivePackLanding> {
        self.apply_receive_pack_update_inner(repo, outcome, None)
    }

    /// Lands an authenticated push with a real, already-durable source claim.
    /// Authentication belongs to the transport. Its served operation produces
    /// the evidence here; actor, repository and outcome bindings are checked
    /// against both active claims and the local producer receipts.
    pub fn apply_receive_pack_update_with_attribution(
        &self,
        repo: &RepoRef,
        outcome: &ReceivePackOutcome,
        attribution: &ReceivePackAttribution,
    ) -> Result<ReceivePackLanding> {
        self.apply_receive_pack_update_inner(repo, outcome, Some(attribution))
    }

    fn apply_receive_pack_update_inner(
        &self,
        repo: &RepoRef,
        outcome: &ReceivePackOutcome,
        attribution: Option<&ReceivePackAttribution>,
    ) -> Result<ReceivePackLanding> {
        if outcome.ref_updates.is_empty() {
            return Err(serve_failed("receive-pack outcome moved no ref"));
        }
        let wire = GitWire::new(self)?;
        let handle = wire.open_repo(repo.clone(), &outcome.repo_root)?;
        let _guard = lock_repository(handle.common_dir())?;
        let repo_id = lfs_repo_id(&handle.identity().as_hex())?;
        let recovered;
        let attribution = match attribution {
            Some(attribution) => attribution,
            None => {
                let existing = self
                    .origin_publication_rows(Some(repo_id))?
                    .into_iter()
                    .find(|row| {
                        outcome.ref_updates.iter().any(|update| {
                            row.ref_name.as_str() == update.name
                                && row.expected_old_oid == update.old_oid
                                && Some(&row.new_oid) == update.new_oid.as_ref()
                        })
                    })
                    .ok_or_else(|| {
                        receive_pack_provenance_refused("no journal-backed operation to replay")
                    })?;
                recovered = ReceivePackAttribution {
                    actor_id: existing.actor_id,
                    provenance_claim_id: existing.provenance_claim_id,
                };
                &recovered
            }
        };
        self.validate_receive_pack_attribution(repo_id, outcome, attribution)?;
        // Decided BEFORE the refs move: a RepositoryLarge pointer whose bytes
        // this vault does not hold refuses the landing, so no head is ever
        // advertised that a stock client could not check out.
        let admitted = admit_landing_lfs_pointers(self, repo_id, &outcome.lfs_pointers)?;
        let learned_at = now_secs();
        let landing = self.land_receive_pack_refs(
            &wire,
            &handle,
            repo_id,
            outcome,
            &admitted,
            Some(attribution),
            learned_at,
        )?;
        // The landing's own postcondition, proved against the repository
        // rather than inferred from the receipts: a replay that changed
        // nothing and a first landing that changed everything both have to end
        // with the repository carrying exactly what this outcome named.
        if !refs_already_applied(self, repo, &outcome.repo_root, &certified_refs(outcome))? {
            return Err(Error::ReceivePackLandingRefused {
                reason: "the landing did not leave the refs it certified".to_owned(),
            });
        }
        Ok(landing)
    }

    /// Lands every ref this outcome named, advances through the publication
    /// protocol and deletions through the plain journaled path.
    ///
    /// The landing is `replayed` only when EVERY ref replayed: a push where one
    /// ref was already durable and another genuinely moved did new work, and
    /// reporting it as a replay would claim the origin had nothing to do.
    #[expect(
        clippy::too_many_arguments,
        reason = "per-ref publication carries availability and authenticated attribution"
    )]
    fn land_receive_pack_refs(
        &self,
        wire: &GitWire<'_>,
        handle: &GitWireRepo,
        repo_id: EntityId,
        outcome: &ReceivePackOutcome,
        admitted: &[LfsPointerIntent],
        attribution: Option<&ReceivePackAttribution>,
        learned_at: u64,
    ) -> Result<ReceivePackLanding> {
        let mut certified: Option<GitWireReceipt> = None;
        let mut replayed = true;
        for update in &outcome.ref_updates {
            let (receipt, was_replayed) = match update.new_oid.as_ref() {
                Some(next) => self.publish_landing_advance(
                    wire,
                    handle,
                    repo_id,
                    update,
                    next,
                    admitted,
                    attribution,
                    learned_at,
                )?,
                None => landed_wire_outcome(wire.publish_refs(
                    handle,
                    vec![update.publication()?],
                    learned_at,
                )?)?,
            };
            // One publication per ref, not an atomic multi-ref push. Preserve
            // each successful ref's attachment even if a later ref is refused.
            // Never roll back a ref over a third party's later value.
            attach_landing_lfs_pointers(
                self,
                wire,
                handle,
                repo_id,
                std::slice::from_ref(update),
                admitted,
                learned_at,
            )?;
            replayed &= was_replayed;
            if certified.is_none() {
                certified = Some(receipt);
            }
        }
        let receipt = certified.ok_or_else(|| serve_failed("receive-pack outcome moved no ref"))?;
        Ok(ReceivePackLanding { receipt, replayed })
    }

    /// Publishes one advancing ref through the origin publication protocol.
    ///
    /// The protocol owns the compare-and-swap, the availability proof, the
    /// LEDGER claim and the visible-ref row in one crash-consistent unit; this
    /// function's whole job is to say what the push asked for and to translate
    /// the protocol's verdict back into a landing.
    #[expect(
        clippy::too_many_arguments,
        reason = "per-ref publication carries availability and authenticated attribution"
    )]
    fn publish_landing_advance(
        &self,
        wire: &GitWire<'_>,
        handle: &GitWireRepo,
        repo_id: EntityId,
        update: &RefUpdate,
        next: &GitOid,
        admitted: &[LfsPointerIntent],
        attribution: Option<&ReceivePackAttribution>,
        learned_at: u64,
    ) -> Result<(GitWireReceipt, bool)> {
        let ref_name = GitRefName::parse_full(update.name.clone())?;
        let attribution = match attribution {
            Some(attribution) => *attribution,
            None => {
                // The old outcome-only API is a replay door, not authority to
                // create a new publication. Recover attribution only from the
                // durable publication it is actually replaying.
                let existing = self
                    .origin_publication_rows(Some(repo_id))?
                    .into_iter()
                    .find(|row| {
                        row.ref_name == ref_name
                            && row.expected_old_oid == update.old_oid
                            && row.new_oid == *next
                    })
                    .ok_or_else(|| Error::ReceivePackLandingRefused {
                        reason: "receive-pack needs authenticated actor and durable provenance"
                            .to_owned(),
                    })?;
                ReceivePackAttribution {
                    actor_id: existing.actor_id,
                    provenance_claim_id: existing.provenance_claim_id,
                }
            }
        };
        let request = OriginPublicationRequest {
            repo_id,
            repo: handle.clone(),
            ref_name: GitRefName::parse_full(update.name.clone())?,
            expected_old_oid: update.old_oid.clone(),
            new_oid: next.clone(),
            required_objects: vec![next.clone()],
            required_lfs_oids: ref_required_lfs_oids(wire, handle, admitted, next)?,
            provenance_claim_id: attribution.provenance_claim_id,
            actor_id: attribution.actor_id,
            occurred: TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
        };
        let receipt = self.publish_origin_ref(wire, request)?;
        landing_from_publication(&update.name, &receipt)
    }
}

/// The values this outcome claims the repository carries once it has landed.
fn certified_refs(outcome: &ReceivePackOutcome) -> Vec<ObservedRef> {
    outcome
        .ref_updates
        .iter()
        .map(|update| ObservedRef {
            name: update.name.clone(),
            oid: update.new_oid.clone(),
        })
        .collect()
}

/// The admitted LFS objects one advancing ref's own tree actually carries.
///
/// The publication gate is per-REF, so an object that another branch of the
/// same push introduced must not gate this one: over-requiring would record a
/// false dependency and could later de-advertise a head for bytes it never
/// needed. Empty for every push that carries no LFS content, which is the
/// common case and reads no tree at all.
fn ref_required_lfs_oids(
    wire: &GitWire<'_>,
    handle: &GitWireRepo,
    admitted: &[LfsPointerIntent],
    tip: &GitOid,
) -> Result<Vec<(LfsOid, u64)>> {
    if admitted.is_empty() || !ref_tip_is_tree_ish(wire, handle, tip)? {
        return Ok(Vec::new());
    }
    let mut trees = BTreeMap::new();
    let mut required = Vec::new();
    for intent in admitted {
        if ref_tree_carries_path(wire, handle, &mut trees, tip, &intent.path)? {
            required.push((intent.oid, intent.size_bytes));
        }
    }
    Ok(required)
}

/// Turns one publication's verdict into this ref's landing evidence.
///
/// The rejection is read BEFORE the status, and that order is the point. A
/// record that already reached `Published` stays `Published` when a later
/// re-drive is refused — the protocol never restates a terminal record — so the
/// wire outcome, not the record, is the authority on whether THIS attempt moved
/// the ref. Reading the status first would report a refused re-drive as a
/// successful landing.
fn landing_from_publication(
    name: &str,
    receipt: &OriginPublicationReceipt,
) -> Result<(GitWireReceipt, bool)> {
    if let Some(reason) = receipt.wire_rejection() {
        return Err(Error::ReceivePackLandingRefused {
            reason: format!("{reason:?}"),
        });
    }
    if receipt.record.status != OriginPublicationStatus::Published {
        return Err(Error::ReceivePackLandingRefused {
            reason: format!(
                "publication for {} is {}",
                printable_ref_name(name),
                receipt.record.status.as_str()
            ),
        });
    }
    let Some(outcome) = receipt.wire.clone() else {
        return Err(Error::ReceivePackLandingRefused {
            reason: format!("publication for {} moved no ref", printable_ref_name(name)),
        });
    };
    landed_wire_outcome(outcome)
}

/// The receipt and replay flag of one journaled ref effect, or a refusal.
fn landed_wire_outcome(outcome: GitWireCommitOutcome) -> Result<(GitWireReceipt, bool)> {
    match outcome {
        GitWireCommitOutcome::Applied(receipt) => Ok((receipt, false)),
        GitWireCommitOutcome::Replayed(receipt) => Ok((receipt, true)),
        GitWireCommitOutcome::Rejected { reason, .. } => Err(Error::ReceivePackLandingRefused {
            reason: format!("{reason:?}"),
        }),
    }
}

/// Classifies this landing's pointers and returns the ones that publish.
///
/// `KeepInGit` is dropped silently and on purpose: a build-required asset stays
/// ordinary Git content, so it publishes as itself, gets no durable ref
/// attachment, and any staged upload of it stays unreferenced and collectible.
/// `StoreInLfs` demands its bytes: publishing a pointer whose object is absent
/// would advertise a head that fails checkout, which is the one outcome
/// ARCH-0068 forbids outright.
fn admit_landing_lfs_pointers(
    vault: &Vault,
    repo_id: EntityId,
    pointers: &[LfsPushedPointer],
) -> Result<Vec<LfsPointerIntent>> {
    if pointers.is_empty() {
        return Ok(Vec::new());
    }
    let policy = DefaultRepositoryLargeLfsPathPolicy;
    let mut admitted = Vec::new();
    for pointer in pointers {
        let intent = pointer.intent(repo_id);
        match vault.admit_lfs_pointer(&policy, &intent)? {
            LfsAdmission::KeepInGit => continue,
            LfsAdmission::StoreInLfs => {
                if !vault.has_lfs_object(intent.oid, intent.size_bytes)? {
                    return Err(Error::ReceivePackLandingRefused {
                        reason: format!(
                            "lfs object for {} is not stored in this vault",
                            printable_ref_name(&intent.path)
                        ),
                    });
                }
                admitted.push(intent);
            }
        }
    }
    Ok(admitted)
}

/// Records which refs now reference which LFS objects, and unrecords the ones
/// a ref stopped referencing by ceasing to exist.
///
/// The attachment family is a per-REF index, so this function owns both
/// directions of it:
///
/// - **A realized deletion detaches.** The ref the update names is gone from
///   the repository, so every row that named it is now a claim about nothing.
///   Only rows go: an object another ref still references keeps its bytes, and
///   so does an object no ref references at all — this is not a collector.
/// - **An update attaches by the ref's OWN tree.** An admitted pointer belongs
///   to the refs whose new tree actually carries its path, which is why the new
///   tree is walked rather than assumed. Attaching every admitted object to
///   every moved ref would let one branch's asset become a permanent claim on
///   every other branch that happened to travel in the same push.
///
/// An update never REMOVES a row. `admitted` is what THIS push introduced, not
/// an inventory of what the ref's tree carries: a commit that touches no
/// pointer admits nothing, and replacing a ref's rows with that empty set would
/// erase attachments that are still true. Rows are dropped when the ref itself
/// goes, and there only.
///
/// A `BuildRequired` path is absent from `admitted` and so stays unattached,
/// whatever tree carries it.
fn attach_landing_lfs_pointers(
    vault: &Vault,
    wire: &GitWire<'_>,
    handle: &GitWireRepo,
    repo_id: EntityId,
    updates: &[RefUpdate],
    admitted: &[LfsPointerIntent],
    learned_at: u64,
) -> Result<()> {
    let mut trees = BTreeMap::new();
    for update in updates {
        let Some(new_oid) = update.new_oid.as_ref() else {
            vault.detach_lfs_objects_from_git_ref(repo_id, &update.name)?;
            continue;
        };
        // A push that introduced no publishable pointer reads no tree at all,
        // which is every push that carries no LFS content.
        if admitted.is_empty() || !ref_tip_is_tree_ish(wire, handle, new_oid)? {
            continue;
        }
        for intent in admitted {
            if !ref_tree_carries_path(wire, handle, &mut trees, new_oid, &intent.path)? {
                continue;
            }
            vault.attach_lfs_object_to_git_ref(repo_id, &update.name, intent.oid, learned_at)?;
        }
    }
    Ok(())
}

/// The tree-entry mode of a subdirectory.
const GIT_TREE_MODE: u32 = 0o040_000;

/// The tree-entry mode of a gitlink: a commit that lives in another repository,
/// so this repository holds no blob for that path.
const GIT_GITLINK_MODE: u32 = 0o160_000;

/// Whether a ref's post-image can be read as a tree at all.
///
/// A commit and an annotated tag both peel to the tree the ref publishes. A ref
/// that names a blob has no tree and therefore carries no path — an answer,
/// deliberately, rather than a failure: the refs have already moved by the time
/// this runs, and an odd but legal ref value must not turn a landed push into
/// an error.
fn ref_tip_is_tree_ish(wire: &GitWire<'_>, handle: &GitWireRepo, tip: &GitOid) -> Result<bool> {
    let kinds = wire.object_info(handle, std::slice::from_ref(tip))?;
    Ok(matches!(
        kinds.get(tip).map(String::as_str),
        Some("commit" | "tag" | "tree")
    ))
}

/// Whether the tree `tip` publishes carries `path` as a file of this
/// repository.
///
/// Component by component, so a path is present only where the directories
/// leading to it are directories and the leaf is a blob this repository holds:
/// a directory of that name, or a gitlink of that name, is not the pointer
/// file.
fn ref_tree_carries_path(
    wire: &GitWire<'_>,
    handle: &GitWireRepo,
    trees: &mut BTreeMap<String, Vec<GitTreeEntry>>,
    tip: &GitOid,
    path: &str,
) -> Result<bool> {
    let mut current = tip.clone();
    let mut components = path.split('/').peekable();
    while let Some(component) = components.next() {
        if component.is_empty() {
            return Ok(false);
        }
        let entries = read_tree_entries(wire, handle, trees, &current)?;
        let Some(entry) = entries
            .iter()
            .find(|entry| entry.name == component.as_bytes())
        else {
            return Ok(false);
        };
        let mode = entry.mode;
        if components.peek().is_none() {
            return Ok(mode != GIT_TREE_MODE && mode != GIT_GITLINK_MODE);
        }
        if mode != GIT_TREE_MODE {
            return Ok(false);
        }
        current = entry.oid.clone();
    }
    Ok(false)
}

/// The direct entries of one tree, read once per landing.
///
/// Refs pushed together share directories, and so do the pointers within one
/// ref. The memo is what keeps a many-pointer push from re-reading the same
/// tree once per pointer per ref; it lives for the one landing that built it
/// and asserts nothing about any later one.
fn read_tree_entries<'trees>(
    wire: &GitWire<'_>,
    handle: &GitWireRepo,
    trees: &'trees mut BTreeMap<String, Vec<GitTreeEntry>>,
    tree: &GitOid,
) -> Result<&'trees [GitTreeEntry]> {
    let entries = match trees.entry(tree.as_str().to_owned()) {
        Entry::Occupied(occupied) => occupied.into_mut(),
        Entry::Vacant(vacant) => vacant.insert(wire.read_tree(handle, tree)?),
    };
    Ok(entries.as_slice())
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
    serve_with_provenance(vault, repo_name, request, seam, None, body, sink)
}

/// Compatibility entry point. A new exchange always produces its own evidence;
/// external claim ids cannot stand in for this request's admission or outcome.
/// Passing `None` uses the same production path as [`serve`].
pub fn serve_with_provenance(
    vault: &Arc<Vault>,
    repo_name: &str,
    request: &ServeRequest,
    seam: DoorSeam,
    provenance_claim_id: Option<EntityId>,
    body: &mut (dyn Read + Send),
    sink: &mut dyn ServeSink,
) -> Result<ServeReport> {
    if provenance_claim_id.is_some() {
        return Err(receive_pack_provenance_refused(
            "a new exchange cannot reuse external evidence",
        ));
    }
    let repo_dir = origin_repo_dir(vault, repo_name)?;
    let project_root = origin_serving_root(vault)?;
    let hooks = DoorHooksDir::materialize(&origin_door_root(vault)?)?;
    let command = ServeCommand::http_backend(&repo_dir, &project_root, hooks.path())?;
    let admission = stamp_admission(vault, request, &repo_dir, seam)?;
    if let Some(stamp) = admission.as_ref() {
        vault.record_receive_pack_admission(&repo_dir, stamp, seam)?;
    }
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
        // The ref list is the one response body this module rewrites, and it
        // is rewritten in flight: the gate holds one pkt-line, never the
        // advertisement.
        let streamed = if request.is_ref_advertisement() {
            let mut gate = AdvertisedRefGate::new(vault, repo_dir, sink);
            stream_response(stdout, &mut gate)
        } else {
            stream_response(stdout, sink)
        };
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

// ---------------------------------------------------------------------------
// The advertisement gate
// ---------------------------------------------------------------------------

/// The hex length of a SHA-1 object id, which is the only width this wire
/// carries.
const ADVERTISED_OID_HEX_LEN: usize = 40;

/// The largest pkt-line this gate will hold.
///
/// Only ONE line is ever held for a decision; this bound covers the partial
/// line left at a chunk boundary, so a backend that never terminates a
/// pkt-line cannot grow the carry without limit.
const SERVE_MAX_PKT_LINE_BYTES: usize = 65_524;

/// The all-zero object id the empty-repository advertisement uses.
const ADVERTISED_ZERO_OID: &str = "0000000000000000000000000000000000000000";

/// The pseudo-ref an advertisement with no refs carries its capabilities on.
const ADVERTISED_CAPABILITIES_REF: &str = "capabilities^{}";

/// One pkt-line, or the flush that ends a section.
enum PktLine {
    Flush,
    Data(Vec<u8>),
}

/// Which section of the advertisement the gate is reading.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AdvertisementPhase {
    /// The `# service=...` banner and its flush, passed through verbatim.
    Banner,
    /// The ref list, which is what this gate exists for.
    Refs,
    /// Anything after the ref list's flush, passed through verbatim.
    Trailer,
}

/// The publication projection for one served repository.
///
/// Resolved ONCE per advertisement, from the first object id the backend
/// printed: [`GitWire::open_repo`] proves a repository against a commit it
/// holds, and an advertised ref value is by construction such a commit. The
/// advertisement has no earlier pin to offer.
struct AdvertisementProjection {
    repo_id: EntityId,
    published: Vec<(GitRefName, GitOid)>,
}

/// The one place a served ref list is decided.
///
/// Every ref the origin advertises must appear in
/// [`Vault::published_origin_refs`]. A seeded repository still needs an explicit
/// publication; raw refs and failed projection reads never grant visibility.
/// `HEAD` survives only when its object is projected, and the all-zero
/// `capabilities^{}` line carries no object. Keep-refs are internal roots (RA4)
/// and are always omitted.
struct AdvertisedRefGate<'a> {
    vault: Arc<Vault>,
    repo_dir: PathBuf,
    inner: &'a mut dyn ServeSink,
    /// Off until the CGI headers prove this really is an advertisement.
    gating: bool,
    carry: Vec<u8>,
    phase: AdvertisementPhase,
    /// The capability suffix, detached from whichever ref line carried it.
    capabilities: Option<Vec<u8>>,
    emitted_ref: bool,
    projection: Option<AdvertisementProjection>,
    unresolved: bool,
}

impl<'a> AdvertisedRefGate<'a> {
    fn new(vault: &Arc<Vault>, repo_dir: &Path, inner: &'a mut dyn ServeSink) -> Self {
        Self {
            vault: Arc::clone(vault),
            repo_dir: repo_dir.to_path_buf(),
            inner,
            gating: false,
            carry: Vec::new(),
            phase: AdvertisementPhase::Banner,
            capabilities: None,
            emitted_ref: false,
            projection: None,
            unresolved: false,
        }
    }

    fn drain_carry(&mut self) -> Result<()> {
        while let Some(line) = take_pkt_line(&mut self.carry)? {
            self.handle_line(line)?;
        }
        if self.carry.len() > SERVE_MAX_PKT_LINE_BYTES {
            return Err(serve_failed(
                "git http-backend produced an oversized pkt-line",
            ));
        }
        Ok(())
    }

    fn handle_line(&mut self, line: PktLine) -> Result<()> {
        match (self.phase, line) {
            (AdvertisementPhase::Banner, PktLine::Flush) => {
                self.phase = AdvertisementPhase::Refs;
                self.emit_flush()
            }
            (AdvertisementPhase::Refs, PktLine::Flush) => {
                self.phase = AdvertisementPhase::Trailer;
                self.close_ref_list()
            }
            (AdvertisementPhase::Trailer, PktLine::Flush) => self.emit_flush(),
            (AdvertisementPhase::Refs, PktLine::Data(data)) => self.handle_ref_line(&data),
            (_, PktLine::Data(data)) => self.emit_data(&data),
        }
    }

    /// Ends the ref list, keeping the capability suffix reachable.
    ///
    /// A stock client reads the capabilities off the FIRST ref line, so an
    /// advertisement whose every ref was gated away still has to carry them:
    /// the `capabilities^{}` pseudo-ref is exactly git's own spelling for
    /// "no refs, these capabilities", and it is what an empty repository sends.
    fn close_ref_list(&mut self) -> Result<()> {
        if !self.emitted_ref && self.capabilities.is_some() {
            let mut payload = Vec::new();
            payload.extend_from_slice(ADVERTISED_ZERO_OID.as_bytes());
            payload.push(b' ');
            payload.extend_from_slice(ADVERTISED_CAPABILITIES_REF.as_bytes());
            self.attach_capabilities(&mut payload);
            payload.push(b'\n');
            self.emit_data(&payload)?;
        }
        self.emit_flush()
    }

    fn handle_ref_line(&mut self, line: &[u8]) -> Result<()> {
        let Some((oid, rest)) = split_advertised_ref(line) else {
            return Err(serve_failed(
                "git http-backend produced a malformed advertised ref",
            ));
        };
        let (name, capabilities) = split_capabilities(rest);
        if self.capabilities.is_none() {
            self.capabilities = capabilities.map(<[u8]>::to_vec);
        }
        if !self.keeps_advertised_ref(oid, name) {
            return Ok(());
        }
        let mut payload = Vec::with_capacity(line.len());
        payload.extend_from_slice(oid);
        payload.push(b' ');
        payload.extend_from_slice(name);
        if !self.emitted_ref {
            self.attach_capabilities(&mut payload);
        }
        payload.push(b'\n');
        self.emitted_ref = true;
        self.emit_data(&payload)
    }

    fn attach_capabilities(&self, payload: &mut Vec<u8>) {
        if let Some(capabilities) = self.capabilities.as_ref() {
            payload.push(0);
            let mut first = true;
            for capability in capabilities.split(|byte| *byte == b' ') {
                if let Some(target) = capability.strip_prefix(b"symref=HEAD:") {
                    let visible = self.projection.as_ref().is_some_and(|projection| {
                        projection
                            .published
                            .iter()
                            .any(|(name, _)| name.as_str().as_bytes() == target)
                    });
                    if !visible {
                        continue;
                    }
                }
                if !first {
                    payload.push(b' ');
                }
                payload.extend_from_slice(capability);
                first = false;
            }
        }
    }

    /// Whether one advertised line survives the projection.
    ///
    /// Every "cannot tell" answer is a refusal. Neither an unknown repository
    /// identity nor a missing journal row is evidence of publication.
    fn keeps_advertised_ref(&mut self, oid: &[u8], name: &[u8]) -> bool {
        let (Ok(name), Ok(oid_text)) = (std::str::from_utf8(name), std::str::from_utf8(oid)) else {
            return false;
        };
        if name == ADVERTISED_CAPABILITIES_REF {
            return oid_text == ADVERTISED_ZERO_OID;
        }
        if name.starts_with(GIT_WIRE_KEEP_REF_PREFIX) {
            return false;
        }
        let Ok(value) = GitOid::parse_hex(oid_text) else {
            return false;
        };
        self.ensure_projection(&value);
        let Some(projection) = self.projection.as_ref() else {
            return false;
        };
        if name == "HEAD" {
            return projection.published.iter().any(|(_, oid)| *oid == value);
        }
        // An auxiliary peeled line cannot authorize an object independently
        // of the publication's exact ref/OID pair.
        let base = name.strip_suffix("^{}").unwrap_or(name);
        let Ok(ref_name) = GitRefName::parse_full(base.to_owned()) else {
            return false;
        };
        if !self
            .vault
            .origin_publication_manages_ref(projection.repo_id, &ref_name)
            .unwrap_or(false)
        {
            return false;
        }
        projection
            .published
            .iter()
            .any(|(published, oid)| *published == ref_name && *oid == value)
    }

    fn ensure_projection(&mut self, pin: &GitOid) {
        if self.projection.is_some() || self.unresolved {
            return;
        }
        match resolve_advertisement_projection(&self.vault, &self.repo_dir, pin) {
            Ok(projection) => self.projection = Some(projection),
            Err(_) => self.unresolved = true,
        }
    }

    fn emit_flush(&mut self) -> Result<()> {
        self.inner.write_chunk(b"0000").map_err(Error::Io)
    }

    fn emit_data(&mut self, payload: &[u8]) -> Result<()> {
        let length = payload
            .len()
            .checked_add(4)
            .filter(|length| *length <= SERVE_MAX_PKT_LINE_BYTES)
            .ok_or_else(|| serve_failed("a gated pkt-line does not fit the wire"))?;
        self.inner
            .write_chunk(format!("{length:04x}").as_bytes())
            .map_err(Error::Io)?;
        self.inner.write_chunk(payload).map_err(Error::Io)
    }
}

impl ServeSink for AdvertisedRefGate<'_> {
    fn begin(&mut self, status: u16, headers: &[(String, String)]) -> io::Result<()> {
        self.gating = status == 200 && headers.iter().any(is_advertisement_content_type);
        if !self.gating {
            return self.inner.begin(status, headers);
        }
        // A gated body is shorter than the one the backend measured, so a
        // declared length would be a lie the client waits on forever.
        let framed = headers
            .iter()
            .filter(|(name, _)| !name.eq_ignore_ascii_case("Content-Length"))
            .cloned()
            .collect::<Vec<_>>();
        self.inner.begin(status, &framed)
    }

    fn write_chunk(&mut self, bytes: &[u8]) -> io::Result<()> {
        if !self.gating {
            return self.inner.write_chunk(bytes);
        }
        self.carry.extend_from_slice(bytes);
        self.drain_carry()
            .map_err(|error| io::Error::other(error.to_string()))
    }
}

fn is_advertisement_content_type(header: &(String, String)) -> bool {
    header.0.eq_ignore_ascii_case("Content-Type")
        && header.1.starts_with("application/x-git-")
        && header.1.contains("-advertisement")
}

/// Resolves the projection this advertisement is gated against.
fn resolve_advertisement_projection(
    vault: &Vault,
    repo_dir: &Path,
    pin: &GitOid,
) -> Result<AdvertisementProjection> {
    let wire = GitWire::new(vault)?;
    let handle = wire.open_repo(local_repo_ref(repo_dir, pin)?, repo_dir)?;
    let repo_id = lfs_repo_id(&handle.identity().as_hex())?;
    let published = vault.published_origin_refs(&wire, repo_id, &handle)?;
    Ok(AdvertisementProjection { repo_id, published })
}

/// Takes the next complete pkt-line out of `carry`, if one is there.
fn take_pkt_line(carry: &mut Vec<u8>) -> Result<Option<PktLine>> {
    if carry.len() < 4 {
        return Ok(None);
    }
    let text = std::str::from_utf8(&carry[..4])
        .map_err(|_| serve_failed("git http-backend produced a non-ASCII pkt-line length"))?;
    let length = usize::from_str_radix(text, 16)
        .map_err(|_| serve_failed("git http-backend produced a non-hex pkt-line length"))?;
    if length == 0 {
        carry.drain(..4);
        return Ok(Some(PktLine::Flush));
    }
    if !(4..=SERVE_MAX_PKT_LINE_BYTES).contains(&length) {
        return Err(serve_failed(
            "git http-backend produced a malformed pkt-line",
        ));
    }
    if carry.len() < length {
        return Ok(None);
    }
    let line = carry[4..length].to_vec();
    carry.drain(..length);
    Ok(Some(PktLine::Data(line)))
}

/// Splits `<oid> <rest>` out of one advertised line, trailing newline removed.
fn split_advertised_ref(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let trimmed = line.strip_suffix(b"\n").unwrap_or(line);
    let space = trimmed.iter().position(|byte| *byte == b' ')?;
    if space != ADVERTISED_OID_HEX_LEN {
        return None;
    }
    Some((&trimmed[..space], &trimmed[space + 1..]))
}

/// Splits the NUL-delimited capability suffix off an advertised ref line.
fn split_capabilities(rest: &[u8]) -> (&[u8], Option<&[u8]>) {
    match rest.iter().position(|byte| *byte == 0) {
        Some(at) => (&rest[..at], Some(&rest[at + 1..])),
        None => (rest, None),
    }
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
        lfs_pointers: report.door.lfs_pointers.clone(),
        staged_objects_dir: repo_dir.join("objects"),
    };
    let repo = outcome.pinned_repo_ref()?;
    let stamp = report
        .admission
        .as_ref()
        .ok_or_else(|| receive_pack_provenance_refused("admission is absent"))?;
    let attribution =
        vault.record_receive_pack_outcome(stamp, &report.door, &outcome, report.status)?;
    let landing =
        vault.apply_receive_pack_update_with_attribution(&repo, &outcome, &attribution)?;
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

    // Synthetic observer input for landing/state-machine tests only. The wire
    // and server roundtrips below produce this evidence through serve instead.
    fn fixture_attribution(vault: &Vault, outcome: &ReceivePackOutcome) -> ReceivePackAttribution {
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
        fn apply_receive_pack_fixture(
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
            lfs_pointers: Vec::new(),
            staged_objects_dir: root.join(".git").join("objects"),
            pack_stats: PackStats {
                request_bytes: 0,
                response_bytes: 0,
                ref_update_count: 1,
            },
        }
    }

    fn sync_plane_rows(vault: &Vault) -> BTreeMap<String, Vec<u8>> {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        vault
            .store
            .sync_state
            .iter(&rtxn)
            .expect("iter sync state")
            .map(|row| {
                let (key, value) = row.expect("sync state row");
                (key.into_owned(), value.to_vec())
            })
            .collect()
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
        assert_eq!(
            command
                .env()
                .get("GIT_NO_REPLACE_OBJECTS")
                .map(String::as_str),
            Some("1"),
            "every git under this serve reads true object bytes"
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

    #[test]
    fn smart_http_vetted_hook_disables_replacement_lookup_on_every_git() {
        assert!(
            DOOR_PRE_RECEIVE_HOOK.contains("export GIT_NO_REPLACE_OBJECTS"),
            "the hook exports the pin to every git it spawns"
        );
        for invocation in DOOR_PRE_RECEIVE_HOOK
            .lines()
            .map(str::trim_start)
            .filter(|line| line.starts_with("git ") || line.contains("$(git "))
        {
            assert!(
                invocation.contains("--no-replace-objects"),
                "this hook git could read substituted bytes: {invocation}"
            );
        }
    }

    fn proposed(name: &str) -> RefUpdate {
        RefUpdate {
            name: name.to_owned(),
            old_oid: None,
            new_oid: Some(GitOid::parse_hex("a".repeat(40)).expect("oid")),
        }
    }

    #[test]
    fn smart_http_unlandable_ref_names_are_refused_before_anything_moves() {
        assert!(
            unlandable_ref_reasons(&[
                proposed("refs/heads/main"),
                proposed("refs/tags/v1.0"),
                proposed("refs/heads/feature-foo"),
            ])
            .is_empty(),
            "a legal batch is untouched by this rule"
        );

        // Legal to git, unpublishable by GitWire: the landing would parse this
        // name only AFTER the backend had moved it.
        let illegal = unlandable_ref_reasons(&[proposed("refs/heads/feature+foo")]);
        assert_eq!(illegal.len(), 1, "one reason for the one offending name");
        assert!(
            illegal[0].starts_with("refs/heads/feature+foo:"),
            "the refusal names the ref: {}",
            illegal[0]
        );

        let replace = unlandable_ref_reasons(&[proposed(&format!(
            "{ORIGIN_REFUSED_REF_PREFIX}{}",
            "b".repeat(40)
        ))]);
        assert_eq!(replace.len(), 1, "a replacement ref is never served");

        let twice =
            unlandable_ref_reasons(&[proposed("refs/heads/main"), proposed("refs/heads/main")]);
        assert_eq!(twice.len(), 1, "a name proposed twice cannot be published");

        let batch = (0..=ORIGIN_MAX_REF_UPDATES)
            .map(|index| proposed(&format!("refs/heads/b{index}")))
            .collect::<Vec<_>>();
        assert_eq!(
            unlandable_ref_reasons(&batch).len(),
            1,
            "a batch past the publication bound is refused whole"
        );
        assert!(
            unlandable_ref_reasons(&batch[..ORIGIN_MAX_REF_UPDATES]).is_empty(),
            "exactly the bound is still a batch the landing can journal"
        );
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
    fn smart_http_noop_evidence_never_claims_landed_policy_or_scanning() {
        let (_vault_dir, vault) = temp_vault();
        let (_repo_dir, root, oid) = seeded_repo();
        let actor = EntityId::now();
        let stamp = NoopDoorHook
            .admit_receive_pack(
                None,
                &actor.to_hex(),
                &unpinned_repo_ref(&root),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                now_secs(),
            )
            .expect("noop stamp");
        vault
            .record_receive_pack_admission(&root, &stamp, DoorSeam::Noop)
            .expect("honest admission");
        let outcome = landing_outcome(&root, &oid);
        let door = DoorWindowReport {
            verdict: DoorWindowVerdict::Clean,
            ref_updates: outcome.ref_updates.clone(),
            lfs_pointers: Vec::new(),
            quarantine_path: None,
        };
        let attribution = vault
            .record_receive_pack_outcome(&stamp, &door, &outcome, 200)
            .expect("honest observation through explicit noop seam");
        let source = vault
            .get_claim(&attribution.provenance_claim_id)
            .expect("read")
            .expect("source");
        assert_eq!(
            receive_pack_field(&source, "scan").expect("scan"),
            &Value::from("not_performed")
        );
        let admission = vault
            .get_claim(&stamp.operation_id())
            .expect("read")
            .expect("admission");
        assert_eq!(
            receive_pack_field(&admission, "effector_check").expect("effector"),
            &Value::from("not_performed")
        );
        vault
            .apply_receive_pack_update_with_attribution(
                &outcome.pinned_repo_ref().expect("repo"),
                &outcome,
                &attribution,
            )
            .expect("explicit no-op transport retains wire compatibility");
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

    #[test]
    fn smart_http_production_push_rejects_before_git_without_admission() {
        struct UnreadBody;
        impl Read for UnreadBody {
            fn read(&mut self, _bytes: &mut [u8]) -> io::Result<usize> {
                panic!("rejected admission must not start the body pump");
            }
        }
        let (_dir, vault) = temp_vault();
        let (_source, repo_dir, _, _) = served_repo(&vault);
        let mut request = ServeRequest {
            method: "POST".to_owned(),
            path_info: "/demo.git/git-receive-pack".to_owned(),
            query_string: String::new(),
            content_type: Some("application/x-git-receive-pack-request".to_owned()),
            content_length: None,
            content_encoding: None,
            git_protocol: None,
            remote_user: None,
            remote_addr: None,
        };
        let mut sink = CapturingSink::default();
        let before = git(&repo_dir, &["rev-parse", "refs/heads/main"]);
        assert!(
            serve(
                &vault,
                "demo",
                &request,
                DoorSeam::Landed,
                &mut UnreadBody,
                &mut sink
            )
            .is_err()
        );
        request.remote_user = Some(EntityId::now().to_hex());
        for supplied in [
            EntityId::now(),
            fixture_attribution(
                &vault,
                &landing_outcome(&repo_dir, &GitOid::parse_hex(before.clone()).expect("head")),
            )
            .provenance_claim_id,
        ] {
            assert!(
                serve_with_provenance(
                    &vault,
                    "demo",
                    &request,
                    DoorSeam::Landed,
                    Some(supplied),
                    &mut UnreadBody,
                    &mut sink
                )
                .is_err(),
                "external evidence is not this request"
            );
        }
        narrow_door_effectors(&vault, Vec::new());
        assert!(matches!(
            serve(
                &vault,
                "demo",
                &request,
                DoorSeam::Landed,
                &mut UnreadBody,
                &mut sink
            ),
            Err(Error::ReceivePackDoorRejected { .. })
        ));
        assert_eq!(sink.status, 0);
        assert_eq!(git(&repo_dir, &["rev-parse", "refs/heads/main"]), before);
        assert!(
            vault
                .origin_publication_rows(None)
                .expect("journal")
                .is_empty()
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

        let mut expected = sync_plane_rows(&vault);
        let landing = vault
            .apply_receive_pack_fixture(&repo, &outcome)
            .expect("land receive-pack outcome");
        assert!(
            !landing.replayed,
            "the first landing journals its own record"
        );

        // These LEDGER claims are required. Their generic CLAIM puts create
        // pe:<claim-id> markers in sync_state, not Git replication payloads.
        let records = vault
            .origin_publication_rows(None)
            .expect("publication journal");
        let [record] = records.as_slice() else {
            panic!("one landed ref must have exactly one publication record");
        };
        assert_eq!(record.status, OriginPublicationStatus::Published);
        let source = vault
            .get_claim(&record.provenance_claim_id)
            .expect("read outcome claim")
            .expect("durable outcome claim");
        let operation_id = EntityId::from_hex(
            receive_pack_field(&source, "operation_id")
                .expect("outcome operation")
                .as_str()
                .expect("operation id string"),
        )
        .expect("operation entity id");
        let rtxn = vault.store.env.read_txn().expect("read txn");
        let epoch =
            crate::hnsw::read_embedding_model_epoch(&vault.store, &rtxn).expect("embedding epoch");
        for (id, predicate) in [
            (operation_id, RECEIVE_PACK_ADMISSION_PREDICATE),
            (record.provenance_claim_id, RECEIVE_PACK_OUTCOME_PREDICATE),
            (
                record
                    .publication_claim_id
                    .expect("durable publication claim id"),
                crate::origin::publication::ORIGIN_PUBLICATION_PREDICATE,
            ),
        ] {
            let claim = vault
                .get_claim_in_txn(&rtxn, &id)
                .expect("read ledger claim")
                .expect("durable ledger claim");
            assert_eq!(claim.predicate, predicate);
            assert_eq!(claim.lifecycle, ClaimLifecycleStatus::Active);
            let body = encode_claim_body(&claim).expect("encode ledger claim");
            assert!(
                expected
                    .insert(
                        Store::pending_embedding_marker_key(&id),
                        Store::pending_embedding_marker_token(epoch, &body).to_vec(),
                    )
                    .is_none(),
                "each new claim must have its own pending-embedding marker"
            );
        }
        drop(rtxn);
        assert_eq!(
            sync_plane_rows(&vault),
            expected,
            "only the ledger claims' versioned hash markers may enter sync_state; \
             no repo object/ref/pack/blob payload or other sync operation may appear"
        );
    }

    #[test]
    fn smart_http_publication_requires_real_attribution_and_durable_provenance() {
        let (_vault_dir, vault) = temp_vault();
        let (_repo_dir, root, oid) = seeded_repo();
        let outcome = landing_outcome(&root, &oid);
        let repo = outcome.pinned_repo_ref().expect("repo");
        assert!(
            vault.apply_receive_pack_update(&repo, &outcome).is_err(),
            "an outcome with no journal cannot invent its actor or provenance"
        );
        let missing = ReceivePackAttribution {
            actor_id: EntityId::now(),
            provenance_claim_id: EntityId::now(),
        };
        assert!(
            vault
                .apply_receive_pack_update_with_attribution(&repo, &outcome, &missing)
                .is_err(),
            "an allocated id is not a durable source claim"
        );
        let attribution = fixture_attribution(&vault, &outcome);
        let source = vault
            .get_claim(&attribution.provenance_claim_id)
            .expect("source")
            .expect("claim");
        let copied_id = EntityId::now();
        vault
            .put_claim(&copied_id, &source, landing_time(), now_secs())
            .expect("generic copied claim");
        let copied = ReceivePackAttribution {
            provenance_claim_id: copied_id,
            ..attribution
        };
        assert!(
            vault
                .apply_receive_pack_update_with_attribution(&repo, &outcome, &copied)
                .is_err(),
            "even a semantically identical claim has no local observer receipt"
        );
        let mut unrelated = source.clone();
        unrelated.predicate = "test.unrelated_source".to_owned();
        let unrelated_id = EntityId::now();
        vault
            .put_claim(&unrelated_id, &unrelated, landing_time(), now_secs())
            .expect("unrelated active claim");
        assert!(
            vault
                .apply_receive_pack_update_with_attribution(
                    &repo,
                    &outcome,
                    &ReceivePackAttribution {
                        provenance_claim_id: unrelated_id,
                        ..attribution
                    }
                )
                .is_err()
        );
        let wrong_actor = ReceivePackAttribution {
            actor_id: EntityId::now(),
            ..attribution
        };
        assert!(
            vault
                .apply_receive_pack_update_with_attribution(&repo, &outcome, &wrong_actor)
                .is_err()
        );
        let (_other_dir, other_root, other_oid) = seeded_repo();
        let other = landing_outcome(&other_root, &other_oid);
        assert!(
            vault
                .apply_receive_pack_update_with_attribution(
                    &other.pinned_repo_ref().expect("other repo"),
                    &other,
                    &attribution
                )
                .is_err()
        );
        let mut different_operation = outcome.clone();
        different_operation.ref_updates[0].name = "refs/heads/forged".to_owned();
        assert!(
            vault
                .apply_receive_pack_update_with_attribution(
                    &repo,
                    &different_operation,
                    &attribution
                )
                .is_err()
        );
        let mut different_intent = outcome.clone();
        different_intent.ref_updates[0].old_oid = Some(oid.clone());
        assert!(
            vault
                .apply_receive_pack_update_with_attribution(&repo, &different_intent, &attribution)
                .is_err()
        );
        let mut different_result = outcome.clone();
        different_result.pack_stats.request_bytes += 1;
        assert!(
            vault
                .apply_receive_pack_update_with_attribution(&repo, &different_result, &attribution)
                .is_err()
        );
        let wire = GitWire::new(&vault).expect("wire");
        let handle = wire.open_repo(repo.clone(), &root).expect("handle");
        let wrong_ref_request = OriginPublicationRequest {
            repo_id: lfs_repo_id(&handle.identity().as_hex()).expect("repo id"),
            repo: handle,
            ref_name: GitRefName::parse_full("refs/heads/forged").expect("ref"),
            expected_old_oid: None,
            new_oid: oid.clone(),
            required_objects: vec![oid],
            required_lfs_oids: Vec::new(),
            actor_id: attribution.actor_id,
            provenance_claim_id: attribution.provenance_claim_id,
            occurred: landing_time(),
            learned_at: now_secs(),
        };
        assert!(
            vault
                .publish_origin_ref(&wire, wrong_ref_request.clone())
                .is_err(),
            "the lower publication door cannot reuse evidence for another ref"
        );
        let mut relabeled = source.clone();
        relabeled.predicate = "test.relabeled_source".to_owned();
        vault
            .put_claim(
                &attribution.provenance_claim_id,
                &relabeled,
                landing_time(),
                now_secs(),
            )
            .expect("generic predicate overwrite fixture");
        assert!(
            vault.publish_origin_ref(&wire, wrong_ref_request).is_err(),
            "rewriting a producer claim predicate cannot evade its source binding"
        );
        let mut forged = source.clone();
        if let Value::Map(fields) = &mut forged.value {
            fields
                .iter_mut()
                .find(|(key, _)| key.as_str() == Some("actor_id"))
                .expect("actor field")
                .1 = Value::from(wrong_actor.actor_id.to_hex());
        }
        vault
            .put_claim(
                &attribution.provenance_claim_id,
                &forged,
                landing_time(),
                now_secs(),
            )
            .expect("generic overwrite of claim fixture");
        assert!(
            vault
                .apply_receive_pack_update_with_attribution(&repo, &outcome, &attribution)
                .is_err(),
            "an active rewritten claim no longer matches the original observer receipt"
        );
        let mut inactive = source.clone();
        inactive.lifecycle = crate::claim::ClaimLifecycleStatus::Retracted;
        vault
            .put_claim(
                &attribution.provenance_claim_id,
                &inactive,
                landing_time(),
                now_secs(),
            )
            .expect("retract source fixture");
        assert!(
            vault
                .apply_receive_pack_update_with_attribution(&repo, &outcome, &attribution)
                .is_err()
        );
        vault
            .put_claim(
                &attribution.provenance_claim_id,
                &source,
                landing_time(),
                now_secs(),
            )
            .expect("restore exact source fixture");
        assert!(
            vault
                .origin_publication_rows(None)
                .expect("journal")
                .is_empty(),
            "every bad source is rejected before staging a publication"
        );
        vault
            .apply_receive_pack_update_with_attribution(&repo, &outcome, &attribution)
            .expect("explicit source claim");
        let repo_id = landed_repo_id(&vault, &repo, &root);
        let rows = vault
            .origin_publication_rows(Some(repo_id))
            .expect("journal");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].actor_id, attribution.actor_id);
        assert_eq!(rows[0].provenance_claim_id, attribution.provenance_claim_id);
        assert!(
            vault
                .get_claim(&rows[0].provenance_claim_id)
                .expect("durable source")
                .is_some()
        );
        assert!(
            vault
                .apply_receive_pack_update(&repo, &outcome)
                .expect("journal-backed replay")
                .replayed
        );
    }

    #[test]
    fn smart_http_receive_pack_evidence_survives_reopen_and_is_not_an_id_only_anchor() {
        let (vault_dir, vault) = temp_vault();
        let (_repo_dir, root, oid) = seeded_repo();
        let outcome = landing_outcome(&root, &oid);
        let attribution = fixture_attribution(&vault, &outcome);
        let repo = outcome.pinned_repo_ref().expect("repo");
        let repo_id = landed_repo_id(&vault, &repo, &root);
        drop(vault);
        let reopened = Vault::open(vault_dir.path(), VaultConfig::default()).expect("reopen");
        reopened
            .validate_receive_pack_attribution(repo_id, &outcome, &attribution)
            .expect("both claims and their atomic local receipts survived");
        let claim = reopened
            .get_claim(&attribution.provenance_claim_id)
            .expect("read")
            .expect("claim");
        let operation = EntityId::from_hex(
            receive_pack_field(&claim, "operation_id")
                .expect("operation")
                .as_str()
                .expect("id"),
        )
        .expect("entity id");
        let mut admission = reopened
            .get_claim(&operation)
            .expect("read admission")
            .expect("admission");
        admission.lifecycle = ClaimLifecycleStatus::Retracted;
        reopened
            .put_claim(&operation, &admission, landing_time(), now_secs())
            .expect("retract fixture");
        assert!(
            reopened
                .apply_receive_pack_update_with_attribution(&repo, &outcome, &attribution)
                .is_err(),
            "an active outcome cannot launder an inactive admission"
        );
        assert!(
            reopened
                .origin_publication_rows(None)
                .expect("journal")
                .is_empty()
        );
    }

    #[test]
    fn smart_http_replayed_receive_pack_outcome_is_a_noop() {
        let (_vault_dir, vault) = temp_vault();
        let (_repo_dir, root, oid) = seeded_repo();
        let outcome = landing_outcome(&root, &oid);
        let repo = outcome.pinned_repo_ref().expect("pinned repo ref");

        let first = vault
            .apply_receive_pack_fixture(&repo, &outcome)
            .expect("first landing");
        let second = vault
            .apply_receive_pack_fixture(&repo, &outcome)
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
            vault.apply_receive_pack_fixture(&repo, &outcome).is_err(),
            "a landing that moves no ref is refused, never receipted"
        );
    }

    const LANDING_LEARNED_AT: u64 = 1_700_000_000;

    fn landing_time() -> TimeRange {
        TimeRange {
            start: LANDING_LEARNED_AT,
            end: LANDING_LEARNED_AT,
        }
    }

    /// One Git-LFS pointer file, byte for byte as a client writes it.
    fn pointer_file(oid: LfsOid, size: u64) -> String {
        format!(
            "version https://git-lfs.github.com/spec/v1\noid sha256:{}\nsize {size}\n",
            oid.to_hex()
        )
    }

    /// Commits one file onto the checked-out branch and returns its commit.
    fn commit_file(root: &Path, path: &str, contents: &str) -> GitOid {
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
    fn landed_repo_id(vault: &Vault, repo: &RepoRef, root: &Path) -> EntityId {
        let wire = GitWire::new(vault).expect("git wire");
        let handle = wire.open_repo(repo.clone(), root).expect("open repo");
        lfs_repo_id(&handle.identity().as_hex()).expect("repo id")
    }

    fn ref_update(name: &str, old_oid: Option<&GitOid>, new_oid: Option<&GitOid>) -> RefUpdate {
        RefUpdate {
            name: name.to_owned(),
            old_oid: old_oid.cloned(),
            new_oid: new_oid.cloned(),
        }
    }

    fn pushed_outcome(
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

    // -- the advertisement gate -------------------------------------------

    /// Collects one serve response without framing it.
    #[derive(Default)]
    struct CapturingSink {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
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
    fn served_repo(vault: &Vault) -> (tempfile::TempDir, PathBuf, GitOid, GitOid) {
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
    fn advertise(vault: &Arc<Vault>, service: &str) -> CapturingSink {
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
    fn advertised_refs(body: &[u8]) -> Vec<(String, String)> {
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

    /// One framed pkt-line.
    fn pkt(text: &str) -> Vec<u8> {
        let mut framed = format!("{:04x}", text.len() + 4).into_bytes();
        framed.extend_from_slice(text.as_bytes());
        framed
    }

    fn advertisement_headers() -> Vec<(String, String)> {
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
    struct PublicationTestOrigin {
        addr: std::net::SocketAddr,
        stop: Arc<AtomicBool>,
        worker: Option<std::thread::JoinHandle<()>>,
    }

    impl PublicationTestOrigin {
        fn start(vault: &Arc<Vault>, principal: EntityId) -> Self {
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

        fn url(&self) -> String {
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
        serve(
            vault,
            "demo",
            &request,
            DoorSeam::Landed,
            &mut body,
            &mut captured,
        )
        .expect("serve stock client");
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
        assert!(
            !git(client.path(), &["ls-remote", "--heads", &url]).contains("refs/heads/recovered")
        );
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
}
