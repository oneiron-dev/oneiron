//! The quarantine-window protocol: hook request and blob parsing, ref-name
//! pre-check, seam scan, verdict publish.

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use super::bounds::ScanBounds;
use super::door::{DoorAdmissionStamp, DoorHook, DoorSeam};
use super::evidence::{RefUpdate, receive_pack_provenance_refused};
use super::hooks::DoorHooksDir;
use super::paths::{
    DOOR_BLOB_TOO_LARGE, DOOR_REFUSAL_NAME_CHARS, DOOR_VERDICT_OK, DOOR_WINDOW_POLL,
    ORIGIN_MAX_REF_UPDATES, ORIGIN_REFUSED_REF_PREFIX, serve_failed,
};
use crate::Vault;
use crate::codebase::RepoRef;
use crate::credential_door::{CredentialDoorService, DoorScanVerdict, PushedBlob};
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitRefName};
use crate::origin::lfs::LfsPushedPointer;

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
    pub(super) fn not_invoked() -> Self {
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

#[derive(Clone, Copy)]
pub(super) struct DoorWindowContext<'a> {
    pub(super) seam: DoorSeam,
    pub(super) admission: Option<&'a DoorAdmissionStamp>,
    /// The bounds the hook was written with, held again here.
    pub(super) scan: ScanBounds,
}

pub(super) struct DoorWindowRequest {
    pub(super) quarantine_path: Option<PathBuf>,
    pub(super) ref_updates: Vec<RefUpdate>,
}

/// Services one door window: waits for the vetted hook, scans the quarantined
/// blobs, and publishes the verdict the hook is blocked on.
///
/// Fail-closed on every axis. A window that times out, a request that cannot be
/// parsed, and a scan that cannot run all publish a refusal, so the hook exits
/// non-zero and the objects never leave quarantine.
pub(super) fn serve_door_window(
    vault: &Arc<Vault>,
    repo: &RepoRef,
    hooks: &DoorHooksDir,
    finished: &AtomicBool,
    deadline: Instant,
    context: DoorWindowContext<'_>,
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
        match scan_window(vault, repo, &request_path, hooks, context) {
            Ok(window) => (
                window.request.ref_updates,
                window.lfs_pointers,
                window.request.quarantine_path,
                window.verdict,
            ),
            Err(refused) => (
                Vec::new(),
                Vec::new(),
                None,
                DoorWindowVerdict::Rejected {
                    reasons: vec![refused.reason().to_owned()],
                },
            ),
        };
    let mut report = DoorWindowReport {
        verdict,
        ref_updates,
        lfs_pointers,
        quarantine_path,
    };
    if report.admitted() {
        // The hook is still blocked. Commit the complete operation BEFORE
        // releasing it to mutate refs. No GitWire call or repository lock is
        // taken on this door thread; the serving thread holds that coordinator.
        let recorded = context
            .admission
            .ok_or_else(|| receive_pack_provenance_refused("intent has no admission"))
            .and_then(|stamp| vault.record_receive_pack_intent(repo, stamp, &report));
        if recorded.is_err() {
            report.verdict = DoorWindowVerdict::Rejected {
                reasons: vec!["receive-pack intent could not be made durable".to_owned()],
            };
        }
    }
    hooks.publish_verdict(&verdict_line(&report.verdict))?;
    Ok(report)
}

/// Why a window's input was not taken. Only the door's own bound is named to
/// the pusher; every other fault is the one generic refusal, whatever it was.
#[derive(Debug)]
pub(super) enum InputRefused {
    /// A blob past the scan's per-blob bound.
    BlobTooLarge,
    /// Input the door could not read whole.
    Unverified,
}

impl InputRefused {
    fn reason(&self) -> &'static str {
        match self {
            Self::BlobTooLarge => DOOR_BLOB_TOO_LARGE,
            Self::Unverified => "receive-pack input could not be verified",
        }
    }
}

impl From<Error> for InputRefused {
    fn from(_: Error) -> Self {
        Self::Unverified
    }
}

impl From<std::io::Error> for InputRefused {
    fn from(_: std::io::Error) -> Self {
        Self::Unverified
    }
}

/// What one window read and decided.
struct WindowScan {
    request: DoorWindowRequest,
    lfs_pointers: Vec<LfsPushedPointer>,
    verdict: DoorWindowVerdict,
}

/// Reads what the hook left behind and decides on it: the ref list, the blob
/// stream it framed from the tip diffs, and the history stream of every other
/// new blob. All three are required — both streams are moved into place
/// BEFORE the request file that announces them, so a readable request with an
/// unreadable extraction is a fault, never an empty push.
///
/// The streams are read one record at a time and each blob is scanned, then
/// dropped, before the next is read: the door holds one blob, never a push. A
/// record that cannot be read whole refuses the window, whatever was scanned
/// before it. Only tip blobs carry the tip paths an LFS pointer is paired
/// with, so only they are read for pointers.
fn scan_window(
    vault: &Arc<Vault>,
    repo: &RepoRef,
    request_path: &Path,
    hooks: &DoorHooksDir,
    context: DoorWindowContext<'_>,
) -> std::result::Result<WindowScan, InputRefused> {
    let request = parse_door_request(&fs::read(request_path)?)?;
    // The name rule decides FIRST, and it decides here rather than at the
    // landing: this is the last moment at which refusing costs nothing,
    // because the hook is still blocked and the backend has moved no ref. A
    // push whose names the landing could not journal is refused whole and
    // goes unscanned; nothing about a legal batch changes.
    let mut unlandable = unlandable_ref_reasons(&request.ref_updates);
    let door = CredentialDoorService::new(Arc::clone(vault));
    let mut scan = (unlandable.is_empty() && context.seam == DoorSeam::Landed)
        .then(|| BlobScan::new(&door, repo));
    let mut lfs_pointers = Vec::new();
    for_each_framed_blob(
        &mut BufReader::new(fs::File::open(hooks.blobs_path())?),
        false,
        context.scan,
        &mut |blob| {
            lfs_pointers.extend(LfsPushedPointer::from_pointer_content(
                &blob.path,
                &blob.content,
            ));
            if let Some(scan) = scan.as_mut() {
                scan.blob(&blob);
            }
        },
    )?;
    for_each_framed_blob(
        &mut BufReader::new(fs::File::open(hooks.history_path())?),
        true,
        context.scan,
        &mut |blob| {
            if let Some(scan) = scan.as_mut() {
                scan.blob(&blob);
            }
        },
    )?;
    // The same rule for a move a publication already made: a push needing more
    // than that publication certified could never be certified once the
    // backend moved it. It reads the tip pointers, so it decides once the
    // streams are read, ahead of the scan's verdict.
    if unlandable.is_empty() {
        unlandable = vault
            .receive_pack_owner_shortfalls(repo, &request.ref_updates, &lfs_pointers)
            .unwrap_or_else(|_| vec![InputRefused::Unverified.reason().to_owned()]);
    }
    let verdict = match scan {
        _ if !unlandable.is_empty() => DoorWindowVerdict::Rejected {
            reasons: unlandable,
        },
        Some(scan) => scan.verdict(),
        None => DoorWindowVerdict::Rejected {
            reasons: vec!["publication requires the landed scan".to_owned()],
        },
    };
    Ok(WindowScan {
        request,
        lfs_pointers,
        verdict,
    })
}

/// The longest record header the door reads: the fixed fields with room to
/// spare, and the longest path the door scans (4 KiB). A longer header is a
/// path the door would refuse anyway, so it is refused before it is held.
const DOOR_MAX_RECORD_HEADER_BYTES: u64 = 8 * 1024;

/// Reads one length-framed blob stream the vetted hook emitted inside the
/// quarantine window, a record at a time, handing each blob to `each` before
/// the next is read. A record whose blob is past `scan`'s per-blob bound is
/// refused before its bytes are read.
///
/// One record is `blob <oid> <bytes> <path>\n` followed by exactly `<bytes>`
/// raw bytes. There is no patch grammar here on purpose: the framing is what
/// makes the extraction TOTAL. Every blob the hook named is present with its
/// complete content, so a binary blob, a blob carrying NUL, and a line
/// beginning `++` or `+++ b/...` are all just bytes — none of them can look
/// like a header and none of them can go unscanned. The history stream
/// (`terminated`) carries the same records, each followed by the one `\n`
/// `git cat-file --batch` writes after an object's bytes.
///
/// The door is handed each blob's whole content, because the whole blob is
/// what the push would make durable. Content the door cannot scan (binary,
/// invalid UTF-8) is the door's own rejection, and a stream this function
/// cannot read whole is a refusal at the window — never a silently empty
/// scan.
pub(super) fn for_each_framed_blob(
    stream: &mut dyn BufRead,
    terminated: bool,
    scan: ScanBounds,
    each: &mut dyn FnMut(PushedBlob),
) -> std::result::Result<(), InputRefused> {
    let mut header = Vec::new();
    loop {
        header.clear();
        Read::take(&mut *stream, DOOR_MAX_RECORD_HEADER_BYTES).read_until(b'\n', &mut header)?;
        if header.is_empty() {
            return Ok(());
        }
        // No newline: the stream ends inside a header, or the header is
        // longer than any the door reads.
        let header = header
            .strip_suffix(b"\n")
            .ok_or_else(|| serve_failed("door blob stream ends inside a record header"))?;
        let header = std::str::from_utf8(header)
            .map_err(|_| serve_failed("door blob record header must be UTF-8"))?;
        let (oid, len, path) = parse_blob_record_header(header)?;
        if len > scan.blob_bytes() {
            return Err(InputRefused::BlobTooLarge);
        }
        let mut content =
            Vec::with_capacity(usize::try_from(len).map_err(|_| InputRefused::Unverified)?);
        Read::take(&mut *stream, len).read_to_end(&mut content)?;
        if content.len() as u64 != len {
            return Err(serve_failed("door blob record is truncated").into());
        }
        if terminated {
            let mut end = [0_u8];
            if stream.read(&mut end)? != 1 || end != [b'\n'] {
                return Err(serve_failed("door history record is not terminated").into());
            }
        }
        each(PushedBlob { path, oid, content });
    }
}

/// The door's verdict over a push's blobs, scanned one at a time as they are
/// read. A blob the scan cannot run on refuses the push, never passes it; the
/// blobs after it are read but not scanned.
struct BlobScan<'a> {
    hook: &'a dyn DoorHook,
    repo: &'a RepoRef,
    reasons: Vec<String>,
    failed: bool,
}

impl<'a> BlobScan<'a> {
    fn new(hook: &'a dyn DoorHook, repo: &'a RepoRef) -> Self {
        Self {
            hook,
            repo,
            reasons: Vec::new(),
            failed: false,
        }
    }

    fn blob(&mut self, blob: &PushedBlob) {
        if self.failed {
            return;
        }
        match self
            .hook
            .pre_receive_scan(self.repo, std::slice::from_ref(blob))
        {
            Ok(DoorScanVerdict::Clean) => {}
            Ok(DoorScanVerdict::Rejected { proposals }) => self.reasons.extend(
                proposals
                    .iter()
                    .map(|proposal| format!("{}: {}", proposal.path, proposal.reason)),
            ),
            Err(_) => self.failed = true,
        }
    }

    fn verdict(self) -> DoorWindowVerdict {
        if self.failed {
            DoorWindowVerdict::Rejected {
                reasons: vec!["receive-pack scan could not complete".to_owned()],
            }
        } else if self.reasons.is_empty() {
            DoorWindowVerdict::Clean
        } else {
            DoorWindowVerdict::Rejected {
                reasons: self.reasons,
            }
        }
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
pub(super) fn unlandable_ref_reasons(updates: &[RefUpdate]) -> Vec<String> {
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
pub(super) fn printable_ref_name(name: &str) -> String {
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

pub(super) fn parse_door_request(bytes: &[u8]) -> Result<DoorWindowRequest> {
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

/// `blob <oid> <bytes> <path>` — the path is last because it is the one field
/// that may carry spaces; the three before it are fixed and are validated here.
fn parse_blob_record_header(header: &str) -> Result<(String, u64, String)> {
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
        .parse::<u64>()
        .map_err(|_| serve_failed("door blob record declares an unparsable length"))?;
    Ok((oid.to_owned(), len, path.to_owned()))
}
