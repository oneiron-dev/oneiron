//! The Git-LFS half of a hand-off push (FIX CONTINUE-CLOUD-LFS-OBJECTS-NOT-SENT).
//!
//! The custody landing stores a pointer only once the vault holds the object
//! it names (`oneiron::origin::smart_http::landing_lfs`: a published head
//! never fails its checkout), so before the pack goes, the objects of the
//! pointers the push adds go up through the custody repo's own Git-LFS door:
//! an upload batch call for at most [`BATCH_OBJECTS`] of them at a time, then,
//! for each object the vault asks for, its bytes from this repo's git-lfs
//! store and the verify call the answer names. The upload's success is the
//! vault's word that it holds those bytes: it checks their size and digest
//! before it answers, a duplicate's too.
//!
//! The pointers are the ones the custody repo's pre-receive frames: each blob
//! the tip diff adds or changes (`git diff-tree --diff-filter=AMT`) from the
//! ref's old commit, or from the empty tree for a new ref, that reads as a
//! pointer by the landing's own grammar
//! ([`LfsPushedPointer::from_pointer_content`]). Git reads each object as
//! stored, as pack-objects and that pre-receive do, never through a local
//! `refs/replace/` stand-in ([`STORED_OBJECTS`]). When this repo lacks the
//! old commit of an existing ref (another clone made it), the diff from the
//! empty tree holds every pointer the custody repo's does, and the ones the
//! old commit already carried too: of those, an object this machine lacks is
//! not sent, never a reason to stop, since the pre-receive diffs from the old
//! commit itself and the landing refuses any pointer it frames whose object
//! the vault lacks ([`OldTip::Unheld`]).
//!
//! Every request carries the slip and a fresh holder proof, as receive-pack's
//! do, and goes to the custody repo's base only: an object's address is built
//! from that base, never taken from the batch answer, whose hrefs name the host
//! the request named and a scheme read from `x-forwarded-proto`. The answer
//! only says which objects to send and which to verify.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use oneiron::origin::lfs::{
    LFS_BASIC_TRANSFER, LFS_JSON_MEDIA_TYPE, LFS_POINTER_SIZE_CUTOFF, LfsPushedPointer,
};
use reqwest::blocking::{Body, Client, RequestBuilder};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};

use super::{STORED_OBJECTS, answered, git, git_path, run_git, run_git_fed};

/// Objects one batch call names: the count Git-LFS servers commonly take, and
/// the engine's own batch client's.
const BATCH_OBJECTS: usize = 100;

/// The media type of an object's bytes.
const OBJECT_TYPE: &str = "application/octet-stream";

/// A request made to prove its caller: the slip and a fresh holder proof.
pub(super) type Proven<'a> = dyn Fn(RequestBuilder) -> anyhow::Result<RequestBuilder> + 'a;

/// The custody repo's Git-LFS door, as the push reaches it.
pub(super) struct LfsDoor<'a> {
    /// The client the push's requests go through.
    pub(super) client: &'a Client,
    /// The custody repo's base, `<origin>/git/<repo>.git`.
    pub(super) base: &'a str,
    /// Adds the slip and a fresh holder proof to a request.
    pub(super) proven: &'a Proven<'a>,
}

/// The ref's old commit, which the custody repo's pre-receive diffs the
/// push's tip from.
#[derive(Clone, Copy)]
pub(super) enum OldTip<'a> {
    /// No ref yet: the custody repo diffs from the empty tree, as this push
    /// does.
    Created,
    /// An old commit this repo holds: this push diffs from it, as the custody
    /// repo does.
    Held(&'a str),
    /// An old commit this repo lacks, so this push diffs from the empty tree:
    /// it reads every pointer the custody repo frames, and the ones the old
    /// commit already carried too.
    Unheld,
}

/// Sends the Git-LFS objects of the pointers `commit` adds over `old` that
/// the custody repo at `door` does not hold yet. Every object the vault asks
/// for is found on this machine before the first byte goes, so one that is
/// no regular file stops the push before any upload, naming its path, and so
/// does a missing one, but for an [`OldTip::Unheld`] ref: there a missing
/// object may be one the old commit already carried, which the custody repo
/// asks for no more, so it is left out, and the paths of those left out are
/// answered. Each is opened again for its upload. Each git run and each
/// request ends by `deadline`.
pub(super) fn send_objects(
    top: &Path,
    old: OldTip<'_>,
    commit: &str,
    door: &LfsDoor<'_>,
    deadline: Instant,
) -> anyhow::Result<Vec<String>> {
    let base = match old {
        OldTip::Held(old) => Some(old),
        OldTip::Created | OldTip::Unheld => None,
    };
    let pointers = added_pointers(top, base, commit, deadline)?;
    if pointers.is_empty() {
        return Ok(Vec::new());
    }
    let mut asked = Vec::new();
    for batch in pointers.chunks(BATCH_OBJECTS) {
        asked.extend(door.asked(batch, deadline)?);
    }
    if asked.is_empty() {
        return Ok(Vec::new());
    }
    let store = object_store(top, deadline)?;
    let mut sent = Vec::new();
    let mut unsent = Vec::new();
    for (pointer, verify) in asked {
        if local_object(&store, pointer)?.is_some() {
            sent.push((pointer, verify));
        } else if matches!(old, OldTip::Unheld) {
            unsent.push(path_of(pointer));
        } else {
            return Err(missing(pointer));
        }
    }
    for (pointer, verify) in sent {
        let object = local_object(&store, pointer)?.ok_or_else(|| missing(pointer))?;
        door.upload(object, pointer, deadline)?;
        if verify {
            door.verify(pointer, deadline)?;
        }
    }
    Ok(unsent)
}

/// `refused`, the custody repo's refusal of a push that left out the Git-LFS
/// objects of the paths `unsent` ([`send_objects`]), naming them: its
/// pre-receive may have framed their pointers.
pub(super) fn naming_unsent(refused: anyhow::Error, unsent: &[String]) -> anyhow::Error {
    if unsent.is_empty() {
        return refused;
    }
    anyhow::anyhow!(
        "{refused}; the Git-LFS objects of {} are not on this machine, and the vault asked \
         for them: fetch them (`git lfs fetch`) or leave the files out of the work",
        unsent.join(", ")
    )
}

/// The error of an object the vault asks for that this machine lacks.
fn missing(pointer: &LfsPushedPointer) -> anyhow::Error {
    anyhow::anyhow!(
        "the Git-LFS object of {} ({}) is not on this machine, and the vault does not hold it: \
         fetch it (`git lfs fetch`) or leave the file out of the work",
        path_of(pointer),
        pointer.oid.to_hex()
    )
}

impl LfsDoor<'_> {
    /// The pointers of `batch` whose objects the vault asks for, each with
    /// whether its answer names a verify call. A refused object, or one the
    /// answer leaves out, stops the push, naming its path.
    fn asked<'p>(
        &self,
        batch: &'p [LfsPushedPointer],
        deadline: Instant,
    ) -> anyhow::Result<Vec<(&'p LfsPushedPointer, bool)>> {
        let body = serde_json::to_vec(&BatchBody {
            operation: "upload",
            transfers: [LFS_BASIC_TRANSFER],
            objects: batch
                .iter()
                .map(|pointer| ObjectRef {
                    oid: pointer.oid.to_hex(),
                    size: pointer.size_bytes,
                })
                .collect(),
        })?;
        let answer = (self.proven)(
            self.client
                .post(format!("{}/info/lfs/objects/batch", self.base))
                .header(CONTENT_TYPE, LFS_JSON_MEDIA_TYPE)
                .header(ACCEPT, LFS_JSON_MEDIA_TYPE)
                .timeout(left(deadline)?)
                .body(body),
        )?
        .send()?;
        let answer: BatchAnswer = serde_json::from_slice(&answered(answer, LFS_JSON_MEDIA_TYPE)?)
            .map_err(|_| {
            anyhow::anyhow!("the custody repo's Git-LFS batch answer did not decode")
        })?;
        let mut asked = Vec::new();
        for pointer in batch {
            let oid = pointer.oid.to_hex();
            let named = path_of(pointer);
            let object = answer
                .objects
                .iter()
                .find(|object| object.oid == oid && object.size == pointer.size_bytes)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "the custody repo's Git-LFS answer left out the object of {named}"
                    )
                })?;
            if let Some(error) = &object.error {
                anyhow::bail!(
                    "the custody repo refused the Git-LFS object of {named} ({}): {}",
                    error.code,
                    error.message
                );
            }
            if object.actions.upload.is_some() {
                asked.push((pointer, object.actions.verify.is_some()));
            }
        }
        Ok(asked)
    }

    /// Sends the bytes of `pointer`'s object, from `object`.
    fn upload(
        &self,
        object: File,
        pointer: &LfsPushedPointer,
        deadline: Instant,
    ) -> anyhow::Result<()> {
        let answer = (self.proven)(
            self.client
                .put(self.object_address(pointer))
                .header(CONTENT_TYPE, OBJECT_TYPE)
                .header(ACCEPT, LFS_JSON_MEDIA_TYPE)
                .timeout(left(deadline)?)
                .body(Body::sized(object, pointer.size_bytes)),
        )?
        .send()?;
        answered(answer, LFS_JSON_MEDIA_TYPE).map_err(|error| {
            error.context(format!("the Git-LFS object of {}", path_of(pointer)))
        })?;
        Ok(())
    }

    /// Makes the verify call the batch answer named for `pointer`'s object,
    /// as git-lfs does: an answer that is no success stops the push, naming
    /// the path. Its `ok` is not read. The vault answers it for an object it
    /// withholds from this machine as for an absent one (FIX 8182), so it
    /// cannot tell a lost upload from a stored object; the upload's success
    /// already said the vault holds those bytes, and the landing still
    /// refuses a pointer whose object the vault lacks.
    fn verify(&self, pointer: &LfsPushedPointer, deadline: Instant) -> anyhow::Result<()> {
        let body = serde_json::to_vec(&ObjectRef {
            oid: pointer.oid.to_hex(),
            size: pointer.size_bytes,
        })?;
        let answer = (self.proven)(
            self.client
                .post(format!("{}/verify", self.object_address(pointer)))
                .header(CONTENT_TYPE, LFS_JSON_MEDIA_TYPE)
                .header(ACCEPT, LFS_JSON_MEDIA_TYPE)
                .timeout(left(deadline)?)
                .body(body),
        )?
        .send()?;
        answered(answer, LFS_JSON_MEDIA_TYPE).map_err(|error| {
            error.context(format!(
                "verifying the Git-LFS object of {}",
                path_of(pointer)
            ))
        })?;
        Ok(())
    }

    /// The address of `pointer`'s object in the custody repo.
    fn object_address(&self, pointer: &LfsPushedPointer) -> String {
        format!("{}/info/lfs/objects/{}", self.base, pointer.oid.to_hex())
    }
}

/// The pointers the push of `commit` over `old` adds, one per object, each
/// with the first path that carries it: the blobs of the custody repo's own
/// tip diff that read as pointers.
fn added_pointers(
    top: &Path,
    old: Option<&str>,
    commit: &str,
    deadline: Instant,
) -> anyhow::Result<Vec<LfsPushedPointer>> {
    let base = match old {
        Some(old) => old.to_owned(),
        None => git(
            top,
            ["hash-object", "-t", "tree", "/dev/null"],
            &[],
            deadline,
        )?,
    };
    let diff = git_output(
        top,
        [
            "diff-tree",
            "-r",
            "-z",
            "--raw",
            "--no-abbrev",
            "--no-commit-id",
            "--diff-filter=AMT",
            base.as_str(),
            commit,
        ],
        None,
        deadline,
    )?;
    // Each entry is `:<modes> <old oid> <new oid> <status>` and its path.
    let mut blobs: Vec<(String, Vec<u8>)> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut fields = diff.split(|&byte| byte == 0);
    while let Some(entry) = fields.next() {
        if entry.is_empty() {
            continue;
        }
        let path = fields
            .next()
            .ok_or_else(|| anyhow::anyhow!("git diff-tree named an entry with no path"))?;
        let entry = String::from_utf8_lossy(entry);
        let new = entry
            .split(' ')
            .nth(3)
            .ok_or_else(|| anyhow::anyhow!("git diff-tree wrote an entry it does not define"))?;
        if seen.insert(new.to_owned()) {
            blobs.push((new.to_owned(), path.to_vec()));
        }
    }
    if blobs.is_empty() {
        return Ok(Vec::new());
    }
    // Only a blob below the pointer cutoff is read whole.
    let asked: String = blobs.iter().map(|(oid, _)| format!("{oid}\n")).collect();
    let sizes = git_output(
        top,
        [
            "cat-file",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        ],
        Some(asked.into_bytes()),
        deadline,
    )?;
    let small: BTreeSet<&str> = std::str::from_utf8(&sizes)?
        .lines()
        .filter_map(|line| {
            let mut parts = line.split(' ');
            let (oid, kind, size) = (parts.next()?, parts.next()?, parts.next()?);
            (kind == "blob" && size.parse::<u64>().ok()? < LFS_POINTER_SIZE_CUTOFF).then_some(oid)
        })
        .collect();
    let small: Vec<&(String, Vec<u8>)> = blobs
        .iter()
        .filter(|(oid, _)| small.contains(oid.as_str()))
        .collect();
    if small.is_empty() {
        return Ok(Vec::new());
    }
    let asked: String = small.iter().map(|(oid, _)| format!("{oid}\n")).collect();
    let contents = git_output(
        top,
        ["cat-file", "--batch"],
        Some(asked.into_bytes()),
        deadline,
    )?;
    let mut pointers = Vec::new();
    let mut objects = BTreeSet::new();
    let mut rest = contents.as_slice();
    for (oid, path) in small {
        let (content, after) = batch_object(rest, oid)?;
        rest = after;
        if let Some(pointer) = LfsPushedPointer::from_pointer_content(path, content)
            && objects.insert((pointer.oid.to_hex(), pointer.size_bytes))
        {
            pointers.push(pointer);
        }
    }
    Ok(pointers)
}

/// The content of the object `oid` at the start of `git cat-file --batch`'s
/// output `rest` (`<oid> <type> <size>`, its bytes, a newline), and what
/// follows it.
fn batch_object<'r>(rest: &'r [u8], oid: &str) -> anyhow::Result<(&'r [u8], &'r [u8])> {
    let broken = || anyhow::anyhow!("git cat-file answered {oid} in a shape it does not define");
    let end = rest
        .iter()
        .position(|&byte| byte == b'\n')
        .ok_or_else(broken)?;
    let header = std::str::from_utf8(&rest[..end])?;
    let mut parts = header.split(' ');
    if parts.next() != Some(oid) {
        return Err(broken());
    }
    let size: usize = parts
        .nth(1)
        .and_then(|size| size.parse().ok())
        .ok_or_else(broken)?;
    let body = rest.get(end + 1..).ok_or_else(broken)?;
    let content = body.get(..size).ok_or_else(broken)?;
    let after = body.get(size + 1..).ok_or_else(broken)?;
    Ok((content, after))
}

/// This repo's git-lfs store: `lfs.storage` when the repo's config names
/// one, below the git directory when it is relative, else the git
/// directory's `lfs`, as git-lfs reads it. The git directory and the value
/// are kept byte for byte: a path may end in a space, or hold a byte that is
/// no UTF-8.
fn object_store(top: &Path, deadline: Instant) -> anyhow::Result<PathBuf> {
    let common = top.join(git_path(top, ["rev-parse", "--git-common-dir"], deadline)?);
    let named = run_git(
        top,
        ["config", "-z", "--type=path", "--get", "lfs.storage"],
        &[],
        deadline,
    )?;
    let named = named.stdout.strip_suffix(b"\0").unwrap_or(&named.stdout);
    Ok(if named.is_empty() {
        common.join("lfs")
    } else {
        common.join(OsStr::from_bytes(named))
    })
}

/// `pointer`'s object in `store`, open to read, when it is a regular file of
/// the size the pointer names; `None` when nothing is at its path. It is
/// opened without waiting, so a FIFO or a device at its path is refused, never
/// waited on.
fn local_object(store: &Path, pointer: &LfsPushedPointer) -> anyhow::Result<Option<File>> {
    let oid = pointer.oid.to_hex();
    let file = store
        .join("objects")
        .join(&oid[..2])
        .join(&oid[2..4])
        .join(&oid);
    let named = path_of(pointer);
    let object = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&file)
    {
        Ok(object) => object,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let found = object.metadata()?;
    anyhow::ensure!(
        found.is_file(),
        "this machine's Git-LFS object of {named} ({oid}) is not a regular file"
    );
    let size = found.len();
    anyhow::ensure!(
        size == pointer.size_bytes,
        "this machine's Git-LFS object of {named} holds {size} bytes, not the {} its pointer names",
        pointer.size_bytes
    );
    Ok(Some(object))
}

/// `git -C top <args>` with `input` on its stdin, reading objects as stored
/// ([`STORED_OBJECTS`]), its stdout as written; a failure names git's own
/// words. It ends by `deadline`.
fn git_output<const N: usize>(
    top: &Path,
    args: [&str; N],
    input: Option<Vec<u8>>,
    deadline: Instant,
) -> anyhow::Result<Vec<u8>> {
    let (name, value) = STORED_OBJECTS;
    let ran = run_git_fed(top, args, &[(name.into(), value.into())], input, deadline)?;
    anyhow::ensure!(
        ran.status.success(),
        "git: {}",
        String::from_utf8_lossy(&ran.stderr).trim()
    );
    Ok(ran.stdout)
}

/// The time left before `deadline`, refused once none is.
fn left(deadline: Instant) -> anyhow::Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    anyhow::ensure!(
        !left.is_zero(),
        "the hand-off's deadline passed before its Git-LFS objects were sent"
    );
    Ok(left)
}

/// `pointer`'s path, printable.
fn path_of(pointer: &LfsPushedPointer) -> String {
    String::from_utf8_lossy(&pointer.path).into_owned()
}

/// An upload batch call's body.
#[derive(Serialize)]
struct BatchBody {
    operation: &'static str,
    transfers: [&'static str; 1],
    objects: Vec<ObjectRef>,
}

/// One object a batch or a verify call names.
#[derive(Serialize)]
struct ObjectRef {
    oid: String,
    size: u64,
}

/// A batch answer: what it says of each object.
#[derive(Deserialize)]
struct BatchAnswer {
    #[serde(default)]
    objects: Vec<AnswerObject>,
}

/// What a batch answer says of one object.
#[derive(Deserialize)]
struct AnswerObject {
    oid: String,
    size: u64,
    #[serde(default)]
    actions: AnswerActions,
    error: Option<AnswerError>,
}

/// The calls a batch answer asks for one object: none when the vault holds
/// it.
#[derive(Deserialize, Default)]
struct AnswerActions {
    upload: Option<IgnoredAny>,
    verify: Option<IgnoredAny>,
}

/// Why a batch answer refused one object.
#[derive(Deserialize)]
struct AnswerError {
    code: u16,
    message: String,
}
