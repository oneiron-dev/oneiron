//! The trusted check helper's framed protocol, and the pinned tree it
//! carries in (FIX 6868).
//!
//! A frame is a 4-byte big-endian length, a kind byte and its payload; the
//! length counts the kind byte. The host sends one header, the pinned
//! commit's commit and tree objects (FIX 7228), the tree's files and an end
//! frame, then keeps the helper's input open: its closing ends the helper
//! and its child. The helper answers each command's result, stdout and
//! stderr, the declared output files it left (FIX 7235), the input digests
//! it observed, and a terminal frame.
//! A command's own stdout is a payload on its own frame, never parsed as
//! protocol. The digests match `checker.py`'s: sha256 over every file in
//! path order, each as its path length, path, mode and content sha256.

use std::io::{self, Read, Write};

use oneiron::merge_queue::QueueCheckTreeSource;
use sha2::{Digest, Sha256};

pub(super) const FRAME_HEADER: u8 = b'H';
pub(super) const FRAME_FILE: u8 = b'F';
pub(super) const FRAME_END: u8 = b'E';
pub(super) const FRAME_RESULT: u8 = b'R';
pub(super) const FRAME_STDOUT: u8 = b'O';
pub(super) const FRAME_STDERR: u8 = b'X';
pub(super) const FRAME_INPUTS: u8 = b'I';
pub(super) const FRAME_DONE: u8 = b'D';
/// One Git object of the guest's local-only object store: its type, a
/// space and its raw bytes (FIX 7228).
pub(super) const FRAME_GIT: u8 = b'G';
/// One declared output file a command left: its path length, path and
/// bytes (FIX 7235).
pub(super) const FRAME_OUTPUT: u8 = b'U';

/// Writes one frame.
pub(super) fn write_frame(writer: &mut dyn Write, kind: u8, payload: &[u8]) -> io::Result<()> {
    let length = payload
        .len()
        .checked_add(1)
        .and_then(|length| u32::try_from(length).ok())
        .ok_or_else(|| io::Error::other("a check frame exceeds the frame codec"))?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&[kind])?;
    writer.write_all(payload)
}

/// Reads one frame, or `None` at a clean end of stream.
pub(super) fn read_frame(reader: &mut dyn Read) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut length = [0_u8; 4];
    match reader.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = u32::from_be_bytes(length) as usize;
    let mut kind = [0_u8; 1];
    if length == 0 {
        return Err(io::Error::other("a check frame has no kind"));
    }
    reader.read_exact(&mut kind)?;
    let mut payload = vec![0_u8; length - 1];
    reader.read_exact(&mut payload)?;
    Ok(Some((kind[0], payload)))
}

/// What sending the tree came to.
pub(super) enum Sent {
    /// Every file went in; the digest of what was sent.
    Tree(String),
    /// The helper's input closed: it ended before the tree was in.
    Closed(io::Error),
}

/// Sends `commit`'s commit and tree objects as Git frames (FIX 7228), then
/// every file of `tree` as file frames, then the end frame. The objects are
/// read in the tree's bounded batches (FIX 7229), the files in path order.
///
/// # Errors
/// An object store read failure.
pub(super) fn send_tree(
    writer: &mut dyn Write,
    tree: &dyn QueueCheckTreeSource,
    commit: &str,
) -> oneiron::Result<Sent> {
    let mut closed = None;
    tree.git_objects(commit, &mut |kind, bytes| {
        let mut payload = Vec::with_capacity(kind.len() + 1 + bytes.len());
        payload.extend_from_slice(kind.as_bytes());
        payload.push(b' ');
        payload.extend_from_slice(bytes);
        if let Err(error) = write_frame(writer, FRAME_GIT, &payload) {
            closed = Some(error);
            return Ok(false);
        }
        Ok(true)
    })?;
    if let Some(error) = closed.take() {
        return Ok(Sent::Closed(error));
    }
    let mut digest = Sha256::new();
    let files = tree.files()?;
    let oids: Vec<&str> = files.iter().map(|file| file.oid.as_str()).collect();
    tree.blobs(&oids, &mut |index, bytes| {
        let file = &files[index];
        let Ok(path_length) = u32::try_from(file.path.len()) else {
            closed = Some(io::Error::other("a path exceeds the frame codec"));
            return Ok(false);
        };
        digest.update(path_length.to_be_bytes());
        digest.update(&file.path);
        digest.update(observed_mode(file.mode).to_be_bytes());
        digest.update(Sha256::digest(bytes));
        let mut payload = Vec::with_capacity(8 + file.path.len() + bytes.len());
        payload.extend_from_slice(&path_length.to_be_bytes());
        payload.extend_from_slice(&file.path);
        payload.extend_from_slice(&file.mode.to_be_bytes());
        payload.extend_from_slice(bytes);
        if let Err(error) = write_frame(writer, FRAME_FILE, &payload) {
            closed = Some(error);
            return Ok(false);
        }
        Ok(true)
    })?;
    if let Some(error) = closed {
        return Ok(Sent::Closed(error));
    }
    if let Err(error) = write_frame(writer, FRAME_END, &[]).and_then(|()| writer.flush()) {
        return Ok(Sent::Closed(error));
    }
    Ok(Sent::Tree(hex(&digest.finalize())))
}

/// The mode a materialized file reads back as: a symlink, or a regular
/// file with or without its executable bit, as `checker.py` observes it.
fn observed_mode(mode: u32) -> u32 {
    if mode == 0o120_000 {
        mode
    } else if mode & 0o111 != 0 {
        0o100_755
    } else {
        0o100_644
    }
}

/// Lowercase hex of `bytes`.
pub(super) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}
