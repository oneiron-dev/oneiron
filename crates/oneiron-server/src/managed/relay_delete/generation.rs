//! The names a relay delete claims and puts back (FIX 6826, FIX 1283).
//!
//! A delete claims its file by renaming it to `.deleting-<leaf>-<request>`,
//! where the leaf is the object for the current file, or
//! `.preimage-<object>-<generation>` for a generation a guarded upload kept.
//! A claim goes back to its own leaf. A current claim whose name a newer
//! upload holds is superseded and unlinked; a kept generation's claim never
//! is, since no upload ever writes a kept generation's name.

use std::io;
use std::os::fd::OwnedFd;

use oneiron_vault_contract::relay_delete::valid_locker_object;
use rustix::fs::{AtFlags, RenameFlags};
use rustix::io::Errno;

use crate::managed::relay::hold_guard::PREIMAGE_PREFIX;

/// The name a claimed file takes, before its leaf and request ids.
const CLAIM_PREFIX: &str = ".deleting-";

/// The claim name for `leaf` under request `request_id`.
pub(super) fn claim_name(leaf: &str, request_id: &str) -> String {
    format!("{CLAIM_PREFIX}{leaf}-{request_id}")
}

/// Puts the claimed file `claim` back at `leaf`, then syncs `dir`. When a
/// newer upload holds a current leaf, the claimed file is superseded and
/// unlinked; a `kept` generation's claim is never unlinked so, and stays
/// claimed, logged. One that does not go back stays claimed, for the next
/// bind to put back.
pub(super) fn put_back(dir: &OwnedFd, claim: &str, leaf: &str, kept: bool) {
    let restored = match rustix::fs::renameat_with(dir, claim, dir, leaf, RenameFlags::NOREPLACE) {
        Err(Errno::EXIST) if !kept => rustix::fs::unlinkat(dir, claim, AtFlags::empty()),
        restored => restored,
    };
    if let Err(errno) = restored.and_then(|()| rustix::fs::fsync(dir)) {
        tracing::warn!(
            kind = ?io::Error::from(errno).kind(),
            "a claimed relay locker object did not go back; the next locker bind puts it back"
        );
    }
}

/// Puts back every claimed file a stopped job left in `dir`. A claim name
/// that does not parse stays as it is, logged, and nothing is guessed.
pub(super) fn recover(dir: &OwnedFd) {
    let entries = match rustix::fs::Dir::read_from(dir) {
        Ok(entries) => entries,
        Err(errno) => {
            tracing::warn!(
                kind = ?io::Error::from(errno).kind(),
                "the relay locker directory did not list; its claimed objects stay"
            );
            return;
        }
    };
    let claims: Vec<Option<String>> = entries
        .map_while(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_bytes()
                .starts_with(CLAIM_PREFIX.as_bytes())
        })
        .map(|entry| entry.file_name().to_str().ok().map(str::to_owned))
        .collect();
    for claim in &claims {
        match claim
            .as_deref()
            .and_then(|claim| claimed_leaf(claim).map(|leaf| (claim, leaf)))
        {
            Some((claim, (leaf, kept))) => put_back(dir, claim, leaf, kept),
            None => tracing::warn!("a relay locker claim name did not parse; it stays as it is"),
        }
    }
}

/// The leaf a claim name `.deleting-<leaf>-<request>` names, split at its
/// last `-`, and whether it is a kept generation's. A leaf is an object (64
/// lowercase hex or `manifest`) or `.preimage-<object>-<generation>`, and a
/// request or a generation id is 32 lowercase hex: none holds a `-` but
/// where the grammar puts one, so a name parses one way or not at all.
fn claimed_leaf(name: &str) -> Option<(&str, bool)> {
    let (leaf, request) = name.strip_prefix(CLAIM_PREFIX)?.rsplit_once('-')?;
    if !lower_hex32(request) {
        return None;
    }
    match leaf.strip_prefix(PREIMAGE_PREFIX) {
        None => valid_locker_object(leaf).then_some((leaf, false)),
        Some(kept) => {
            let (object, generation) = kept.rsplit_once('-')?;
            (valid_locker_object(object) && lower_hex32(generation)).then_some((leaf, true))
        }
    }
}

/// Whether `value` is 32 lowercase hex digits.
fn lower_hex32(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
