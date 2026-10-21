//! A checkout push's changed paths (FIX 6867, G1-PUSH): the stream the
//! vetted hook lists while the objects are still quarantined, read back as
//! one [`GitPushRefChange`] per proposed ref, for the final intent writer to
//! judge under the run's Grant.
//!
//! One record is `move <old> <new> <bytes>\n` followed by exactly `<bytes>`
//! of NUL-terminated repo paths: every path the move changes, any status,
//! both names of a rename. A ref deletion changes no path. A record that is
//! malformed, a path that is not UTF-8, or a moving ref the stream does not
//! name refuses the push: an unlisted change is never an empty one.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use super::door::DoorAdmissionStamp;
use super::evidence::RefUpdate;
use super::hooks::DoorHooksDir;
use super::paths::serve_failed;
use crate::error::Result;
use crate::federation::git_push::GitPushRefChange;

/// One move's key: its old value (`None` for a creation) and its new one.
type MoveKey = (Option<String>, String);

/// The changes the push `stamp` admitted makes, when it was admitted on a
/// checkout's run Grant; `None` for every other push, which the writer does
/// not judge path by path.
///
/// # Errors
/// The stream is missing or malformed, or names no record for a moving ref.
pub(super) fn checkout_changes(
    hooks: &DoorHooksDir,
    stamp: &DoorAdmissionStamp,
    updates: &[RefUpdate],
) -> Result<Option<Vec<GitPushRefChange>>> {
    if !stamp.push.as_ref().is_some_and(|push| push.is_checkout()) {
        return Ok(None);
    }
    let moves = read_moves(&fs::read(hooks.paths_path())?)?;
    updates
        .iter()
        .map(|update| {
            let paths = match &update.new_oid {
                None => BTreeSet::new(),
                Some(new) => {
                    let key = (
                        update.old_oid.as_ref().map(|old| old.as_str().to_owned()),
                        new.as_str().to_owned(),
                    );
                    moves
                        .get(&key)
                        .cloned()
                        .ok_or_else(|| serve_failed("a moving ref has no listed paths"))?
                }
            };
            Ok(GitPushRefChange {
                git_ref: update.name.clone(),
                paths,
            })
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

/// Parses the whole stream into its moves.
fn read_moves(mut bytes: &[u8]) -> Result<BTreeMap<MoveKey, BTreeSet<String>>> {
    let malformed = || serve_failed("door path record is not `move <old> <new> <bytes>`");
    let mut moves = BTreeMap::new();
    while !bytes.is_empty() {
        let end = bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or_else(malformed)?;
        let header = std::str::from_utf8(&bytes[..end]).map_err(|_| malformed())?;
        let mut fields = header.split(' ');
        let (Some("move"), Some(old), Some(new), Some(size), None) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return Err(malformed());
        };
        let size: usize = size.parse().map_err(|_| malformed())?;
        let body = bytes
            .get(end + 1..end + 1 + size)
            .ok_or_else(|| serve_failed("door path record is truncated"))?;
        let mut paths = BTreeSet::new();
        if !body.is_empty() {
            let names = body
                .strip_suffix(b"\0")
                .ok_or_else(|| serve_failed("door path record is not NUL-terminated"))?;
            for name in names.split(|byte| *byte == 0) {
                let name = std::str::from_utf8(name)
                    .map_err(|_| serve_failed("a changed path is not UTF-8"))?;
                paths.insert(name.to_owned());
            }
        }
        let old = (!old.bytes().all(|byte| byte == b'0')).then(|| old.to_owned());
        moves.insert((old, new.to_owned()), paths);
        bytes = &bytes[end + 1 + size..];
    }
    Ok(moves)
}
