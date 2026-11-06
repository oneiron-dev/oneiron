//! Core half of `origin::smart_http::push_paths`: its store-layer items live in `oneiron_store::origin::smart_http::push_paths` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::origin::smart_http::push_paths::*;

use super::door::DoorAdmissionStamp;
use super::evidence::RefUpdate;
use super::hooks::DoorHooksDir;
use super::paths::serve_failed;
use crate::error::Result;
use crate::origin::git_ref_change::GitPushRefChange;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;

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
    if !stamp
        .push
        .as_ref()
        .is_some_and(|push| push.names_checkout())
    {
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
