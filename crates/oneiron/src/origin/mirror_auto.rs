//! Core half of `origin::mirror_auto`: its store-layer items live in `oneiron_store::origin::mirror_auto` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::origin::mirror_auto::*;

use super::mirror_run::MirrorTrigger;
use super::publish::{MirrorRunScope, MirrorSelection};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind, Result};
use crate::git_wire::{GitOid, GitRefName, GitWire, GitWireRepo};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

impl Vault {
    /// What a full-auto run sends (module docs): each published ref at its
    /// green tip or newest green ancestor, the rest held for checks.
    pub(super) fn full_auto_selection(
        &self,
        wire: &GitWire<'_>,
        handle: &GitWireRepo,
        refs: Vec<(GitRefName, GitOid)>,
        deletions: Vec<GitRefName>,
    ) -> Result<MirrorSelection> {
        let green = self.mirror_green_heads(wire, handle)?;
        let listed: HashSet<GitOid> = green.keys().cloned().collect();
        let tips: Vec<GitOid> = refs.iter().map(|(_, tip)| tip.clone()).collect();
        let kinds = wire.object_info(handle, &tips)?;
        let mut selection = MirrorSelection {
            vector: Vec::new(),
            deletions,
            pending: Vec::new(),
        };
        for (name, tip) in refs {
            if FULL_AUTO_REQUIRES_GREEN && !listed.contains(&tip) {
                let commit = kinds.get(&tip).is_some_and(|kind| kind == "commit");
                let ancestor = if FULL_AUTO_PUSHES_NEWEST_GREEN_PER_REF && commit {
                    wire.newest_listed_ancestor(handle, &tip, &listed)?
                } else {
                    None
                };
                if let Some(ancestor) = &ancestor {
                    selection.vector.push((name.clone(), ancestor.clone()));
                }
                selection.pending.push((name, tip, ancestor));
                continue;
            }
            selection.vector.push((name, tip));
        }
        Ok(selection)
    }

    /// The fingerprint of what a full-auto run would read: the published
    /// refs, the deletions, the queue's green pointer and the mirror row's
    /// revision and generation.
    pub(super) fn full_auto_fingerprint(
        &self,
        handle: &GitWireRepo,
        refs: &[(GitRefName, GitOid)],
        deletions: &[GitRefName],
        revision: u64,
        generation: Option<EntityId>,
    ) -> Result<String> {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron:origin-mirror-full-auto-seen:v1");
        for (name, tip) in refs {
            hasher.update(name.as_str().as_bytes());
            hasher.update(b"\0");
            hasher.update(tip.as_str().as_bytes());
            hasher.update(b"\n");
        }
        hasher.update(b"d");
        for name in deletions {
            hasher.update(name.as_str().as_bytes());
            hasher.update(b"\n");
        }
        let pointer = self.mirror_green_pointer(handle)?.unwrap_or_default();
        hasher.update(pointer.as_bytes());
        hasher.update(&revision.to_le_bytes());
        hasher.update(
            generation
                .map(|id| id.to_hex())
                .unwrap_or_default()
                .as_bytes(),
        );
        Ok(hasher.finalize().to_hex().to_string())
    }

    /// A full-auto mirror's selection when it is due: what it would send
    /// differs from the plan it settled last, that plan did not land whole,
    /// or a push-now asks. Its held heads go on its status either way.
    pub(super) fn full_auto_due(
        &self,
        scope: &MirrorRunScope<'_, '_>,
        refs: Vec<(GitRefName, GitOid)>,
        deletions: Vec<GitRefName>,
        trigger: MirrorTrigger,
    ) -> Result<Option<MirrorSelection>> {
        let forced = matches!(trigger, MirrorTrigger::PushNow(_));
        let target = scope.target;
        let seen = self.full_auto_fingerprint(
            scope.handle,
            &refs,
            &deletions,
            target.strategy_revision,
            target.target_generation,
        );
        let seen = match seen {
            Ok(seen) => seen,
            Err(error) => return Err(self.hold_mirror_run(scope, &error)),
        };
        if !forced && self.full_auto_seen(scope.repo_id, &seen) {
            return Ok(None);
        }
        let selection = match self.full_auto_selection(scope.wire, scope.handle, refs, deletions) {
            Ok(selection) => selection,
            Err(error) => return Err(self.hold_mirror_run(scope, &error)),
        };
        let pending: Vec<OriginMirrorPendingCheck> = selection
            .pending
            .iter()
            .map(|(name, head, sent)| OriginMirrorPendingCheck {
                ref_name: name.as_str().to_owned(),
                head: head.as_str().to_owned(),
                sent: sent.as_ref().map(|oid| oid.as_str().to_owned()),
            })
            .collect();
        self.note_mirror_automation(scope.repo_id, target.target_generation, |status| {
            status.pending_checks = pending;
        });
        let last = match self.mirror_plan_settled_last(scope.repo_id) {
            Ok(last) => last,
            Err(error) => return Err(self.hold_mirror_run(scope, &error)),
        };
        let unchanged = match &last {
            Some((vector, landed)) => *landed && *vector == selection.vector_digest(),
            None => selection.vector.is_empty() && selection.deletions.is_empty(),
        };
        if unchanged && !forced {
            self.keep_full_auto_seen(scope.repo_id, Some(seen));
            return Ok(None);
        }
        self.keep_full_auto_seen(scope.repo_id, None);
        Ok(Some(selection))
    }
}
