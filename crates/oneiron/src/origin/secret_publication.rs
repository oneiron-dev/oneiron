//! Core half of `origin::secret_publication`: its store-layer items live in `oneiron_store::origin::secret_publication` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::origin::secret_publication::*;

use super::mirror::{OriginMirrorTarget, TARGETS};
use super::secret_marks::{RepoMarkFacts, RepoSecretMark, RepoSecretPlacement};
use super::secret_projection::index::UNATTRIBUTABLE_MARK_FAILS_CLOSED;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitRefEnd, GitReviewItem, GitWire, GitWireRepo};
use heed::RoTxn;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::sync::{LazyLock, Mutex, PoisonError};

/// One mark's liveness: an explicit native owner not-a-secret clears via
/// the span's exact custody; unknown, `Opaque` and provider-unproven marks
/// still block, a local rotation proves nothing, and history/masking are
/// unchanged. A `Span` custody ruled not-a-secret reads `NotASecret`, any
/// other `Span` reads `Unknown`, and a read that fails holds `Unknown`.
pub(crate) fn repo_secret_liveness(
    vault: &Vault,
    txn: &RoTxn<'_>,
    mark: &RepoSecretMark,
) -> RepoSecretLiveness {
    let custody = match &mark.placement {
        RepoSecretPlacement::Span { custody, .. } => custody,
        RepoSecretPlacement::Opaque => return RepoSecretLiveness::Unknown,
    };
    match crate::secret_custody::ruled_no_secret_in_txn(&vault.store, txn, custody) {
        Ok(true) => RepoSecretLiveness::NotASecret,
        Ok(false) => RepoSecretLiveness::Unknown,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "owner not-a-secret could not be read; its mark stays blocking"
            );
            RepoSecretLiveness::Unknown
        }
    }
}

/// The audience a mirror row takes from its setup: the visibility the owner
/// states; unstated, the same URL keeps its own and a new one is `unknown`
/// (CALLS OLD-AUDIENCE).
pub(crate) fn configured_audience(
    stated: Option<RepoDestinationVisibility>,
    previous: Option<&OriginMirrorTarget>,
    url: &str,
) -> RepoDestinationAudience {
    let kept = previous
        .filter(|row| row.url == url)
        .map(|row| row.audience.visibility);
    RepoDestinationAudience::mirror(
        stated
            .or(kept)
            .unwrap_or(RepoDestinationVisibility::Unknown),
    )
}

impl Vault {
    /// Each of `tips`' hold at `repo_id`'s mirror, in order: `None` sends as
    /// before (module docs). It reads the mirror's audience as its row
    /// stands now; a row that is gone reads `unknown`. It never fails: what
    /// it cannot read holds.
    pub(crate) fn require_no_marked_live_history(
        &self,
        wire: &GitWire<'_>,
        handle: &GitWireRepo,
        repo_id: EntityId,
        tips: &[GitOid],
    ) -> Vec<Option<SecretPublicationHold>> {
        if tips.is_empty() {
            return Vec::new();
        }
        let mut join = match self.public_mark_join(repo_id) {
            Ok(None) => return vec![None; tips.len()],
            Ok(Some(join)) => join,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "secret marks could not be read whole; a public send is held"
                );
                return vec![Some(SecretPublicationHold::SecretHistoryUnknown); tips.len()];
            }
        };
        let key = (handle.identity().as_hex(), join.digest());
        let judged = judged_tips(&key);
        let mut clean = judged.clean;
        let mut marked = Vec::new();
        let holds = tips
            .iter()
            .map(|tip| {
                if judged.marked.contains(tip) {
                    return Some(SecretPublicationHold::MarkedLiveSecret);
                }
                if clean.contains(tip) {
                    return None;
                }
                let (hold, commit) = tip_hold(wire, handle, tip, &clean, &mut join);
                match (hold, commit) {
                    (None, Some(commit)) => {
                        clean.retain(|kept| *kept != commit);
                        clean.push(commit);
                    }
                    (Some(SecretPublicationHold::MarkedLiveSecret), _) => marked.push(tip.clone()),
                    _ => {}
                }
                hold
            })
            .collect();
        keep_judged_tips(key, clean, marked);
        holds
    }

    /// Every object a blocking mark marks, in any store: what an exact
    /// publish review's freeze-time advisory names a history by (FIX
    /// 10969). `None`, with a warning, when the marks cannot be read whole;
    /// the send-time gate reads them again either way.
    pub(crate) fn publication_blocking_objects(&self) -> Option<BTreeSet<GitOid>> {
        let read = || -> Result<BTreeSet<GitOid>> {
            let txn = self.store.env.read_txn()?;
            let (facts, _) =
                RepoMarkFacts::read_scoped_in_txn(self, &txn, UNATTRIBUTABLE_MARK_FAILS_CLOSED)?;
            Ok(facts.blob_oids(|mark: &RepoSecretMark| {
                repo_secret_liveness(self, &txn, mark).blocks_public()
            }))
        };
        read()
            .inspect_err(|error| {
                tracing::warn!(
                    kind = ?error.kind(),
                    "secret marks could not be read whole; a publish review carries no advisory"
                );
            })
            .ok()
    }

    /// What a public send's history is joined against, read once through
    /// the per-blob mark reader; `None` for a destination that does not
    /// hold, or a vault with no mark. A mark that does not decode and names
    /// no blob, or a store failure in the walk, fails the read under
    /// [`UNATTRIBUTABLE_MARK_FAILS_CLOSED`] (A1: unknown is live); one tied
    /// to its blob holds only the refs whose history carries that blob.
    fn public_mark_join(&self, repo_id: EntityId) -> Result<Option<MarkJoin>> {
        let txn = self.store.env.read_txn()?;
        let audience = TARGETS.get(&self.store, &txn, &repo_id)?.map_or(
            RepoDestinationAudience::mirror(RepoDestinationVisibility::Unknown),
            |row| row.audience,
        );
        if !audience.holds_marked_history() {
            return Ok(None);
        }
        let (facts, unread) =
            RepoMarkFacts::read_scoped_in_txn(self, &txn, UNATTRIBUTABLE_MARK_FAILS_CLOSED)?;
        let blocking = facts.blob_oids(|mark: &RepoSecretMark| {
            repo_secret_liveness(self, &txn, mark).blocks_public()
        });
        Ok(
            (!blocking.is_empty() || !unread.is_empty()).then(|| MarkJoin {
                blocking,
                unread,
                hashed: BTreeSet::new(),
            }),
        )
    }
}

/// One tip's hold, and the commit it ends at. `clean` are commits already
/// proven clean, whose history is not walked again: a marked object a tip
/// reaches through one of them would have held that one.
fn tip_hold(
    wire: &GitWire<'_>,
    handle: &GitWireRepo,
    tip: &GitOid,
    clean: &[GitOid],
    join: &mut MarkJoin,
) -> (Option<SecretPublicationHold>, Option<GitOid>) {
    let peeled = match wire.peel_ref_tip_retained(handle, tip) {
        Ok(peeled) => peeled,
        Err(error) => return (Some(unknown(&error)), None),
    };
    let blocking = &join.blocking;
    let tagged =
        blocking.contains(tip) || peeled.tags.iter().any(|tag| blocking.contains(&tag.tag));
    let end = match &peeled.end {
        GitRefEnd::Commit(oid) | GitRefEnd::Tree(oid) | GitRefEnd::Blob(oid) => oid,
    };
    if tagged || blocking.contains(end) {
        return (Some(SecretPublicationHold::MarkedLiveSecret), None);
    }
    let hashing = !join.unread.is_empty();
    let mut blobs = BTreeSet::new();
    let mut met = false;
    let mut visit = |item: GitReviewItem| {
        let (object, blob) = match item {
            GitReviewItem::Commit { commit, .. } => (Some(commit), false),
            GitReviewItem::Path { mode, object, .. } => (object, mode != GITLINK_MODE),
        };
        let Some(object) = object else {
            return Ok(());
        };
        if blocking.contains(&object) {
            met = true;
            return Err(Error::InvariantViolation(MARKED_OBJECT_MET));
        }
        if hashing && blob {
            blobs.insert(object);
        }
        Ok(())
    };
    let (walked, commit) = match &peeled.end {
        GitRefEnd::Commit(commit) => (
            wire.for_each_review_item_retained(handle, commit, clean, &mut visit),
            Some(commit.clone()),
        ),
        GitRefEnd::Tree(tree) => (
            wire.for_each_tree_path_retained(handle, tree, &mut visit),
            None,
        ),
        GitRefEnd::Blob(_) => (Ok(()), None),
    };
    match walked {
        Ok(()) => {}
        Err(_) if met => return (Some(SecretPublicationHold::MarkedLiveSecret), None),
        Err(error) => return (Some(unknown(&error)), None),
    }
    if hashing && let GitRefEnd::Blob(blob) = &peeled.end {
        blobs.insert(blob.clone());
    }
    match unread_blob_met(wire, handle, blobs, join) {
        Ok(false) => (None, commit),
        Ok(true) => (Some(SecretPublicationHold::MarkedLiveSecret), None),
        Err(error) => (Some(unknown(&error)), None),
    }
}

/// Whether one of `blobs` hashes to a blob whose marks do not decode: it
/// holds as marked (CALL S4FIX-UNKNOWN-MARK). Each blob is read whole once a
/// call, and only while such a mark exists.
fn unread_blob_met(
    wire: &GitWire<'_>,
    handle: &GitWireRepo,
    blobs: BTreeSet<GitOid>,
    join: &mut MarkJoin,
) -> Result<bool> {
    for blob in blobs {
        if join.hashed.contains(&blob) {
            continue;
        }
        let object = wire.read_object_to_spool(handle, &blob)?;
        if join.unread.contains(&object.content_blake3()) {
            return Ok(true);
        }
        join.hashed.insert(blob);
    }
    Ok(false)
}
