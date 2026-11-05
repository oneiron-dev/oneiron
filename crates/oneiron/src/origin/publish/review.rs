//! Core half of `origin::publish::review`: its store-layer items live in `oneiron_store::origin::publish::review` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::origin::publish::review::*;

use super::types::{
    OriginPublishLfsBytes, OriginPublishReview, OriginPublishReviewItem, OriginPublishReviewPage,
};
use crate::Vault;
use crate::error::Result;
use crate::git_wire::{GitOid, GitReviewItem, GitWire, GitWireRepo};
use std::collections::BTreeSet;

/// A review as one walk built it.
pub(super) struct BuiltReview {
    pub(super) review: OriginPublishReview,
    pub(super) pages: Vec<OriginPublishReviewPage>,
    /// Every distinct path, as the pages spell it.
    pub(super) paths: BTreeSet<String>,
}

impl BuiltReview {
    /// The paths a Grant's bounds judge: `None` when a path's Git bytes are
    /// not UTF-8 and its text is lossy (FIX 10003).
    pub(super) fn grant_paths(&self) -> Option<BTreeSet<String>> {
        (!self.review.lossy_paths).then(|| self.paths.clone())
    }
}

impl Vault {
    /// Walks what pushing `commit` over `base` (`None`: an absent or unheld
    /// tip) would expose, and binds it in one digest.
    pub(super) fn build_publish_review(
        &self,
        wire: &GitWire<'_>,
        handle: &GitWireRepo,
        commit: &GitOid,
        base: Option<&GitOid>,
    ) -> Result<BuiltReview> {
        let blocking = self.publication_blocking_objects();
        self.build_publish_review_excluding(wire, handle, commit, base, &[], blocking.as_ref())
    }

    /// [`Self::build_publish_review`] that also leaves out what `reviewed`
    /// reach: the commits an automatic mirror plan reviewed under its earlier
    /// refs (FIX 6866 part 2), each bound into the digest. With none, the
    /// review and its digest are an exact publish's. With `blocking`, the
    /// objects a blocking mark marks, it says whether the history names one
    /// (FIX 10969); the digest never binds that advisory.
    pub(super) fn build_publish_review_excluding(
        &self,
        wire: &GitWire<'_>,
        handle: &GitWireRepo,
        commit: &GitOid,
        base: Option<&GitOid>,
        reviewed: &[GitOid],
        blocking: Option<&BTreeSet<GitOid>>,
    ) -> Result<BuiltReview> {
        let mut hasher = blake3::Hasher::new_derive_key(ORIGIN_PUBLISH_REVIEW_DIGEST_CONTEXT);
        field(&mut hasher, commit.as_str().as_bytes());
        field(
            &mut hasher,
            base.map_or(&b""[..], |base| base.as_str().as_bytes()),
        );
        for oid in reviewed {
            field(&mut hasher, oid.as_str().as_bytes());
        }
        let mut pages = Vec::new();
        let mut page = Vec::new();
        let mut paths = BTreeSet::new();
        let mut lossy_paths = false;
        let (mut commits, mut entries) = (0_u64, 0_u64);
        let mut secret_history = blocking.map(|_| false);
        let exclude: Vec<GitOid> = base.into_iter().chain(reviewed).cloned().collect();
        // Retained reads: a page or one tree level past the wire's output
        // bound is read whole, so no review fails for a level's width.
        wire.for_each_review_item_retained(handle, commit, &exclude, &mut |item| {
            hash_item(&mut hasher, &item);
            if let (
                Some(blocking),
                GitReviewItem::Path {
                    object: Some(object),
                    ..
                },
            ) = (blocking, &item)
                && blocking.contains(object)
            {
                secret_history = Some(true);
            }
            page.push(match item {
                GitReviewItem::Commit { commit, parents } => {
                    commits = commits.saturating_add(1);
                    OriginPublishReviewItem::Commit {
                        commit: commit.as_str().to_owned(),
                        parents: parents.iter().map(|oid| oid.as_str().to_owned()).collect(),
                    }
                }
                GitReviewItem::Path {
                    status,
                    mode,
                    object,
                    path,
                } => {
                    entries = entries.saturating_add(1);
                    lossy_paths |= std::str::from_utf8(&path).is_err();
                    let path = String::from_utf8_lossy(&path).into_owned();
                    paths.insert(path.clone());
                    OriginPublishReviewItem::Path {
                        status: status.to_string(),
                        mode,
                        object: object.map(|oid| oid.as_str().to_owned()),
                        path,
                    }
                }
            });
            if page.len() == ORIGIN_PUBLISH_REVIEW_PAGE_ITEMS {
                pages.push(OriginPublishReviewPage {
                    items: std::mem::take(&mut page),
                });
            }
            Ok(())
        })?;
        if !page.is_empty() {
            pages.push(OriginPublishReviewPage { items: page });
        }
        let count = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        let built = BuiltReview {
            review: OriginPublishReview {
                digest: hasher.finalize().to_hex().to_string(),
                subtracted: base.map(|base| base.as_str().to_owned()),
                commits,
                entries,
                paths: count(paths.len()),
                pages: count(pages.len()),
                lfs_bytes: OriginPublishLfsBytes::NotSent,
                lossy_paths,
                secret_history,
            },
            pages,
            paths,
        };
        admit_review_policy(&built)?;
        Ok(built)
    }
}

/// The one hook a history policy plugs into: every review passes it before
/// a request records it. The owner's secrets-in-history rule is pending (FIX
/// 6866 ruling), so no rule is built and every review passes; an exact
/// review carries the marked-history advisory its approver reads (FIX
/// 10969), and the send-time gate refuses.
pub(super) fn admit_review_policy(_review: &BuiltReview) -> Result<()> {
    Ok(())
}
