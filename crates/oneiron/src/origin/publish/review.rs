//! The full-ancestry review of one exact publish (FIX 6866; CALLS "FIX 6866
//! review scope"): what the push would expose, recorded in pages on the
//! request and bound to its tuple by one digest, before anything goes out.
//!
//! The review is `Reach(commit) - Reach(remote tip)`: every commit with all
//! its merge parents, and each path, mode and object each of them introduces
//! against each parent, so a file added and later deleted or reverted is
//! still named. The remote tip is subtracted only when this store holds it;
//! otherwise, and when the branch is absent, the review covers the commit's
//! whole history. Nothing is skipped for its size, and no read bound ends
//! the walk (Rule 5): a commit page or tree level too large for one captured
//! read is read whole through a retained spool. Git-LFS bytes are stated as
//! not sent. This module is the one place a later history policy
//! (the pending secrets-in-history rule) plugs into:
//! [`admit_review_policy`] sees every review before a request records it.

use std::collections::BTreeSet;

use oneiron_contracts::fingerprint::{LegacyDigest, purposes};

use super::types::{
    OriginPublishLfsBytes, OriginPublishReview, OriginPublishReviewItem, OriginPublishReviewPage,
};
use crate::Vault;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;
use crate::git_wire::{GitOid, GitReviewItem, GitWire, GitWireRepo};

/// Items one stored review page holds (CALLS "FIX 6866 review page").
pub const ORIGIN_PUBLISH_REVIEW_PAGE_ITEMS: usize = 512;

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
        let mut digest = review_digest(commit, base, reviewed);
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
            hash_item(&mut digest, &item);
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
                digest: digest_hex(&digest),
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

/// A review digest's start: the commit, the subtracted tip (empty when none) and
/// each commit `reviewed` names. Vaults hold these digests, so they keep their bytes
/// (K, PLAN-UC-04 3.2): each field framed by its length as a u64 little-endian.
fn review_digest(commit: &GitOid, base: Option<&GitOid>, reviewed: &[GitOid]) -> LegacyDigest {
    let mut digest = LegacyDigest::new(purposes::origin::PUBLISH_REVIEW);
    let commit = commit.as_str().as_bytes();
    let base = base.map_or(&b""[..], |base| base.as_str().as_bytes());
    digest
        .len_u64_le(commit.len())
        .raw(commit)
        .len_u64_le(base.len())
        .raw(base);
    for oid in reviewed {
        let oid = oid.as_str().as_bytes();
        digest.len_u64_le(oid.len()).raw(oid);
    }
    digest
}

/// One item into the digest: `c` or `p`, then each field framed by its length
/// and the parent count, each as a u64 little-endian.
pub(super) fn hash_item(digest: &mut LegacyDigest, item: &GitReviewItem) {
    match item {
        GitReviewItem::Commit { commit, parents } => {
            let commit = commit.as_str().as_bytes();
            digest
                .raw(b"c")
                .len_u64_le(commit.len())
                .raw(commit)
                .len_u64_le(parents.len());
            for parent in parents {
                let parent = parent.as_str().as_bytes();
                digest.len_u64_le(parent.len()).raw(parent);
            }
        }
        GitReviewItem::Path {
            status,
            mode,
            object,
            path,
        } => {
            let status = status.to_string();
            let object = object.as_ref().map_or("", GitOid::as_str);
            digest.raw(b"p");
            for field in [
                status.as_bytes(),
                mode.as_bytes(),
                object.as_bytes(),
                path.as_slice(),
            ] {
                digest.len_u64_le(field.len()).raw(field);
            }
        }
    }
}

/// A finished review, section or plan digest as it is stored: 64 lower hex.
pub(super) fn digest_hex(digest: &LegacyDigest) -> String {
    bytes_to_hex_lower(&digest.finish())
}

/// An exact publish's review digest over `items`, for the K-proof door
/// (`test_doors::fingerprint_keep_origin`).
#[cfg(oneiron_test_support)]
pub(crate) fn publish_review_digest_for_test(
    commit: &GitOid,
    base: Option<&GitOid>,
    reviewed: &[GitOid],
    items: &[GitReviewItem],
) -> String {
    let mut digest = review_digest(commit, base, reviewed);
    for item in items {
        hash_item(&mut digest, item);
    }
    digest_hex(&digest)
}
