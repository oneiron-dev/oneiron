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

use crate::git_wire::ids::GitOid;
use crate::git_wire::publish_review::GitReviewItem;
use crate::git_wire::repo::GitWireRepo;
use oneiron_base::error::Result;

/// Items one stored review page holds (CALLS "FIX 6866 review page").
pub const ORIGIN_PUBLISH_REVIEW_PAGE_ITEMS: usize = 512;

/// The digest's BLAKE3 derive-key context.
pub const ORIGIN_PUBLISH_REVIEW_DIGEST_CONTEXT: &str = "oneiron:origin-publish-review:v1";

/// One item into the digest, each field length-prefixed.
pub fn hash_item(hasher: &mut blake3::Hasher, item: &GitReviewItem) {
    match item {
        GitReviewItem::Commit { commit, parents } => {
            hasher.update(b"c");
            field(hasher, commit.as_str().as_bytes());
            hasher.update(
                &u64::try_from(parents.len())
                    .unwrap_or(u64::MAX)
                    .to_le_bytes(),
            );
            for parent in parents {
                field(hasher, parent.as_str().as_bytes());
            }
        }
        GitReviewItem::Path {
            status,
            mode,
            object,
            path,
        } => {
            hasher.update(b"p");
            field(hasher, status.to_string().as_bytes());
            field(hasher, mode.as_bytes());
            field(
                hasher,
                object.as_ref().map_or("", GitOid::as_str).as_bytes(),
            );
            field(hasher, path);
        }
    }
}

pub fn field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}
