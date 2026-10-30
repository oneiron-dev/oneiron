//! The review section of one whole ref an automatic mirror plan pushes (FIX
//! 6866 part 2; CALLS "FIX 6866 automatic review record").
//!
//! A commit tip's section is an exact publish's full-ancestry review
//! (`review`): `Reach(new) - Reach(the tip the plan read)`, with every merge
//! parent and each path, mode and object each commit introduces against each
//! parent; the tip is subtracted only when this store holds it as a commit,
//! else the section covers the whole closure. A plan reviews its refs in
//! order, and a later ref leaves out what an earlier ref's section already
//! names, so the plan's pages hold the union once while each ref keeps its
//! own section. A tag tip names each annotated tag on its way first, its raw
//! bytes (message included) in the digest, or for a tag too large to read
//! whole its oid and size; a tree tip names every path it
//! holds; a blob tip names itself. Every section passes the one history
//! policy hook an exact publish's review passes.

use std::collections::BTreeSet;

use super::ORIGIN_PUBLISH_REVIEW_PAGE_ITEMS;
use super::mirror_plan::MirrorRunScope;
use super::mirror_plan_types::MirrorObservedTip;
use super::review::{BuiltReview, admit_review_policy, field, hash_item};
use super::types::{
    OriginPublishLfsBytes, OriginPublishReview, OriginPublishReviewItem, OriginPublishReviewPage,
};
use crate::Vault;
use crate::error::Result;
use crate::git_wire::{
    GitOid, GitRefEnd, GitRefName, GitRefTag, GitReviewItem, GitWire, GitWireRepo,
};

/// A section digest's BLAKE3 derive-key context.
const ORIGIN_MIRROR_REVIEW_DIGEST_CONTEXT: &str = "oneiron:origin-mirror-review:v1";

/// One ref's section as its walk built it, and the commit the walk covered,
/// which later refs leave out.
pub(super) struct RefSection {
    pub(super) built: BuiltReview,
    pub(super) walked: Option<GitOid>,
}

/// A section being built: its digest, pages and counts.
struct Section {
    hasher: blake3::Hasher,
    pages: Vec<OriginPublishReviewPage>,
    page: Vec<OriginPublishReviewItem>,
    paths: BTreeSet<String>,
    commits: u64,
    entries: u64,
}

impl Section {
    fn new(name: &GitRefName, new: &GitOid, observed: &MirrorObservedTip) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(ORIGIN_MIRROR_REVIEW_DIGEST_CONTEXT);
        field(&mut hasher, name.as_str().as_bytes());
        field(&mut hasher, new.as_str().as_bytes());
        field(&mut hasher, observed.oid().unwrap_or("").as_bytes());
        Self {
            hasher,
            pages: Vec::new(),
            page: Vec::new(),
            paths: BTreeSet::new(),
            commits: 0,
            entries: 0,
        }
    }

    fn push(&mut self, item: OriginPublishReviewItem) {
        self.page.push(item);
        if self.page.len() == ORIGIN_PUBLISH_REVIEW_PAGE_ITEMS {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if !self.page.is_empty() {
            self.pages.push(OriginPublishReviewPage {
                items: std::mem::take(&mut self.page),
            });
        }
    }

    fn tag(&mut self, tag: &GitRefTag) {
        self.hasher
            .update(if tag.raw.is_some() { b"t" } else { b"T" });
        field(&mut self.hasher, tag.tag.as_str().as_bytes());
        match &tag.raw {
            Some(raw) => field(&mut self.hasher, raw),
            None => field(&mut self.hasher, &tag.size.to_le_bytes()),
        }
        self.push(OriginPublishReviewItem::Object {
            object_type: "tag".to_owned(),
            object: tag.tag.as_str().to_owned(),
            target: Some(tag.target.as_str().to_owned()),
            name: Some(tag.name.clone()),
            size: tag.raw.is_none().then_some(tag.size),
        });
    }

    fn object(&mut self, kind: &str, object: &GitOid) {
        self.hasher.update(b"o");
        field(&mut self.hasher, kind.as_bytes());
        field(&mut self.hasher, object.as_str().as_bytes());
        self.push(OriginPublishReviewItem::Object {
            object_type: kind.to_owned(),
            object: object.as_str().to_owned(),
            target: None,
            name: None,
            size: None,
        });
    }

    /// A path a tree tip holds.
    fn git_item(&mut self, item: &GitReviewItem) {
        hash_item(&mut self.hasher, item);
        if let GitReviewItem::Path {
            status,
            mode,
            object,
            path,
        } = item
        {
            self.entries = self.entries.saturating_add(1);
            let path = String::from_utf8_lossy(path).into_owned();
            self.paths.insert(path.clone());
            self.push(OriginPublishReviewItem::Path {
                status: status.to_string(),
                mode: mode.clone(),
                object: object.as_ref().map(|oid| oid.as_str().to_owned()),
                path,
            });
        }
    }

    /// A commit walk's review, whole: its digest, pages and counts.
    fn absorb(&mut self, walk: BuiltReview) {
        field(&mut self.hasher, walk.review.digest.as_bytes());
        self.flush();
        self.pages.extend(walk.pages);
        self.paths.extend(walk.paths);
        self.commits = self.commits.saturating_add(walk.review.commits);
        self.entries = self.entries.saturating_add(walk.review.entries);
    }

    fn finish(mut self, subtracted: Option<String>) -> BuiltReview {
        self.flush();
        let count = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        BuiltReview {
            review: OriginPublishReview {
                digest: self.hasher.finalize().to_hex().to_string(),
                subtracted,
                commits: self.commits,
                entries: self.entries,
                paths: count(self.paths.len()),
                pages: count(self.pages.len()),
                lfs_bytes: OriginPublishLfsBytes::NotSent,
            },
            pages: self.pages,
            paths: self.paths,
        }
    }
}

/// The empty section of a full-auto ref the mirror already holds, or holds
/// a descendant of: nothing goes out for it.
pub(super) fn covered_section(
    name: &GitRefName,
    new: &GitOid,
    observed: &MirrorObservedTip,
) -> BuiltReview {
    Section::new(name, new, observed).finish(observed.oid().map(str::to_owned))
}

impl Vault {
    /// Reviews what pushing `new` to `name` over the tip `observed` would
    /// expose, leaving out what `reviewed` (the commits earlier sections
    /// walked) reach. A ref already at `new` exposes nothing.
    pub(super) fn review_whole_ref(
        &self,
        wire: &GitWire<'_>,
        handle: &GitWireRepo,
        name: &GitRefName,
        new: &GitOid,
        observed: &MirrorObservedTip,
        reviewed: &[GitOid],
    ) -> Result<RefSection> {
        let mut section = Section::new(name, new, observed);
        if observed.oid() == Some(new.as_str()) {
            let built = section.finish(Some(new.as_str().to_owned()));
            admit_review_policy(&built)?;
            return Ok(RefSection {
                built,
                walked: None,
            });
        }
        let peeled = wire.peel_ref_tip(handle, new)?;
        for tag in &peeled.tags {
            section.tag(tag);
        }
        let (walked, subtracted) = match &peeled.end {
            GitRefEnd::Commit(commit) => {
                let base = self.held_commit_of(wire, handle, observed)?;
                let walk = self.build_publish_review_excluding(
                    wire,
                    handle,
                    commit,
                    base.as_ref(),
                    reviewed,
                )?;
                section.absorb(walk);
                (
                    Some(commit.clone()),
                    base.map(|base| base.as_str().to_owned()),
                )
            }
            GitRefEnd::Tree(tree) => {
                section.object("tree", tree);
                wire.for_each_tree_path_retained(handle, tree, &mut |item| {
                    section.git_item(&item);
                    Ok(())
                })?;
                (None, None)
            }
            GitRefEnd::Blob(blob) => {
                section.object("blob", blob);
                (None, None)
            }
        };
        let built = section.finish(subtracted);
        admit_review_policy(&built)?;
        Ok(RefSection { built, walked })
    }

    /// The commit the tip a plan read peels to, when this store holds it:
    /// only that history is left out of a section.
    fn held_commit_of(
        &self,
        wire: &GitWire<'_>,
        handle: &GitWireRepo,
        observed: &MirrorObservedTip,
    ) -> Result<Option<GitOid>> {
        let Some(tip) = observed.oid() else {
            return Ok(None);
        };
        let tip = GitOid::parse_hex(tip)?;
        let peeled = wire.peel_tips(handle, std::slice::from_ref(&tip))?;
        Ok(peeled.first().and_then(|tip| tip.commit().cloned()))
    }

    /// Whether the mirror's ref already stands at `new`, or at a commit held
    /// here that descends from it: a full-auto run never rewinds a ref.
    pub(super) fn mirror_holds_descendant(
        &self,
        scope: &MirrorRunScope<'_, '_>,
        new: &GitOid,
        tip: &MirrorObservedTip,
    ) -> Result<bool> {
        let Some(tip) = tip.oid() else {
            return Ok(false);
        };
        if tip == new.as_str() {
            return Ok(true);
        }
        let tip = GitOid::parse_hex(tip)?;
        let peeled = scope
            .wire
            .peel_tips(scope.handle, std::slice::from_ref(&tip))?;
        let Some(held) = peeled.first().and_then(|tip| tip.commit().cloned()) else {
            return Ok(false);
        };
        scope.wire.commits_reachable_from(
            scope.handle,
            std::slice::from_ref(new),
            std::slice::from_ref(&held),
        )
    }
}
