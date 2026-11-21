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

use oneiron_contracts::fingerprint::{LegacyDigest, purposes};

use super::ORIGIN_PUBLISH_REVIEW_PAGE_ITEMS;
use super::mirror_plan::MirrorRunScope;
use super::mirror_plan_types::MirrorObservedTip;
use super::review::{BuiltReview, admit_review_policy, digest_hex, hash_item};
use super::types::{
    OriginPublishLfsBytes, OriginPublishReview, OriginPublishReviewItem, OriginPublishReviewPage,
};
use crate::Vault;
use crate::error::Result;
use crate::git_wire::{
    GitOid, GitRefEnd, GitRefName, GitRefTag, GitReviewItem, GitWire, GitWireRepo,
};
use std::collections::BTreeSet;

/// One ref's section as its walk built it, and the commit the walk covered,
/// which later refs leave out.
pub(super) struct RefSection {
    pub(super) built: BuiltReview,
    pub(super) walked: Option<GitOid>,
}

/// A section being built: its digest, pages and counts.
struct Section {
    digest: LegacyDigest,
    pages: Vec<OriginPublishReviewPage>,
    page: Vec<OriginPublishReviewItem>,
    paths: BTreeSet<String>,
    lossy_paths: bool,
    commits: u64,
    entries: u64,
}

impl Section {
    /// Its digest starts with the ref name, the new object and the observed tip
    /// (empty when none). Vaults hold section digests, so they keep their bytes (K,
    /// PLAN-UC-04 3.2): each field framed by its length as a u64 little-endian.
    fn new(name: &GitRefName, new: &GitOid, observed: &MirrorObservedTip) -> Self {
        let mut digest = LegacyDigest::new(purposes::origin::MIRROR_REVIEW);
        for field in [name.as_str(), new.as_str(), observed.oid().unwrap_or("")] {
            digest.len_u64_le(field.len()).raw(field.as_bytes());
        }
        Self {
            digest,
            pages: Vec::new(),
            page: Vec::new(),
            paths: BTreeSet::new(),
            lossy_paths: false,
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
        let oid = tag.tag.as_str();
        self.digest
            .raw(if tag.raw.is_some() { b"t" } else { b"T" })
            .len_u64_le(oid.len())
            .raw(oid.as_bytes());
        match &tag.raw {
            Some(raw) => {
                self.digest.len_u64_le(raw.len()).raw(raw);
            }
            None => {
                let size = tag.size.to_le_bytes();
                self.digest.len_u64_le(size.len()).raw(&size);
            }
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
        self.digest.raw(b"o");
        for field in [kind, object.as_str()] {
            self.digest.len_u64_le(field.len()).raw(field.as_bytes());
        }
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
        hash_item(&mut self.digest, item);
        if let GitReviewItem::Path {
            status,
            mode,
            object,
            path,
        } = item
        {
            self.entries = self.entries.saturating_add(1);
            self.lossy_paths |= std::str::from_utf8(path).is_err();
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
        let walked = walk.review.digest.as_bytes();
        self.digest.len_u64_le(walked.len()).raw(walked);
        self.flush();
        self.pages.extend(walk.pages);
        self.paths.extend(walk.paths);
        self.lossy_paths |= walk.review.lossy_paths;
        self.commits = self.commits.saturating_add(walk.review.commits);
        self.entries = self.entries.saturating_add(walk.review.entries);
    }

    fn finish(mut self, subtracted: Option<String>) -> BuiltReview {
        self.flush();
        let count = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        BuiltReview {
            review: OriginPublishReview {
                digest: digest_hex(&self.digest),
                subtracted,
                commits: self.commits,
                entries: self.entries,
                paths: count(self.paths.len()),
                pages: count(self.pages.len()),
                lfs_bytes: OriginPublishLfsBytes::NotSent,
                lossy_paths: self.lossy_paths,
                secret_history: None,
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

/// A section's digest after `writes`, in order, for the K-proof door
/// (`test_doors::fingerprint_keep_origin`).
#[cfg(oneiron_test_support)]
pub(crate) fn section_digest_for_test(
    name: &GitRefName,
    new: &GitOid,
    observed: &MirrorObservedTip,
    writes: &[crate::test_doors::fingerprint_keep_origin::MirrorSectionWrite],
) -> String {
    use crate::test_doors::fingerprint_keep_origin::MirrorSectionWrite;
    let mut section = Section::new(name, new, observed);
    for write in writes {
        match write {
            MirrorSectionWrite::Tag(tag) => section.tag(tag),
            MirrorSectionWrite::Object { kind, object } => section.object(kind, object),
            MirrorSectionWrite::Item(item) => section.git_item(item),
            MirrorSectionWrite::Walk(digest) => section.absorb(BuiltReview {
                review: OriginPublishReview {
                    digest: digest.clone(),
                    subtracted: None,
                    commits: 0,
                    entries: 0,
                    paths: 0,
                    pages: 0,
                    lfs_bytes: OriginPublishLfsBytes::NotSent,
                    lossy_paths: false,
                    secret_history: None,
                },
                pages: Vec::new(),
                paths: BTreeSet::new(),
            }),
        }
    }
    section.finish(None).review.digest
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
                    None,
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
