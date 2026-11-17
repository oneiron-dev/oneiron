//! K-proof (oracle) for PLAN-UC-04 stage 3.2: the origin publish review digest and a
//! mirror plan's section, vector and plan digests keep their bytes.
//!
//! The four digests now start their BLAKE3 through the fingerprint crate's K door
//! (`purposes::origin::PUBLISH_REVIEW`, `MIRROR_REVIEW`, `MIRROR_VECTOR` and
//! `MIRROR_PLAN`). A publish request stores its review digest, which an approval names
//! and the send compares; a frozen mirror plan stores its digest, each ref's section
//! digest and its vector digest, which a full-auto mirror compares with its next
//! selection. So each must give main's bytes for every value. `base` below holds main's
//! lines at 9f9cd3693163, copied by range (each range is named above its copy; the generator
//! is `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`) and differing from
//! them only in indentation. The two walk-built digests, the review and the section,
//! are driven here by the writes their walks make, through the test door
//! `fingerprint_keep_origin`; the few lines around those copies only start and finish
//! the hasher, as main's walks do.

use oneiron::EntityId;
use oneiron::git_wire::{GitOid, GitRefName, GitRefTag, GitReviewItem};
use oneiron::origin::mirror_strategy::OriginMirrorSyncStrategy;
use oneiron::origin::publish::{
    MirrorObservedTip, OriginPublishDestination, OriginPublishLfsBytes, OriginPublishReview,
};
use oneiron::test_doors::fingerprint_keep_origin::{
    self as door, MirrorPlanFields, MirrorPlanRefFields, MirrorSectionWrite,
};
use oneiron_contracts::fingerprint::{LegacyHash, TagMode, purposes};
use oneiron_store::origin::publish::mirror_plan_types::MirrorPendingHead;
use oneiron_store::origin::secret_publication::{
    RepoDestinationAudience, RepoDestinationRole, RepoDestinationVisibility,
};

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
mod base {
    use oneiron::git_wire::{GitOid, GitRefName, GitRefTag, GitReviewItem};
    use oneiron::origin::publish::MirrorObservedTip;
    use oneiron::test_doors::fingerprint_keep_origin::MirrorPlanFields as MirrorPushPlan;

    /// The derive-key contexts main started the four digests with.
    pub(crate) const CONTEXTS: [&str; 4] = [
        ORIGIN_PUBLISH_REVIEW_DIGEST_CONTEXT,
        ORIGIN_MIRROR_REVIEW_DIGEST_CONTEXT,
        ORIGIN_MIRROR_VECTOR_DIGEST_CONTEXT,
        ORIGIN_MIRROR_PLAN_DIGEST_CONTEXT,
    ];

    // main 9f9cd3693163: crates/oneiron/src/origin/publish/review.rs:29-30
    /// The digest's BLAKE3 derive-key context.
    const ORIGIN_PUBLISH_REVIEW_DIGEST_CONTEXT: &str = "oneiron:origin-publish-review:v1";

    // main's line keeps its `pub`, which the private module cannot reach.
    #[allow(unreachable_pub)]
    // main 9f9cd3693163: crates/oneiron-store/src/origin/publish/mirror_review.rs:25-26
    /// A section digest's BLAKE3 derive-key context.
    pub const ORIGIN_MIRROR_REVIEW_DIGEST_CONTEXT: &str = "oneiron:origin-mirror-review:v1";

    // main 9f9cd3693163: crates/oneiron/src/origin/publish/mirror_plan.rs:32-36
    /// A plan digest's BLAKE3 derive-key context.
    const ORIGIN_MIRROR_PLAN_DIGEST_CONTEXT: &str = "oneiron:origin-mirror-plan:v1";

    /// A vector digest's BLAKE3 derive-key context.
    const ORIGIN_MIRROR_VECTOR_DIGEST_CONTEXT: &str = "oneiron:origin-mirror-vector:v1";

    /// An exact publish's review digest: main's start (in its walk), each item the
    /// walk meets, and the walk's finish.
    pub(crate) fn review_digest(
        commit: &GitOid,
        base: Option<&GitOid>,
        reviewed: &[GitOid],
        items: &[GitReviewItem],
    ) -> String {
// main 9f9cd3693163: crates/oneiron/src/origin/publish/review.rs:77-85
        let mut hasher = blake3::Hasher::new_derive_key(ORIGIN_PUBLISH_REVIEW_DIGEST_CONTEXT);
        field(&mut hasher, commit.as_str().as_bytes());
        field(
            &mut hasher,
            base.map_or(&b""[..], |base| base.as_str().as_bytes()),
        );
        for oid in reviewed {
            field(&mut hasher, oid.as_str().as_bytes());
        }
        for item in items {
            hash_item(&mut hasher, item);
        }
        hasher.finalize().to_hex().to_string()
    }

    // main 9f9cd3693163: crates/oneiron/src/origin/publish/review.rs:174-210
    /// One item into the digest, each field length-prefixed.
    pub(super) fn hash_item(hasher: &mut blake3::Hasher, item: &GitReviewItem) {
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

    pub(super) fn field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
        hasher.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(bytes);
    }

    /// The digest half of main's mirror `Section`: the same writes, without the pages.
    pub(crate) struct Section {
        hasher: blake3::Hasher,
    }

    /// A walked commit's review, as `Section::absorb` reads it.
    pub(crate) struct BuiltReview {
        pub(crate) review: Review,
    }

    pub(crate) struct Review {
        pub(crate) digest: String,
    }

    impl Section {
        pub(crate) fn new(name: &GitRefName, new: &GitOid, observed: &MirrorObservedTip) -> Self {
    // main 9f9cd3693163: crates/oneiron/src/origin/publish/mirror_review.rs:40-43
            let mut hasher = blake3::Hasher::new_derive_key(ORIGIN_MIRROR_REVIEW_DIGEST_CONTEXT);
            field(&mut hasher, name.as_str().as_bytes());
            field(&mut hasher, new.as_str().as_bytes());
            field(&mut hasher, observed.oid().unwrap_or("").as_bytes());
            Self { hasher }
        }

        pub(crate) fn tag(&mut self, tag: &GitRefTag) {
    // main 9f9cd3693163: crates/oneiron/src/origin/publish/mirror_review.rs:71-77
            self.hasher
                .update(if tag.raw.is_some() { b"t" } else { b"T" });
            field(&mut self.hasher, tag.tag.as_str().as_bytes());
            match &tag.raw {
                Some(raw) => field(&mut self.hasher, raw),
                None => field(&mut self.hasher, &tag.size.to_le_bytes()),
            }
        }

        pub(crate) fn object(&mut self, kind: &str, object: &GitOid) {
    // main 9f9cd3693163: crates/oneiron/src/origin/publish/mirror_review.rs:88-90
            self.hasher.update(b"o");
            field(&mut self.hasher, kind.as_bytes());
            field(&mut self.hasher, object.as_str().as_bytes());
        }

        pub(crate) fn git_item(&mut self, item: &GitReviewItem) {
    // main 9f9cd3693163: crates/oneiron/src/origin/publish/mirror_review.rs:102-102
            hash_item(&mut self.hasher, item);
        }

        pub(crate) fn absorb(&mut self, walk: BuiltReview) {
    // main 9f9cd3693163: crates/oneiron/src/origin/publish/mirror_review.rs:125-125
            field(&mut self.hasher, walk.review.digest.as_bytes());
        }

        pub(crate) fn finish(self) -> String {
            self.hasher.finalize().to_hex().to_string()
        }
    }

    /// The two lists of a mirror selection its vector digest reads.
    pub(crate) struct MirrorSelection {
        pub(crate) vector: Vec<(GitRefName, GitOid)>,
        pub(crate) deletions: Vec<GitRefName>,
    }

    impl MirrorSelection {
    // main 9f9cd3693163: crates/oneiron/src/origin/publish/mirror_plan.rs:48-61
        /// The digest of what the selection sends, which a full-auto mirror
        /// compares with the plan it settled last.
        pub(crate) fn vector_digest(&self) -> String {
            let mut hasher = blake3::Hasher::new_derive_key(ORIGIN_MIRROR_VECTOR_DIGEST_CONTEXT);
            for (name, oid) in &self.vector {
                field(&mut hasher, name.as_str().as_bytes());
                field(&mut hasher, oid.as_str().as_bytes());
            }
            hasher.update(b"d");
            for name in &self.deletions {
                field(&mut hasher, name.as_str().as_bytes());
            }
            hasher.finalize().to_hex().to_string()
        }
    }

    // main 9f9cd3693163: crates/oneiron/src/origin/publish/mirror_plan.rs:237-282
    /// One digest over a plan's destination (its audience included), strategy,
    /// refs, observations, batches, sections and held heads.
    fn plan_digest(plan: &MirrorPushPlan) -> String {
        let mut hasher = blake3::Hasher::new_derive_key(ORIGIN_MIRROR_PLAN_DIGEST_CONTEXT);
        hasher.update(plan.repo_id.as_bytes());
        let destination = &plan.destination;
        field(&mut hasher, destination.url.as_bytes());
        field(&mut hasher, destination.user.as_bytes());
        field(&mut hasher, destination.secret_ref.as_bytes());
        let generation = destination.target_generation.map(|id| id.to_hex());
        field(&mut hasher, generation.unwrap_or_default().as_bytes());
        field(
            &mut hasher,
            destination.audience.visibility.as_str().as_bytes(),
        );
        field(&mut hasher, destination.audience.role.as_str().as_bytes());
        field(&mut hasher, plan.strategy.as_str().as_bytes());
        hasher.update(&plan.strategy_revision.to_le_bytes());
        for plan_ref in &plan.refs {
            field(&mut hasher, plan_ref.ref_name.as_bytes());
            field(
                &mut hasher,
                plan_ref.new.as_deref().unwrap_or("").as_bytes(),
            );
            let (state, value) = match &plan_ref.observed {
                MirrorObservedTip::Absent => ("absent", ""),
                MirrorObservedTip::At { oid } => ("at", oid.as_str()),
                MirrorObservedTip::Unknown { cause } => ("unknown", cause.as_str()),
            };
            field(&mut hasher, state.as_bytes());
            field(&mut hasher, value.as_bytes());
            hasher.update(&plan_ref.batch.unwrap_or(u32::MAX).to_le_bytes());
            let section = plan_ref
                .review
                .as_ref()
                .map_or("", |review| review.digest.as_str());
            field(&mut hasher, section.as_bytes());
        }
        for held in &plan.pending_checks {
            field(&mut hasher, held.ref_name.as_bytes());
            field(&mut hasher, held.head.as_bytes());
            field(&mut hasher, held.sent.as_deref().unwrap_or("").as_bytes());
        }
        field(&mut hasher, plan.vector.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    pub(crate) fn mirror_plan_digest(plan: &MirrorPushPlan) -> String {
        plan_digest(plan)
    }
}

fn oid(seed: u8) -> GitOid {
    GitOid::parse_hex(format!("{seed:02x}").repeat(20)).expect("40 lower hex, not the null oid")
}

fn ref_name(name: &str) -> GitRefName {
    GitRefName::parse_full(name).expect("a full ref name")
}

fn id(seed: u8) -> EntityId {
    EntityId::from_bytes(std::array::from_fn(|at| seed ^ (at as u8).wrapping_mul(17)))
        .expect("an id with no reserved bytes")
}

/// A review digest's hex as a plan or a section stores it.
fn hex(seed: u8) -> String {
    format!("{seed:02x}").repeat(32)
}

fn commit(commit: u8, parents: &[u8]) -> GitReviewItem {
    GitReviewItem::Commit {
        commit: oid(commit),
        parents: parents.iter().copied().map(oid).collect(),
    }
}

fn path(status: char, mode: &str, object: Option<u8>, path: &[u8]) -> GitReviewItem {
    GitReviewItem::Path {
        status,
        mode: mode.to_owned(),
        object: object.map(oid),
        path: path.to_vec(),
    }
}

/// Item lists a walk could meet: none; a root commit, a commit, a merge; added and
/// deleted paths; an empty path; path bytes that are not UTF-8 and a status of two UTF-8
/// bytes; two splits of the same bytes; and a commit that comes back.
fn item_lists() -> Vec<Vec<GitReviewItem>> {
    vec![
        vec![],
        vec![commit(1, &[])],
        vec![commit(1, &[2])],
        vec![commit(1, &[2, 3])],
        vec![commit(1, &[2]), path('A', "100644", Some(4), b"src/lib.rs")],
        vec![commit(1, &[2]), path('D', "100755", None, b"bin/run")],
        vec![
            path('M', "120000", Some(5), b""),
            path('T', "160000", Some(6), b"vendor/sub"),
        ],
        vec![
            path('A', "100644", Some(4), b"caf\xc3\xa9/\xff\xfe"),
            path('\u{e9}', "", Some(4), b"x"),
        ],
        vec![
            path('A', "100644", Some(4), b"ab"),
            path('A', "100644", Some(4), b"c"),
        ],
        vec![
            path('A', "100644", Some(4), b"a"),
            path('A', "100644", Some(4), b"bc"),
        ],
        vec![
            commit(1, &[2]),
            path('A', "100644", Some(4), b"f"),
            commit(2, &[]),
            path('D', "100644", None, b"f"),
        ],
    ]
}

fn review(digest: String) -> OriginPublishReview {
    OriginPublishReview {
        digest,
        subtracted: None,
        commits: 0,
        entries: 0,
        paths: 0,
        pages: 0,
        lfs_bytes: OriginPublishLfsBytes::NotSent,
        lossy_paths: false,
        secret_history: None,
    }
}

#[test]
fn the_origin_purposes_keep_main_s_contexts() {
    let legacy = [
        purposes::origin::PUBLISH_REVIEW,
        purposes::origin::MIRROR_REVIEW,
        purposes::origin::MIRROR_VECTOR,
        purposes::origin::MIRROR_PLAN,
    ];
    for (purpose, context) in legacy.into_iter().zip(base::CONTEXTS) {
        assert_eq!(purpose.tag(), context);
        assert_eq!(purpose.hash(), LegacyHash::Blake3);
        assert_eq!(purpose.tag_mode(), TagMode::DeriveKeyContext);
    }
}

#[test]
fn the_publish_review_digest_keeps_its_bytes() {
    let mut checked = 0;
    for commit in [oid(1), oid(7)] {
        for subtracted in [None, Some(oid(8))] {
            for reviewed in [vec![], vec![oid(9)], vec![oid(9), oid(10)]] {
                for items in item_lists() {
                    assert_eq!(
                        door::publish_review_digest(
                            &commit,
                            subtracted.as_ref(),
                            &reviewed,
                            &items
                        ),
                        base::review_digest(&commit, subtracted.as_ref(), &reviewed, &items),
                        "{commit:?} {subtracted:?} {reviewed:?} {items:?}"
                    );
                    checked += 1;
                }
            }
        }
    }
    // 2 commits x 2 bases x 3 reviewed lists x 11 item lists.
    assert_eq!(checked, 132);
}

fn tag(raw: Option<&[u8]>, size: u64) -> GitRefTag {
    GitRefTag {
        tag: oid(3),
        target: oid(1),
        target_kind: "commit".to_owned(),
        name: "v1".to_owned(),
        size,
        raw: raw.map(<[u8]>::to_vec),
    }
}

fn object(kind: &str, seed: u8) -> MirrorSectionWrite {
    MirrorSectionWrite::Object {
        kind: kind.to_owned(),
        object: oid(seed),
    }
}

/// Write lists a section's walk could make: none (a ref at its tip); a commit tip; tags
/// on the way, a large one by its size and an empty one; a `T` and a `t` whose framed
/// bytes match; a tree with paths, an empty tree, a blob, a tag on a blob; a commit item;
/// and an empty walk digest.
fn write_lists() -> Vec<Vec<MirrorSectionWrite>> {
    use MirrorSectionWrite::{Item, Tag, Walk};
    vec![
        vec![],
        vec![Walk(hex(10))],
        vec![
            Tag(tag(Some(b"object 0101\ntype commit\n\nmessage\n"), 40)),
            Walk(hex(10)),
        ],
        vec![
            Tag(tag(None, 1 << 40)),
            Tag(tag(Some(b""), 0)),
            Walk(hex(11)),
        ],
        vec![Tag(tag(None, 0))],
        vec![Tag(tag(Some(&[0; 8]), 0))],
        vec![
            object("tree", 4),
            Item(path('A', "100644", Some(5), b"README")),
            Item(path('A', "040000", Some(6), b"\xff")),
        ],
        vec![object("tree", 4)],
        vec![object("blob", 5)],
        vec![Tag(tag(Some(b"x"), 1)), object("blob", 5)],
        vec![Item(commit(1, &[2]))],
        vec![Walk(String::new())],
    ]
}

#[test]
fn the_mirror_section_digest_keeps_its_bytes() {
    let new = oid(1);
    let mut checked = 0;
    for name in [ref_name("refs/heads/main"), ref_name("refs/tags/v1")] {
        for observed in [
            MirrorObservedTip::Absent,
            MirrorObservedTip::At {
                oid: oid(2).as_str().to_owned(),
            },
            MirrorObservedTip::Unknown {
                cause: "the mirror read failed".to_owned(),
            },
            MirrorObservedTip::Unknown {
                cause: String::new(),
            },
        ] {
            for writes in write_lists() {
                let mut section = base::Section::new(&name, &new, &observed);
                for write in &writes {
                    match write {
                        MirrorSectionWrite::Tag(tag) => section.tag(tag),
                        MirrorSectionWrite::Object { kind, object } => section.object(kind, object),
                        MirrorSectionWrite::Item(item) => section.git_item(item),
                        MirrorSectionWrite::Walk(digest) => section.absorb(base::BuiltReview {
                            review: base::Review {
                                digest: digest.clone(),
                            },
                        }),
                    }
                }
                assert_eq!(
                    door::mirror_section_digest(&name, &new, &observed, &writes),
                    section.finish(),
                    "{name:?} {observed:?} {writes:?}"
                );
                checked += 1;
            }
        }
    }
    // 2 refs x 4 observed tips x 12 write lists.
    assert_eq!(checked, 96);
}

#[test]
fn the_mirror_vector_digest_keeps_its_bytes() {
    let main = ref_name("refs/heads/main");
    let tag = ref_name("refs/tags/v1");
    let old = ref_name("refs/heads/old");
    let nested = ref_name("refs/heads/a/b");
    let mut checked = 0;
    for vector in [
        vec![],
        vec![(main.clone(), oid(1))],
        vec![(main.clone(), oid(1)), (tag.clone(), oid(2))],
    ] {
        for deletions in [vec![], vec![old.clone()], vec![old.clone(), nested.clone()]] {
            assert_eq!(
                door::mirror_vector_digest(&vector, &deletions),
                base::MirrorSelection {
                    vector: vector.clone(),
                    deletions: deletions.clone(),
                }
                .vector_digest(),
                "{vector:?} {deletions:?}"
            );
            checked += 1;
        }
    }
    // 3 vectors x 3 deletion lists.
    assert_eq!(checked, 9);
}

fn destinations() -> Vec<OriginPublishDestination> {
    let audience = |visibility, role| RepoDestinationAudience { visibility, role };
    vec![
        OriginPublishDestination {
            url: "https://example.org/team/repo.git".to_owned(),
            user: "git".to_owned(),
            secret_ref: "custody/mirror-token".to_owned(),
            target_generation: Some(id(1)),
            audience: audience(
                RepoDestinationVisibility::Public,
                RepoDestinationRole::Mirror,
            ),
        },
        OriginPublishDestination {
            url: String::new(),
            user: String::new(),
            secret_ref: String::new(),
            target_generation: None,
            audience: audience(
                RepoDestinationVisibility::Unknown,
                RepoDestinationRole::OriginalSource,
            ),
        },
        OriginPublishDestination {
            url: "https://example.org/r".to_owned(),
            user: "u\u{e9}".to_owned(),
            secret_ref: "c".to_owned(),
            target_generation: Some(id(2)),
            audience: audience(
                RepoDestinationVisibility::Private,
                RepoDestinationRole::Mirror,
            ),
        },
    ]
}

/// Ref lists a plan could hold: none; a pushed ref; a deletion; a ref whose tip read
/// failed, in the last batch number, with an empty section digest; a push and a
/// deletion.
fn plan_ref_lists() -> Vec<Vec<MirrorPlanRefFields>> {
    let pushed = MirrorPlanRefFields {
        ref_name: "refs/heads/main".to_owned(),
        new: Some(oid(1).as_str().to_owned()),
        observed: MirrorObservedTip::Absent,
        batch: Some(0),
        review: Some(review(hex(10))),
    };
    let deleted = MirrorPlanRefFields {
        ref_name: "refs/heads/old".to_owned(),
        new: None,
        observed: MirrorObservedTip::At {
            oid: oid(2).as_str().to_owned(),
        },
        batch: None,
        review: None,
    };
    let unread = MirrorPlanRefFields {
        ref_name: "refs/tags/v1".to_owned(),
        new: Some(oid(3).as_str().to_owned()),
        observed: MirrorObservedTip::Unknown {
            cause: "the mirror read failed".to_owned(),
        },
        batch: Some(u32::MAX),
        review: Some(review(String::new())),
    };
    vec![
        vec![],
        vec![pushed.clone()],
        vec![deleted.clone()],
        vec![unread],
        vec![pushed, deleted],
    ]
}

fn pending_lists() -> Vec<Vec<MirrorPendingHead>> {
    let held = |sent: Option<u8>| MirrorPendingHead {
        ref_name: "refs/heads/main".to_owned(),
        head: oid(4).as_str().to_owned(),
        sent: sent.map(|seed| oid(seed).as_str().to_owned()),
    };
    vec![vec![], vec![held(None)], vec![held(Some(5)), held(None)]]
}

#[test]
fn the_mirror_plan_digest_keeps_its_bytes() {
    let mut checked = 0;
    for destination in destinations() {
        for (strategy, strategy_revision) in [
            (OriginMirrorSyncStrategy::AskMe, 0),
            (OriginMirrorSyncStrategy::Schedule, 1),
            (OriginMirrorSyncStrategy::FullAuto, u64::MAX),
        ] {
            for refs in plan_ref_lists() {
                for pending_checks in pending_lists() {
                    for vector in [String::new(), hex(12)] {
                        let fields = MirrorPlanFields {
                            repo_id: id(3),
                            destination: destination.clone(),
                            strategy,
                            strategy_revision,
                            refs: refs.clone(),
                            pending_checks: pending_checks.clone(),
                            vector,
                        };
                        assert_eq!(
                            door::mirror_plan_digest(&fields),
                            base::mirror_plan_digest(&fields),
                            "{fields:?}"
                        );
                        checked += 1;
                    }
                }
            }
        }
    }
    // 3 destinations x 3 strategies x 5 ref lists x 3 held lists x 2 vectors.
    assert_eq!(checked, 270);
}
