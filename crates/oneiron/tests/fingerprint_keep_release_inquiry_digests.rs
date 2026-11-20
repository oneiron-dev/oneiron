//! K-proof (oracle) for PLAN-UC-04 stage 6.2d: a publisher training offer's world settings
//! digest and an inquiry's answer effect digest keep their bytes.
//!
//! The offer's digest of its worlds' settings revisions
//! (`purposes::feedback::TRAINING_POLICY_REVISION`) and an inquiry's answer effect digest
//! (`purposes::inquiry::ANSWER_EFFECT`) start through the fingerprint crate's K door. The first
//! is stored in an offer's custody row and compared afresh before the offer is released; the
//! second is stored in the pending check-in an inquiry's ladder opens and in its receipt, and an
//! answer or a consume compares it. So each must give main's bytes for every input.
//!
//! Main's `policy_digest` reads each world's revision from an `AuthorityFold`, which a test
//! cannot build. The head splits it: `policy_digest` maps each world of the set, in the set's
//! order, to its revision on the fold, and hands the pairs to the digest the door reaches. Here
//! main's copy runs on a stand-in fold by main's names, and the door gets the same pairs.
//! The `base_*` modules hold main's lines at f3db86cd3f7f, copied by range (each range is named
//! above its copy; the generator is `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`)
//! and differing from them only in indentation. The few lines around the copies are the
//! imports main's lines name, the stand-in fold and wrappers for main's private items.
//!
//! The door builds only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_release_inquiry_digests`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};

use oneiron::EntityId;
use oneiron::inquiry::{Inquiry, InquiryAsker, InquiryKeep, InquiryTask};
use oneiron::test_doors::fingerprint_keep_release_inquiry_digests as door;
use oneiron_contracts::fingerprint::{LegacyHash, TagMode, purposes};

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
mod base_release {
    use std::collections::{BTreeMap, BTreeSet};

    use oneiron::EntityId;

    /// Main's `PolicyRevision` (oneiron-authority `world_key_wraps.rs`): a world's
    /// settings revision.
    pub(crate) struct PolicyRevision(pub(crate) [u8; 32]);

    /// A stand-in for main's `AuthorityFold`: each world's settings revision, and zeros
    /// for a world it does not hold.
    pub(crate) struct AuthorityFold(pub(crate) BTreeMap<EntityId, [u8; 32]>);

    impl AuthorityFold {
        pub(crate) fn world_policy_revision(&self, world: EntityId) -> PolicyRevision {
            PolicyRevision(self.0.get(&world).copied().unwrap_or([0; 32]))
        }
    }

    // main f3db86cd3f7f: crates/oneiron/src/feedback/conversation_training/release.rs:61-62
    /// The key context of an offer's worlds' settings digest.
    const POLICY_REVISION_CONTEXT: &str = "oneiron publisher training world policy revision v1";

    // main f3db86cd3f7f: crates/oneiron/src/feedback/conversation_training/release.rs:546-554
    /// The digest of `worlds`' settings revisions on `fold`.
    fn policy_digest(fold: &AuthorityFold, worlds: &BTreeSet<EntityId>) -> [u8; 32] {
        let mut digest = blake3::Hasher::new_derive_key(POLICY_REVISION_CONTEXT);
        for world in worlds {
            digest.update(world.as_bytes());
            digest.update(&fold.world_policy_revision(*world).0);
        }
        *digest.finalize().as_bytes()
    }

    /// Main's key context, which is private there.
    pub(crate) const MAIN_POLICY_REVISION_CONTEXT: &str = POLICY_REVISION_CONTEXT;

    /// Main's settings digest, which is private there.
    pub(crate) fn main_policy_digest(fold: &AuthorityFold, worlds: &BTreeSet<EntityId>) -> [u8; 32] {
        policy_digest(fold, worlds)
    }
}

#[rustfmt::skip]
mod base_inquiry {
    use oneiron::inquiry::Inquiry;
    use oneiron::{EntityId, Result};

    // main f3db86cd3f7f: crates/oneiron/src/inquiry/member.rs:80-81
    /// The tag the answer effect's digest starts with.
    const EFFECT_DIGEST_TAG: &[u8] = b"oneiron.inquiry.answer.v1";

    // main f3db86cd3f7f: crates/oneiron/src/inquiry/member.rs:559-568
    /// The digest of an inquiry's answer effect: statements of this vault
    /// leaving over `grant` for exactly `inquiry`. An answer over any other
    /// settles nothing.
    fn effect_digest(grant: EntityId, inquiry: &Inquiry) -> Result<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(EFFECT_DIGEST_TAG);
        hasher.update(grant.as_bytes());
        hasher.update(&inquiry.encode_wire()?);
        Ok(*hasher.finalize().as_bytes())
    }

    /// Main's tag, which is private there.
    pub(crate) const MAIN_EFFECT_DIGEST_TAG: &[u8] = EFFECT_DIGEST_TAG;

    /// Main's answer effect digest, which is private there.
    pub(crate) fn main_effect_digest(grant: EntityId, inquiry: &Inquiry) -> Result<[u8; 32]> {
        effect_digest(grant, inquiry)
    }
}

fn id(n: u8) -> EntityId {
    EntityId::from_hex(&format!("{n:02x}{}", "ab".repeat(15))).expect("a valid id")
}

fn small(n: usize) -> u8 {
    u8::try_from(n).expect("a small index")
}

#[test]
fn the_release_inquiry_purposes_keep_main_s_recipes() {
    let training = purposes::feedback::TRAINING_POLICY_REVISION;
    assert_eq!(training.tag(), base_release::MAIN_POLICY_REVISION_CONTEXT);
    assert_eq!(training.hash(), LegacyHash::Blake3);
    assert_eq!(training.tag_mode(), TagMode::DeriveKeyContext);

    let answer = purposes::inquiry::ANSWER_EFFECT;
    assert_eq!(
        answer.tag().as_bytes(),
        base_inquiry::MAIN_EFFECT_DIGEST_TAG
    );
    assert_eq!(answer.hash(), LegacyHash::Blake3);
    assert_eq!(answer.tag_mode(), TagMode::HashedFirst);
}

#[test]
fn the_training_policy_digest_keeps_its_bytes() {
    let worlds: Vec<EntityId> = [0x00, 0x01, 0x10, 0x7f, 0x80, 0xab, 0xfe, 0xff]
        .into_iter()
        .map(id)
        .collect();
    // Three folds: each world with its own revision except every third (zeros), no world,
    // and every world at 0xff.
    let own: BTreeMap<EntityId, [u8; 32]> = worlds
        .iter()
        .enumerate()
        .filter(|(n, _)| n % 3 != 2)
        .map(|(n, world)| {
            let seed = small(n);
            let revision: [u8; 32] =
                std::array::from_fn(|i| seed.wrapping_mul(37).wrapping_add(small(i)));
            (*world, revision)
        })
        .collect();
    let full: BTreeMap<EntityId, [u8; 32]> =
        worlds.iter().map(|world| (*world, [0xff; 32])).collect();
    let folds = [
        base_release::AuthorityFold(own),
        base_release::AuthorityFold(BTreeMap::new()),
        base_release::AuthorityFold(full),
    ];

    // The empty set, each prefix and each suffix of the worlds, and every other world.
    let mut sets: Vec<BTreeSet<EntityId>> = vec![BTreeSet::new()];
    for n in 1..=worlds.len() {
        sets.push(worlds.iter().copied().take(n).collect());
        sets.push(worlds.iter().rev().copied().take(n).collect());
    }
    sets.push(worlds.iter().copied().step_by(2).collect());
    assert_eq!(sets.len(), 18);

    for fold in &folds {
        for set in &sets {
            // The head's `policy_digest`: each world of the set, in the set's order, with its
            // revision on the fold.
            let pairs: Vec<(EntityId, [u8; 32])> = set
                .iter()
                .map(|world| (*world, fold.world_policy_revision(*world).0))
                .collect();
            assert_eq!(
                door::training_policy_digest(&pairs),
                base_release::main_policy_digest(fold, set),
                "{set:?}"
            );
        }
    }
}

fn inquiries() -> Vec<Inquiry> {
    let vaults = [
        "0".repeat(64),
        "cd".repeat(32),
        "0123456789abcdef".repeat(4),
    ];
    let roles = ["r", "member", "ünïcode role — 日本語 🦀", " padded role "];
    let task_purposes = [
        "p".to_owned(),
        "quote \" and \\ backslash".to_owned(),
        "a".repeat(4096),
    ];
    let questions = [
        "q?".to_owned(),
        "a question\nover two lines".to_owned(),
        "emoji 🦀 and a \u{0} byte".to_owned(),
        "  spaced  ".to_owned(),
        "b".repeat(5000),
    ];
    let expiries = [1, 1_700_000_000, u64::MAX];
    (0..12)
        .map(|n| Inquiry {
            id: id(0x20 + small(n)),
            from: InquiryAsker {
                vault: vaults[n % vaults.len()].clone(),
                actor: id(0x40 + small(n)),
                role: roles[n % roles.len()].to_owned(),
            },
            task: InquiryTask {
                id: id(0x60 + small(n)),
                purpose: task_purposes[n % task_purposes.len()].clone(),
            },
            question: questions[n % questions.len()].clone(),
            keep: if n % 2 == 0 {
                InquiryKeep::Task
            } else {
                InquiryKeep::Copy
            },
            expires_at: expiries[n % expiries.len()],
        })
        .collect()
}

#[test]
fn the_inquiry_effect_digest_keeps_its_bytes() {
    let inquiries = inquiries();
    assert_eq!(inquiries.len(), 12);
    let mut cases = 0;
    for grant in [id(0x00), id(0x5a), id(0xff)] {
        for inquiry in &inquiries {
            assert_eq!(
                door::inquiry_effect_digest(grant, inquiry).expect("a valid inquiry"),
                base_inquiry::main_effect_digest(grant, inquiry).expect("a valid inquiry"),
                "{inquiry:?}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 36);
}

#[test]
fn an_invalid_inquiry_has_no_effect_digest_on_either_side() {
    let valid = inquiries().remove(0);
    let mut invalid = Vec::new();
    for vault in ["CD".repeat(32), "cd".repeat(31), String::new()] {
        let mut inquiry = valid.clone();
        inquiry.from.vault = vault;
        invalid.push(inquiry);
    }
    for role in ["", "  ", "two\nlines"] {
        let mut inquiry = valid.clone();
        inquiry.from.role = role.to_owned();
        invalid.push(inquiry);
    }
    let mut inquiry = valid.clone();
    inquiry.task.purpose = "two\nlines".to_owned();
    invalid.push(inquiry);
    let mut inquiry = valid.clone();
    inquiry.question = " \n ".to_owned();
    invalid.push(inquiry);
    let mut inquiry = valid;
    inquiry.expires_at = 0;
    invalid.push(inquiry);
    assert_eq!(invalid.len(), 9);
    for inquiry in &invalid {
        assert!(
            door::inquiry_effect_digest(id(0x5a), inquiry).is_err(),
            "{inquiry:?}"
        );
        assert!(
            base_inquiry::main_effect_digest(id(0x5a), inquiry).is_err(),
            "{inquiry:?}"
        );
    }
}
