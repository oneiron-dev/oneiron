//! K-proof (oracle) for the check-in effect digests of P2.5's delete and security-control
//! doors: each keeps its bytes through the fingerprint crate's K door.
//!
//! Five effect digests (`purposes::check_in`) now start through `LegacyDigest`. A pending
//! check-in stores the digest of the effect it asks for (`PendingCheckIn.effect_digest`, in
//! the `CHECK_IN_PENDING` row and its key), and the door that spends an approved ask
//! compares it with the effect it runs. So each must give the bytes it gave before. The
//! `base` module holds those functions as the P2.5 stack's top 61d7de0d7bf0 wrote them,
//! copied by range (the range is named above its copy; the generator is
//! `lanes/kimi/OPUS-CHECKIN/pr2/p25/s2/fingerprint/gen_keep_oracle.py`) and differing from
//! them only in indentation.
//!
//! `cargo test --locked -p oneiron --all-features --test fingerprint_keep_check_in_effect_digests`.

use std::collections::HashSet;

use oneiron::EntityId;
use oneiron::check_in::{
    attempt_archive_delete_effect_digest, embedding_space_probe_delete_effect_digest,
    mail_compliance_set_effect_digest, policy_row_change_effect_digest,
    record_delete_effect_digest,
};
// `deletion` is the path the base copy of `record_delete_effect_digest` names.
use oneiron::deletion::{self, DeleteReason};
use oneiron::policy_model::{PolicyRowAction, PolicyRowChange, PolicyRowScope};
use oneiron_contracts::fingerprint::{LegacyHash, TagMode, purposes};

// Not formatted, so each copy stays line for line equal to the base's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base {
    use oneiron::policy_model::PolicyRowChange;
    use oneiron::{EntityId, Error, Result};

    // P2.5 top 61d7de0d7bf0: crates/oneiron/src/check_in/effect.rs:562-577
    /// The digest of an Owner policy row change: the effect an asker's
    /// `vault.check_in.open` names for `vault.policy.owner.row.change`, and the
    /// one the Owner's change spends (2k4; P25-SHAPE Q1 = A). BLAKE3, key
    /// derived from `oneiron check_in policy row change v1`, over the change's
    /// MessagePack encoding with field names, as the change ledger keeps it.
    ///
    /// # Errors
    ///
    /// The change does not encode.
    pub fn policy_row_change_effect_digest(change: &PolicyRowChange) -> Result<[u8; 32]> {
        let encoded = rmp_serde::to_vec_named(change)
            .map_err(|_| Error::InvariantViolation("policy row change encode"))?;
        let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in policy row change v1");
        hasher.update(&encoded);
        Ok(*hasher.finalize().as_bytes())
    }

    // P2.5 top 61d7de0d7bf0: crates/oneiron/src/check_in/effect.rs:585-603
    /// The digest of turning org compliance search on or off (`enabled`) for
    /// `purpose`: the effect `vault.mail.compliance.set` judges, and the one an
    /// approved check-in for it spends (2k4; P25-SHAPE Q1 = A). BLAKE3, key
    /// derived from `oneiron check_in mail compliance set v1`, over one byte, 1
    /// to turn it on, the purpose's length as eight big-endian bytes and its
    /// bytes.
    #[must_use]
    pub fn mail_compliance_set_effect_digest(enabled: bool, purpose: &str) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in mail compliance set v1");
        hasher
            .update(&[u8::from(enabled)])
            .update(
                &u64::try_from(purpose.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            )
            .update(purpose.as_bytes());
        *hasher.finalize().as_bytes()
    }

    // P2.5 top 61d7de0d7bf0: crates/oneiron/src/check_in/effect.rs:605-611
    /// `text`'s length as one byte (at most 255; custody ids are at most 128)
    /// and its bytes.
    fn update_short_text(hasher: &mut blake3::Hasher, text: &str) {
        hasher
            .update(&[u8::try_from(text.len()).unwrap_or(u8::MAX)])
            .update(text.as_bytes());
    }

    // P2.5 top 61d7de0d7bf0: crates/oneiron/src/check_in/effect.rs:613-627
    /// The digest of deleting `record` for `reason`: the effect a person's
    /// `vault.delete` judges, and the one an approved check-in for it spends
    /// (2k5; P25-SHAPE Q1 = A). BLAKE3, key derived from `oneiron check_in
    /// record delete v1`, over the record's 16 id bytes and the reason's wire
    /// token, as its length in one byte and its bytes.
    #[must_use]
    pub fn record_delete_effect_digest(
        record: &EntityId,
        reason: crate::deletion::DeleteReason,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in record delete v1");
        hasher.update(record.as_bytes());
        update_short_text(&mut hasher, reason.as_str());
        *hasher.finalize().as_bytes()
    }

    // P2.5 top 61d7de0d7bf0: crates/oneiron/src/check_in/effect.rs:629-640
    /// The digest of deleting stored embedding space probe `probe`: the effect
    /// an asker's `vault.check_in.open` names for
    /// `vault.embedding_spaces.probes.delete`, and the one the Owner's delete
    /// spends (2k5; P25-SHAPE Q1 = A). BLAKE3, key derived from `oneiron
    /// check_in embedding space probe delete v1`, over the probe's 16 id bytes.
    #[must_use]
    pub fn embedding_space_probe_delete_effect_digest(probe: &[u8; 16]) -> [u8; 32] {
        let mut hasher =
            blake3::Hasher::new_derive_key("oneiron check_in embedding space probe delete v1");
        hasher.update(probe);
        *hasher.finalize().as_bytes()
    }

    // P2.5 top 61d7de0d7bf0: crates/oneiron/src/check_in/effect.rs:642-653
    /// The digest of deleting the cleanup-archived completed attempt `attempt`:
    /// the effect an Admin's or a Deputy's `vault.archive.attempt.delete.confirm`
    /// is judged over (2k5e; P25-SHAPE Q1 = A). The confirm's own expectation
    /// binds the exact queue bytes in the same writer. BLAKE3, key derived from
    /// `oneiron check_in attempt archive delete v1`, over the attempt's 16 id
    /// bytes.
    #[must_use]
    pub fn attempt_archive_delete_effect_digest(attempt: &[u8; 16]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in attempt archive delete v1");
        hasher.update(attempt);
        *hasher.finalize().as_bytes()
    }
}

/// A deterministic byte stream (a 64-bit LCG's top byte), so every run hashes the same
/// inputs.
struct Bytes(u64);

impl Bytes {
    fn byte(&mut self) -> u8 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 56) as u8
    }

    fn id(&mut self) -> [u8; 16] {
        std::array::from_fn(|_| self.byte())
    }

    /// `len` ASCII letters and digits.
    fn text(&mut self, len: usize) -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        (0..len)
            .map(|_| char::from(ALPHABET[usize::from(self.byte()) % ALPHABET.len()]))
            .collect()
    }
}

/// Texts of every shape: empty, short, a NUL, multi-byte, and longer than one byte of
/// length can say.
fn texts() -> Vec<String> {
    vec![
        String::new(),
        "no account numbers in outbound mail".to_owned(),
        "nul \0 inside".to_owned(),
        "日本語 — 🦀".to_owned(),
        "x".repeat(300),
    ]
}

/// Ids of every shape: all zero, all ones, and 200 generated ones.
fn ids(seed: u64) -> Vec<[u8; 16]> {
    let mut bytes = Bytes(seed);
    let mut out = vec![[0_u8; 16], [0xff_u8; 16]];
    out.extend((0..200).map(|_| bytes.id()));
    out
}

/// Each kind of change, at each scope, with each action and text.
fn policy_row_changes() -> Vec<PolicyRowChange> {
    let scopes = [
        PolicyRowScope::Vault,
        PolicyRowScope::World("world-a".to_owned()),
        PolicyRowScope::Project("project-b".to_owned()),
        PolicyRowScope::WorldProject {
            world: "world-a".to_owned(),
            project: "project-b".to_owned(),
        },
    ];
    let actions = [
        PolicyRowAction::Warn,
        PolicyRowAction::Reword,
        PolicyRowAction::Block,
        PolicyRowAction::RouteToHelp,
    ];
    let mut out = Vec::new();
    for scope in &scopes {
        for text in texts() {
            let row_ref = format!("row-{}", text.len());
            for action in actions {
                out.push(PolicyRowChange::Add {
                    row_ref: row_ref.clone(),
                    text: text.clone(),
                    action,
                    scope: scope.clone(),
                });
                out.push(PolicyRowChange::Edit {
                    row_ref: row_ref.clone(),
                    text: text.clone(),
                    action,
                    scope: scope.clone(),
                });
                out.push(PolicyRowChange::AddWithWhy {
                    row_ref: row_ref.clone(),
                    text: text.clone(),
                    action,
                    scope: scope.clone(),
                    why: format!("why {}", text.len()),
                });
                out.push(PolicyRowChange::EditWithWhy {
                    row_ref: row_ref.clone(),
                    text: text.clone(),
                    action,
                    scope: scope.clone(),
                    why: text.clone(),
                });
            }
            out.push(PolicyRowChange::Remove {
                row_ref: text.clone(),
                scope: scope.clone(),
            });
            out.push(PolicyRowChange::DraftWhy {
                row_ref: row_ref.clone(),
                scope: scope.clone(),
                why: text.clone(),
            });
        }
    }
    out
}

/// Asserts that no two inputs gave one digest, so the inputs differ where the digest reads.
fn assert_distinct(digests: &[[u8; 32]]) {
    let distinct: HashSet<&[u8; 32]> = digests.iter().collect();
    assert_eq!(distinct.len(), digests.len());
}

#[test]
fn the_check_in_purposes_derive_their_key_from_their_tag() {
    for (purpose, tag) in [
        (
            purposes::check_in::POLICY_ROW_CHANGE,
            "oneiron check_in policy row change v1",
        ),
        (
            purposes::check_in::MAIL_COMPLIANCE_SET,
            "oneiron check_in mail compliance set v1",
        ),
        (
            purposes::check_in::RECORD_DELETE,
            "oneiron check_in record delete v1",
        ),
        (
            purposes::check_in::EMBEDDING_SPACE_PROBE_DELETE,
            "oneiron check_in embedding space probe delete v1",
        ),
        (
            purposes::check_in::ATTEMPT_ARCHIVE_DELETE,
            "oneiron check_in attempt archive delete v1",
        ),
    ] {
        assert_eq!(purpose.tag(), tag);
        assert_eq!(purpose.hash(), LegacyHash::Blake3);
        assert_eq!(purpose.tag_mode(), TagMode::DeriveKeyContext);
    }
    assert_eq!(purposes::check_in::LEGACY.len(), 5);
    assert!(purposes::check_in::ALL.is_empty());
}

#[test]
fn the_policy_row_change_digest_keeps_its_bytes() {
    let changes = policy_row_changes();
    assert_eq!(changes.len(), 360);
    let mut digests = Vec::with_capacity(changes.len());
    for change in &changes {
        let base = base::policy_row_change_effect_digest(change).expect("the base digest");
        let head = policy_row_change_effect_digest(change).expect("the head digest");
        assert_eq!(head, base, "{change:?}");
        digests.push(head);
    }
    assert_distinct(&digests);
}

#[test]
fn the_mail_compliance_set_digest_keeps_its_bytes() {
    let mut bytes = Bytes(0x9e37_79b9_7f4a_7c15);
    let mut search_purposes = texts();
    search_purposes.extend(
        [1, 63, 64, 65, 255, 256, 1023, 1024, 1025, 65_537]
            .into_iter()
            .map(|len| "p".repeat(len)),
    );
    search_purposes.extend((1..=100).map(|len| bytes.text(len * 3)));
    assert_eq!(search_purposes.len(), 115);
    let mut digests = Vec::new();
    for enabled in [false, true] {
        for purpose in &search_purposes {
            let base = base::mail_compliance_set_effect_digest(enabled, purpose);
            let head = mail_compliance_set_effect_digest(enabled, purpose);
            assert_eq!(head, base, "enabled {enabled}, {} bytes", purpose.len());
            digests.push(head);
        }
    }
    assert_distinct(&digests);
}

#[test]
fn the_record_delete_digest_keeps_its_bytes() {
    let reasons = [
        DeleteReason::UserDelete,
        DeleteReason::UserHardDelete,
        DeleteReason::OwnerErase,
        DeleteReason::GdprDelete,
        DeleteReason::PolicyDelete,
        DeleteReason::ArchivedByCleanup,
    ];
    let mut digests = Vec::new();
    for id in ids(0x51_7cc1_b727_220a) {
        let record = EntityId::from_bytes_unchecked(id);
        for reason in reasons {
            let base = base::record_delete_effect_digest(&record, reason);
            let head = record_delete_effect_digest(&record, reason);
            assert_eq!(head, base, "{reason:?}");
            digests.push(head);
        }
    }
    assert_eq!(digests.len(), 202 * 6);
    assert_distinct(&digests);
}

#[test]
fn the_embedding_space_probe_delete_digest_keeps_its_bytes() {
    let mut digests = Vec::new();
    for probe in ids(0x2545_f491_4f6c_dd1d) {
        let base = base::embedding_space_probe_delete_effect_digest(&probe);
        let head = embedding_space_probe_delete_effect_digest(&probe);
        assert_eq!(head, base, "{probe:02x?}");
        digests.push(head);
    }
    assert_eq!(digests.len(), 202);
    assert_distinct(&digests);
}

#[test]
fn the_attempt_archive_delete_digest_keeps_its_bytes() {
    let mut digests = Vec::new();
    for attempt in ids(0x6a09_e667_f3bc_c908) {
        let base = base::attempt_archive_delete_effect_digest(&attempt);
        let head = attempt_archive_delete_effect_digest(&attempt);
        assert_eq!(head, base, "{attempt:02x?}");
        digests.push(head);
    }
    assert_eq!(digests.len(), 202);
    assert_distinct(&digests);
}
