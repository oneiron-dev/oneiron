//! [SKILL-SUPERSEDE-VERSION-REFUSAL-NAMES-NO-MEMBER]: the supersede door's
//! same-version refusal names the member skill whose bytes changed while its
//! version did not (with its old/new content hashes), so the owner who bumped
//! the pack's version knows which member must bump. The refusal keeps its
//! kind (`InvalidSkillBody`) and its sentence; only the text names the member.
//! Public doors only. Run with
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test skill_supersede_version_refusal_names_member`.

use oneiron::skill::{SkillLifecycle, SkillRecord, canonical_skill_tree_hash};
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EntityId, ErrorKind, TimeRange, Vault, VaultConfig,
};

/// The bundled member both revisions carry.
const MEMBER: &str = "fixture.pack-member";

fn open() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    (dir, vault)
}

/// A candidate member revision over `body`, with its content-hash hex.
fn candidate(version: &str, body: &[u8]) -> (SkillRecord, String) {
    let hash = canonical_skill_tree_hash([("SKILL.md", body)]).expect("hash the fixture tree");
    let hex = hash.to_hex();
    let record = SkillRecord::new(
        MEMBER,
        "A bundled skill whose bytes changed",
        version,
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("fixture"),
        )]),
    )
    .with_content_hash(hash);
    (record, hex)
}

/// Admits a candidate revision: a state flip, so no version bump is needed.
fn admit(vault: &Vault, id: &EntityId, record: &SkillRecord, at: u64) {
    let mut active = record.clone();
    active.lifecycle_status = SkillLifecycle::Active;
    vault
        .update_skill_record(id, &active, TimeRange { start: at, end: at }, at + 1)
        .expect("admit the candidate");
}

#[test]
fn same_version_supersede_refusal_names_member_and_hashes() {
    let (_dir, vault) = open();
    let old_id = EntityId::now();
    let (old_candidate, old_hex) = candidate("1", b"# member bytes\n");
    vault
        .put_skill_record(
            &old_id,
            &old_candidate,
            TimeRange { start: 10, end: 10 },
            11,
        )
        .expect("put the old revision");
    admit(&vault, &old_id, &old_candidate, 12);

    let new_id = EntityId::now();
    let (new_candidate, new_hex) = candidate("1", b"# member bytes, edited\n");
    assert_ne!(old_hex, new_hex, "the fixture must change the bytes");
    vault
        .put_skill_record(
            &new_id,
            &new_candidate,
            TimeRange { start: 14, end: 14 },
            15,
        )
        .expect("put the new revision");
    admit(&vault, &new_id, &new_candidate, 16);

    let err = vault
        .supersede_skill_record(&old_id, &new_id, TimeRange { start: 18, end: 18 }, 19)
        .expect_err("the same version must not supersede");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
    let message = err.to_string();
    assert!(
        message.contains("must carry a new version"),
        "the refusal keeps its sentence: {message}"
    );
    assert!(
        message.contains(MEMBER),
        "the refusal names the member: {message}"
    );
    assert!(
        message.contains(old_hex.as_str()),
        "the refusal names the old hash: {message}"
    );
    assert!(
        message.contains(new_hex.as_str()),
        "the refusal names the new hash: {message}"
    );
    assert_eq!(
        vault
            .get_skill_record(&old_id)
            .expect("read the old revision")
            .map(|record| record.lifecycle_status),
        Some(SkillLifecycle::Active),
        "the refused supersession leaves the old revision active"
    );
}

#[test]
fn bumped_version_supersede_still_succeeds() {
    let (_dir, vault) = open();
    let old_id = EntityId::now();
    let (old_candidate, _) = candidate("1", b"# member bytes\n");
    vault
        .put_skill_record(
            &old_id,
            &old_candidate,
            TimeRange { start: 10, end: 10 },
            11,
        )
        .expect("put the old revision");
    admit(&vault, &old_id, &old_candidate, 12);

    let new_id = EntityId::now();
    let (new_candidate, _) = candidate("2", b"# member bytes, edited\n");
    vault
        .put_skill_record(
            &new_id,
            &new_candidate,
            TimeRange { start: 14, end: 14 },
            15,
        )
        .expect("put the new revision");
    admit(&vault, &new_id, &new_candidate, 16);

    vault
        .supersede_skill_record(&old_id, &new_id, TimeRange { start: 18, end: 18 }, 19)
        .expect("a bumped version supersedes");
    assert_eq!(
        vault
            .get_skill_record(&old_id)
            .expect("read the old revision")
            .map(|record| record.lifecycle_status),
        Some(SkillLifecycle::Superseded)
    );
}
