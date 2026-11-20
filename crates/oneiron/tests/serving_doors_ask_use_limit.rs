//! A row a kept privacy erase holds for storage only leaves by no serving door that asked no use
//! limit (FIX USE-LIMIT-NOT-ASKED-BY-SERVING-DOORS).
//!
//! Public doors only; neutral fixtures; vaults in tempdirs.
//!
//! * `bare_text_search_keeps_a_use_limited_row_out`: on a hosted vault two CLAIMs carry indexed
//!   text. A customer hold refuses the privacy erase of one, which keeps it stored and
//!   use-limited. The bare text search, under the default rank profile and under a caller's
//!   BM25+ profile, then serves the other CLAIM and never the kept one.
//! * `bare_vector_search_keeps_a_use_limited_row_out`: the same, for two CLAIMs with vectors
//!   and the bare vector search.
//! * `a_prebuilt_persona_snapshot_export_of_a_kept_subject_refuses`: a persona snapshot compiled
//!   before its PERSON is kept carries the person's words; its export after the keep refuses as
//!   a fresh compile of the kept PERSON does, and records nothing. Another PERSON's prebuilt
//!   compile still exports.
//! * `a_prebuilt_persona_snapshot_export_citing_a_kept_claim_refuses`: a compile whose identity
//!   row cites a CLAIM that is then kept refuses to export.
//!
//! All four run red at main f75de13fe4c, whose bare hit lists check deletion and staleness only
//! and whose export renders a prebuilt compile without asking any row's use limit, and green at
//! the fix.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test serving_doors_ask_use_limit`.

use oneiron::config::Bm25RankProfile;
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::LegalHoldTarget;
use oneiron::memory::{EraseOptions, EraseReason};
use oneiron::persona_snapshot::{
    PERSONA_SNAPSHOT_NAME_PREDICATE, PersonaSnapshotCompile, PersonaSnapshotCompileOptions,
    PersonaSnapshotExportConsent, PersonaSnapshotStrikeList,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT};
use oneiron::store::GateDecisionId;
use oneiron::{
    Bm25Formula, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject,
    EdgeActorClass, EntityId, Error, HostingPrivacyPosture, Memory, TimeRange, Vault, VaultConfig,
};
use rmpv::Value;

const AT: u64 = 100;
const DIMENSIONS: usize = 4;
const HELD_MARKER: &str = "quillwort";
const KEPT_MARKER: &str = "bladderwrack";

fn range() -> TimeRange {
    TimeRange { start: AT, end: AT }
}

/// A hosted vault with a device keystore, so a held privacy erase keeps its record
/// use-limited.
fn open_hosted_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir for the hosted vault");
    let mut config = VaultConfig::default();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    config.dimensions = DIMENSIONS;
    let vault = Vault::open_owned(dir.path(), config).expect("open the hosted vault");
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    (dir, vault)
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault names its embedded owner actor");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: owner proof")
}

fn owner_memory(vault: &Vault) -> Memory<'_> {
    let actor = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault names its embedded owner actor");
    vault.memory(actor, EdgeActorClass::Human)
}

/// Places a customer hold on `record` and runs its privacy erase, which the hold refuses: the
/// record stays stored and use-limited.
fn keep_use_limited(vault: &Vault, record: EntityId) {
    let hold = vault
        .place_legal_hold(
            &owner_proof(vault),
            vec![LegalHoldTarget::Record(record)],
            Some("matter-serving-doors".to_owned()),
        )
        .expect("FIXTURE: place the customer hold");
    assert!(hold.stands(), "FIXTURE: the customer hold stands: {hold:?}");
    let memory = owner_memory(vault);
    let preview = memory
        .preview_entity_delete(&record)
        .expect("FIXTURE: preview the privacy erase");
    let outcome = memory
        .confirm_entity_erase(
            &preview,
            EraseOptions {
                reason: EraseReason::GdprDelete,
                also_same_bytes: false,
                veto_starter: None,
            },
        )
        .expect("FIXTURE: the privacy erase runs");
    assert_eq!(
        outcome.first.reason.as_str(),
        "privacy_erase_kept",
        "FIXTURE: the held privacy erase is kept: {outcome:?}"
    );
    assert!(
        vault
            .legal_hold_use_limit(&record)
            .expect("FIXTURE: read the use limit")
            .is_some(),
        "FIXTURE: the kept erase use-limits the record"
    );
}

fn put_person(vault: &Vault, name: &[u8]) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, range(), AT, name)
        .expect("FIXTURE: put the PERSON");
    id
}

fn put_claim(vault: &Vault, predicate: &str, subject: EntityId, value: &str) -> EntityId {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        Value::from(value),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: claim body");
    body.salience = Some(0.9);
    body.source = Some(oneiron::claim::ClaimSource::UserStated);
    vault
        .put_claim(&id, &body, range(), AT)
        .expect("FIXTURE: put the CLAIM");
    id
}

/// A CLAIM about `subject` whose value the text index holds.
fn put_indexed_claim(vault: &Vault, subject: EntityId, value: &str) -> EntityId {
    let id = put_claim(vault, "profile.note", subject, value);
    vault
        .batch()
        .text(&id, &[("body", value)])
        .commit()
        .expect("FIXTURE: index the claim's value");
    id
}

fn text_hits(vault: &Vault, query: &str, profile: &Bm25RankProfile) -> Vec<EntityId> {
    vault
        .search_text_with_profile(query, 10, profile)
        .expect("the bare text search answers")
        .into_iter()
        .map(|hit| hit.id)
        .collect()
}

fn plus_profile() -> Bm25RankProfile {
    Bm25RankProfile::default().with_formula(Bm25Formula::Plus { delta: 1.0 })
}

#[test]
fn bare_text_search_keeps_a_use_limited_row_out() {
    let (_dir, vault) = open_hosted_vault();
    let person = put_person(&vault, b"a person");
    let held = put_indexed_claim(&vault, person, HELD_MARKER);
    let kept = put_indexed_claim(&vault, person, KEPT_MARKER);
    for profile in [Bm25RankProfile::default(), plus_profile()] {
        assert!(
            text_hits(&vault, HELD_MARKER, &profile).contains(&held),
            "FIXTURE: before the hold the text search serves the held CLAIM ({profile:?})"
        );
    }

    keep_use_limited(&vault, held);

    for profile in [Bm25RankProfile::default(), plus_profile()] {
        assert!(
            !text_hits(&vault, HELD_MARKER, &profile).contains(&held),
            "the bare text search keeps the use-limited CLAIM out ({profile:?})"
        );
        assert!(
            text_hits(&vault, KEPT_MARKER, &profile).contains(&kept),
            "the bare text search still serves the other CLAIM ({profile:?})"
        );
    }
    assert!(
        !vault
            .search_text(HELD_MARKER, 10)
            .expect("the bare text search answers")
            .iter()
            .any(|hit| hit.id == held),
        "search_text keeps the use-limited CLAIM out"
    );
}

#[test]
fn bare_vector_search_keeps_a_use_limited_row_out() {
    let (_dir, vault) = open_hosted_vault();
    let person = put_person(&vault, b"a person");
    let held = put_claim(&vault, "profile.note", person, "first note");
    let kept = put_claim(&vault, "profile.note", person, "second note");
    vault
        .batch()
        .vector(&held, &[1.0, 0.0, 0.0, 0.0])
        .vector(&kept, &[0.0, 1.0, 0.0, 0.0])
        .commit()
        .expect("FIXTURE: the claim vectors");
    vault
        .set_indexed_idle_delay_ms(0)
        .expect("FIXTURE: idle publish delay");
    vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("FIXTURE: idle publish of the staged vectors");
    let query = [0.8_f32, 0.6, 0.0, 0.0];
    let hits = |vault: &Vault| -> Vec<EntityId> {
        vault
            .search_vector(&query, 10)
            .expect("the bare vector search answers")
            .into_iter()
            .map(|hit| hit.id)
            .collect()
    };
    let before = hits(&vault);
    assert!(
        before.contains(&held) && before.contains(&kept),
        "FIXTURE: before the hold the vector search serves both CLAIMs: {before:?}"
    );

    keep_use_limited(&vault, held);

    let after = hits(&vault);
    assert!(
        !after.contains(&held),
        "the bare vector search keeps the use-limited CLAIM out: {after:?}"
    );
    assert!(
        after.contains(&kept),
        "the bare vector search still serves the other CLAIM: {after:?}"
    );
}

/// A PERSON with a name CLAIM, compiled for the owner's preview.
fn compiled_person(vault: &Vault, name: &str) -> (EntityId, EntityId, PersonaSnapshotCompile) {
    let person = put_person(vault, b"a person");
    let name_claim = put_claim(vault, PERSONA_SNAPSHOT_NAME_PREDICATE, person, name);
    let compile = vault
        .compile_persona_snapshot(&person, &PersonaSnapshotCompileOptions::default())
        .expect("FIXTURE: compile the persona snapshot");
    let cited = format!("claim:{}", name_claim.to_hex());
    assert!(
        compile.identity_line.contains(name),
        "FIXTURE: the compile carries the person's name: {:?}",
        compile.identity_line
    );
    assert!(
        compile
            .rows
            .iter()
            .any(|row| row.provenance_refs.contains(&cited)),
        "FIXTURE: a compile row cites the name CLAIM: {:?}",
        compile.rows
    );
    (person, name_claim, compile)
}

fn consent(compile: &PersonaSnapshotCompile) -> PersonaSnapshotExportConsent {
    PersonaSnapshotExportConsent {
        granted_by: "owner".to_owned(),
        compile_stamp: compile.stamp.identity(),
        granted_at_secs: AT,
    }
}

fn export_count(vault: &Vault) -> usize {
    vault
        .entities_by_type(ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT)
        .expect("read the export records")
        .len()
}

#[test]
fn a_prebuilt_persona_snapshot_export_of_a_kept_subject_refuses() {
    let (_dir, vault) = open_hosted_vault();
    let (held, _, held_compile) = compiled_person(&vault, "Wren Halloway");
    let (_, _, other_compile) = compiled_person(&vault, "Ines Marlow");

    keep_use_limited(&vault, held);
    assert!(
        matches!(
            vault.compile_persona_snapshot(&held, &PersonaSnapshotCompileOptions::default()),
            Err(Error::EntityNotFound)
        ),
        "FIXTURE: a fresh compile of the kept PERSON refuses"
    );
    let before = export_count(&vault);

    let refused = vault.export_persona_snapshot(
        &held_compile,
        &PersonaSnapshotStrikeList::default(),
        &consent(&held_compile),
    );
    assert!(
        matches!(refused, Err(Error::EntityNotFound)),
        "the export of a compile made before the keep refuses: {refused:?}"
    );
    assert_eq!(
        export_count(&vault),
        before,
        "the refused export records nothing"
    );
    let exported = vault
        .export_persona_snapshot(
            &other_compile,
            &PersonaSnapshotStrikeList::default(),
            &consent(&other_compile),
        )
        .expect("another PERSON's prebuilt compile still exports");
    assert_eq!(
        exported.subject_ref, other_compile.subject_ref,
        "the other export is its own person's"
    );
    assert_eq!(
        export_count(&vault),
        before + 1,
        "the other export records its export"
    );
}

#[test]
fn a_prebuilt_persona_snapshot_export_citing_a_kept_claim_refuses() {
    let (_dir, vault) = open_hosted_vault();
    let (_, name_claim, compile) = compiled_person(&vault, "Wren Halloway");

    keep_use_limited(&vault, name_claim);

    let refused = vault.export_persona_snapshot(
        &compile,
        &PersonaSnapshotStrikeList::default(),
        &consent(&compile),
    );
    assert!(
        matches!(refused, Err(Error::EntityNotFound)),
        "the export of a compile citing a kept CLAIM refuses: {refused:?}"
    );
}
