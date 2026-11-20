//! A kept privacy erase of a PERSON keeps the content about that person from use at every read
//! door, as it keeps the PERSON row (FIX KEPT-PRIVACY-ERASE-USE-LIMITS-DERIVED-PERSON-CONTENT;
//! Engine ANSWER WITHHELD-PERSON-CONTENT-RULE, 20 Nov, option C).
//!
//! Public doors only; neutral fixtures; vaults in tempdirs.
//!
//! * `a_kept_privacy_erase_keeps_the_content_about_the_person_from_every_read`: on a hosted vault
//!   two PERSONs, held and kept, each have a CLAIM about them, a CLAIM about a link they are an
//!   end of, a FACET scenario mask, a PSYCH_PROFILE and a PERSONA_SNAPSHOT_EXPORT. A customer
//!   hold then refuses held's privacy erase, which keeps held stored and use-limited. Every one
//!   of held's five rows stays stored, and none reads through the owner's raw or typed doors;
//!   every one of kept's still reads.
//! * `a_claim_about_a_link_to_the_kept_person_reads_from_neither_end`: a CLAIM about a link whose
//!   source is held, and one about a link whose target is held, both read as absent; a CLAIM
//!   about a link between two other PERSONs still reads.
//! * `a_kept_privacy_erase_keeps_the_claims_about_the_person_out_of_recall`: the owner's lexical
//!   recall serves a CLAIM about held and one about kept before the hold, and only kept's after.
//! * `a_retained_revision_about_the_kept_person_reads_as_absent_at_its_pin`: a CLAIM about held is
//!   pinned, then re-put under its id about another PERSON. After the hold the pinned revision
//!   reads as absent, while the current row, about the other PERSON, still reads.
//!
//! All four run red at main 57bf91c64fc, whose read doors ask each row's own use limit only,
//! and green at the fix.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test kept_privacy_erase_use_limits_person_content`.

use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::LegalHoldTarget;
use oneiron::federation::Sensitivity;
use oneiron::memory::{Effort, EraseOptions, EraseReason, RecallScope};
use oneiron::persona_snapshot::PersonaSnapshotExportRecord;
use oneiron::psych_profile::{
    PsychProfile, PsychProfileConfidence, PsychProfileSource, PsychProfileSourceWords,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::store::revision_ref::RevisionRef;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EdgeKind,
    EntityId, HostingPrivacyPosture, Memory, TimeRange, Vault, VaultConfig,
};
use oneiron_store::vault::entity_revision::types::ReadMode;
use rmpv::Value;
use serde_json::json;

const AT: u64 = 100;

fn range() -> TimeRange {
    TimeRange { start: AT, end: AT }
}

/// A hosted vault with a device keystore, so a held privacy erase keeps its record
/// use-limited.
fn open_hosted_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir for the hosted vault");
    let mut config = VaultConfig::default();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
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
            Some("matter-person-content".to_owned()),
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

fn claim_body(predicate: &str, subject: ClaimSubject, value: &str) -> ClaimBody {
    ClaimBody::new(
        predicate,
        subject,
        Value::from(value),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: claim body")
}

fn put_claim(vault: &Vault, predicate: &str, subject: ClaimSubject, value: &str) -> EntityId {
    let id = EntityId::now();
    vault
        .put_claim(&id, &claim_body(predicate, subject, value), range(), AT)
        .expect("FIXTURE: put the claim");
    id
}

/// A CLAIM whose value lexical recall finds: the raw door posts no text, so the fixture indexes
/// the value as a typed claim writer does.
fn put_recallable_claim(vault: &Vault, subject: EntityId, value: &str) -> EntityId {
    let id = put_claim(vault, "profile.note", ClaimSubject::Entity(subject), value);
    vault
        .batch()
        .text(&id, &[("body", value)])
        .commit()
        .expect("FIXTURE: index the claim's value");
    id
}

/// A CLAIM about the `mentions` link from `source` to `target`.
fn put_link_claim(vault: &Vault, source: EntityId, target: EntityId) -> EntityId {
    vault
        .put_edge(&source, EdgeKind::Mentions, &target, 1.0)
        .expect("FIXTURE: put the link");
    put_claim(
        vault,
        "relationship.context",
        ClaimSubject::Edge {
            source,
            kind: EdgeKind::Mentions,
            target,
        },
        "met at the climbing gym",
    )
}

fn put_scenario_mask(vault: &Vault, person: EntityId) -> EntityId {
    let facet = EntityId::now();
    vault
        .put_persona_scenario(
            &person,
            &facet,
            &json!({"tone": "formal at work"}),
            Sensitivity::Private,
            AT,
        )
        .expect("FIXTURE: put the scenario mask");
    facet
}

fn put_profile(vault: &Vault, person: EntityId) -> EntityId {
    let source = EntityId::now();
    let profile = PsychProfile::new(
        person,
        "compact",
        "Prefers quiet mornings.",
        "Narrative about the person.",
        vec![source],
        PsychProfileConfidence::new(0.9, 0.8, 0.7).expect("FIXTURE: confidence"),
    )
    .expect("FIXTURE: profile")
    .with_sources(vec![PsychProfileSource {
        revision_ref: source,
        document_ref: source,
        world_ref: None,
        document_revision: RevisionRef(*source.as_bytes()),
        words: PsychProfileSourceWords::Record {
            content: [0x5C; 32],
        },
    }])
    .expect("FIXTURE: profile sources");
    let id = EntityId::now();
    vault
        .put_psych_profile(&id, &profile)
        .expect("FIXTURE: put the profile");
    id
}

fn put_persona_card(vault: &Vault, person: EntityId) -> EntityId {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault names its embedded owner actor");
    let record = PersonaSnapshotExportRecord {
        subject_ref: person,
        audience_ref: None,
        identity_line: "A climber who likes matcha.".to_owned(),
        compiled_at_secs: AT,
        stale_after_secs: 86_400,
        compiled_fingerprint: "a".repeat(64),
        takes_included: false,
        granted_by: owner.to_hex(),
        granted_at_secs: AT,
        exported_at_secs: AT,
        included_row_ids: Vec::new(),
        struck_row_ids: Vec::new(),
        artifact_fingerprint: "b".repeat(64),
        omitted_refs: Vec::new(),
    };
    let id = EntityId::now();
    vault
        .put_persona_snapshot_export(&id, &record)
        .expect("FIXTURE: put the persona card");
    id
}

/// The rows of one PERSON's content, by kind.
struct PersonContent {
    claim: EntityId,
    link_claim: EntityId,
    mask: EntityId,
    profile: EntityId,
    card: EntityId,
}

impl PersonContent {
    fn rows(&self) -> [(&'static str, EntityId); 5] {
        [
            ("CLAIM about the person", self.claim),
            ("CLAIM about a link from the person", self.link_claim),
            ("FACET scenario mask", self.mask),
            ("PSYCH_PROFILE", self.profile),
            ("PERSONA_SNAPSHOT_EXPORT", self.card),
        ]
    }
}

fn put_content(vault: &Vault, person: EntityId, other: EntityId) -> PersonContent {
    PersonContent {
        claim: put_claim(
            vault,
            "preference.food",
            ClaimSubject::Entity(person),
            "matcha",
        ),
        link_claim: put_link_claim(vault, person, other),
        mask: put_scenario_mask(vault, person),
        profile: put_profile(vault, person),
        card: put_persona_card(vault, person),
    }
}

/// What the owner's raw and typed doors read of `content`, one answer per door.
fn reads(vault: &Vault, content: &PersonContent) -> Vec<(String, bool)> {
    let mut reads = Vec::new();
    for (kind, id) in content.rows() {
        reads.push((
            format!("Vault::get of the {kind}"),
            vault.get(&id).expect("read the row").is_some(),
        ));
        reads.push((
            format!("Vault::get_raw of the {kind}"),
            vault.get_raw(&id).expect("read the raw row").is_some(),
        ));
    }
    for (kind, id) in [
        ("CLAIM about the person", content.claim),
        ("CLAIM about a link from the person", content.link_claim),
    ] {
        reads.push((
            format!("Vault::get_claim of the {kind}"),
            vault.get_claim(&id).expect("read the claim").is_some(),
        ));
    }
    reads.push((
        "Vault::get_psych_profile".to_owned(),
        vault
            .get_psych_profile(&content.profile)
            .expect("read the profile")
            .is_some(),
    ));
    reads.push((
        "Vault::get_live_psych_profile".to_owned(),
        vault
            .get_live_psych_profile(&content.profile)
            .expect("read the live profile")
            .is_some(),
    ));
    reads.push((
        "Vault::get_persona_snapshot_export".to_owned(),
        vault
            .get_persona_snapshot_export(&content.card)
            .expect("read the persona card")
            .is_some(),
    ));
    reads
}

#[test]
fn a_kept_privacy_erase_keeps_the_content_about_the_person_from_every_read() {
    let (_dir, vault) = open_hosted_vault();
    let held = put_person(&vault, b"held person");
    let kept = put_person(&vault, b"kept person");
    let third = put_person(&vault, b"third person");
    let held_content = put_content(&vault, held, third);
    let kept_content = put_content(&vault, kept, third);
    for (door, read) in reads(&vault, &held_content)
        .into_iter()
        .chain(reads(&vault, &kept_content))
    {
        assert!(read, "FIXTURE: before the hold {door} reads");
    }

    keep_use_limited(&vault, held);
    for (kind, id) in held_content.rows() {
        assert!(
            vault
                .get_entity_type(&id)
                .expect("FIXTURE: read the row's type")
                .is_some(),
            "FIXTURE: the kept erase leaves the {kind} stored"
        );
        assert!(
            vault
                .legal_hold_use_limit(&id)
                .expect("FIXTURE: read the row's own use limit")
                .is_none(),
            "FIXTURE: the {kind} carries no use limit of its own"
        );
    }
    assert!(
        vault.get(&held).expect("read the PERSON").is_none(),
        "FIXTURE: the kept PERSON itself reads as absent"
    );

    for (door, read) in reads(&vault, &held_content) {
        assert!(
            !read,
            "{door} keeps the content about the use-limited PERSON from use"
        );
    }
    for (door, read) in reads(&vault, &kept_content) {
        assert!(read, "{door} still reads the content about another PERSON");
    }
}

#[test]
fn a_claim_about_a_link_to_the_kept_person_reads_from_neither_end() {
    let (_dir, vault) = open_hosted_vault();
    let held = put_person(&vault, b"held person");
    let first = put_person(&vault, b"first person");
    let second = put_person(&vault, b"second person");
    let from_held = put_link_claim(&vault, held, first);
    let to_held = put_link_claim(&vault, second, held);
    let between_others = put_link_claim(&vault, first, second);
    for id in [from_held, to_held, between_others] {
        assert!(
            vault.get_claim(&id).expect("read the claim").is_some(),
            "FIXTURE: before the hold every link claim reads"
        );
    }

    keep_use_limited(&vault, held);

    assert!(
        vault
            .get_claim(&from_held)
            .expect("read the claim")
            .is_none(),
        "a claim about a link from the use-limited PERSON reads as absent"
    );
    assert!(
        vault.get_claim(&to_held).expect("read the claim").is_none(),
        "a claim about a link to the use-limited PERSON reads as absent"
    );
    assert!(
        vault
            .get_claim(&between_others)
            .expect("read the claim")
            .is_some(),
        "a claim about a link between two other PERSONs still reads"
    );
}

/// One analyzer token each (lowercase alnum, no separators), so lexical recall finds exactly the
/// claim whose value carries it.
const HELD_MARKER: &str = "keptlimitheld7q2z";
const KEPT_MARKER: &str = "keptlimitkept7q2z";

/// Whether the owner's lexical recall of `marker` serves `claim`.
fn recalled(memory: &Memory<'_>, marker: &str, claim: &EntityId) -> bool {
    let hex = claim.to_hex();
    memory
        .recall(
            marker,
            Effort::Light,
            &RecallScope::default(),
            50,
            None,
            None,
        )
        .expect("the owner's recall")
        .items
        .iter()
        .any(|item| {
            item.record
                .as_ref()
                .is_some_and(|record| record.id == hex && record.kind == "CLAIM")
        })
}

#[test]
fn a_kept_privacy_erase_keeps_the_claims_about_the_person_out_of_recall() {
    let (_dir, vault) = open_hosted_vault();
    let held = put_person(&vault, b"held person");
    let kept = put_person(&vault, b"kept person");
    let held_claim = put_recallable_claim(&vault, held, HELD_MARKER);
    let kept_claim = put_recallable_claim(&vault, kept, KEPT_MARKER);
    let memory = owner_memory(&vault);
    assert!(
        recalled(&memory, HELD_MARKER, &held_claim),
        "FIXTURE: before the hold recall serves the claim about held"
    );
    assert!(
        recalled(&memory, KEPT_MARKER, &kept_claim),
        "FIXTURE: before the hold recall serves the claim about kept"
    );

    keep_use_limited(&vault, held);

    assert!(
        !recalled(&memory, HELD_MARKER, &held_claim),
        "recall keeps the claim about the use-limited PERSON out"
    );
    assert!(
        recalled(&memory, KEPT_MARKER, &kept_claim),
        "recall still serves the claim about another PERSON"
    );
}

#[test]
fn a_retained_revision_about_the_kept_person_reads_as_absent_at_its_pin() {
    let (_dir, vault) = open_hosted_vault();
    let held = put_person(&vault, b"held person");
    let other = put_person(&vault, b"other person");
    let claim = put_claim(
        &vault,
        "preference.food",
        ClaimSubject::Entity(held),
        "matcha",
    );
    let pin = vault
        .pin_entity_revision(&claim)
        .expect("FIXTURE: pin the revision about held");
    vault
        .put_claim(
            &claim,
            &claim_body("preference.food", ClaimSubject::Entity(other), "sencha"),
            range(),
            AT,
        )
        .expect("FIXTURE: re-put the claim about the other PERSON");
    let current = vault
        .get_claim(&claim)
        .expect("FIXTURE: read the claim")
        .expect("FIXTURE: the claim reads");
    assert!(
        matches!(current.subject, ClaimSubject::Entity(subject) if subject == other),
        "FIXTURE: the current row is about the other PERSON"
    );
    assert!(
        vault
            .get_raw_with_mode(&claim, ReadMode::Pinned(pin))
            .expect("FIXTURE: read the pinned revision")
            .is_some(),
        "FIXTURE: before the hold the pinned revision reads"
    );

    keep_use_limited(&vault, held);

    assert!(
        vault
            .get_raw_with_mode(&claim, ReadMode::Pinned(pin))
            .expect("read the pinned revision")
            .is_none(),
        "the revision about the use-limited PERSON reads as absent at its pin"
    );
    assert!(
        vault
            .get_raw_with_mode(&claim, ReadMode::Live)
            .expect("read the current row")
            .is_some(),
        "the current row, about another PERSON, still reads"
    );
}
