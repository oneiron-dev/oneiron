//! The whole-vault export keeps out the rows whose content is about a PERSON it keeps out (FIX
//! WHOLE-VAULT-EXPORT-CARRIES-CONTENT-ABOUT-A-WITHHELD-PERSON; Engine ANSWER
//! WITHHELD-PERSON-CONTENT-RULE = A, 20 Nov).
//!
//! Public doors only; neutral fixtures; vaults in tempdirs.
//!
//! * `a_whole_vault_export_keeps_out_the_content_about_a_use_limited_person`: on a hosted vault
//!   two PERSONs, held and kept, each have a CLAIM about them, a CLAIM about a link they are an
//!   end of, a FACET scenario mask, a PSYCH_PROFILE and a PERSONA_SNAPSHOT_EXPORT. A customer
//!   hold then refuses held's privacy erase, which keeps held stored and use-limited. The export
//!   carries none of held's five rows and every one of kept's.
//! * `a_claim_about_a_link_to_a_use_limited_person_stays_out_from_either_end`: a CLAIM about a
//!   link whose source is held, and one about a link whose target is held, both stay out; a
//!   CLAIM about a link between two other PERSONs travels.
//!
//! Both run red at main ec33a9efeaa, whose export door reads only each row's own id, and green
//! at the fix.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test archive_export_withholds_content_about_a_withheld_person`.

use std::collections::BTreeSet;

use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::LegalHoldTarget;
use oneiron::federation::Sensitivity;
use oneiron::memory::{EraseOptions, EraseReason};
use oneiron::persona_snapshot::PersonaSnapshotExportRecord;
use oneiron::psych_profile::{
    PsychProfile, PsychProfileConfidence, PsychProfileSource, PsychProfileSourceWords,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::store::revision_ref::RevisionRef;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EdgeKind,
    EntityId, HostingPrivacyPosture, TimeRange, Vault, VaultConfig,
};
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

/// Places a customer hold on `record` and runs its privacy erase, which the hold refuses: the
/// record stays stored and use-limited, and a whole-vault export keeps it out.
fn use_limit(vault: &Vault, record: EntityId) {
    let hold = vault
        .place_legal_hold(
            &owner_proof(vault),
            vec![LegalHoldTarget::Record(record)],
            Some("matter-person-content".to_owned()),
        )
        .expect("FIXTURE: place the customer hold");
    assert!(hold.stands(), "FIXTURE: the customer hold stands: {hold:?}");
    let actor = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault names its embedded owner actor");
    let memory = vault.memory(actor, EdgeActorClass::Human);
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

fn put_claim(vault: &Vault, predicate: &str, subject: ClaimSubject, value: &str) -> EntityId {
    let id = EntityId::now();
    let body = ClaimBody::new(
        predicate,
        subject,
        Value::from(value),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: claim body");
    vault
        .put_claim(&id, &body, range(), AT)
        .expect("FIXTURE: put the claim");
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

/// The ids of every entity and claim a whole-vault export of `vault` carries.
fn carried_ids(vault: &Vault) -> BTreeSet<String> {
    let archive = vault
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();
    let document = vault
        .read_whole_vault_archive(&archive)
        .expect("the archive reads back");
    document
        .evidence_ledger
        .entities
        .iter()
        .chain(document.claims.iter())
        .map(|row| row.id.clone())
        .collect()
}

#[test]
fn a_whole_vault_export_keeps_out_the_content_about_a_use_limited_person() {
    let (_dir, vault) = open_hosted_vault();
    let held = put_person(&vault, b"held person");
    let kept = put_person(&vault, b"kept person");
    let third = put_person(&vault, b"third person");
    let held_content = put_content(&vault, held, third);
    let kept_content = put_content(&vault, kept, third);
    let before = carried_ids(&vault);
    for (kind, id) in held_content.rows().iter().chain(kept_content.rows().iter()) {
        assert!(
            before.contains(&id.to_hex()),
            "FIXTURE: before the hold the export carries the {kind}"
        );
    }

    use_limit(&vault, held);
    for (kind, id) in held_content.rows() {
        assert!(
            vault
                .get_entity_type(&id)
                .expect("FIXTURE: read the row's type")
                .is_some(),
            "FIXTURE: the kept erase leaves the {kind} stored"
        );
    }

    let after = carried_ids(&vault);
    assert!(
        !after.contains(&held.to_hex()),
        "FIXTURE: the export keeps the use-limited PERSON out"
    );
    for (kind, id) in held_content.rows() {
        assert!(
            !after.contains(&id.to_hex()),
            "the export keeps the {kind} of the use-limited PERSON out"
        );
    }
    for (kind, id) in kept_content.rows() {
        assert!(
            after.contains(&id.to_hex()),
            "the export still carries the {kind} of a PERSON it carries"
        );
    }
}

#[test]
fn a_claim_about_a_link_to_a_use_limited_person_stays_out_from_either_end() {
    let (_dir, vault) = open_hosted_vault();
    let held = put_person(&vault, b"held person");
    let first = put_person(&vault, b"first person");
    let second = put_person(&vault, b"second person");
    let from_held = put_link_claim(&vault, held, first);
    let to_held = put_link_claim(&vault, second, held);
    let between_others = put_link_claim(&vault, first, second);
    let before = carried_ids(&vault);
    for id in [from_held, to_held, between_others] {
        assert!(
            before.contains(&id.to_hex()),
            "FIXTURE: before the hold the export carries every link claim"
        );
    }

    use_limit(&vault, held);

    let after = carried_ids(&vault);
    assert!(
        !after.contains(&from_held.to_hex()),
        "the export keeps out a claim about a link from the use-limited PERSON"
    );
    assert!(
        !after.contains(&to_held.to_hex()),
        "the export keeps out a claim about a link to the use-limited PERSON"
    );
    assert!(
        after.contains(&between_others.to_hex()),
        "the export still carries a claim about a link between two PERSONs it carries"
    );
}
