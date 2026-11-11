//! FIX LEARNING-CELL-POSITIONAL-DECODE: a learning claim value is written
//! with named fields, so a cell with skipped qualifiers reads back; a value
//! written positionally before still decodes to its cell, and compares equal
//! to the named value the projector writes for it.
#![cfg(oneiron_test_support)]

use oneiron::learning::{
    Anchor, ESTIMATOR_VERSION, Estimate, EstimateForm, EstimateLabels, EstimateValue, LearningCell,
    LearningEvidence, LearningPredicate, Observation, Prior, TypeRef, Window,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::skill_reliability::SKILL_OUTCOME_AXIS;
use oneiron::task_type::{SeedTaskType, TaskTypeRef};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::learning_claim_value as door;
use oneiron::{EntityId, Vault, VaultConfig};

const NOW: u64 = 10;

fn vault_with_person(dir: &std::path::Path) -> (Vault, EntityId) {
    let vault = Vault::open(dir, VaultConfig::default()).expect("open vault");
    vault.ensure_embedded_owner_actor().expect("embedded owner");
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
            b"person",
        )
        .expect("put the person");
    (vault, person)
}

/// A reliability cell with no consent scope: the qualifier after the axis is
/// skipped, and so is the project of a vault cell.
fn reliability_cell(vault: &Vault, person: EntityId, project: Option<EntityId>) -> LearningCell {
    let tree = oneiron::task_type::type_tree(vault, None).expect("vault type tree");
    let task_type = TaskTypeRef::seed(SeedTaskType::Build, tree.version());
    LearningCell::new(LearningPredicate::Reliability, person)
        .executor(person.to_hex())
        .type_ref(TypeRef::from(&task_type))
        .axis(SKILL_OUTCOME_AXIS)
        .project(project)
}

/// Records three runs and returns the estimate the last fold projected.
fn record_runs(vault: &Vault, cell: &LearningCell) -> Estimate {
    let mut projected = None;
    for success in [true, true, false] {
        let evidence = LearningEvidence::anchored(
            EntityId::now().to_hex(),
            NOW,
            Anchor::HeldOut,
            Observation::Success(success),
        );
        projected = oneiron::learning::record_evidence(vault, cell, &evidence, NOW).unwrap_or_else(
            |error| panic!("project {:?}: record run evidence: {error:?}", cell.project),
        );
    }
    projected.expect("the cell has own runs")
}

#[test]
fn vault_and_project_cells_without_consent_scope_read_back_what_was_recorded() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let (vault, person) = vault_with_person(dir.path());
    for project in [None, Some(EntityId::now())] {
        let cell = reliability_cell(&vault, person, project);
        assert_eq!(cell.consent_scope, None);
        let recorded = record_runs(&vault, &cell);
        let read = oneiron::learning::learning_estimate(&vault, &cell)
            .expect("read the cell")
            .unwrap_or_else(|| panic!("project {project:?}: the cell has a head"));
        assert_eq!(
            read, recorded,
            "project {project:?}: the head reads back the estimate the fold recorded",
        );
    }
}

#[test]
fn a_positional_claim_value_written_before_named_fields_decodes_to_its_cell() {
    let subject = EntityId::now();
    let estimate = Estimate {
        value: EstimateValue::Beta {
            alpha: 4.0,
            beta: 2.0,
        },
        runs: 3.0,
        prior: Prior::shipped(EstimateForm::Beta),
        of: "success".to_owned(),
        labels: EstimateLabels::default(),
        window: Window {
            half_life: 2_592_000,
        },
        ver: ESTIMATOR_VERSION,
    };
    // Every qualifier set, so no field is skipped: the one positional shape
    // that read back before named fields.
    let every_qualifier = LearningCell::new(LearningPredicate::Setting, subject)
        .executor("model@1")
        .type_ref(TypeRef::root(1))
        .axis("quality")
        .consent_scope("owner")
        .setting_key("credit_decay")
        .project(Some(EntityId::now()));
    // A vault cell with no consent scope: the shape written before cells had
    // a project, which skips the trailing qualifiers and has no project field.
    let vault_cell = LearningCell::new(LearningPredicate::Reliability, subject)
        .executor("model@1")
        .type_ref(TypeRef::root(1))
        .axis("quality");
    for (shape, cell) in [
        ("every qualifier set", every_qualifier),
        ("vault cell, no consent scope", vault_cell),
    ] {
        let bytes =
            door::positional_claim_bytes(&cell, &estimate).expect("positional claim value bytes");
        let (decoded_cell, decoded_estimate) = door::decode_claim_bytes(&bytes)
            .unwrap_or_else(|error| panic!("{shape}: the positional value decodes: {error:?}"));
        assert_eq!(decoded_cell, cell, "{shape}: the same cell");
        assert_eq!(decoded_estimate, estimate, "{shape}: the same estimate");
    }
}

#[test]
fn a_positional_head_compares_equal_to_the_named_projection_of_the_same_claim() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let (vault, person) = vault_with_person(dir.path());
    let cell = reliability_cell(&vault, person, None);
    record_runs(&vault, &cell);
    let twin = door::respell_head_positional(&vault, &cell, NOW)
        .expect("replace the head with its positional twin");
    assert_eq!(
        door::active_head_ids(&vault, &cell).expect("active heads"),
        vec![twin],
    );
    oneiron::learning::reproject_all_cells(&vault, NOW).expect("reproject every cell");
    assert_eq!(
        door::active_head_ids(&vault, &cell).expect("active heads"),
        vec![twin],
        "a reprojection that moves nothing keeps the positional head: it decodes to the claim \
         the projector would write",
    );
}
