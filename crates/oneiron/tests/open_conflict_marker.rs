//! Native's open-conflict marker over a real vault.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test open_conflict_marker`.
//! Two bound attempts park the one judge set native assembly forms: a
//! candidate against an unequal stored head, and two sibling candidates.
//! Each marker is then read back as the Dreamer reads its open conflicts.
#![cfg(oneiron_test_support)]

#[path = "extraction_verdict/support.rs"]
mod support;

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::dreamer_consolidation::selection::SelectionConfig;
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::open_conflict_marker::park_native_open_conflict;
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};
use std::sync::Arc;
use support::{
    ExtractionVerdictTestResult, QUEUE_NOW, bind_extraction, extraction_attempt_hex,
    extraction_candidate, open_extraction_verdict_vault, page_turns_with_versions,
    read_bound_extraction_page,
};

/// The predicate both fixtures contest.
const FOOD: &str = "preference.food";

/// Opens the extraction fixture vault with the Dreamer's Steward grant standing
/// and a selection that holds no candidate back, so native assembly judges at once.
fn open_vault(dir: &tempfile::TempDir) -> ExtractionVerdictTestResult<Arc<Vault>> {
    let vault = Arc::new(open_extraction_verdict_vault(dir)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    vault.set_consolidation_selection(&SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 1,
        ..vault.consolidation_selection()?
    })?;
    Ok(vault)
}

/// Lands one user-stated food preference about `subject` and returns its id.
fn land_head(
    vault: &Vault,
    subject: EntityId,
    value: &str,
) -> ExtractionVerdictTestResult<EntityId> {
    let head = EntityId::now();
    let mut body = ClaimBody::new(
        FOOD,
        ClaimSubject::Entity(subject),
        RmpValue::from(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    body.scope_facet = vault.default_facet()?;
    let now = vault.now_recorded_at();
    vault.put_claim(
        &head,
        &body,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    Ok(head)
}

/// The clock both doors read at: one second past the vault's recorded clock, in milliseconds.
fn pass_clock_ms(vault: &Vault) -> u64 {
    vault
        .now_recorded_at()
        .saturating_add(1)
        .saturating_mul(1_000)
}

/// The ids a marker value holds at `key` as lowercase hex: one binary id, or an array of them.
fn hex_ids_at(value: &RmpValue, key: &str) -> Vec<String> {
    let RmpValue::Map(rows) = value else {
        return Vec::new();
    };
    let Some((_, found)) = rows.iter().find(|(name, _)| name.as_str() == Some(key)) else {
        return Vec::new();
    };
    let items = match found {
        RmpValue::Array(items) => items.as_slice(),
        other => std::slice::from_ref(other),
    };
    items
        .iter()
        .filter_map(|item| match item {
            RmpValue::Binary(bytes) => {
                Some(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
            }
            _ => None,
        })
        .collect()
}

/// The door's member claims as hex, in set order.
fn parked_members(parked: &Value) -> ExtractionVerdictTestResult<Vec<String>> {
    let members = parked["members"]
        .as_array()
        .ok_or("the door names its members")?;
    let mut ids = Vec::with_capacity(members.len());
    for member in members {
        ids.push(member.as_str().ok_or("a member is a hex id")?.to_owned());
    }
    Ok(ids)
}

/// A candidate that disputes a stored head is parked as one marker: it names the head
/// as its prior and stored member, and retains the candidate whole as its alternative.
#[test]
fn native_parks_a_candidate_against_its_unequal_head() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(&dir)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let head = land_head(&vault, subject, "green tea")?;
    let witnessed = witness_extraction_turns(&vault, &["owen chooses black coffee"])?;
    let (attempt_id, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let attempt = extraction_attempt_hex(attempt_id);
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &attempt)?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 1, "the page serves the one witnessed turn");
    let operands = vec![extraction_candidate(
        &subject.to_hex(),
        FOOD,
        json!("black coffee"),
        &turns[0].0,
        turns[0].1.clone(),
    )];

    let parked = park_native_open_conflict(&vault, &attempt, pass_clock_ms(&vault), &operands)?;
    assert_eq!(parked["prior_heads"], json!([head.to_hex()]));
    assert_eq!(parked["prior_head"], json!(head.to_hex()));
    let members = parked_members(&parked)?;
    assert_eq!(members.len(), 1, "one candidate disputes the head");

    let open = vault
        .memory(dreamer(&vault)?, EdgeActorClass::System)
        .open_conflicts(None, Some(subject), usize::MAX)?;
    let [conflict] = open.as_slice() else {
        return Err(format!("the Dreamer reads {} open conflicts, not one", open.len()).into());
    };
    assert_eq!(json!(conflict.marker.to_hex()), parked["marker"]);
    assert_eq!(conflict.subject, subject);
    assert_eq!(
        conflict.members,
        vec![head],
        "the head is the one stored member"
    );
    assert_eq!(conflict.predicates, vec![FOOD.to_owned()]);
    assert!(!conflict.reverted, "no settlement was reverted");
    let [alternative] = conflict.alternatives.as_slice() else {
        return Err("the marker retains its one dropped candidate".into());
    };
    assert_eq!(alternative.id.to_hex(), members[0]);
    assert_eq!(alternative.predicate, FOOD);
    assert_eq!(alternative.attempt.as_bytes(), attempt_id.as_bytes());

    assert_eq!(conflict.body.predicate, "core.conflict.open");
    assert_eq!(conflict.body.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(
        hex_ids_at(&conflict.body.value, "prior_head"),
        vec![head.to_hex()]
    );
    assert_eq!(
        hex_ids_at(&conflict.body.value, "prior_heads"),
        vec![head.to_hex()]
    );
    assert_eq!(hex_ids_at(&conflict.body.value, "candidates"), members);
    Ok(())
}

/// Two sibling candidates with unequal values are parked as one marker with no prior
/// head: no member is a stored claim, and both candidates are retained on it.
#[test]
fn native_parks_two_sibling_candidates_with_no_head() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(&dir)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(
        &vault,
        &["owen chooses green tea", "owen chooses black coffee"],
    )?;
    let (attempt_id, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let attempt = extraction_attempt_hex(attempt_id);
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &attempt)?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 2, "the page serves both witnessed turns");
    let operands = vec![
        extraction_candidate(
            &subject.to_hex(),
            FOOD,
            json!("green tea"),
            &turns[0].0,
            turns[0].1.clone(),
        ),
        extraction_candidate(
            &subject.to_hex(),
            FOOD,
            json!("black coffee"),
            &turns[1].0,
            turns[1].1.clone(),
        ),
    ];

    let parked = park_native_open_conflict(&vault, &attempt, pass_clock_ms(&vault), &operands)?;
    assert_eq!(parked["prior_heads"], json!([]));
    assert_eq!(parked["prior_head"], Value::Null);
    let members = parked_members(&parked)?;
    assert_eq!(members.len(), 2, "both candidates are in the one set");

    let open = vault
        .memory(dreamer(&vault)?, EdgeActorClass::System)
        .open_conflicts(None, Some(subject), usize::MAX)?;
    let [conflict] = open.as_slice() else {
        return Err(format!("the Dreamer reads {} open conflicts, not one", open.len()).into());
    };
    assert_eq!(json!(conflict.marker.to_hex()), parked["marker"]);
    assert_eq!(
        conflict.members,
        Vec::<EntityId>::new(),
        "no member is stored"
    );
    assert_eq!(conflict.predicates, vec![FOOD.to_owned(), FOOD.to_owned()]);
    let mut retained: Vec<String> = conflict
        .alternatives
        .iter()
        .map(|alternative| alternative.id.to_hex())
        .collect();
    retained.sort_unstable();
    let mut expected = members.clone();
    expected.sort_unstable();
    assert_eq!(retained, expected, "both candidates are retained whole");

    assert_eq!(conflict.body.predicate, "core.conflict.open");
    assert_eq!(
        hex_ids_at(&conflict.body.value, "prior_head"),
        Vec::<String>::new()
    );
    assert_eq!(
        hex_ids_at(&conflict.body.value, "prior_heads"),
        Vec::<String>::new()
    );
    assert_eq!(hex_ids_at(&conflict.body.value, "candidates"), members);
    Ok(())
}
