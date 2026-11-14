//! Pages the Dreamer's open conflicts under the caller's live read grant.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test conflicts_page`.
#![cfg(oneiron_test_support)]

use oneiron::dreamer_consolidation::ConflictReviewScope;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::define_agent;
use oneiron::test_doors::consolidation::{consolidate_unbound_turn_pair, open_dreamer_vault};
use oneiron::test_doors::derive::{
    Claim, Derived, Named, commit, narrow_steward_grant_to_project, open_conflict, witness_turn,
};
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, owner, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// Returns a fixture or assertion error without hiding its source.
type ConflictsPageTestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// The verb under test, invoked by name with plain JSON, so this file
/// compiles while the handler is still missing and fails at runtime on the
/// unknown verb.
const CONFLICTS_PAGE_VERB: &str = "vault.consolidation.conflicts.page";

/// Opens a vault the way the strength page test does: the Dreamer fixture
/// vault, reopened owned, with engine machines provisioned and the embedded
/// owner ensured.
fn open_conflicts_vault(dir: &tempfile::TempDir) -> ConflictsPageTestResult<Vault> {
    drop(open_dreamer_vault(dir.path(), "owen")?);
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    Ok(vault)
}

/// Seeds one named person through the existing fixture door.
fn seed_person(vault: &Vault, name: &str) -> ConflictsPageTestResult<EntityId> {
    let person = EntityId::now();
    seed_named_person(vault, &person, name, vault.now_recorded_at())?;
    Ok(person)
}

/// Lands one Dreamer claim about `person` under `predicate`, citing the
/// witnessed `turn`, in a derivation batch of its own; its id.
fn landed_claim(
    vault: &Vault,
    actor: EntityId,
    person: EntityId,
    turn: EntityId,
    run: &str,
    predicate: &'static str,
    value: &str,
) -> ConflictsPageTestResult<EntityId> {
    let committed = commit(
        vault,
        actor,
        EdgeActorClass::System,
        run,
        &[Derived::Claim(Claim {
            local: "claim",
            predicate,
            subject: Named::Stored(person),
            value: json!(value),
            evidence: vec![Named::Stored(turn)],
        })],
    )?;
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(item.landed, "the claim lands: {item:?}");
    Ok(item.rows[0])
}

/// Lands two Dreamer claims about `person` under `predicate` with unequal
/// values, each in a batch of its own (as `derive_settlement` does), and
/// returns their identifiers.
fn commit_conflicting_pair(
    vault: &Vault,
    actor: EntityId,
    person: EntityId,
    turn: EntityId,
    run: &str,
    predicate: &'static str,
    values: (&str, &str),
) -> ConflictsPageTestResult<(EntityId, EntityId)> {
    let first = landed_claim(
        vault,
        actor,
        person,
        turn,
        &format!("{run}-first"),
        predicate,
        values.0,
    )?;
    let second = landed_claim(
        vault,
        actor,
        person,
        turn,
        &format!("{run}-second"),
        predicate,
        values.1,
    )?;
    Ok((first, second))
}

/// Reads the conflicts for `actor` of `class` and returns the page body.
fn read_conflicts_page(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
    input: Value,
) -> MemoryResult<Value> {
    invoke(&vault.memory(actor, class), CONFLICTS_PAGE_VERB, input)
        .map(|answer| answer["value"].clone())
}

/// Returns the cursor that resumes after `marker`.
fn conflict_cursor(marker: EntityId) -> Value {
    json!({"cursor": format!("conflicts:{}", marker.to_hex())})
}

/// Returns the markers a page serves, in page order.
fn page_markers(page: &Value) -> Vec<String> {
    page["conflicts"]
        .as_array()
        .unwrap_or_else(|| panic!("conflicts is an array"))
        .iter()
        .map(|conflict| {
            conflict["marker"]
                .as_str()
                .unwrap_or_else(|| panic!("the marker is a string"))
                .to_owned()
        })
        .collect()
}

/// Returns the project a stored claim landed in.
fn claim_project(vault: &Vault, claim: EntityId) -> ConflictsPageTestResult<EntityId> {
    Ok(vault
        .get_claim(&claim)?
        .unwrap_or_else(|| panic!("the landed claim exists"))
        .scope_project)
}

/// The Dreamer pages the one open conflict its live Steward read reaches,
/// with both members whole.
#[test]
fn the_dreamer_pages_the_open_conflicts_its_grant_reaches() -> ConflictsPageTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_conflicts_vault(&dir)?;
    let person = seed_person(&vault, "owen")?;
    let turn = witness_turn(&vault, "call me owen")?;
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let (first, second) = commit_conflicting_pair(
        &vault,
        actor,
        person,
        turn,
        "run-1",
        "preference.coffee",
        ("an oat milk flat white", "a cortado"),
    )?;
    let marker = open_conflict(&vault, second, first)?;
    let page = read_conflicts_page(&vault, actor, EdgeActorClass::System, json!({}))?;
    let conflicts = page["conflicts"]
        .as_array()
        .unwrap_or_else(|| panic!("conflicts is an array"));
    assert_eq!(conflicts.len(), 1);
    let conflict = &conflicts[0];
    assert_eq!(conflict["marker"], marker.to_hex());
    assert_eq!(conflict["subject"], person.to_hex());
    assert_eq!(conflict["predicates"], json!(["preference.coffee"]));
    let members = conflict["members"]
        .as_array()
        .unwrap_or_else(|| panic!("members is an array"));
    assert_eq!(members.len(), 2);
    for member in members {
        let id = member["claim"]
            .as_str()
            .unwrap_or_else(|| panic!("the member claim is a string"));
        let (claim, expected) = if id == first.to_hex() {
            (first, "an oat milk flat white")
        } else if id == second.to_hex() {
            (second, "a cortado")
        } else {
            panic!("the member is one of the pair: {id}");
        };
        let stored = vault
            .get_claim(&claim)?
            .unwrap_or_else(|| panic!("the member is a stored claim"));
        assert_eq!(member["predicate"], "preference.coffee");
        assert_eq!(member["value"], expected);
        assert_eq!(
            member["source"],
            json!(stored.source.map(|source| source.as_str()))
        );
        assert_eq!(member["approval"], stored.approval.as_str());
        assert_eq!(member["keep"], true, "a standing member may be kept");
        let confidence = member["confidence"]
            .as_f64()
            .unwrap_or_else(|| panic!("the confidence is a number"));
        assert!((confidence - f64::from(stored.confidence)).abs() < 1e-6);
        assert_eq!(member["valid_from"], json!(stored.valid_from));
        assert_eq!(member["valid_to"], json!(stored.valid_to));
    }
    assert_eq!(conflict["alternatives"], json!([]));
    assert_eq!(conflict["reverted"], false);
    assert_eq!(conflict["values_omitted"], false);
    assert!(page["next"].is_null());
    Ok(())
}

/// A conflict with a member the reader does not read is left out whole: the
/// page names neither the outside member, nor the member it still reads, nor
/// the marker.
#[test]
fn a_conflict_with_a_member_the_reader_does_not_read_is_left_out() -> ConflictsPageTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_conflicts_vault(&dir)?;
    // Each TURN names both people, so either TURN holds either quote.
    let reply = json!({
        "persons": [
            {"id": "new:P1", "name": "owen", "evidence_turn_refs": ["T1"]},
            {"id": "new:P2", "name": "yuki", "evidence_turn_refs": ["T2"]},
        ],
        "candidates": [
            {
                "subject": "new:P1", "predicate": "profile.name", "value": "owen",
                "confidence": 0.8, "evidence_refs": [{"source": "T1", "quote": "owen"}],
            },
            {
                "subject": "new:P2", "predicate": "profile.name", "value": "yuki",
                "confidence": 0.8, "evidence_refs": [{"source": "T2", "quote": "yuki"}],
            },
        ],
    })
    .to_string();
    let pass = consolidate_unbound_turn_pair(
        &vault,
        "call me owen, and this is yuki",
        "call me yuki, and this is owen",
        EntityId::now(),
        &reply,
    )?;
    assert_eq!(pass.landed.len(), 2);
    let mut claims = pass.landed;
    claims.sort_by_key(EntityId::to_hex);
    let (read, unread) = (claims[0], claims[1]);
    let read_project = claim_project(&vault, read)?;
    assert_ne!(
        read_project,
        claim_project(&vault, unread)?,
        "each claim lands in its own TURN's project"
    );
    // The marker inherits its project from the member the Dreamer keeps
    // reading, so the marker reads and only the member is outside the grant.
    let marker = open_conflict(&vault, read, unread)?;
    let actor = dreamer(&vault)?;
    let grant = stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    narrow_steward_grant_to_project(&vault, grant, read_project)?;
    let page = read_conflicts_page(&vault, actor, EdgeActorClass::System, json!({}))?;
    assert!(
        page["conflicts"]
            .as_array()
            .unwrap_or_else(|| panic!("conflicts is an array"))
            .is_empty()
    );
    assert!(page["next"].is_null());
    let served = page.to_string();
    assert!(!served.contains(&marker.to_hex()));
    assert!(!served.contains(&read.to_hex()));
    assert!(!served.contains(&unread.to_hex()));
    // The owner still pages the conflict whole: it exists and is only left
    // out for the narrowed Dreamer.
    let owner = vault.ensure_embedded_owner_actor()?;
    let whole = read_conflicts_page(&vault, owner, EdgeActorClass::Human, json!({}))?;
    assert_eq!(page_markers(&whole), vec![marker.to_hex()]);
    Ok(())
}

/// A conflict whose subject the owner holds is the owner's to answer: the
/// Dreamer's page leaves it out, and the owner's page under proof serves it.
#[test]
fn a_conflict_the_owner_holds_is_left_out_for_the_dreamer() -> ConflictsPageTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_conflicts_vault(&dir)?;
    let person = seed_person(&vault, "owen")?;
    let turn = witness_turn(&vault, "call me owen")?;
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let (first, second) = commit_conflicting_pair(
        &vault,
        actor,
        person,
        turn,
        "run-1",
        "preference.coffee",
        ("an oat milk flat white", "a cortado"),
    )?;
    let marker = open_conflict(&vault, second, first)?;
    let before = read_conflicts_page(&vault, actor, EdgeActorClass::System, json!({}))?;
    assert_eq!(
        page_markers(&before),
        vec![marker.to_hex()],
        "the Dreamer pages the conflict before the hold"
    );
    let proof = owner(&vault)?;
    let owner_actor = vault.ensure_embedded_owner_actor()?;
    vault
        .memory(owner_actor, EdgeActorClass::Human)
        .hold_dreamer_conflict_review(&proof, ConflictReviewScope::Subject(person))?;
    let held = read_conflicts_page(&vault, actor, EdgeActorClass::System, json!({}))?;
    assert!(
        page_markers(&held).is_empty(),
        "the held conflict is the owner's"
    );
    assert!(held["next"].is_null());
    assert!(!held.to_string().contains(&marker.to_hex()));
    let whole = read_conflicts_page(&vault, owner_actor, EdgeActorClass::Human, json!({}))?;
    assert_eq!(page_markers(&whole), vec![marker.to_hex()]);
    Ok(())
}

/// A reader without a live Steward read is refused, even with a conflict waiting.
#[test]
fn a_reader_without_a_live_steward_read_is_refused() -> ConflictsPageTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_conflicts_vault(&dir)?;
    let person = seed_person(&vault, "owen")?;
    let turn = witness_turn(&vault, "call me owen")?;
    let actor = dreamer(&vault)?;
    let (first, second) = commit_conflicting_pair(
        &vault,
        actor,
        person,
        turn,
        "run-1",
        "preference.coffee",
        ("an oat milk flat white", "a cortado"),
    )?;
    let _marker = open_conflict(&vault, second, first)?;
    let agent = define_agent(&vault)?;
    let Err(error) = read_conflicts_page(&vault, agent, EdgeActorClass::Agent, json!({})) else {
        panic!("an agent without a live Steward read is refused");
    };
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN);
    Ok(())
}

/// Bounded pages walk every conflict exactly once, in marker order, and the
/// last page carries no cursor.
#[test]
fn the_pages_walk_every_conflict_once() -> ConflictsPageTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_conflicts_vault(&dir)?;
    let person = seed_person(&vault, "owen")?;
    let turn = witness_turn(&vault, "call me owen")?;
    let actor = dreamer(&vault)?;
    let pairs = [
        (
            "run-1",
            "preference.coffee",
            "an oat milk flat white",
            "a cortado",
        ),
        ("run-2", "preference.tea", "a sencha", "an earl grey"),
        ("run-3", "preference.snack", "a rice cracker", "an apple"),
    ];
    let mut markers = Vec::new();
    for (run, predicate, first_value, second_value) in pairs {
        let (first, second) = commit_conflicting_pair(
            &vault,
            actor,
            person,
            turn,
            run,
            predicate,
            (first_value, second_value),
        )?;
        markers.push(open_conflict(&vault, second, first)?);
    }
    let expected = markers
        .iter()
        .map(EntityId::to_hex)
        .collect::<BTreeSet<_>>();
    let owner = vault.ensure_embedded_owner_actor()?;
    let mut seen = BTreeSet::new();
    let mut ordered = Vec::new();
    let mut cursor = Value::Null;
    for index in 0..3 {
        let page = read_conflicts_page(
            &vault,
            owner,
            EdgeActorClass::Human,
            json!({"cursor": cursor, "limit": 1}),
        )?;
        let served = page_markers(&page);
        assert_eq!(served.len(), 1);
        assert!(
            seen.insert(served[0].clone()),
            "each conflict is served once"
        );
        ordered.push(served[0].clone());
        cursor = page["next"].clone();
        assert_eq!(cursor.is_null(), index == 2);
        if index < 2 {
            assert_eq!(cursor, json!(format!("conflicts:{}", served[0])));
        }
    }
    assert_eq!(seen, expected);
    assert_eq!(ordered, expected.into_iter().collect::<Vec<_>>());
    // A cursor naming the first marker resumes after it.
    let first = EntityId::from_hex(&ordered[0]).unwrap_or_else(|_| panic!("a marker parses"));
    let resumed =
        read_conflicts_page(&vault, owner, EdgeActorClass::Human, conflict_cursor(first))?;
    assert_eq!(page_markers(&resumed), ordered[1..].to_vec());
    assert!(resumed["next"].is_null());
    Ok(())
}
