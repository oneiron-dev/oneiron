//! Pages the Dreamer's observations under the caller's live read grant.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test strength_observations_page`.
#![cfg(oneiron_test_support)]

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::registry::ENTITY_TYPE_CLAIM;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::define_agent;
use oneiron::test_doors::consolidation::{consolidate_unbound_turn, open_dreamer_vault};
use oneiron::test_doors::derive::{claim_subject, narrow_steward_grant_to_project};
use oneiron::test_doors::steward::{
    STEWARD_READ_VERB, STEWARD_VERBS, dreamer, record_strength_observations, stand_steward_grant,
    stand_steward_grant_in_bands,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};
use std::collections::BTreeSet;

type StrengthPageTestResult<T> = Result<T, Box<dyn std::error::Error>>;

fn open_strength_observation_vault(dir: &tempfile::TempDir) -> StrengthPageTestResult<Vault> {
    drop(open_dreamer_vault(dir.path(), "owen")?);
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    Ok(vault)
}

/// Lands the claims through the promotion writer, then records one independent
/// user-stated claim as their second source, without recording the first twice.
fn observe_strength_claim(
    vault: &Vault,
    predicates: &[&str],
) -> StrengthPageTestResult<(Vec<EntityId>, [EntityId; 2], u64)> {
    let reply = json!({
        "persons": [{"id": "new:P1", "name": "owen", "evidence_turn_refs": ["T1"]}],
        "candidates": predicates.iter().map(|predicate| json!({
            "subject": "new:P1",
            "predicate": predicate,
            "value": "owen",
            "confidence": 0.8,
            "evidence_refs": [{"source": "T1", "quote": "owen"}],
        })).collect::<Vec<_>>(),
    })
    .to_string();
    let pass = consolidate_unbound_turn(vault, "call me owen", None, None, &reply)?;
    assert_eq!(pass.landed.len(), predicates.len());
    let person = claim_subject(vault, pass.landed[0])?
        .unwrap_or_else(|| panic!("the generated claim has a person subject"));
    let mut source = ClaimBody::new(
        "profile.hobby",
        ClaimSubject::Entity(person),
        rmpv::Value::from("yuki"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    source.source = Some(ClaimSource::UserStated);
    let second = EntityId::now();
    let latest = vault.now_recorded_at().saturating_add(1);
    vault.put_claim(
        &second,
        &source,
        TimeRange {
            start: latest,
            end: latest,
        },
        latest,
    )?;
    for claim in &pass.landed {
        record_strength_observations(vault, *claim, &[second], latest.saturating_mul(1_000))?;
    }
    Ok((
        pass.landed,
        [pass.turn, second],
        latest.saturating_mul(1_000),
    ))
}

fn invoke_strength_owner(vault: &Vault, verb: &str, input: Value) -> MemoryResult<Value> {
    let owner = vault.ensure_embedded_owner_actor()?;
    invoke(&vault.memory(owner, EdgeActorClass::Human), verb, input)
}

fn read_strength_observation_page(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
    input: Value,
) -> MemoryResult<Value> {
    invoke(
        &vault.memory(actor, class),
        "vault.consolidation.strength.observations.page",
        input,
    )
    .map(|answer| answer["value"].clone())
}

fn assert_strength_pin(pin: &Value) {
    let pin = pin.as_str().unwrap_or_else(|| panic!("a pin is a string"));
    assert_eq!(pin.len(), 64);
    assert!(
        pin.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
}

fn assert_current_observation(page: &Value, claim: EntityId, sources: &[EntityId; 2], latest: u64) {
    let claims = page["claims"]
        .as_array()
        .unwrap_or_else(|| panic!("claims is an array"));
    assert_eq!(claims.len(), 1);
    let observed = &claims[0];
    assert_eq!(observed["claim"], claim.to_hex());
    assert_eq!(observed["predicate"], "profile.name");
    assert_eq!(observed["last_activity_ms"], latest);
    assert_eq!(observed["status"], "current");
    let mut expected = sources
        .iter()
        .map(|source| {
            json!({
                "status": "current", "source": source.to_hex(),
            })
        })
        .collect::<Vec<_>>();
    expected.sort_by_key(|source| source["source"].as_str().map(str::to_owned));
    assert_eq!(observed["sources"], json!(expected));
    assert_eq!(observed["sources_omitted"], false);
    assert_eq!(
        observed["signals"],
        json!({
            "source_count": 2, "latest_learned_at_ms": latest, "distinct_diversity": 2,
        })
    );
    assert_strength_pin(&observed["pin"]);
    assert!(page["next"].is_null());
}

/// Observes two claims, moves the one with the higher id into a project of
/// its own, and holds the Dreamer's Steward grant to the other's project, so
/// the Dreamer reads the lower claim and not the higher; `(read, unread)`.
fn observe_a_read_and_an_unread_claim(
    vault: &Vault,
) -> StrengthPageTestResult<(EntityId, EntityId)> {
    let (mut claims, _, _) = observe_strength_claim(vault, &["profile.name", "profile.nickname"])?;
    claims.sort_by_key(EntityId::to_hex);
    let (read, unread) = (claims[0], claims[1]);
    let mut body = vault
        .get_claim(&unread)?
        .unwrap_or_else(|| panic!("the observed claim exists"));
    body.scope_project = EntityId::now();
    let at = vault.now_recorded_at();
    vault.put_claim(&unread, &body, TimeRange { start: at, end: at }, at)?;
    let project = vault
        .get_claim(&read)?
        .unwrap_or_else(|| panic!("the observed claim exists"))
        .scope_project;
    let grant = stand_steward_grant(vault, dreamer(vault)?, &STEWARD_VERBS)?;
    narrow_steward_grant_to_project(vault, grant, project)?;
    Ok((read, unread))
}

fn page_claim_ids(page: &Value) -> Vec<String> {
    page["claims"]
        .as_array()
        .unwrap_or_else(|| panic!("claims is an array"))
        .iter()
        .map(|claim| {
            claim["claim"]
                .as_str()
                .unwrap_or_else(|| panic!("the claim id is a string"))
                .to_owned()
        })
        .collect()
}

fn observation_cursor(id: EntityId) -> Value {
    json!({"cursor": format!("strength-observations:{}", id.to_hex())})
}

#[test]
fn the_owner_reads_an_observed_claim_with_its_policy_config_and_pins() -> StrengthPageTestResult<()>
{
    let dir = tempfile::tempdir()?;
    let vault = open_strength_observation_vault(&dir)?;
    let (claims, sources, latest) = observe_strength_claim(&vault, &["profile.name"])?;
    let policy = json!({"archive_below": 0.3, "quiet_ms": 5_000});
    invoke_strength_owner(&vault, "vault.consolidation.strength.set", policy.clone())?;
    let config = serde_json::to_value(vault.consolidation_selection()?)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let page = read_strength_observation_page(&vault, owner, EdgeActorClass::Human, json!({}))?;
    assert_current_observation(&page, claims[0], &sources, latest);
    assert_eq!(page["policy"], policy);
    assert_eq!(page["config"], config);
    assert_strength_pin(&page["policy_pin"]);
    assert_strength_pin(&page["config_pin"]);
    Ok(())
}

#[test]
fn a_dreamer_reads_through_its_steward_read_and_is_refused_once_narrowed_off_read()
-> StrengthPageTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_strength_observation_vault(&dir)?;
    let (claims, sources, latest) = observe_strength_claim(&vault, &["profile.name"])?;
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let page = read_strength_observation_page(&vault, actor, EdgeActorClass::System, json!({}))?;
    assert_current_observation(&page, claims[0], &sources, latest);
    stand_steward_grant(&vault, actor, &["derive", "archive"])?;
    let Err(error) =
        read_strength_observation_page(&vault, actor, EdgeActorClass::System, json!({}))
    else {
        panic!("a Dreamer narrowed off read is refused");
    };
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN);
    Ok(())
}

#[test]
fn an_agent_with_no_grant_is_refused() -> StrengthPageTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_strength_observation_vault(&dir)?;
    let agent = define_agent(&vault)?;
    let Err(error) =
        read_strength_observation_page(&vault, agent, EdgeActorClass::Agent, json!({}))
    else {
        panic!("an ungranted agent is refused");
    };
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN);
    Ok(())
}

#[test]
fn a_source_the_reader_may_not_read_is_withheld_with_no_detail() -> StrengthPageTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_strength_observation_vault(&dir)?;
    let (claims, sources, _) = observe_strength_claim(&vault, &["profile.name"])?;
    let actor = dreamer(&vault)?;
    stand_steward_grant_in_bands(&vault, actor, &[STEWARD_READ_VERB], &[ENTITY_TYPE_CLAIM])?;
    let page = read_strength_observation_page(&vault, actor, EdgeActorClass::System, json!({}))?;
    let claim = &page["claims"][0];
    assert_eq!(claim["claim"], claims[0].to_hex());
    assert_eq!(claim["status"], "withheld");
    let served = claim["sources"]
        .as_array()
        .unwrap_or_else(|| panic!("sources is an array"));
    assert_eq!(served.len(), 2);
    let withheld = served
        .iter()
        .find(|source| source["status"] == "withheld")
        .unwrap_or_else(|| panic!("the TURN is withheld"));
    let object = withheld
        .as_object()
        .unwrap_or_else(|| panic!("a source is an object"));
    assert_eq!(
        object.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["status"]
    );
    assert_eq!(withheld, &json!({"status": "withheld"}));
    assert_eq!(
        served.last(),
        Some(withheld),
        "a withheld source has no place"
    );
    assert!(served.contains(&json!({"status": "current", "source": sources[1].to_hex()})));
    assert!(!page.to_string().contains(&sources[0].to_hex()));
    assert!(claim["signals"].is_null());
    assert!(claim["pin"].is_null());
    Ok(())
}

#[test]
fn a_claim_the_reader_may_not_read_changes_no_page_whatever_the_cursor()
-> StrengthPageTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_strength_observation_vault(&dir)?;
    let (read, unread) = observe_a_read_and_an_unread_claim(&vault)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let whole = read_strength_observation_page(&vault, owner, EdgeActorClass::Human, json!({}))?;
    assert_eq!(page_claim_ids(&whole), vec![read.to_hex(), unread.to_hex()]);
    let actor = dreamer(&vault)?;
    let first = read_strength_observation_page(&vault, actor, EdgeActorClass::System, json!({}))?;
    assert_eq!(page_claim_ids(&first), vec![read.to_hex()]);
    let before_unread = read_strength_observation_page(
        &vault,
        actor,
        EdgeActorClass::System,
        observation_cursor(read),
    )?;
    let after_unread = read_strength_observation_page(
        &vault,
        actor,
        EdgeActorClass::System,
        observation_cursor(unread),
    )?;
    assert_eq!(
        before_unread, after_unread,
        "the unread claim moves no answer"
    );
    assert!(page_claim_ids(&before_unread).is_empty());
    assert!(before_unread["next"].is_null());
    let keys = before_unread
        .as_object()
        .unwrap_or_else(|| panic!("a page is an object"))
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        keys,
        BTreeSet::from([
            "claims",
            "config",
            "config_pin",
            "next",
            "policy",
            "policy_pin"
        ])
    );
    let limited =
        read_strength_observation_page(&vault, actor, EdgeActorClass::System, json!({"limit": 1}))?;
    assert_eq!(page_claim_ids(&limited), vec![read.to_hex()]);
    assert!(limited["next"].is_null(), "no later claim reads");
    for page in [&first, &before_unread, &after_unread, &limited] {
        assert!(!page.to_string().contains(&unread.to_hex()));
    }
    Ok(())
}

#[test]
fn a_source_changed_since_it_was_observed_is_moved_and_the_claim_has_no_pin()
-> StrengthPageTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_strength_observation_vault(&dir)?;
    let (_, sources, latest) = observe_strength_claim(&vault, &["profile.name"])?;
    let mut source = vault
        .get_claim(&sources[1])?
        .unwrap_or_else(|| panic!("the independent source exists"));
    source.value = rmpv::Value::from("owen");
    let at = latest / 1_000;
    vault.put_claim(&sources[1], &source, TimeRange { start: at, end: at }, at)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let page = read_strength_observation_page(&vault, owner, EdgeActorClass::Human, json!({}))?;
    let claim = &page["claims"][0];
    assert_eq!(claim["status"], "moved");
    let served = claim["sources"]
        .as_array()
        .unwrap_or_else(|| panic!("sources is an array"));
    assert!(served.contains(&json!({"status": "moved", "source": sources[1].to_hex()})));
    assert!(claim["signals"].is_null());
    assert!(claim["pin"].is_null());
    Ok(())
}

#[test]
fn the_pins_change_when_the_policy_or_the_config_changes() -> StrengthPageTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_strength_observation_vault(&dir)?;
    observe_strength_claim(&vault, &["profile.name"])?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let before = read_strength_observation_page(&vault, owner, EdgeActorClass::Human, json!({}))?;
    let mut policy = before["policy"].clone();
    policy["quiet_ms"] = json!(policy["quiet_ms"].as_u64().unwrap_or_default() + 1);
    invoke_strength_owner(&vault, "vault.consolidation.strength.set", policy)?;
    let after_policy =
        read_strength_observation_page(&vault, owner, EdgeActorClass::Human, json!({}))?;
    assert_ne!(before["policy_pin"], after_policy["policy_pin"]);
    assert_eq!(before["config_pin"], after_policy["config_pin"]);
    let config = vault.consolidation_selection()?;
    invoke_strength_owner(
        &vault,
        "vault.consolidation.selection_timing.set",
        json!({
            "soak_ms": config.soak_ms + 1, "recency_window_ms": config.recency_window_ms,
        }),
    )?;
    let after_config =
        read_strength_observation_page(&vault, owner, EdgeActorClass::Human, json!({}))?;
    assert_ne!(after_policy["config_pin"], after_config["config_pin"]);
    assert_eq!(after_policy["policy_pin"], after_config["policy_pin"]);
    assert_eq!(before["claims"][0]["pin"], after_config["claims"][0]["pin"]);
    Ok(())
}

#[test]
fn a_page_bound_of_one_row_pages_every_observed_claim_once() -> StrengthPageTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_strength_observation_vault(&dir)?;
    let (claims, _, _) = observe_strength_claim(
        &vault,
        &["profile.name", "profile.nickname", "profile.city"],
    )?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let expected = claims.iter().map(EntityId::to_hex).collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut cursor = Value::Null;
    let mut ordered = Vec::new();
    for index in 0..3 {
        let page = read_strength_observation_page(
            &vault,
            owner,
            EdgeActorClass::Human,
            json!({"cursor": cursor, "limit": 1}),
        )?;
        let claims = page["claims"]
            .as_array()
            .unwrap_or_else(|| panic!("claims is an array"));
        assert_eq!(claims.len(), 1);
        let claim = claims[0]["claim"]
            .as_str()
            .unwrap_or_else(|| panic!("the claim id is a string"));
        assert!(seen.insert(claim.to_owned()), "each claim is served once");
        ordered.push(claim.to_owned());
        cursor = page["next"].clone();
        assert_eq!(cursor.is_null(), index == 2);
    }
    assert_eq!(seen, expected);
    assert_eq!(ordered, expected.into_iter().collect::<Vec<_>>());
    Ok(())
}
