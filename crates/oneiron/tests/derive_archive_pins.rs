//! An archive item is judged against the pins its reader was served: the
//! claim's observation row, the strength policy and the scoring config, as
//! `vault.consolidation.strength.observations.page` gave them, rechecked
//! with the item's observed sources in the item's own savepoint. A derive
//! item's refusal receipt names the grant the item was judged by.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test derive_archive_pins`.
#![cfg(oneiron_test_support)]

use oneiron::attempt_queue::AttemptId;
use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::registry::ENTITY_TYPE_CLAIM;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::consolidation::{consolidate_unbound_turn, open_dreamer_vault};
use oneiron::test_doors::derive::{
    ArchivePins, Committed, Derived, Named, PinnedArchive, SameAs, claim_subject,
    commit_in_attempt, derive_frontier, derive_item_receipts, row_live,
};
use oneiron::test_doors::steward::{
    STEWARD_ARCHIVE_VERB, STEWARD_READ_VERB, STEWARD_VERBS, archive_every_quiet_claim, dreamer,
    record_strength_observations, stand_steward_grant, stand_steward_grant_in_bands,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

type ArchivePinsTestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// The claims one consolidation pass landed, each observed with the TURN and
/// one independent user-stated claim of its own.
struct ObservedArchiveClaims {
    claims: Vec<EntityId>,
    sources: Vec<EntityId>,
    attempt: AttemptId,
    latest_ms: u64,
}

fn open_archive_pins_vault(dir: &tempfile::TempDir) -> ArchivePinsTestResult<Vault> {
    drop(open_dreamer_vault(dir.path(), "owen")?);
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    Ok(vault)
}

/// A user-stated `predicate` claim about `person`, stored at `at`.
fn put_independent_claim(
    vault: &Vault,
    person: EntityId,
    predicate: &str,
    at: u64,
) -> ArchivePinsTestResult<EntityId> {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(person),
        rmpv::Value::from("yuki"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    let id = EntityId::now();
    vault.put_claim(&id, &body, TimeRange { start: at, end: at }, at)?;
    Ok(id)
}

/// Lands one claim per `predicates` entry through the promotion writer, then
/// records the independent claim of the same index in `independents` as its
/// second source. No independent predicate is one a landed claim has.
fn observe_archive_claims(
    vault: &Vault,
    predicates: &[&str],
    independents: &[&str],
) -> ArchivePinsTestResult<ObservedArchiveClaims> {
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
    assert_eq!(independents.len(), predicates.len());
    let person = claim_subject(vault, pass.landed[0])?
        .unwrap_or_else(|| panic!("the generated claim has a person subject"));
    let latest = vault.now_recorded_at().saturating_add(1);
    let latest_ms = latest.saturating_mul(1_000);
    let mut sources = Vec::with_capacity(independents.len());
    for (claim, predicate) in pass.landed.iter().zip(independents) {
        let source = put_independent_claim(vault, person, predicate, latest)?;
        record_strength_observations(vault, *claim, &[source], latest_ms)?;
        sources.push(source);
    }
    Ok(ObservedArchiveClaims {
        claims: pass.landed,
        sources,
        attempt: pass.attempt,
        latest_ms,
    })
}

/// Every claim is weak under the policy, and the observations recorded one
/// second ahead of the clock are quiet once the clock passes them.
fn quiet_archive_policy(vault: &Vault) -> ArchivePinsTestResult<()> {
    archive_every_quiet_claim(vault)?;
    std::thread::sleep(std::time::Duration::from_millis(2_100));
    Ok(())
}

/// The Dreamer's observation page, read by name on its own handle.
fn dreamer_observation_page(vault: &Vault, dreamer: EntityId) -> ArchivePinsTestResult<Value> {
    let answer = invoke(
        &vault.memory(dreamer, EdgeActorClass::System),
        "vault.consolidation.strength.observations.page",
        json!({}),
    )?;
    Ok(answer["value"].clone())
}

fn invoke_as_owner(vault: &Vault, verb: &str, input: Value) -> ArchivePinsTestResult<()> {
    let owner = vault.ensure_embedded_owner_actor()?;
    invoke(&vault.memory(owner, EdgeActorClass::Human), verb, input)?;
    Ok(())
}

/// The pins `page` served for `claim`.
fn served_pins(page: &Value, claim: EntityId) -> ArchivePins {
    let pin = |value: &Value, what: &str| {
        value
            .as_str()
            .unwrap_or_else(|| panic!("the page serves {what}"))
            .to_owned()
    };
    let served = page["claims"]
        .as_array()
        .unwrap_or_else(|| panic!("the page serves claims"))
        .iter()
        .find(|served| served["claim"] == claim.to_hex())
        .unwrap_or_else(|| panic!("the page serves the claim"));
    ArchivePins {
        observation_pin: pin(&served["pin"], "the claim's pin"),
        policy_pin: pin(&page["policy_pin"], "a policy pin"),
        config_pin: pin(&page["config_pin"], "a config pin"),
    }
}

fn pinned_archive(local: &'static str, claim: EntityId, pins: ArchivePins) -> Derived {
    Derived::PinnedArchive(PinnedArchive {
        local,
        claim: Named::Stored(claim),
        score: 0.1,
        pins,
    })
}

fn commit_as_dreamer(
    vault: &Vault,
    dreamer: EntityId,
    attempt: AttemptId,
    items: &[Derived],
) -> ArchivePinsTestResult<Committed> {
    Ok(commit_in_attempt(
        vault,
        dreamer,
        EdgeActorClass::System,
        "run-archive-pins",
        Some(attempt),
        items,
    )?)
}

fn only_reasons(committed: &Committed) -> Vec<String> {
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(!item.landed, "the item is refused");
    item.reasons.clone()
}

#[test]
fn an_archive_at_the_pins_it_read_lands() -> ArchivePinsTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_archive_pins_vault(&dir)?;
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let observed = observe_archive_claims(&vault, &["profile.name"], &["profile.hobby"])?;
    let claim = observed.claims[0];
    quiet_archive_policy(&vault)?;
    let pins = served_pins(&dreamer_observation_page(&vault, actor)?, claim);

    let committed = commit_as_dreamer(
        &vault,
        actor,
        observed.attempt,
        &[pinned_archive("archive", claim, pins)],
    )?;
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(item.landed, "the archive lands: {:?}", item.reasons);
    assert!(
        !row_live(&vault, claim)?,
        "the archived claim is no longer live"
    );
    Ok(())
}

#[test]
fn a_moved_source_refuses_its_archive_and_the_other_lands() -> ArchivePinsTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_archive_pins_vault(&dir)?;
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let observed = observe_archive_claims(
        &vault,
        &["profile.name", "profile.nickname"],
        &["profile.hobby", "profile.city"],
    )?;
    let [moved_claim, kept_claim] = [observed.claims[0], observed.claims[1]];
    quiet_archive_policy(&vault)?;
    let page = dreamer_observation_page(&vault, actor)?;
    let moved_pins = served_pins(&page, moved_claim);
    let kept_pins = served_pins(&page, kept_claim);

    // The first claim's own independent source changes after the read.
    let source = observed.sources[0];
    let mut changed = vault
        .get_claim(&source)?
        .unwrap_or_else(|| panic!("the independent source is stored"));
    changed.value = rmpv::Value::from("owen");
    let at = observed.latest_ms / 1_000;
    vault.put_claim(&source, &changed, TimeRange { start: at, end: at }, at)?;

    let committed = commit_as_dreamer(
        &vault,
        actor,
        observed.attempt,
        &[
            pinned_archive("moved", moved_claim, moved_pins),
            pinned_archive("kept", kept_claim, kept_pins),
        ],
    )?;
    let [moved, kept] = committed.items.as_slice() else {
        panic!("two items: {:?}", committed.items);
    };
    assert!(!moved.landed, "the archive over a moved source is refused");
    assert_eq!(moved.reasons, ["gate.deny.derive.archive_source_moved"]);
    assert!(kept.landed, "the other archive lands: {:?}", kept.reasons);
    assert!(
        row_live(&vault, moved_claim)?,
        "the refused claim stays live"
    );
    assert!(
        !row_live(&vault, kept_claim)?,
        "the landed claim is archived"
    );
    Ok(())
}

#[test]
fn a_source_withheld_now_refuses_the_archive() -> ArchivePinsTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_archive_pins_vault(&dir)?;
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let observed = observe_archive_claims(&vault, &["profile.name"], &["profile.hobby"])?;
    let claim = observed.claims[0];
    quiet_archive_policy(&vault)?;
    let pins = served_pins(&dreamer_observation_page(&vault, actor)?, claim);

    // Every verb still stands, over CLAIM rows alone: the TURN source is out
    // of the grant's reach, the claim itself is not.
    stand_steward_grant_in_bands(&vault, actor, &STEWARD_VERBS, &[ENTITY_TYPE_CLAIM])?;

    let committed = commit_as_dreamer(
        &vault,
        actor,
        observed.attempt,
        &[pinned_archive("archive", claim, pins)],
    )?;
    assert_eq!(
        only_reasons(&committed),
        ["gate.deny.derive.archive_source_withheld"]
    );
    assert!(row_live(&vault, claim)?, "the refused claim stays live");
    Ok(())
}

#[test]
fn an_archive_read_under_another_policy_or_config_is_refused() -> ArchivePinsTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_archive_pins_vault(&dir)?;
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let observed = observe_archive_claims(&vault, &["profile.name"], &["profile.hobby"])?;
    let claim = observed.claims[0];
    quiet_archive_policy(&vault)?;
    let pins = served_pins(&dreamer_observation_page(&vault, actor)?, claim);

    // Another policy, under which the score is still weak.
    invoke_as_owner(
        &vault,
        "vault.consolidation.strength.set",
        json!({"archive_below": 0.5, "quiet_ms": 1}),
    )?;
    let committed = commit_as_dreamer(
        &vault,
        actor,
        observed.attempt,
        &[pinned_archive("archive", claim, pins)],
    )?;
    assert_eq!(
        only_reasons(&committed),
        ["gate.deny.derive.archive_policy_changed"]
    );

    // Read again under that policy, then the scoring config changes.
    let pins = served_pins(&dreamer_observation_page(&vault, actor)?, claim);
    let config = vault.consolidation_selection()?;
    invoke_as_owner(
        &vault,
        "vault.consolidation.selection_timing.set",
        json!({
            "soak_ms": config.soak_ms + 1, "recency_window_ms": config.recency_window_ms,
        }),
    )?;
    let committed = commit_as_dreamer(
        &vault,
        actor,
        observed.attempt,
        &[pinned_archive("archive", claim, pins)],
    )?;
    assert_eq!(
        only_reasons(&committed),
        ["gate.deny.derive.archive_config_changed"]
    );
    assert!(row_live(&vault, claim)?, "the refused claim stays live");
    Ok(())
}

#[test]
fn an_archive_after_a_new_observation_is_refused() -> ArchivePinsTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_archive_pins_vault(&dir)?;
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let observed = observe_archive_claims(&vault, &["profile.name"], &["profile.hobby"])?;
    let claim = observed.claims[0];
    quiet_archive_policy(&vault)?;
    let pins = served_pins(&dreamer_observation_page(&vault, actor)?, claim);

    // One more independent source is observed for the claim after the read.
    let person = claim_subject(&vault, claim)?
        .unwrap_or_else(|| panic!("the generated claim has a person subject"));
    let added = put_independent_claim(&vault, person, "profile.city", vault.now_recorded_at())?;
    record_strength_observations(&vault, claim, &[added], observed.latest_ms)?;

    let committed = commit_as_dreamer(
        &vault,
        actor,
        observed.attempt,
        &[pinned_archive("archive", claim, pins)],
    )?;
    assert_eq!(
        only_reasons(&committed),
        ["gate.deny.derive.archive_observation_changed"]
    );
    assert!(row_live(&vault, claim)?, "the refused claim stays live");
    Ok(())
}

#[test]
fn a_narrowed_archive_refusal_names_the_grant_and_frontier() -> ArchivePinsTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_archive_pins_vault(&dir)?;
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let observed = observe_archive_claims(&vault, &["profile.name"], &["profile.hobby"])?;
    let claim = observed.claims[0];
    quiet_archive_policy(&vault)?;
    let pins = served_pins(&dreamer_observation_page(&vault, actor)?, claim);

    // The Dreamer keeps `read` and `archive` and loses `derive`: its rows no
    // longer land what it derives.
    let grant = stand_steward_grant(&vault, actor, &[STEWARD_READ_VERB, STEWARD_ARCHIVE_VERB])?;

    let committed = commit_as_dreamer(
        &vault,
        actor,
        observed.attempt,
        &[pinned_archive("archive", claim, pins)],
    )?;
    assert_eq!(
        only_reasons(&committed),
        ["gate.deny.derive.no_landing_rows"]
    );
    let receipts = derive_item_receipts(&vault, &claim)?;
    let [receipt] = receipts.as_slice() else {
        panic!("one item receipt: {receipts:?}");
    };
    assert_eq!(receipt.outcome, "deny");
    assert_eq!(receipt.reasons, ["gate.deny.derive.no_landing_rows"]);
    assert_eq!(receipt.grant_ref, Some(grant.to_hex()));
    assert_eq!(receipt.read_frontier_hash, derive_frontier(&vault)?);
    Ok(())
}

#[test]
fn a_refused_item_of_another_kind_names_the_grant() -> ArchivePinsTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_archive_pins_vault(&dir)?;
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let observed = observe_archive_claims(&vault, &["profile.name"], &["profile.hobby"])?;
    let claim = observed.claims[0];
    let grant = stand_steward_grant(&vault, actor, &[STEWARD_READ_VERB, STEWARD_ARCHIVE_VERB])?;

    // A SameAs needs `derive`; the verdict refuses it before its rows are
    // read, and the receipt is about its source claim.
    let committed = commit_as_dreamer(
        &vault,
        actor,
        observed.attempt,
        &[Derived::SameAs(SameAs {
            local: "same",
            source: Named::Stored(claim),
            target: Named::Stored(observed.sources[0]),
        })],
    )?;
    assert_eq!(
        only_reasons(&committed),
        ["gate.deny.derive.grant_lacks_derive"]
    );
    let receipts = derive_item_receipts(&vault, &claim)?;
    let [receipt] = receipts.as_slice() else {
        panic!("one item receipt: {receipts:?}");
    };
    assert_eq!(receipt.outcome, "deny");
    assert_eq!(receipt.grant_ref, Some(grant.to_hex()));
    Ok(())
}
