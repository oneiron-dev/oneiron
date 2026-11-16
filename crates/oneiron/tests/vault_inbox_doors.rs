//! The owner inbox doors keep the concern-card and owner-route promises
//! (ruling L4-23 = A: each test proves a promise at its public door). Every
//! call enters through `oneiron_testkit::door::invoke`, the generated verb
//! dispatch every transport shares: `vault.inbox.*` as the embedded owner on
//! a vault opened with `open_owned`, `self.inbox.*` as the owner or as the
//! agent a card is about.
//!
//! - P1 canon `oneiron/planning/agent-mind-design-v1.md:387` "Concern cards
//!   always reach the owner ... under 'Waiting on you' ... The lens groups
//!   them per agent": `vault.inbox.lens` as the owner shows the card's row
//!   (kind `concern`, pile `waiting_on_you`, `concern.agent` the subject,
//!   `payload_ref` the handle) and `concern_groups` holds that agent with
//!   that row; the subject's own `self.inbox.lens` shows no row about
//!   itself.
//! - P2 the same file, `:381` "outcome, set by the leader or owner:
//!   confirmed, dismissed or unresolved": the owner sets each of the three
//!   on its own card through `self.inbox.concern.outcome` and reads it back
//!   through `self.inbox.concern`; `open` and an unknown word are refused.
//! - P3 the same file, `:434` "Dismissal history suppresses repeats; it
//!   never rewrites the receipts": the card before and after a dismissal
//!   holds the same evidence and DIAGNOSTICs, and its review receipts grew
//!   by one naming `dismissed`.
//! - P4 `oneiron/agents/oneiron-arch-0027-import-pipeline-v1.md:376` "the
//!   owner's own export still restores, on the review path": that review
//!   path, `vault.inbox.groups.resolve` of kind `restore`, is the owner's
//!   own route. An agent is refused FORBIDDEN; the owner reaches the restore
//!   lookup, which answers NOT_FOUND for a key no restore of his holds.
//! - Refusals: each `vault.inbox.*` verb as an agent is FORBIDDEN; as the
//!   owner a non-cursor `after`, an identity AND an agent filter, a partial
//!   `before_*` and a non-hex filter are BAD_REQUEST.
//!
//! No public verb seeds a concern card, so each card lands through
//! `test_doors::agent_health::land_concern`, which runs the Coach review's
//! own landing (`pipeline::land`: DIAGNOSTIC, route, merge, card write).
//! Subject agents come from `test_doors::coach::define_agent`. The owner
//! PERSON is created before any card lands: until it exists the live-owner
//! census is empty, and a card merged with no owner has no recipient and
//! projects no row.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test vault_inbox_doors`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::memory::Memory;
use oneiron::store::diagnostic_record::AgentHealthSignal;
use oneiron::test_doors::agent_health::land_concern;
use oneiron::test_doors::coach::define_agent;
use oneiron::{EdgeActorClass, EntityId, Vault};
use oneiron_testkit::{FixtureVault, TestVault, door, fixture_cache};
use serde_json::{Value, json};

/// An owned empty vault whose owner PERSON exists before any card lands.
/// The `TestVault` holds the directory and must outlive the `Vault`.
struct Harness {
    dir: TestVault,
    vault: Vault,
}

impl Harness {
    fn new() -> Self {
        let dir = FixtureVault::empty(&fixture_cache!())
            .expect("the empty fixture")
            .copy()
            .expect("a private copy");
        let vault = dir.open_owned().expect("an owned open");
        let _issuer = oneiron::test_support::provision_engine_machines(&vault);
        door::owner(&vault).expect("the owner exists before any card lands");
        Self { dir, vault }
    }

    /// The vault's embedded owner, as a caller of the owner doors.
    fn owner(&self) -> Memory<'_> {
        door::owner(&self.vault).expect("the owner")
    }

    /// One agent, as a caller of its own doors.
    fn agent(&self, id: EntityId) -> Memory<'_> {
        self.vault.memory(id, EdgeActorClass::Agent)
    }

    /// One Concern-tone card about `subject` (`misalignment`, the one
    /// Concern signal), through the review's own landing. Its handle.
    fn land_concern_about(&self, subject: EntityId) -> String {
        land_concern(
            &self.vault,
            subject,
            AgentHealthSignal::Misalignment,
            vec![EntityId::now()],
            self.dir.clock().now(),
        )
        .expect("the finding lands")
    }
}

fn lens_row_by_payload(page: &Value, handle: &str) -> Option<Value> {
    page["items"]
        .as_array()
        .expect("lens items")
        .iter()
        .find(|row| row["payload_ref"].as_str() == Some(handle))
        .cloned()
}

/// P1. Seeded fault: `crates/oneiron/src/dreamer_runner/maintenance/agent_health/delivery.rs:73`,
/// the row's `payload_ref: Some(card_ref)` made `None`, so the owner's row no
/// longer carries the card it waits on.
#[test]
fn concern_cards_reach_the_owner_grouped_per_agent() {
    let harness = Harness::new();
    let owner = harness.owner();
    let subject = define_agent(&harness.vault).expect("a subject agent");
    let handle = harness.land_concern_about(subject);

    let page =
        door::invoke(&owner, "vault.inbox.lens", json!({})).expect("the owner reads the lens");
    let row = lens_row_by_payload(&page, &handle).expect("the card projects one owner row");
    assert_eq!(row["kind"], "concern");
    assert_eq!(row["pile"], "waiting_on_you");
    assert_eq!(row["concern"]["agent"], subject.to_hex());
    let item_id = format!(
        "concern:{}",
        handle.strip_prefix("health:").expect("a health: handle")
    );
    assert_eq!(row["item_id"], item_id);
    let groups = page["concern_groups"].as_array().expect("concern groups");
    assert_eq!(groups.len(), 1, "one agent with concerns: {groups:?}");
    assert_eq!(groups[0]["agent"], subject.to_hex());
    assert_eq!(groups[0]["items"], json!([item_id]));

    // The subject's own slice keeps only rows addressed to it, and a card's
    // recipients never name its subject.
    let own = door::invoke(&harness.agent(subject), "self.inbox.lens", json!({}))
        .expect("the subject reads its own lens");
    let own_items = own["items"].as_array().expect("own items");
    assert!(
        own_items
            .iter()
            .all(|row| row["payload_ref"].as_str() != Some(handle.as_str())
                && row["concern"]["agent"].as_str() != Some(subject.to_hex().as_str())),
        "the subject sees no concern about itself: {own_items:?}"
    );
}

/// P2. Seeded fault: `crates/oneiron/src/dreamer_runner/maintenance/agent_health/doors.rs:89`,
/// the settle summary's `outcome` made the constant `"settled"`.
#[test]
fn concern_outcomes_are_confirmed_dismissed_or_unresolved() {
    let harness = Harness::new();
    let owner = harness.owner();
    let mut handles = Vec::new();
    for _ in 0..3 {
        let subject = define_agent(&harness.vault).expect("a subject agent");
        handles.push(harness.land_concern_about(subject));
    }

    // A live vault owner reads and settles every card (`may_read`).
    for (handle, spelling) in handles.iter().zip(["confirmed", "dismissed", "unresolved"]) {
        let summary = door::invoke(
            &owner,
            "self.inbox.concern.outcome",
            json!({"card": handle, "outcome": spelling}),
        )
        .expect("the owner settles the card");
        assert_eq!(summary["outcome"], spelling);
        let view = door::invoke(&owner, "self.inbox.concern", json!({"card": handle}))
            .expect("the owner reads the card back");
        assert_eq!(view["body"]["outcome"], spelling);
    }

    // `open` is the review's alone, and no other word decodes.
    for word in ["open", "ignored"] {
        let refused = door::invoke(
            &owner,
            "self.inbox.concern.outcome",
            json!({"card": handles[0], "outcome": word}),
        )
        .expect_err(&format!("outcome {word} is refused"));
        assert_eq!(refused.code, "BAD_REQUEST", "{word}: {refused:?}");
    }
}

/// P3. Seeded fault: `crates/oneiron/src/dreamer_runner/maintenance/agent_health/doors.rs:163`,
/// `settle` also clears the card's evidence. The settle summary is not
/// asserted here, so P2's fault leaves this test green.
#[test]
fn dismissal_keeps_the_receipts_and_appends_one() {
    let harness = Harness::new();
    let owner = harness.owner();
    let subject = define_agent(&harness.vault).expect("a subject agent");
    let handle = harness.land_concern_about(subject);

    let before = door::invoke(&owner, "self.inbox.concern", json!({"card": handle}))
        .expect("the card before dismissal");
    let receipts = before["body"]["review_outcomes"]
        .as_array()
        .expect("receipts before")
        .len();
    door::invoke(
        &owner,
        "self.inbox.concern.outcome",
        json!({"card": handle, "outcome": "dismissed"}),
    )
    .expect("the owner dismisses the card");

    let after = door::invoke(&owner, "self.inbox.concern", json!({"card": handle}))
        .expect("the card after dismissal");
    assert_eq!(after["body"]["outcome"], "dismissed");
    assert_eq!(
        after["body"]["evidence"], before["body"]["evidence"],
        "dismissal never rewrites the evidence"
    );
    assert_eq!(
        after["body"]["diagnostics"], before["body"]["diagnostics"],
        "dismissal never rewrites the DIAGNOSTICs"
    );
    let grown = after["body"]["review_outcomes"]
        .as_array()
        .expect("receipts after");
    assert_eq!(grown.len(), receipts + 1, "one receipt appended: {grown:?}");
    assert_eq!(
        grown.last().expect("the new receipt")["outcome"],
        "dismissed"
    );
}

/// P4. Seeded fault: `crates/oneiron/src/memory/run_review/restore_group.rs:93`,
/// `if receipt.is_none()` made `is_some()`, so a key no restore of the owner
/// holds answers an empty review instead of NOT_FOUND.
#[test]
fn restore_review_is_the_owners_own_route() {
    let harness = Harness::new();
    let owner = harness.owner();
    let agent = define_agent(&harness.vault).expect("an agent caller");
    let body =
        json!({"kind": "restore", "group_key": EntityId::now().to_hex(), "verb": "review_each"});

    let refused = door::invoke(
        &harness.agent(agent),
        "vault.inbox.groups.resolve",
        body.clone(),
    )
    .expect_err("an agent is refused the owner's route");
    assert_eq!(refused.code, "FORBIDDEN", "{refused:?}");

    let missing = door::invoke(&owner, "vault.inbox.groups.resolve", body)
        .expect_err("no restore of the owner has that key");
    assert_eq!(missing.code, "NOT_FOUND", "{missing:?}");
}

#[test]
fn a_foreign_or_malformed_owner_inbox_act_is_refused() {
    let harness = Harness::new();
    let owner = harness.owner();
    let agent_id = define_agent(&harness.vault).expect("an agent caller");
    let agent = harness.agent(agent_id);
    let hex = agent_id.to_hex();
    let restore =
        json!({"kind": "restore", "group_key": EntityId::now().to_hex(), "verb": "review_each"});
    let rows: Vec<(&str, &Memory<'_>, &str, Value, &str)> = vec![
        (
            "lens as an agent",
            &agent,
            "vault.inbox.lens",
            json!({}),
            "FORBIDDEN",
        ),
        (
            "groups as an agent",
            &agent,
            "vault.inbox.groups",
            json!({}),
            "FORBIDDEN",
        ),
        (
            "resolve as an agent",
            &agent,
            "vault.inbox.groups.resolve",
            restore,
            "FORBIDDEN",
        ),
        (
            "review as an agent",
            &agent,
            "vault.inbox.concerns.review",
            json!({}),
            "FORBIDDEN",
        ),
        (
            "groups after a non-cursor",
            &owner,
            "vault.inbox.groups",
            json!({"after": "not-a-cursor"}),
            "BAD_REQUEST",
        ),
        (
            "lens over an identity and an agent",
            &owner,
            "vault.inbox.lens",
            json!({"identity": hex.clone(), "agent": hex}),
            "BAD_REQUEST",
        ),
        (
            "lens with a partial before",
            &owner,
            "vault.inbox.lens",
            json!({"before_impact": 200, "before_at": 1}),
            "BAD_REQUEST",
        ),
        (
            "lens over a non-hex agent",
            &owner,
            "vault.inbox.lens",
            json!({"agent": "not-hex"}),
            "BAD_REQUEST",
        ),
    ];
    for (name, caller, verb, body, code) in rows {
        let refused = door::invoke(caller, verb, body).expect_err(&format!("refused: {name}"));
        assert_eq!(refused.code, code, "{name}: {refused:?}");
    }
}
