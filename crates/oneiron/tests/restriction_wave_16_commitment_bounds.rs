//! Restriction wave 16, rows C120 and C122: the owner's bounds on promise text
//! (`commitment.content.max_text_bytes`) and on a filed reminder wording
//! (`commitment.reminder.max_wording_bytes`). Default = today: a promise past
//! 8,192 bytes and a wording past 4,096 bytes are refused until the owner
//! raises the key.
//!
//! - the owner raises the text bound to 16,384, then a 9,000-byte
//!   `vault.commitments.create` stands; unset, 8,193 bytes is refused with
//!   today's refusal and 8,192 is created; 0 and 65,537 are refused;
//! - a 9,000-byte promise created under the raised bound keeps working after
//!   the owner lowers it back: its occurrence is minted and fulfilled, and the
//!   series still reads its whole text;
//! - the owner raises the wording bound to 8,192, then a 5,000-byte wording
//!   files; unset, 4,097 bytes is refused and 4,096 files; 0 is refused.
//!
//! Every call enters through `oneiron_testkit::door::invoke`, on a vault opened
//! with the process writer lease, as the `vault.commitments.*` door tests do.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test restriction_wave_16_commitment_bounds`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::commitment_wake::COMMITMENT_REMINDER_CONTENT_PREFIX;
use oneiron::memory::Memory;
use oneiron::{EntityId, Vault};
use oneiron_testkit::{FixtureVault, TestVault, door, fixture_cache};
use serde_json::{Value, json};

const SET: &str = "vault.settings.set";
const TEXT_KEY: &str = "commitment.content.max_text_bytes";
const WORDING_KEY: &str = "commitment.reminder.max_wording_bytes";
/// Today's refusal of promise text past its bound.
const TEXT_REFUSAL: &str = "commitment content text must be non-empty and bounded";
/// Today's refusal of a wording past its bound.
const WORDING_REFUSAL: &str = "reminder wording is empty or too long";
/// The lead every series here asks.
const LEAD: u64 = 100;

/// A private copy of the empty fixture, opened with the writer lease so the
/// owner rows admit the embedded owner. The `TestVault` holds the directory
/// and the clock and must outlive the `Vault`.
fn owned_vault() -> (TestVault, Vault) {
    let copy = FixtureVault::empty(&fixture_cache!())
        .expect("the empty fixture")
        .copy()
        .expect("a private copy");
    let vault = copy.open_owned().expect("an owned open");
    (copy, vault)
}

/// Provisions the engine's MACHINE writers, as a host does at bootstrap: the
/// projector mints each occurrence as one of them, and a filed wording is the
/// dreamer's.
fn provision_machines(vault: &Vault) {
    let _issuer = oneiron::test_support::provision_engine_machines(vault);
}

/// The owner's set of `value` on the vault row of `key`.
fn set(owner: &Memory<'_>, key: &str, value: Value) -> Result<Value, String> {
    door::invoke(
        owner,
        SET,
        json!({ "key": key, "scope": { "kind": "vault" }, "value": value }),
    )
    .map_err(|error| format!("{error:?}"))
}

/// The owner's applied set of `value` on `key`.
fn set_applied(owner: &Memory<'_>, key: &str, value: Value) {
    let applied = set(owner, key, value).unwrap_or_else(|error| panic!("{SET} answers: {error}"));
    assert_eq!(applied["status"], json!("applied"), "{applied}");
}

/// One TURN the owner wrote, as a commitment's evidence; its hex id.
fn witness_turn(owner: &Memory<'_>) -> String {
    let conversation = door::invoke(
        owner,
        "vault.conversations.create",
        json!({"body": {"kind": "group", "title": "the promise"}}),
    )
    .expect("the owner creates a conversation");
    let turn = door::invoke(
        owner,
        "vault.conversations.records.append",
        json!({"conversation": conversation["id"], "advance": true, "body": {"txt": "I will send it"}}),
    )
    .expect("the owner appends a TURN");
    turn["id"].as_str().expect("the TURN's id").to_owned()
}

/// The owner's `vault.commitments.create` of a one-off promise of `text`,
/// owed by and to the owner and due 10,000 s out.
fn create(copy: &TestVault, owner: &Memory<'_>, turn: &str, text: &str) -> Result<Value, String> {
    let me = owner.actor().to_hex();
    let now = copy.clock().now();
    door::invoke(
        owner,
        "vault.commitments.create",
        json!({
            "obligor": {"kind": "owner", "entity_ref": me},
            "beneficiary": me,
            "content": {"text": text},
            "schedule": {"kind": "once", "due": now + 10_000},
            "lead_seconds": LEAD,
            "strength": "commitment",
            "birth_provenance": {"kind": "run_tree_node", "reference": "run:wave-16-bounds"},
            "occurred_at": now,
            "evidence_turn_refs": [turn],
        }),
    )
    .map_err(|error| format!("{error:?}"))
}

fn ref_of(view: &Value) -> String {
    view["commitment_ref"]
        .as_str()
        .expect("the view names its commitment")
        .to_owned()
}

fn get(owner: &Memory<'_>, commitment: &str) -> Value {
    door::invoke(
        owner,
        "vault.commitments.get",
        json!({"commitment_ref": commitment}),
    )
    .expect("the owner reads a commitment")
}

/// Text of exactly `bytes` ASCII bytes.
fn text_of(bytes: usize) -> String {
    "p".repeat(bytes)
}

/// A reminder content ref the wording doors parse: a due reminder of one
/// occurrence.
fn reminder_ref(due_at: u64) -> String {
    format!(
        "{COMMITMENT_REMINDER_CONTENT_PREFIX}{}:due:{due_at}",
        EntityId::now().to_hex()
    )
}

#[test]
fn a_nine_thousand_byte_promise_is_created_once_the_owner_raises_the_text_bound() {
    let (copy, vault) = owned_vault();
    provision_machines(&vault);
    let owner = door::owner(&vault).expect("the owner");
    let turn = witness_turn(&owner);
    set_applied(&owner, TEXT_KEY, json!(16_384));
    let receipt = create(&copy, &owner, &turn, &text_of(9_000))
        .expect("a 9,000-byte promise stands under the raised bound");
    let series = ref_of(&receipt["commitment"]);
    let text = get(&owner, &series)["content"]["text"]
        .as_str()
        .expect("the promise's text")
        .len();
    assert_eq!(text, 9_000);
}

#[test]
fn with_the_text_bound_unset_a_promise_past_eight_kib_is_refused() {
    let (copy, vault) = owned_vault();
    provision_machines(&vault);
    let owner = door::owner(&vault).expect("the owner");
    let turn = witness_turn(&owner);
    let refused = create(&copy, &owner, &turn, &text_of(8_193))
        .expect_err("8,193 bytes is past today's bound");
    assert!(refused.contains(TEXT_REFUSAL), "{refused}");
    create(&copy, &owner, &turn, &text_of(8_192)).expect("8,192 bytes is created on the default");
}

#[test]
fn a_text_bound_of_zero_or_past_the_ceiling_is_refused() {
    let (_copy, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    for value in [0, 65_537] {
        let refused =
            set(&owner, TEXT_KEY, json!(value)).expect_err("a bound outside 1..=65,536 is refused");
        assert!(
            refused.contains("from 1 to 65536 bytes"),
            "{value}: {refused}"
        );
    }
    set_applied(&owner, TEXT_KEY, json!(65_536));
}

#[test]
fn a_promise_stored_under_a_raised_bound_keeps_its_status_changes_after_the_owner_lowers_it() {
    let (copy, vault) = owned_vault();
    provision_machines(&vault);
    let owner = door::owner(&vault).expect("the owner");
    let turn = witness_turn(&owner);
    set_applied(&owner, TEXT_KEY, json!(16_384));
    let receipt = create(&copy, &owner, &turn, &text_of(9_000))
        .expect("a 9,000-byte promise stands under the raised bound");
    let series = ref_of(&receipt["commitment"]);
    let due = receipt["index"]["next_due"]
        .as_u64()
        .expect("the series is indexed");
    set_applied(&owner, TEXT_KEY, json!(8_192));

    // The projector mints the occurrence with the series' stored text.
    let now = copy.clock().now();
    copy.clock().advance(due - now);
    let minted = vault
        .reconcile_commitment_schedule(due)
        .expect("the projector runs")
        .minted_instances;
    assert_eq!(
        minted.len(),
        1,
        "the occurrence is minted under the lowered bound"
    );
    let occurrence = minted[0].to_hex();

    // A status change carries the stored text.
    let closed = door::invoke(
        &owner,
        "vault.commitments.fulfill",
        json!({"commitment_ref": occurrence, "source": {"kind": "user_done"}, "evidence_turn_refs": [turn]}),
    )
    .expect("the occurrence is fulfilled under the lowered bound");
    assert_eq!(closed["status"], "fulfilled");
    let text = get(&owner, &series)["content"]["text"]
        .as_str()
        .expect("the series' text")
        .len();
    assert_eq!(text, 9_000, "the stored promise still reads whole");
    let refused = create(&copy, &owner, &turn, &text_of(9_000))
        .expect_err("a new 9,000-byte promise is refused under the lowered bound");
    assert!(refused.contains(TEXT_REFUSAL), "{refused}");
}

#[test]
fn a_five_thousand_byte_reminder_wording_files_once_the_owner_raises_the_wording_bound() {
    let (copy, vault) = owned_vault();
    provision_machines(&vault);
    let owner = door::owner(&vault).expect("the owner");
    set_applied(&owner, WORDING_KEY, json!(8_192));
    let now = copy.clock().now();
    vault
        .file_commitment_reminder_wording(&reminder_ref(now + 10_000), &text_of(5_000), now)
        .expect("a 5,000-byte wording files under the raised bound");
}

#[test]
fn with_the_wording_bound_unset_a_wording_past_four_kib_is_refused() {
    let (copy, vault) = owned_vault();
    provision_machines(&vault);
    let now = copy.clock().now();
    let content_ref = reminder_ref(now + 10_000);
    let refused = vault
        .file_commitment_reminder_wording(&content_ref, &text_of(4_097), now)
        .expect_err("4,097 bytes is past today's bound");
    assert!(
        format!("{refused:?}").contains(WORDING_REFUSAL),
        "{refused:?}"
    );
    vault
        .file_commitment_reminder_wording(&content_ref, &text_of(4_096), now)
        .expect("4,096 bytes files on the default");
}

#[test]
fn a_wording_bound_of_zero_is_refused() {
    let (_copy, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let refused = set(&owner, WORDING_KEY, json!(0)).expect_err("a bound of zero is refused");
    assert!(refused.contains("at least one byte"), "{refused}");
}
