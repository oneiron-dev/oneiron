//! The `vault.commitments.*` doors keep the commitment promises (ruling
//! L4-23 = A: each test proves a promise at its public door). Every call
//! enters through `oneiron_testkit::door::invoke`, the generated verb
//! dispatch every transport shares; all ten rows are the owner's, so they run
//! on a vault opened with the process writer lease (`TestVault::open_owned`),
//! as an embedded host's are. No verb runs the projector, so the tests move
//! the fixture clock and call the public `Vault::reconcile_commitment_schedule`
//! (the engine's one projector), as the reconciler does.
//!
//! - P1 `canon cross/hosting/cross-arch-0022-node-supervisor-vault-lifecycle.md:195`
//!   "Commitments fire EVENT-class wakes on the existing projector and
//!   reconciler": `vault.commitments.create` indexes the series in its own
//!   write, and the existing projector mints the occurrence at its lead time
//!   (due minus `lead_seconds`), not before; birth fires and approves nothing.
//! - P2 the fulfill, release and supersede rows ("confirms an obligation
//!   fulfilled", "releases an obligation", "supersedes an obligation"): each
//!   moves a materialized occurrence to its own terminal status, and a series
//!   head is not closed.
//! - P3 the ledger row ("due-sorted open obligations owed by and to one
//!   counterparty contact"): the dues the contact owes and the dues owed to it
//!   are listed while open, in due order; a closed one leaves the ledger and
//!   stays point-readable.
//! - P4 the reminder_route rows ("null when unset", "Sets (or, with null,
//!   clears) ... under the native validation"): the route round-trips, null
//!   clears it, and an invalid route is refused.
//! - Refusals, one table: an agent caller on all ten rows, malformed bodies,
//!   unknown ids and a bad schedule.
//!
//! Not in this file: `cross-arch-0022:317` "An agent minting \"check X every
//! morning\" is minting a commitment" takes the proposing claim door
//! (`vault.claims.upsert`; the landed series projects once approved), not
//! these owner rows, which refuse an agent; and "one with no transport fails
//! the attempt as not started" is the server's connector-send drain
//! (`crates/oneiron-server/src/server/connector_sends.rs`), which no
//! in-process door reaches.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test vault_commitments_doors`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::channel_identity::{ChannelIdentity, ChannelIdentityBinding, SelfHeldShape};
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::memory::Memory;
use oneiron::{EdgeActorClass, EntityId, Vault};
use oneiron_testkit::{FixtureVault, TestVault, door, fixture_cache};
use serde_json::{Value, json};

/// The lead every series here asks: its occurrence is minted this long
/// before it is due.
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
/// projector mints each occurrence as one of them.
fn provision_machines(vault: &Vault) {
    let _issuer = oneiron::test_support::provision_engine_machines(vault);
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

/// A `vault.commitments.create` body for a one-off promise due at `due`.
fn once_body(
    obligor: (&str, &str),
    beneficiary: &str,
    text: &str,
    due: u64,
    now: u64,
    turn: &str,
) -> Value {
    json!({
        "obligor": {"kind": obligor.0, "entity_ref": obligor.1},
        "beneficiary": beneficiary,
        "content": {"text": text},
        "schedule": {"kind": "once", "due": due},
        "lead_seconds": LEAD,
        "strength": "commitment",
        "birth_provenance": {"kind": "run_tree_node", "reference": "run:commitment-doors"},
        "occurred_at": now,
        "evidence_turn_refs": [turn],
    })
}

/// Creates one series; the create receipt.
fn create(owner: &Memory<'_>, body: Value) -> Value {
    door::invoke(owner, "vault.commitments.create", body).expect("the owner creates a commitment")
}

fn ref_of(view: &Value) -> String {
    view["commitment_ref"]
        .as_str()
        .expect("the view names its commitment")
        .to_owned()
}

/// Moves the fixture clock to `at` and runs the existing projector there;
/// the hex ids of the occurrences that pass minted.
fn reconcile_at(copy: &TestVault, vault: &Vault, at: u64) -> Vec<String> {
    let now = copy.clock().now();
    assert!(at >= now, "the clock only moves forward here");
    copy.clock().advance(at - now);
    vault
        .reconcile_commitment_schedule(at)
        .expect("the projector runs")
        .minted_instances
        .iter()
        .map(EntityId::to_hex)
        .collect()
}

/// A one-off owner promise due 10,000 s out, projected at its due time (past
/// any lead, so a lead fault leaves this setup whole); (series, occurrence).
fn projected_promise(
    copy: &TestVault,
    vault: &Vault,
    owner: &Memory<'_>,
    turn: &str,
    text: &str,
) -> (String, String) {
    let me = owner.actor().to_hex();
    let now = copy.clock().now();
    let due = now + 10_000;
    let series =
        ref_of(&create(owner, once_body(("owner", &me), &me, text, due, now, turn))["commitment"]);
    let minted = reconcile_at(copy, vault, due);
    assert_eq!(minted.len(), 1, "fixture: one occurrence minted");
    (series, minted[0].clone())
}

fn get(owner: &Memory<'_>, commitment: &str) -> Value {
    door::invoke(
        owner,
        "vault.commitments.get",
        json!({"commitment_ref": commitment}),
    )
    .expect("the owner reads a commitment")
}

fn list(owner: &Memory<'_>, verb: &str, commitment: &str) -> Vec<Value> {
    door::invoke(owner, verb, json!({"commitment_ref": commitment}))
        .unwrap_or_else(|error| panic!("{verb} reads: {error:?}"))
        .as_array()
        .expect("an array")
        .clone()
}

/// The close body for `verb` on `commitment`.
fn close_body(verb: &str, commitment: &str, turn: &str) -> Value {
    if verb == "vault.commitments.fulfill" {
        json!({"commitment_ref": commitment, "source": {"kind": "user_done"}, "evidence_turn_refs": [turn]})
    } else {
        json!({"commitment_ref": commitment, "evidence_turn_refs": [turn]})
    }
}

/// P1 (ARCH-0022:195). Create indexes the series in its own write; the
/// existing projector mints the occurrence at due minus lead, and nothing
/// before; birth fires and approves nothing.
/// Red proof: `commitment_schedule/projection/occurrences.rs:41` projects at
/// the due time itself, so the lead pass mints nothing.
#[test]
fn the_existing_projector_mints_an_occurrence_at_its_lead() {
    let (copy, vault) = owned_vault();
    provision_machines(&vault);
    let owner = door::owner(&vault).expect("the owner");
    let me = owner.actor().to_hex();
    let turn = witness_turn(&owner);
    let now = copy.clock().now();
    let due = now + 10_000;

    let receipt = create(
        &owner,
        once_body(
            ("owner", &me),
            &me,
            "send the signed lease",
            due,
            now,
            &turn,
        ),
    );
    assert_eq!(receipt["index"]["outcome"], "indexed", "{receipt}");
    assert_eq!(receipt["index"]["next_due"], due);
    assert_eq!(receipt["index"]["project_at"], due - LEAD);
    let series = ref_of(&receipt["commitment"]);
    assert_eq!(receipt["commitment"]["status"], "open");
    assert!(
        receipt["commitment"]["occurrence"].is_null(),
        "the birth is the series"
    );
    assert!(list(&owner, "vault.commitments.instances", &series).is_empty());

    assert!(
        reconcile_at(&copy, &vault, due - LEAD - 1).is_empty(),
        "nothing is minted before the lead"
    );
    let minted = reconcile_at(&copy, &vault, due - LEAD);
    assert_eq!(minted.len(), 1, "the lead pass mints the occurrence");

    let occurrences = list(&owner, "vault.commitments.instances", &series);
    assert_eq!(occurrences.len(), 1);
    assert_eq!(ref_of(&occurrences[0]), minted[0]);
    assert_eq!(occurrences[0]["occurrence"]["due_at"], due);
    assert_eq!(occurrences[0]["series_ref"].as_str(), Some(series.as_str()));
    assert_eq!(occurrences[0]["status"], "open");
    assert!(
        list(&owner, "vault.commitments.proposals", &series).is_empty(),
        "birth and projection fire and approve nothing"
    );
}

/// P2 (fulfill/release/supersede rows). Each close moves a materialized
/// occurrence to its own terminal status; a series head is not closed.
/// Red proof: `memory/commitment_doors/mod.rs:440` closes a release as
/// superseded.
#[test]
fn each_close_moves_an_occurrence_to_its_terminal_status() {
    let (copy, vault) = owned_vault();
    provision_machines(&vault);
    let owner = door::owner(&vault).expect("the owner");
    let turn = witness_turn(&owner);

    for (verb, status) in [
        ("vault.commitments.fulfill", "fulfilled"),
        ("vault.commitments.release", "released"),
        ("vault.commitments.supersede", "superseded"),
    ] {
        let (series, occurrence) = projected_promise(&copy, &vault, &owner, &turn, verb);
        let closed = door::invoke(&owner, verb, close_body(verb, &occurrence, &turn))
            .unwrap_or_else(|error| panic!("{verb} closes the occurrence: {error:?}"));
        assert_eq!(closed["status"], status, "{verb}");
        assert_eq!(
            get(&owner, &occurrence)["status"],
            status,
            "{verb} is read back"
        );
        if verb == "vault.commitments.fulfill" {
            assert_eq!(
                closed["receipt"]["fulfillment_source"],
                json!({"kind": "user_done"})
            );
        }

        let error = door::invoke(&owner, verb, close_body(verb, &series, &turn))
            .expect_err("a series head is not closed");
        assert_eq!(error.code, "BAD_REQUEST", "{verb} on the series head");
    }
}

/// P3 (ledger row). The dues a contact owes and the dues owed to it are
/// listed while open, in due order; a closed one leaves the ledger and stays
/// point-readable.
/// Red proof: `memory/commitment_doors/ledger.rs:54` keeps the closed rows
/// and drops the open ones.
#[test]
fn the_ledger_lists_open_dues_and_drops_a_closed_one() {
    let (copy, vault) = owned_vault();
    let now = copy.clock().now();
    // The contact and its local channel identity, through the engine's own
    // create doors (no verb writes them).
    let identity = EntityId::from_bytes([0x41; 16]).expect("an identity id");
    vault
        .create_channel_identity(
            &identity,
            &ChannelIdentity::requested(
                "email",
                "owner@example.test",
                SelfHeldShape::DedicatedAddress,
                ChannelIdentityBinding::actor(
                    vault.ensure_embedded_owner_actor().expect("the owner"),
                ),
                now,
            ),
        )
        .expect("the channel identity");
    let contact = EntityId::from_bytes([0x42; 16]).expect("a contact id");
    vault
        .create_counterparty_contact(
            &contact,
            &CounterpartyContactRecord::user_introduction(identity, "them@example.test", now)
                .expect("a contact record"),
        )
        .expect("the contact");
    let them = contact.to_hex();
    provision_machines(&vault);
    let owner = door::owner(&vault).expect("the owner");
    let me = owner.actor().to_hex();
    let turn = witness_turn(&owner);

    let (early, late) = (now + 10_000, now + 20_000);
    create(
        &owner,
        once_body(
            ("third_party", &them),
            &me,
            "they send the report",
            late,
            now,
            &turn,
        ),
    );
    create(
        &owner,
        once_body(
            ("third_party", &them),
            &me,
            "they sign the form",
            early,
            now,
            &turn,
        ),
    );
    create(
        &owner,
        once_body(
            ("owner", &me),
            &them,
            "we pay the invoice",
            late,
            now,
            &turn,
        ),
    );
    let minted = reconcile_at(&copy, &vault, late);
    assert_eq!(minted.len(), 3, "fixture: three occurrences minted");

    let read = |what: &str| {
        door::invoke(
            &owner,
            "vault.commitments.ledger",
            json!({"contact_ref": them}),
        )
        .unwrap_or_else(|error| panic!("the ledger reads {what}: {error:?}"))
    };
    let refs = |ledger: &Value, side: &str| -> Vec<String> {
        ledger[side]
            .as_array()
            .expect("a ledger side")
            .iter()
            .map(|item| ref_of(&item["commitment"]))
            .collect()
    };
    let ledger = read("while open");
    assert_eq!(ledger["contact_ref"].as_str(), Some(them.as_str()));
    assert_eq!(ledger["channel"], "email");
    assert_eq!(ledger["counterparty"], "them@example.test");
    for side in ["owed_by_them", "owed_to_them"] {
        let from: Vec<u64> = ledger[side]
            .as_array()
            .expect("a ledger side")
            .iter()
            .map(|item| item["valid_from"].as_u64().expect("a due key"))
            .collect();
        assert!(
            from.windows(2).all(|pair| pair[0] <= pair[1]),
            "{side} is due-sorted: {from:?}"
        );
    }
    let (by_them, to_them) = (refs(&ledger, "owed_by_them"), refs(&ledger, "owed_to_them"));
    for occurrence in &minted {
        let side = if get(&owner, occurrence)["obligor"]["kind"] == "third_party" {
            &by_them
        } else {
            &to_them
        };
        assert!(
            side.contains(occurrence),
            "open due {occurrence} is listed: {ledger}"
        );
    }

    let closed = &minted[0];
    door::invoke(
        &owner,
        "vault.commitments.fulfill",
        close_body("vault.commitments.fulfill", closed, &turn),
    )
    .expect("the owner fulfils one due");
    let ledger = read("after a close");
    for side in ["owed_by_them", "owed_to_them"] {
        assert!(
            !refs(&ledger, side).contains(closed),
            "the closed due leaves {side}"
        );
    }
    assert_eq!(
        refs(&ledger, "owed_by_them").len() + refs(&ledger, "owed_to_them").len(),
        by_them.len() + to_them.len() - 1,
        "only the closed due leaves"
    );
    assert_eq!(
        get(&owner, closed)["status"],
        "fulfilled",
        "the closed due stays readable"
    );
}

/// P4 (reminder_route rows). The route round-trips, null clears it, and an
/// invalid route is refused.
/// Red proof: `commitment_wake/reminder.rs:82` drops the channel check, so a
/// route with an empty channel lands.
#[test]
fn the_reminder_route_round_trips_and_refuses_an_invalid_route() {
    let (_copy, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let get_route = || {
        door::invoke(&owner, "vault.commitments.reminder_route.get", json!({}))
            .expect("the owner reads the route")["route"]
            .clone()
    };
    assert!(get_route().is_null(), "no route until one is set");

    let set = door::invoke(
        &owner,
        "vault.commitments.reminder_route.set",
        json!({"route": {"channel": "chat", "verb": "send", "target": "owner:primary", "utc_offset_minutes": 540}}),
    )
    .expect("the owner sets a route");
    let route = get_route();
    assert_eq!(route, set["route"], "the set answer is the stored route");
    assert_eq!(route["channel"], "chat");
    assert_eq!(route["verb"], "send");
    assert_eq!(route["target"], "owner:primary");
    assert_eq!(route["utc_offset_minutes"], 540);

    let cleared = door::invoke(
        &owner,
        "vault.commitments.reminder_route.set",
        json!({"route": null}),
    )
    .expect("the owner clears the route");
    assert!(cleared["route"].is_null());
    assert!(get_route().is_null(), "null clears the route");

    for (case, route) in [
        (
            "an empty channel",
            json!({"channel": "", "verb": "send", "target": "owner:primary"}),
        ),
        (
            "an empty target",
            json!({"channel": "chat", "verb": "send", "target": ""}),
        ),
        (
            "an offset past 14 h",
            json!({"channel": "chat", "verb": "send", "target": "owner:primary", "utc_offset_minutes": 999}),
        ),
        (
            "an unknown zone with no offset",
            json!({"channel": "chat", "verb": "send", "target": "owner:primary", "iana_timezone": "Nowhere/Nothing"}),
        ),
    ] {
        let error = door::invoke(
            &owner,
            "vault.commitments.reminder_route.set",
            json!({"route": route}),
        )
        .expect_err(case);
        assert_eq!(error.code, "BAD_REQUEST", "{case}: {error:?}");
        assert!(get_route().is_null(), "{case} leaves no route");
    }
}

/// Refusals. An agent is refused every row, its body well formed (the
/// dispatch decodes the body before the owner check); the owner's malformed
/// bodies, unknown ids and bad schedule are refused with their codes.
/// Red proof: `memory/owner_door.rs:85` answers a non-owner NOT_FOUND
/// (`-red1`); `memory/commitment_doors/types.rs:15` lets an unknown field
/// into a create (`-red2`).
#[test]
fn a_foreign_or_malformed_commitment_act_is_refused() {
    let (copy, vault) = owned_vault();
    let agent = oneiron::test_doors::coach::define_agent(&vault).expect("an agent");
    provision_machines(&vault);
    let owner = door::owner(&vault).expect("the owner");
    let me = owner.actor().to_hex();
    let turn = witness_turn(&owner);
    let (series, occurrence) = projected_promise(&copy, &vault, &owner, &turn, "refusal fixture");
    let now = copy.clock().now();
    let unknown = EntityId::from_bytes([0x99; 16])
        .expect("an unused id")
        .to_hex();
    let promise = once_body(("owner", &me), &me, "x", now + 10_000, now, &turn);

    let agent = vault.memory(agent, EdgeActorClass::Agent);
    for (verb, body) in [
        ("vault.commitments.create", promise.clone()),
        (
            "vault.commitments.get",
            json!({"commitment_ref": occurrence}),
        ),
        (
            "vault.commitments.instances",
            json!({"commitment_ref": series}),
        ),
        (
            "vault.commitments.proposals",
            json!({"commitment_ref": series}),
        ),
        ("vault.commitments.ledger", json!({"contact_ref": unknown})),
        (
            "vault.commitments.fulfill",
            close_body("vault.commitments.fulfill", &occurrence, &turn),
        ),
        (
            "vault.commitments.release",
            close_body("vault.commitments.release", &occurrence, &turn),
        ),
        (
            "vault.commitments.supersede",
            close_body("vault.commitments.supersede", &occurrence, &turn),
        ),
        ("vault.commitments.reminder_route.get", json!({})),
        (
            "vault.commitments.reminder_route.set",
            json!({"route": null}),
        ),
    ] {
        let error = door::invoke(&agent, verb, body).expect_err(verb);
        assert_eq!(error.code, "FORBIDDEN", "an agent on {verb}: {error:?}");
    }
    assert_eq!(
        get(&owner, &occurrence)["status"],
        "open",
        "no agent act closed it"
    );

    let with = |field: &str, value: Value| {
        let mut body = promise.clone();
        body[field] = value;
        body
    };
    for (case, verb, body, code) in [
        (
            "an unknown field",
            "vault.commitments.create",
            with("bogus", json!(1)),
            "BAD_REQUEST",
        ),
        (
            "a zero interval",
            "vault.commitments.create",
            with(
                "schedule",
                json!({"kind": "interval", "period": 0, "anchor": now}),
            ),
            "BAD_REQUEST",
        ),
        (
            "a promise learned before it was made",
            "vault.commitments.create",
            with("learned_at", json!(now - 1)),
            "BAD_REQUEST",
        ),
        (
            "no evidence",
            "vault.commitments.create",
            with("evidence_turn_refs", json!([])),
            "BAD_REQUEST",
        ),
        (
            "evidence that is no TURN",
            "vault.commitments.create",
            with("evidence_turn_refs", json!([series])),
            "BAD_REQUEST",
        ),
        (
            "a malformed party",
            "vault.commitments.create",
            with("beneficiary", json!("zzz")),
            "BAD_REQUEST",
        ),
        (
            "an unknown party",
            "vault.commitments.create",
            with("beneficiary", json!(unknown)),
            "NOT_FOUND",
        ),
        (
            "a malformed ref",
            "vault.commitments.get",
            json!({"commitment_ref": "zzz"}),
            "BAD_REQUEST",
        ),
        (
            "an unknown commitment",
            "vault.commitments.get",
            json!({"commitment_ref": unknown}),
            "NOT_FOUND",
        ),
        (
            "an unknown series",
            "vault.commitments.instances",
            json!({"commitment_ref": unknown}),
            "NOT_FOUND",
        ),
        (
            "an unknown series",
            "vault.commitments.proposals",
            json!({"commitment_ref": unknown}),
            "NOT_FOUND",
        ),
        (
            "an unknown contact",
            "vault.commitments.ledger",
            json!({"contact_ref": unknown}),
            "NOT_FOUND",
        ),
        (
            "an unknown commitment",
            "vault.commitments.fulfill",
            close_body("vault.commitments.fulfill", &unknown, &turn),
            "NOT_FOUND",
        ),
        (
            "an unknown brief",
            "vault.commitments.fulfill",
            json!({"commitment_ref": occurrence, "source": {"kind": "brief_completion", "brief_ref": unknown}, "evidence_turn_refs": [turn]}),
            "NOT_FOUND",
        ),
        (
            "an unknown commitment",
            "vault.commitments.release",
            close_body("vault.commitments.release", &unknown, &turn),
            "NOT_FOUND",
        ),
        (
            "an unknown commitment",
            "vault.commitments.supersede",
            close_body("vault.commitments.supersede", &unknown, &turn),
            "NOT_FOUND",
        ),
        (
            "an unknown field",
            "vault.commitments.reminder_route.get",
            json!({"bogus": 1}),
            "BAD_REQUEST",
        ),
        (
            "a route missing its verb and target",
            "vault.commitments.reminder_route.set",
            json!({"route": {"channel": "chat"}}),
            "BAD_REQUEST",
        ),
    ] {
        let error = door::invoke(&owner, verb, body).expect_err(case);
        assert_eq!(error.code, code, "{verb} with {case}: {error:?}");
    }
    assert_eq!(
        get(&owner, &occurrence)["status"],
        "open",
        "no refused act closed it"
    );
}
