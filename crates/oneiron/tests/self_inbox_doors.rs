//! The `self.inbox.*` doors keep the agent inbox promises (ruling L4-23 = A:
//! each test proves a promise at its public door). Every call enters through
//! `oneiron_testkit::door::invoke`, the generated verb dispatch every
//! transport shares, as the agent itself: `vault.memory(agent, Agent)`.
//!
//! - P1 canon `oneiron/planning/agent-mind-design-v1.md:86` "The inbox is a
//!   lens, never storage": a Digest NOTIFICATION addressed to the agent
//!   shows as one lens row; rendering twice answers the same page; once the
//!   notice is acknowledged in the store, the row is gone from the lens.
//! - P2 the same file, section 1.4 (read state): "Only explicit verbs write
//!   them. Rendering writes nothing": reading the lens and the notice list
//!   leaves the row new and the notice unseen; `get`, `later` and `done`
//!   move it to open, later and done.
//! - P3 the same file, "an item waits as an INBOX row until the agent opens
//!   it" (`self.inbox.get` opens a body): the unopened row carries refs and
//!   no body; `get` returns the notice and the row stays open.
//! - Refusals: an unknown row, a malformed cursor or notice id, a zero
//!   limit, a lens over another actor, and a concern card handle that is
//!   malformed or names no card.
//!
//! The notice is written as the engine writes one (`put_notification_in_txn`
//! is this same entity put; `Vault::put_entity` is its public door).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test self_inbox_doors`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use oneiron::inbox::{
    NotificationBody, NotificationKind, NotificationSource, encode_notification_body,
};
use oneiron::memory::Memory;
use oneiron::registry::ENTITY_TYPE_NOTIFICATION;
use oneiron::test_doors::coach::define_agent;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault};
use oneiron_testkit::{FixtureVault, TestVault, door, fixture_cache};
use serde_json::{Value, json};

/// A vault with one agent and one unacknowledged Digest notice addressed to
/// it. The `TestVault` holds the directory and must outlive the `Vault`.
struct Inbox {
    _dir: TestVault,
    vault: Vault,
    agent: EntityId,
    notice: EntityId,
    now: u64,
}

impl Inbox {
    fn new() -> Self {
        let dir = FixtureVault::empty(&fixture_cache!())
            .expect("the empty fixture")
            .copy()
            .expect("a private copy");
        let now = dir.clock().now();
        let vault = dir.open_owned().expect("an owned open");
        let _issuer = oneiron::test_support::provision_engine_machines(&vault);
        let agent = define_agent(&vault).expect("an agent");
        let notice = EntityId::now();
        let body = NotificationBody {
            kind: NotificationKind::Digest,
            source: NotificationSource {
                producer: "self-inbox-doors".to_owned(),
                event: notice.to_hex(),
                ..NotificationSource::default()
            },
            subject_refs: Vec::new(),
            recipient: Some(agent.to_hex()),
            created_at: now,
            origin_conversation: None,
            seen_by: BTreeMap::new(),
            acked_by: BTreeMap::new(),
        };
        let bytes = encode_notification_body(&body).expect("the notice encodes");
        vault
            .put_entity(
                &notice,
                ENTITY_TYPE_NOTIFICATION,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &bytes,
            )
            .expect("the notice lands");
        Self {
            _dir: dir,
            vault,
            agent,
            notice,
            now,
        }
    }

    /// The agent, as a caller of its own doors.
    fn agent(&self) -> Memory<'_> {
        self.vault.memory(self.agent, EdgeActorClass::Agent)
    }

    /// The lens row the notice projects.
    fn row_id(&self) -> String {
        format!("digest:{}", self.notice.to_hex())
    }
}

fn lens(agent: &Memory<'_>) -> Value {
    door::invoke(agent, "self.inbox.lens", json!({})).expect("the agent reads its lens")
}

fn lens_row(page: &Value, item_id: &str) -> Option<Value> {
    page["items"]
        .as_array()
        .expect("lens items")
        .iter()
        .find(|row| row["item_id"] == item_id)
        .cloned()
}

/// The read state the lens shows on the row `item_id`.
fn read_state(agent: &Memory<'_>, item_id: &str) -> Value {
    lens_row(&lens(agent), item_id).expect("the row")["read_state"].clone()
}

/// The notice `id` on one `self.inbox.list` page.
fn listed(agent: &Memory<'_>, id: &EntityId) -> Value {
    let page = door::invoke(agent, "self.inbox.list", json!({})).expect("the agent lists");
    page["rows"]
        .as_array()
        .expect("list rows")
        .iter()
        .find(|row| row["id"] == id.to_hex())
        .cloned()
        .expect("the notice is listed")
}

#[test]
fn the_inbox_is_a_lens_over_the_store() {
    let inbox = Inbox::new();
    let agent = inbox.agent();
    let first = lens(&agent);
    let row = lens_row(&first, &inbox.row_id()).expect("the notice projects one row");
    assert_eq!(row["kind"], "digest");
    assert_eq!(row["pile"], "updates");
    assert_eq!(row["payload_ref"], inbox.notice.to_hex());
    assert_eq!(lens(&agent), first, "rendering again answers the same page");

    let acked = door::invoke(
        &agent,
        "self.inbox.mark",
        json!({"notification_ref": inbox.notice.to_hex(), "mark": "acked"}),
    )
    .expect("the agent acknowledges its notice");
    assert_eq!(acked["acked"], true);
    assert!(
        lens_row(&lens(&agent), &inbox.row_id()).is_none(),
        "the store acknowledged the notice, so the lens shows no row"
    );
}

#[test]
fn only_explicit_verbs_write_read_state() {
    let inbox = Inbox::new();
    let agent = inbox.agent();
    let row_id = inbox.row_id();

    assert_eq!(read_state(&agent, &row_id), "new");
    assert_eq!(
        read_state(&agent, &row_id),
        "new",
        "rendering the lens writes nothing"
    );
    let notice = listed(&agent, &inbox.notice);
    assert_eq!(
        (&notice["seen"], &notice["acked"]),
        (&json!(false), &json!(false))
    );
    let notice = listed(&agent, &inbox.notice);
    assert_eq!(notice["seen"], false, "listing writes nothing");
    assert_eq!(read_state(&agent, &row_id), "new");

    let opened = door::invoke(&agent, "self.inbox.get", json!({"item_id": row_id}))
        .expect("the agent opens the row");
    assert_eq!(opened["item"]["read_state"], "open");
    assert_eq!(read_state(&agent, &row_id), "open");
    assert_eq!(
        listed(&agent, &inbox.notice)["seen"],
        true,
        "opening sees the notice"
    );

    let until = inbox.now + 3600;
    let later = door::invoke(
        &agent,
        "self.inbox.later",
        json!({"item_id": row_id, "until": until}),
    )
    .expect("the agent puts the row off");
    assert_eq!(later["read_state"], "later");
    assert_eq!(later["until"], until);
    assert_eq!(read_state(&agent, &row_id), "later");

    let done = door::invoke(&agent, "self.inbox.done", json!({"item_id": row_id}))
        .expect("the agent closes the row");
    assert_eq!(done["read_state"], "done");
    assert_eq!(
        listed(&agent, &inbox.notice)["acked"],
        true,
        "done acknowledges the notice"
    );
}

#[test]
fn a_row_waits_unopened_until_get() {
    let inbox = Inbox::new();
    let agent = inbox.agent();
    let row = lens_row(&lens(&agent), &inbox.row_id()).expect("the row waits");
    assert_eq!(row["read_state"], "new");
    assert!(
        row.get("messages").is_none() && row.get("notification").is_none(),
        "an unopened row carries refs, no body: {row}"
    );

    let opened = door::invoke(&agent, "self.inbox.get", json!({"item_id": inbox.row_id()}))
        .expect("the agent opens the row");
    assert_eq!(opened["item"]["item_id"], inbox.row_id());
    assert_eq!(opened["notification"]["id"], inbox.notice.to_hex());
    assert_eq!(
        lens_row(&lens(&agent), &inbox.row_id()).expect("the row stays")["read_state"],
        "open",
        "an opened row stays open until it is done"
    );
}

#[test]
fn a_malformed_or_foreign_inbox_act_is_refused() {
    let inbox = Inbox::new();
    let agent = inbox.agent();
    let other = define_agent(&inbox.vault).expect("a second agent");
    let unknown = EntityId::now().to_hex();
    let no_card = format!("health:{}:loop:{}", inbox.agent.to_hex(), "0".repeat(32));
    let rows: Vec<(&str, &str, Value, Option<&str>)> = vec![
        (
            "get an unknown row",
            "self.inbox.get",
            json!({"item_id": "digest:nothing"}),
            Some("NOT_FOUND"),
        ),
        (
            "close an unknown row",
            "self.inbox.done",
            json!({"item_id": "digest:nothing"}),
            Some("NOT_FOUND"),
        ),
        (
            "put off an unknown row",
            "self.inbox.later",
            json!({"item_id": "digest:nothing"}),
            Some("NOT_FOUND"),
        ),
        (
            "list zero rows",
            "self.inbox.list",
            json!({"limit": 0}),
            Some("BAD_REQUEST"),
        ),
        (
            "list after a non-id",
            "self.inbox.list",
            json!({"after": "not-an-id"}),
            Some("BAD_REQUEST"),
        ),
        (
            "mark a non-id",
            "self.inbox.mark",
            json!({"notification_ref": "not-an-id", "mark": "seen"}),
            Some("BAD_REQUEST"),
        ),
        (
            "mark a notice never delivered",
            "self.inbox.mark",
            json!({"notification_ref": unknown, "mark": "seen"}),
            Some("NOT_FOUND"),
        ),
        (
            "mark with an unknown mark",
            "self.inbox.mark",
            json!({"notification_ref": inbox.notice.to_hex(), "mark": "read"}),
            None,
        ),
        (
            "read another agent's lens",
            "self.inbox.lens",
            json!({"agent": other.to_hex()}),
            Some("BAD_REQUEST"),
        ),
        (
            "an unknown field",
            "self.inbox.get",
            json!({"item_id": inbox.row_id(), "extra": 1}),
            None,
        ),
        (
            "read a malformed card",
            "self.inbox.concern",
            json!({"card": "not-a-handle"}),
            Some("BAD_REQUEST"),
        ),
        (
            "read a card that does not exist",
            "self.inbox.concern",
            json!({"card": no_card}),
            Some("NOT_FOUND"),
        ),
        (
            "settle a malformed card",
            "self.inbox.concern.outcome",
            json!({"card": "not-a-handle", "outcome": "dismissed"}),
            Some("BAD_REQUEST"),
        ),
        (
            "settle a card that does not exist",
            "self.inbox.concern.outcome",
            json!({"card": no_card, "outcome": "dismissed"}),
            Some("NOT_FOUND"),
        ),
        (
            "settle with an unknown outcome",
            "self.inbox.concern.outcome",
            json!({"card": no_card, "outcome": "ignored"}),
            None,
        ),
        (
            "move on a malformed card",
            "self.inbox.concern.move",
            json!({"card": "not-a-handle", "move": "ask_coach"}),
            Some("BAD_REQUEST"),
        ),
        (
            "move on a card that does not exist",
            "self.inbox.concern.move",
            json!({"card": no_card, "move": "ask_coach"}),
            Some("NOT_FOUND"),
        ),
    ];
    for (name, verb, body, code) in rows {
        let refused = door::invoke(&agent, verb, body).expect_err(&format!("refused: {name}"));
        if let Some(code) = code {
            assert_eq!(refused.code, code, "{name}: {refused:?}");
        }
    }
    // Nothing above moved the row.
    assert_eq!(
        lens_row(&lens(&agent), &inbox.row_id()).expect("the row")["read_state"],
        "new"
    );
}
