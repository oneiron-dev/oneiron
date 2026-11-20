//! Census row L5-25 remainder, FIX [RUN-RECEIPT-UNNAMED-TEXT-PROVENANCE]
//! (DEC-0005 world privacy, fix 12): a connector reply's model call names the
//! rows its prompt is read from, so its run's receipts name their worlds
//! (`RunAdmission::sourced`, `Vault::source_row_worlds`). Those rows are the
//! answering agent, whose instructions lead the prompt, every message of the
//! conversation's history, and the MESSAGE the exchange's inbound lands at.
//! A history message that names no row leaves them unknown.
//!
//! `cargo test --locked -p oneiron --all-features --test
//! connector_reply_source_rows`.

use oneiron::memory::TranscriptMessage;
use oneiron::surface_event::SurfaceConnectorPayload;
use oneiron::{EntityId, Vault};

const REPLY_REF: &str = "connector-reply";

fn origin(event: &str, identity: EntityId) -> SurfaceConnectorPayload {
    serde_json::from_value(serde_json::json!({
        "surface_event_id": event,
        "channel": "slack",
        "receiving_address_or_handle": "room-1",
        "receiving_identity_ref": identity.to_hex(),
        "actor_ref": identity.to_hex(),
        "counterparty": {"state": "known", "counterparty_ref": EntityId::now().to_hex()},
        "source": {"app": "slack", "user_ref": "U1"},
        "action": {"kind": "message"},
        "route": "actor_self",
        "thread_ref": "T1",
        "correlation_id": event,
        "received_at": 20,
        "foreign_inbound": true,
        "claims_not_instructions": true,
        "identity_retiring": false
    }))
    .expect("a connector origin decodes")
}

fn said(id: String, role: &str, text: &str) -> TranscriptMessage {
    TranscriptMessage {
        id,
        short_id: None,
        role: role.to_owned(),
        message_type: None,
        occurred: 10,
        text: text.to_owned(),
        metadata: None,
        result: None,
        incomplete: false,
        generating: false,
    }
}

#[test]
fn a_connector_reply_names_its_agent_history_and_inbound_rows() {
    let agent = EntityId::now();
    let origin = origin("event-2", EntityId::now());
    let earlier = EntityId::now();
    let answered = EntityId::now();
    let history = [
        said(earlier.to_hex(), "counterparty", "is the order on its way?"),
        said(answered.to_hex(), "companion", "it ships today"),
    ];
    let rows = Vault::connector_reply_source_rows(agent, &origin, REPLY_REF, &history)
        .expect("the exchange's ids derive")
        .expect("every history message names its row");
    for named in [agent, earlier, answered] {
        assert!(
            rows.contains(&named),
            "the reply's rows name {named:?}: {rows:?}"
        );
    }
    let inbound: Vec<&EntityId> = rows
        .iter()
        .filter(|row| ![agent, earlier, answered].contains(row))
        .collect();
    assert_eq!(
        inbound.len(),
        1,
        "one more row, the inbound MESSAGE: {rows:?}"
    );
    let alone = Vault::connector_reply_source_rows(agent, &origin, REPLY_REF, &[])
        .expect("the exchange's ids derive")
        .expect("no history is no unknown part");
    assert_eq!(
        alone.len(),
        2,
        "a first message's reply reads the agent and the inbound: {alone:?}"
    );
    assert!(alone.contains(&agent) && alone.contains(inbound[0]));
}

#[test]
fn each_exchange_names_its_own_inbound_row() {
    let agent = EntityId::now();
    let identity = EntityId::now();
    let inbound_of = |event: &str| {
        let rows =
            Vault::connector_reply_source_rows(agent, &origin(event, identity), REPLY_REF, &[])
                .expect("the exchange's ids derive")
                .expect("no history is no unknown part");
        rows.into_iter()
            .find(|row| *row != agent)
            .expect("the inbound MESSAGE is named")
    };
    assert_eq!(
        inbound_of("event-1"),
        inbound_of("event-1"),
        "a rerun names the same inbound row"
    );
    assert_ne!(
        inbound_of("event-1"),
        inbound_of("event-2"),
        "another message's reply names its own inbound row"
    );
}

#[test]
fn a_history_message_with_no_row_id_leaves_the_reply_unknown() {
    let agent = EntityId::now();
    let origin = origin("event-3", EntityId::now());
    let history = [
        said(EntityId::now().to_hex(), "counterparty", "hello"),
        said("not-a-row".to_owned(), "counterparty", "words from nowhere"),
    ];
    let rows = Vault::connector_reply_source_rows(agent, &origin, REPLY_REF, &history)
        .expect("the exchange's ids derive");
    assert_eq!(
        rows, None,
        "a part with no row leaves the reply's rows unknown"
    );
}
