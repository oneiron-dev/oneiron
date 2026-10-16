//! F05 repros at the SDK surface: a lens tree, a generated-UI segment stream,
//! a client state patch and a PsychProfile snapshot are each refused at the
//! first entry past their bound, before the rest of the input is read or
//! copied. Each over-bound input is followed by a tail the decoder must never
//! reach; the shipped decoders read on into it.

use std::io::{self, Read};

use oneiron::lens::{
    GENERATED_UI_WIRE_VERSION, GeneratedUiActionEvent, GeneratedUiRender, GeneratedUiSegment,
    LensNode,
};
use oneiron::psych_profile::{
    PsychProfile, PsychProfileConfidence, decode_psych_profile_body, encode_psych_profile_body,
};
use oneiron::{EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

/// Most source revisions one PsychProfile snapshot cites (the engine's bound).
const SOURCE_BOUND: usize = 4096;

/// A reader whose bytes end where the decoder must have stopped.
struct ReadPastRefusal;

impl Read for ReadPastRefusal {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("the decoder read past the refusal point"))
    }
}

fn decode_prefix<T: serde::de::DeserializeOwned>(prefix: &str) -> serde_json::Error {
    let Err(error) = serde_json::from_reader::<_, T>(prefix.as_bytes().chain(ReadPastRefusal))
    else {
        panic!("a truncated input cannot decode");
    };
    error
}

fn leaf(id: &str) -> String {
    format!(
        r#"{{"id":"{id}","atom":{{"kind":"throbber","props":{{"label":"loading"}}}},"fallbackText":"{id}"}}"#
    )
}

fn leaves(prefix: &str, count: usize) -> String {
    (0..count)
        .map(|n| leaf(&format!("{prefix}{n}")))
        .collect::<Vec<_>>()
        .join(",")
}

fn branch_open(id: &str) -> String {
    format!(
        r#"{{"id":"{id}","atom":{{"kind":"throbber","props":{{"label":"loading"}}}},"fallbackText":"{id}","children":["#
    )
}

#[test]
fn a_lens_tree_past_its_shared_entry_budget_is_refused_at_the_first_excess_entry() {
    // Two branches whose child arrays are each under the per-array cap but
    // together pass the 4096-entry tree budget: 2 + 2048 + 2047 entries fit,
    // the next one does not.
    let over = format!(
        "{root}{a}{a_leaves}]}},{b}{b_leaves},",
        root = branch_open("root"),
        a = branch_open("a"),
        a_leaves = leaves("a", 2048),
        b = branch_open("b"),
        b_leaves = leaves("b", 2100),
    );
    let error = decode_prefix::<LensNode>(&over);
    assert!(!error.is_io(), "decoder read past the budget: {error}");
    assert!(
        error
            .to_string()
            .contains("generated lens collections must contain at most 4096 total items"),
        "{error}"
    );

    // Control: the largest tree validation admits (4096 nodes, 4095 entries)
    // still decodes whole.
    let at_bound = format!(
        "{root}{a}{a_leaves}]}},{b}{b_leaves}]}}]}}",
        root = branch_open("root"),
        a = branch_open("a"),
        a_leaves = leaves("a", 2048),
        b = branch_open("b"),
        b_leaves = leaves("b", 2045),
    );
    let tree: LensNode = serde_json::from_str(&at_bound).expect("a tree at the bound decodes");
    assert_eq!(
        tree.children[0].children.len() + tree.children[1].children.len(),
        4093
    );
}

fn segment(kind: &str, payload: Value) -> GeneratedUiSegment {
    serde_json::from_value(json!({ "segment": kind, "payload": payload })).expect("segment")
}

fn element(card_id: &str, node_id: &str) -> GeneratedUiSegment {
    segment(
        "card_element",
        json!({
            "protocolVersion": GENERATED_UI_WIRE_VERSION,
            "cardId": card_id,
            "node": {
                "id": node_id,
                "atom": { "kind": "throbber", "props": { "label": "loading" } },
                "fallbackText": node_id
            }
        }),
    )
}

#[test]
fn a_segment_stream_is_refused_at_the_first_element_past_its_declared_count() {
    let start = segment(
        "card_start",
        json!({
            "protocolVersion": GENERATED_UI_WIRE_VERSION,
            "catalog": "lens_atom_kit",
            "cardId": "card-1",
            "root": "root",
            "nodeCount": 1,
            "fallbackText": "root"
        }),
    );
    let state = segment(
        "card_state_update",
        json!({
            "protocolVersion": GENERATED_UI_WIRE_VERSION,
            "cardId": "card-1",
            "dataModel": {
                "root": "root",
                "nodeCount": 1,
                "catalog": "lens_atom_kit",
                "lifecycle": { "phase": "active", "revision": 0 }
            }
        }),
    );

    // The element after the excess one names another card; a reader that walks
    // on past the declared count reports that instead of the over-count.
    let over = [
        start.clone(),
        element("card-1", "root"),
        element("card-1", "extra"),
        element("card-2", "stray"),
        state.clone(),
    ];
    let error = GeneratedUiRender::from_segments(&over).expect_err("over-count stream");
    assert!(
        error
            .to_string()
            .contains("card_element count must match card_start node count"),
        "{error}"
    );

    let render = GeneratedUiRender::from_segments(&[start, element("card-1", "root"), state])
        .expect("a stream at its declared count reassembles");
    assert_eq!(render.nodes.len(), 1);
}

#[test]
fn a_state_patch_path_longer_than_any_state_pointer_stops_the_event_decode() {
    let event_head =
        r#"{"cardId":"card-1","elementId":"remind","actionId":"reminder.toggle","patch":["#;
    let long_path = format!("/$state/{}", "k".repeat(200));
    let over = format!(
        r#"{event_head}{{"op":"replace","path":"{long_path}","value":{{"type":"bool","value":true}}}},"#
    );
    let error = decode_prefix::<GeneratedUiActionEvent>(&over);
    assert!(!error.is_io(), "decoder read past the long path: {error}");
    assert!(
        error
            .to_string()
            .contains("generated-ui state patch path must be at most 136 bytes"),
        "{error}"
    );

    // Control: an ordinary toggle and a removal at the longest legal key decode.
    let longest_key = "k".repeat(128);
    let ordinary = format!(
        r#"{event_head}{{"op":"replace","path":"/$state/remind","value":{{"type":"bool","value":true}}}},{{"op":"remove","path":"/$state/{longest_key}"}}],"occurredAt":17}}"#
    );
    let event: GeneratedUiActionEvent =
        serde_json::from_str(&ordinary).expect("ordinary patches decode");
    assert_eq!(event.patch.len(), 2);
}

fn source_ids(count: usize) -> Vec<EntityId> {
    (0..count)
        .map(|n| {
            let mut bytes = [0x5A; 16];
            bytes[12..].copy_from_slice(&u32::try_from(n).expect("small count").to_be_bytes());
            EntityId::from_bytes(bytes).expect("source id")
        })
        .collect()
}

fn profile(subject: EntityId, sources: Vec<EntityId>) -> oneiron::Result<PsychProfile> {
    PsychProfile::new(
        subject,
        "compact",
        "text",
        "Narrative.",
        sources,
        PsychProfileConfidence::new(0.9, 0.8, 0.7).expect("confidence"),
    )
}

#[test]
fn a_psych_profile_citing_more_sources_than_one_snapshot_holds_is_refused_at_every_door() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open(dir.path(), config).expect("open vault");
    crate::common::provision_engine_machines(&vault);
    let subject = EntityId::from_bytes([0x5B; 16]).expect("subject");
    let over = SOURCE_BOUND + 1;

    // Constructor, then a host-built record handed to the store.
    profile(subject, source_ids(over)).expect_err("the constructor refuses");
    let mut forged = profile(subject, source_ids(1)).expect("profile");
    forged.source_revision_ids = source_ids(over);
    vault
        .put_psych_profile(&subject, &forged)
        .expect_err("the store refuses");
    assert!(vault.get_psych_profile(&subject).expect("read").is_none());

    // A peer's or a file's body: re-encode a valid body with one source too many.
    let body = encode_psych_profile_body(&profile(subject, source_ids(1)).expect("profile"))
        .expect("encode");
    let rmpv::Value::Map(mut entries) =
        rmpv::decode::read_value(&mut body.as_slice()).expect("decode map")
    else {
        panic!("a profile body is a map");
    };
    for (key, value) in &mut entries {
        if key.as_str() == Some("sourceRevisionIds") {
            *value = rmpv::Value::Array(
                source_ids(over)
                    .iter()
                    .map(|id| rmpv::Value::from(id.to_hex()))
                    .collect(),
            );
        }
    }
    let mut forged_body = Vec::new();
    rmpv::encode::write_value(&mut forged_body, &rmpv::Value::Map(entries)).expect("encode");
    decode_psych_profile_body(&forged_body).expect_err("the decoder refuses");

    // Control: a snapshot at the bound stores and reads back whole.
    let at_bound = profile(subject, source_ids(SOURCE_BOUND)).expect("a profile at the bound");
    vault
        .put_psych_profile(&subject, &at_bound)
        .expect("a profile at the bound stores");
    let stored = vault
        .get_psych_profile(&subject)
        .expect("read")
        .expect("stored");
    assert_eq!(stored.source_revision_ids.len(), SOURCE_BOUND);
}
