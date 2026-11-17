//! Door for `tests/sync_checkpoint_pins.rs` (UC-10 PR 6): what the checkpoint
//! dispatch answers for a fixed cross product of window root map, key and
//! value. [`pins`] asks `root_entry`, `key_refusal`, `withheld_part_key`,
//! `withheld_client_key` and `withheld_key` of every one of the
//! [`window_roots`] and one root no map is named, for every key and every value
//! of two fixed lists, and prints one line each. A run before the dispatch moves
//! onto one row table and a run after it are separate processes, so every id,
//! byte and Loro peer here is fixed: no clock, no random source, no minted id.
//! Compiled only under `--cfg oneiron_test_support`; never API.
//!
//! The keys and the values asked are built in the child module
//! `fixture_table`, family by family.

use serde::Serialize;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use crate::store::checkpoint_payload::rows::OtherClient;
use crate::sync::carrier_parts::{Parts, split_parts};
use crate::sync::checkpoint_payload::{
    KindPlacement, SyncPayloadOwners, SyncUnclassified, WINDOW_ROOTS, root_entry, test_support,
};
use crate::temporal::TimeRange;
use crate::test_fixtures::entity_record;

use fixture_table::build_table;

mod fixture_table;

/// A root no window map is named: every function answers it as unknown.
const UNKNOWN_ROOT: &str = "no_such_root";

/// The id most fixtures are filed under: an entity, a turn, a message, a NOTE.
const ROW: u8 = 0x11;
/// A second id: an edge's target, a fork, the key another row is filed under.
const OTHER: u8 = 0x12;
/// The actor the fixtures name.
const ACTOR: u8 = 0x41;
/// An agent a turn addresses.
const AGENT: u8 = 0x42;
/// The room a turn rides in.
const ROOM: u8 = 0x52;
/// The message a pin quotes.
const MESSAGE: u8 = 0x4d;
/// The learned-at stamp of every entity row.
const FIXED_AT: u64 = 1_700_000_000_000;
/// The Loro peer of the text a pin quotes.
const QUOTE_PEER: u64 = 1;
/// The length of a message writer's proof (32 + 16 + 64).
const WRITER_PROOF_LEN: usize = 112;

fn refused(reason: &str) -> Error {
    Error::InvalidConfig(format!("checkpoint pins door: {reason}"))
}

/// A fixed id standing for one role of the fixtures.
fn fixed(byte: u8) -> EntityId {
    EntityId::from_bytes_unchecked([byte; 16])
}

/// `row` as named MessagePack.
fn msgpack<T: Serialize>(row: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(row).map_err(|_| refused("a row that does not encode as MessagePack"))
}

/// `row` as JSON.
fn json<T: Serialize>(row: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(row).map_err(|_| refused("a row that does not encode as JSON"))
}

/// Tells entity kinds apart by their type byte, as a registry would: a PERSON
/// is its own tree's, an ASSET is the body client's, every other kind is
/// unclassified for one fixed reason. A CLAIM or a NOTE is placed from its own
/// bytes before this is asked.
struct KindsByTypeByte;

impl SyncPayloadOwners for KindsByTypeByte {
    fn entity_kind(&self, entity_type: u8) -> KindPlacement {
        match entity_type {
            ENTITY_TYPE_PERSON => KindPlacement::Owner,
            ENTITY_TYPE_ASSET => KindPlacement::Other(OtherClient::Body),
            _ => KindPlacement::Unclassified(SyncUnclassified::UnknownKind),
        }
    }
}

/// The keys and the values every root is asked, each under a short fixed label,
/// in the order they were added.
#[derive(Default)]
struct Table {
    keys: Vec<(&'static str, String)>,
    values: Vec<(&'static str, Vec<u8>)>,
}

impl Table {
    fn key(&mut self, label: &'static str, key: impl Into<String>) {
        self.keys.push((label, key.into()));
    }

    fn value(&mut self, label: &'static str, value: impl Into<Vec<u8>>) {
        self.values.push((label, value.into()));
    }
}

/// Adds the parts `joined` splits into, each as a value labelled `label`, and
/// answers the parts a manifest of it lists.
fn add_parts(table: &mut Table, label: &'static str, joined: &[u8]) -> Result<Parts> {
    let (parts, pieces) = split_parts(joined)?;
    for (_, piece) in pieces {
        table.value(label, piece);
    }
    Ok(parts)
}

/// One raw entity row: the metadata header (occurred `1..1`, the fixed learned
/// stamp, row version zero) and `body`.
fn row_bytes(kind: u8, body: &[u8]) -> Vec<u8> {
    entity_record(kind, TimeRange { start: 1, end: 1 }, FIXED_AT, 0, body)
}

/// The window roots the table asks about: every [`WINDOW_ROOTS`] name, in the
/// order the capture reads them.
#[must_use]
pub fn window_roots() -> Vec<&'static str> {
    WINDOW_ROOTS.to_vec()
}

/// One line per root, key and value of the fixed cross product, in a fixed
/// order: the roots are [`window_roots`] then one unknown root; the keys and
/// the values are the same lists for every root, so a key or a value valid for
/// one map is asked under every other. Each line holds `root_entry`'s placement
/// of the value, then what `key_refusal`, `withheld_part_key`,
/// `withheld_client_key` and `withheld_key` answer of the key.
///
/// # Errors
/// A fixture row that does not encode.
pub fn pins() -> Result<Vec<String>> {
    let table = build_table()?;
    let mut roots = window_roots();
    roots.push(UNKNOWN_ROOT);
    let mut lines = Vec::with_capacity(roots.len() * table.keys.len() * table.values.len());
    for root in roots {
        for (key_label, key) in &table.keys {
            let answers = key_answers(root, key);
            for (value_label, value) in &table.values {
                let entry = root_entry(root, key, value, &KindsByTypeByte);
                lines.push(format!(
                    "{root} {key_label} {value_label} | entry={entry:?} | {answers}"
                ));
            }
        }
    }
    Ok(lines)
}

/// Every fixture meant to place as a row of its root under its own key: the
/// root, the key's label and the value's label. A value that places as no row
/// shows in [`fixture_placements`], so a fixture that does not encode is seen.
const OWN_ROWS: &[(&str, &str, &str)] = &[
    ("entities", "id", "row_person"),
    ("entities", "id", "row_asset"),
    ("entities", "id", "row_turn"),
    ("entities", "id", "row_claim"),
    ("entities", "id", "row_claim_dreamer"),
    ("entities", "id", "row_claim_origin"),
    ("entities", "id", "row_note_shell"),
    ("entities", "id", "row_note_erased"),
    ("entities", "id", "row_note_authored"),
    ("entities", "id", "row_author_carrier"),
    ("edges", "edge_authored_by", "edge_authored_by_value"),
    ("edges", "edge_mentions", "edge_mentions_value"),
    ("tombstones", "id", "zero16"),
    ("retained_claim_worlds", "id", "zero16"),
    ("row_births", "id", "row_birth"),
    ("origin_positions", "id", "origin_position"),
    ("peer_origins", "id", "zero32"),
    ("message_writers", "id", "zero112"),
    ("withdrawn_cutoffs", "id", "cutoff9"),
    ("withdrawn_cutoffs", "epoch_floor_session", "zero16"),
    ("withdrawn_cutoffs", "epoch_floor_conversation", "zero16"),
    ("documents", "note_doc", "note_doc_text"),
    ("documents", "note_format", "note_format_value"),
    ("document_heads", "id", "note_head"),
    ("head_move_receipts", "id", "note_receipt"),
    ("note_forks", "id", "note_fork_authored"),
    ("note_forks", "id", "note_fork_erased"),
    ("note_proposals", "id", "note_bundle"),
    ("entity_documents", "id", "x_value"),
    ("room_turns", "id", "turn_whole"),
    ("room_turns", "id", "turn_manifest"),
    ("room_turns", "part_fixed", "turn_part"),
    ("room_facts", "fact_claim", "fact_whole"),
    ("room_facts", "fact_claim", "fact_manifest"),
    ("room_facts", "part_fixed", "fact_part"),
    ("document_pins", "pin", "pin_whole_authored"),
    ("document_pins", "pin_other", "pin_whole_erased"),
    ("document_pins", "pin", "pin_manifest"),
    ("document_pins", "part_fixed", "pin_part"),
    ("message_docs", "id", "message_head"),
    ("message_docs", "part_fixed", "message_part"),
    (
        "office_proposals",
        "office_proposal",
        "office_proposal_value",
    ),
    ("typed_body_rows", "typed_receipt", "typed_receipt_erased"),
    ("typed_body_rows", "typed_fork", "typed_fork_open_parts"),
    ("typed_body_rows", "typed_fork", "typed_fork_open_whole"),
    ("typed_body_rows", "typed_fork", "typed_fork_discarded"),
    ("typed_body_rows", "typed_fork", "typed_fork_opener_named"),
    ("typed_body_rows", "part_fixed", "typed_fork_part"),
    ("repo_manifests", "repo_portable", "repo_head"),
    ("repo_manifests", "part_fixed", "repo_part"),
    ("turn_program_arms", "id", "arming_disarmed"),
    ("turn_program_wakes", "wake", "wake_admitted"),
    ("asset_body_refs", "id", "x_value"),
    ("source_audiences", "audience_record", "audience_binding"),
    (
        "source_audiences",
        "audience_withheld",
        "audience_withheld_none",
    ),
    (
        "source_audiences",
        "audience_withheld",
        "audience_withheld_by",
    ),
    (
        "source_audiences",
        "audience_policy",
        "audience_policy_value",
    ),
];

/// One line for each of the fixtures meant to place as a row of its root under
/// its own key: the root, the labels and `root_entry`'s placement. None is
/// meant to be unclassified as undecodable; one that is did not encode as its
/// family's codec reads it.
///
/// # Errors
/// A fixture row that does not encode, or a fixture named by a label or a root
/// the table does not hold.
pub fn fixture_placements() -> Result<Vec<String>> {
    let table = build_table()?;
    let mut lines = Vec::with_capacity(OWN_ROWS.len());
    for (root, key_label, value_label) in OWN_ROWS {
        if !WINDOW_ROOTS.contains(root) {
            return Err(refused("a fixture of a root that is no window root"));
        }
        let key = table
            .keys
            .iter()
            .find(|(label, _)| label == key_label)
            .ok_or_else(|| refused("a fixture of a key the table does not hold"))?;
        let value = table
            .values
            .iter()
            .find(|(label, _)| label == value_label)
            .ok_or_else(|| refused("a fixture of a value the table does not hold"))?;
        let entry = root_entry(root, &key.1, &value.1, &KindsByTypeByte);
        lines.push(format!(
            "{root} {key_label} {value_label} | entry={entry:?}"
        ));
    }
    Ok(lines)
}

/// What the dispatch answers of the key `key` of `root`, whatever its value.
fn key_answers(root: &str, key: &str) -> String {
    format!(
        "key={:?} | part={} | client={:?} | withheld={:?}",
        test_support::key_refusal(root, key),
        test_support::withheld_part_key(root, key),
        test_support::withheld_client_key(root, key),
        test_support::withheld_key(root, key),
    )
}
