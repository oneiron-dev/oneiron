//! Moved from `crates/oneiron/src/edit_distance/reservoir.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::edit_distance::reservoir::eligibility::ReservoirSourcePeople;
pub use oneiron_verb_wire::edit_distance::reservoir::eligibility::ReservoirSourcePreview;
pub use oneiron_verb_wire::edit_distance::reservoir::eligibility::ReservoirSourceRow;
use serde::Serialize;

/// Only accepted schema version for any row this module stores.
pub const ROW_VERSION: u8 = 1;

pub const CANDIDATE_ROW_LABEL: &str = "reservoir candidate row";

pub const EXPORT_RECEIPT_ROW_LABEL: &str = "reservoir export receipt row";

// ---------------------------------------------------------------------------
// The pair
// ---------------------------------------------------------------------------

/// One preference pair: what the model drafted, and what the decider kept.
///
/// Every tag is optional and its absence is EXPLICIT. Old rows predate the tag
/// ledgers, and a mandatory `String` would force the projection to choose
/// between dropping a usable pair and inventing a sentinel — both of which
/// corrupt a training corpus more quietly than a missing tag ever could.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrainingPair {
    /// The proposal as drafted — the DPO `rejected` side.
    pub rejected: String,
    /// The proposal as the decider left it — the `chosen` side, and the SFT
    /// target on its own.
    pub chosen: String,
    /// The kind of work this pair came from (`AmendmentEvidence::scope`).
    pub task_class: Option<String>,
    /// The skill the amended proposal rode, when it rode one.
    #[serde(serialize_with = "serialize_opt_entity_hex")]
    pub skill: Option<EntityId>,
    /// The executor identity at revision the amendment's evidence was stamped
    /// with (FIX 9812) — never the model serving NOW, which would be a guess
    /// about history. `None` when the stamp is unknown.
    pub model_id: Option<String>,
    /// The amendment this pair came from, as the id ED-00 mints for the
    /// artifact that carried it.
    ///
    /// One value names both ends of the join: the retention row holding the two
    /// texts lives under this id, and the amendment ledgers live under
    /// [`amendment_receipt_id`] of it. A consumer that wants the Δ, the
    /// evidence or the fold reads that spelling; a consumer that wants the
    /// artifact reads this one.
    #[serde(serialize_with = "serialize_entity_hex")]
    pub receipt_ref: EntityId,
}

/// Ids cross the wire as lower hex, the one spelling every other receipt field
/// in this engine uses — a consumer joining an exported pair back to its
/// artifact compares strings, never byte encodings.
pub fn serialize_entity_hex<S: serde::Serializer>(
    id: &EntityId,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(&id.to_hex())
}

/// The optional spelling of the same hex encoding: `None` rides the wire as
/// `null`, `Some` as the hex string.
pub fn serialize_opt_entity_hex<S: serde::Serializer>(
    id: &Option<EntityId>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    id.as_ref().map(EntityId::to_hex).serialize(serializer)
}

/// Rows serialize through the house canonical-JSON door, so a row's bytes are a
/// function of its values rather than of map iteration order.
pub fn encode_row<T: Serialize>(row: &T, label: &'static str) -> Result<Vec<u8>> {
    oneiron_model::llm::canonical_json_bytes(row).map_err(|_| Error::CorruptedIndex(label))
}
