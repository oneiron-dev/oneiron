//! Moved from `crates/oneiron/src/skill_optimize/gate/verdict.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::skill_optimize::gate::verdict::TradeoffChoice;

/// Resolution of one exact pending vector, and the ladder rung that made it
/// (ARCH-0053 §10a: preference rule, then a typed judgment on the band, then
/// the responsible person).
///
/// `owner` is the person the ladder answers to. On the [`TradeoffRung::Person`]
/// rung `authentication` is that person's authenticated decision and
/// `evidence` an opaque host reference, or the digest of the A/B question the
/// pick answered. On the [`TradeoffRung::Preference`] rung `authentication`
/// names the stored rule and on [`TradeoffRung::Judgment`] the pinned model; both
/// carry the digest of the bound question as `evidence`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeoffResolution {
    pub pending: EntityId,
    pub owner: EntityId,
    pub authentication: String,
    pub evidence: String,
    pub rung: TradeoffRung,
}

/// The rung of the preference ladder that settled a pending tradeoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TradeoffRung {
    /// An authored or learned preference rule matched the axis signature.
    Preference,
    /// A typed judgment on the band: a verdict bound to the exact question, at
    /// or above the high band.
    Judgment,
    /// The authenticated person: the owner door or an A/B pick.
    Person,
    /// A live agent holding a responsible role the ask reached
    /// (ROLES-EVERYWHERE).
    Role,
}
