//! FIX 987: `vault.connectors.slates.redraft` and `vault.connectors.slates.narrow`
//! (ARCH-0072 "re-draft", and "any holder may narrow its own Grant").
//!
//! A re-draft is the owner's: the configured drafter proposes changed rows
//! with their rationale at the slate's revision and stamps, activates or
//! grants nothing; the owner accepts a proposal through the slate's own
//! stamp, at that revision. A host with no drafter answers
//! [`ConnectorSlateRedraftReply::Unavailable`] and the slate is unchanged; an
//! embedded vault has no drafter. A narrow is the key's holder's own act: the
//! authenticated caller, never an owner proof and never a submitted holder.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::connector_key::{
    ConnectorKeySlateNarrowed, ConnectorSlateRedraft, SlateDisposition, SlateHolderNarrow,
};
use crate::entity_id::EntityId;
use crate::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult};

/// Why a re-draft names no proposal on a host with no slate drafter: one
/// sentence, so a later ruling changes one line.
pub const SLATE_REDRAFT_UNAVAILABLE: &str =
    "this host has no connector slate drafter configured; the slate is unchanged";

/// `vault.connectors.slates.redraft`: the owner's instruction for re-drafting
/// one connector grant slate.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSlateRedraftRequest {
    /// The slate to re-draft, 32 hex.
    pub slate_ref: String,
    /// The slate revision the owner reviewed.
    pub expected_revision: u64,
    /// What the owner wants changed, in his own words.
    pub instruction: String,
}

/// What a re-draft came to. Nothing is stamped, activated or granted.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ConnectorSlateRedraftReply {
    /// The drafter's proposal: only the rows it would change.
    Proposed {
        slate_ref: String,
        /// The revision the proposal was drafted against; the owner's stamp
        /// of it names this revision.
        expected_revision: u64,
        /// Each changed row's proposed setting, by row key.
        proposed: BTreeMap<String, SlateDisposition>,
        /// Each changed row's rationale, by row key.
        rationale: BTreeMap<String, String>,
    },
    /// No drafter is configured: nothing is proposed and the slate is
    /// unchanged. Admission and delta drafts keep their rule draft.
    Unavailable { code: String, reason: String },
}

impl ConnectorSlateRedraftReply {
    /// The engine's proposal, as the owner reviews it.
    #[must_use]
    pub fn proposed(redraft: ConnectorSlateRedraft) -> Self {
        Self::Proposed {
            slate_ref: redraft.slate_id.to_hex(),
            expected_revision: redraft.expected_revision,
            proposed: redraft
                .proposed
                .into_iter()
                .map(|(row, setting)| (row, setting.disposition))
                .collect(),
            rationale: redraft.rationale,
        }
    }

    /// The answer of a host with no slate drafter.
    #[must_use]
    pub fn unavailable() -> Self {
        Self::Unavailable {
            code: MEMORY_CODE_MODEL_UNAVAILABLE.to_owned(),
            reason: SLATE_REDRAFT_UNAVAILABLE.to_owned(),
        }
    }
}

/// `vault.connectors.slates.narrow`: the key's holder tightens its own rows
/// or facet set of what the key's calls meet.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSlateNarrowRequest {
    /// The connector key the holder's calls run under, 32 hex.
    pub key_ref: String,
    /// The revision of the slate the key's calls meet, as the holder read it.
    pub expected_revision: u64,
    /// Rows to tighten, by row key (a tool name, or `@elicitation`), each to
    /// a stricter setting than it has now.
    #[serde(default)]
    pub narrows: BTreeMap<String, SlateDisposition>,
    /// Facets to keep reaching, 32-hex ids: a subset of those reached now.
    #[serde(default)]
    pub facets: Option<Vec<String>>,
}

/// What the key's calls meet after a holder narrow.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectorSlateNarrowView {
    pub key_ref: String,
    /// The slate the key's calls meet: its own, else its catalog's.
    pub slate_ref: String,
    pub slate_revision: u64,
    /// Each row's effective setting on this key, by row key.
    pub settings: BTreeMap<String, SlateDisposition>,
    /// The facets the key reaches, 32-hex ids; absent: every facet.
    pub facets: Option<Vec<String>>,
    /// The holder narrows in force on this key, by row key.
    pub narrows: BTreeMap<String, SlateHolderNarrow>,
}

impl ConnectorSlateNarrowView {
    /// The engine's narrowed key, for its holder.
    #[must_use]
    pub fn of(narrowed: &ConnectorKeySlateNarrowed) -> Self {
        Self {
            key_ref: narrowed.key_id.to_hex(),
            slate_ref: narrowed.slate_id.to_hex(),
            slate_revision: narrowed.slate_revision,
            settings: narrowed.settings.clone(),
            facets: narrowed
                .facets
                .as_ref()
                .map(|facets| facets.iter().map(EntityId::to_hex).collect()),
            narrows: narrowed.narrows.clone(),
        }
    }
}

/// `vault.connectors.slates.narrow` by `holder`, the authenticated caller:
/// the narrowed key and the rows the narrow read (the key, and a per-grant
/// key's grant).
///
/// # Errors
/// Malformed refs, and the engine's refusals: a caller that is not the key's
/// live holder, a narrow that does not tighten, a moved slate.
pub fn narrow_connector_slate_as(
    vault: &crate::Vault,
    holder: EntityId,
    input: ConnectorSlateNarrowRequest,
) -> MemoryResult<(ConnectorSlateNarrowView, Vec<EntityId>)> {
    let key_id = EntityId::from_hex(&input.key_ref)
        .map_err(|_| MemoryError::bad_request("key_ref must be 32 hex"))?;
    let facets = input
        .facets
        .map(|facets| {
            facets
                .iter()
                .map(|facet| EntityId::from_hex(facet))
                .collect::<Result<BTreeSet<_>, _>>()
        })
        .transpose()
        .map_err(|_| MemoryError::bad_request("facets must be 32-hex ids"))?;
    let narrowed = vault.narrow_connector_key_slate(
        &key_id,
        holder,
        input.expected_revision,
        &input.narrows,
        facets,
    )?;
    let rows = std::iter::once(narrowed.key_id)
        .chain(narrowed.grant_id)
        .collect();
    Ok((ConnectorSlateNarrowView::of(&narrowed), rows))
}

/// `vault.connectors.slates.narrow` on an embedded handle: its bound actor,
/// as the key's holder. Never the embedded owner's proof: a holder's narrow
/// is the holder's own act.
pub fn narrow_connector_slate_embedded(
    memory: &Memory<'_>,
    input: ConnectorSlateNarrowRequest,
) -> MemoryResult<ConnectorSlateNarrowView> {
    crate::memory::verify_actor_binding(memory.vault(), memory.actor(), memory.actor_class())?;
    narrow_connector_slate_as(memory.vault(), memory.actor(), input).map(|(view, _)| view)
}
