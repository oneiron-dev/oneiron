//! The recall scope a caller asks for and the read receipt every read
//! returns, as napi objects.

use napi_derive::napi;

/// Recall scoping (S5): narrowing only; unset = vault floor.
#[napi(object)]
pub struct NapiRecallScope {
    /// WORLD entity ref; scopes to that world plus base reality.
    pub world_ref: Option<String>,
    /// Facet entity ref; strict facet narrowing when set.
    pub facet: Option<String>,
    /// Registry kinds to return; unset returns every kind but
    /// conversations, sessions, facets and worlds.
    pub kinds: Option<Vec<String>>,
    /// Project audience ids to select from (FIX 8115). Omitted or empty
    /// adds no narrowing to what the caller may read.
    pub project_refs: Option<Vec<String>>,
    /// Conversation entity refs. Empty adds no narrowing; with `person_ref`,
    /// only conversations selected by both axes remain.
    pub conversation_refs: Option<Vec<String>>,
    /// PERSON entity ref; selects conversations where they authored at least
    /// one live MESSAGE, never conversations that merely mention them.
    pub person_ref: Option<String>,
}

/// One read scope on a receipt: the requested, ceiling, or applied tuple.
#[napi(object)]
pub struct NapiReadScope {
    /// Admitted entity types as registry kinds (`CLAIM`, `MESSAGE`, ...);
    /// absent means every registered type (FIX 8117).
    pub entity_types: Option<Vec<String>>,
    /// Highest admitted sensitivity band.
    pub max_sensitivity_band: u32,
    /// Whether stale claims are admitted.
    pub include_stale: bool,
    /// Lowest admitted claim confidence.
    pub min_confidence: f64,
    /// Lowest admitted claim salience.
    pub min_salience: f64,
    /// Whether the scope admits nothing.
    pub deny_all: bool,
}

/// The mandatory receipt every read returns: what was asked, the actor's
/// ceiling, what applied, and which axes narrowed.
#[napi(object)]
pub struct NapiReadReceipt {
    /// The scope the caller asked for.
    pub requested: NapiReadScope,
    /// The actor's ceiling.
    pub actor_ceiling: NapiReadScope,
    /// The intersection that applied.
    pub applied: NapiReadScope,
    /// Axes that narrowed the read.
    pub narrowed_axes: Vec<String>,
    /// Stored rows this actor may not read.
    pub suppressed_count: u32,
    /// Machine-readable re-plan hint: the narrowed axes.
    pub replan_hint: Vec<String>,
}
