//! Moved from `crates/oneiron/src/context_board/self_brief/ceilings.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::federation::Scope;
use oneiron_authority::federation::ScopeAxis;
use oneiron_authority::federation::ScopeId;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
use oneiron_store::config::context_spec::ContextSpec;
use std::collections::BTreeSet;

/// A run's branch-resource bound, as its admitted dispatch stored it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BriefBranchBound {
    /// The dispatch carries no branch scope: it reads and writes no branch
    /// resource.
    NoBranchResourceAccess,
    /// Exactly these branch axes and resource sets. An empty resource set
    /// grants no access.
    Restricted { scope: oneiron_model::llm::Scope },
}

impl BriefBranchBound {
    /// The bound a dispatch's stored branch scope states: no scope is no
    /// branch-resource access.
    pub fn of_dispatch(scope: Option<&oneiron_model::llm::Scope>) -> Self {
        scope.map_or(Self::NoBranchResourceAccess, |scope| Self::Restricted {
            scope: scope.clone(),
        })
    }
}

/// A run's projection descriptor, as its admitted dispatch stored it. It
/// names what the run may see; it is no saved selection of content.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BriefContextBound {
    /// The dispatch declared no descriptor: the resolver's own applies.
    NoDeclaredSpec,
    Declared {
        spec: ContextSpec,
    },
}

impl BriefContextBound {
    /// The descriptor a dispatch stored, without its dev-only `_annotation`,
    /// which resolution drops so it reaches no prompt; the note bounds
    /// nothing.
    pub fn of_dispatch(spec: Option<&ContextSpec>) -> Self {
        spec.map_or(Self::NoDeclaredSpec, |spec| Self::Declared {
            spec: ContextSpec {
                annotation: None,
                ..spec.clone()
            },
        })
    }
}

/// The run ceiling: the bounds the run's admitted dispatch attempt stored.
/// A spawned child's branch bound is the one its dispatch stored after
/// attenuating it against its parent, never the spawn's request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BriefRunCeiling {
    pub run_id: EntityId,
    pub attempt: AttemptId,
    pub branch: BriefBranchBound,
    pub context: BriefContextBound,
}

/// The credential ceiling: the bounds of the verified credential the caller
/// presented, and, labelled apart, the bounds of the registered connector
/// the call arrived on. Neither replaces the other.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BriefCredentialCeiling {
    /// The verified slip's effective six-axis scope.
    pub scope: Scope,
    /// The slip's exact named secret and repository bounds.
    pub records: BTreeSet<String>,
    /// The slip's exact named credential-door effectors; empty means none.
    pub channels: BTreeSet<String>,
    /// The scope the admitted read key reads under, a separate projection of
    /// `scope`; `null` when the read key carries no proof scope.
    pub read_scope: Option<Scope>,
    /// The registered connector's own bounds; `null` for a call no
    /// registered connector carries.
    pub connector: Option<BriefConnectorCeiling>,
}

/// A registered MCP connector's bounds, as its registration holds them,
/// beside its credential's. They are no part of the signed slip's scope.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BriefConnectorCeiling {
    /// The world the connector is narrowed to; `null` when it was never
    /// narrowed to one.
    pub world_ref: Option<EntityId>,
    /// The facet the connector's writes are born in; `null` when it names
    /// none.
    pub facet_ref: Option<EntityId>,
    /// The facets the connector reads.
    pub facets: ScopeAxis<ScopeId>,
    /// The registered bound-verb ceiling; `null` when the registration
    /// names none.
    pub bound_verbs: Option<BTreeSet<String>>,
}

/// What a class ceiling governs, under the keys its source row uses. A
/// `null` holder is the vault row.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BriefCeilingTarget {
    /// A manifest actor-ceiling row: the actor class it names and, when it
    /// names one, the actor ref.
    Actor {
        actor_class: String,
        actor_ref: Option<String>,
    },
    /// The approval ceiling the policy resolves for this actor from the
    /// actor-ceiling rows that match it, composed most-restrictive: the
    /// actor class and the actor's own ref.
    ResolvedActor {
        actor_class: String,
        actor_ref: String,
    },
    /// The live agent definition, with its fork and foreign bounds, that
    /// applies to `actor`.
    Definition { actor: EntityId },
    /// An act-policy row: the act class, the subject class and the holder.
    Act {
        act_class: String,
        subject_class: String,
        holder: Option<EntityId>,
    },
    /// A wait-policy row: the wait class and the holder.
    Wait {
        wait_class: String,
        holder: Option<EntityId>,
    },
    /// A scoped policy grant row: the effector it covers and the actor class
    /// and actor ref it names.
    Effector {
        effector: String,
        actor_class: Option<String>,
        actor_ref: Option<String>,
    },
}

/// An act class's posture as its row states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BriefActPosture {
    /// The class may not run, whatever capabilities the subject holds.
    Deny,
    /// The class is not barred. This is no permission to act: the substrate
    /// check still requires the capability the act needs.
    RequireCapability,
}

/// What a class's vault row lets the class's holder rows do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BriefClassPrecedence {
    /// A holder row narrows inside the vault row.
    NestedNarrowing,
    /// Holder rows are ignored for the class: the vault row is the answer.
    VaultOnly,
}
