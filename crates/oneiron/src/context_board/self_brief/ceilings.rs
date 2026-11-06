//! The ceilings a brief describes (Engine rulings GRANT and CLASSES, 21:47).
//!
//! The run's, the credential's and the delegation parents' bounds are three
//! separate typed descriptions, and none of them is a Grant. The policy's
//! concrete class ceilings are dated descriptions of configured rows, with
//! no verdict: class verdicts stay unavailable. Execution rechecks every one
//! of them, and nothing here is read back as authority.
//!
//! A `null` value is the source's own none (no bound, no holder); a whole
//! description no host produced is left out of the brief and named on its
//! unavailable line.
//!
//! A host builds the run ceiling from the dispatch attempt it bound
//! ([`brief_run_ceiling`]) and the credential ceiling from the slip it
//! verified ([`brief_credential_ceiling`]); the parent ceiling and the class
//! ceilings are read from the store
//! ([`crate::Vault::self_brief_parent_ceiling`],
//! [`crate::Vault::self_brief_ceilings`]). None of them writes anything.

use std::collections::BTreeSet;

use crate::agent_dispatch::AgentDispatchInput;
use crate::attempt_queue::AttemptId;
use crate::authority::VerifiedSlip;
use crate::claim::ScopedReadActorKey;
use crate::context_projection::ContextSpec;
use crate::entity_id::EntityId;
use crate::federation::{Scope, ScopeAxis, ScopeId};
use crate::policy_manifest_doors::{PolicyCeiling, PolicyGrantValue};

/// A run's branch-resource bound, as its admitted dispatch stored it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BriefBranchBound {
    /// The dispatch carries no branch scope: it reads and writes no branch
    /// resource.
    NoBranchResourceAccess,
    /// Exactly these branch axes and resource sets. An empty resource set
    /// grants no access.
    Restricted { scope: crate::llm::Scope },
}

impl BriefBranchBound {
    /// The bound a dispatch's stored branch scope states: no scope is no
    /// branch-resource access.
    pub(crate) fn of_dispatch(scope: Option<&crate::llm::Scope>) -> Self {
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
    pub(crate) fn of_dispatch(spec: Option<&ContextSpec>) -> Self {
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

/// The run ceiling of run `run_id`, which serves dispatch attempt `attempt`
/// whose admitted input is `input`: the branch bound and the projection
/// descriptor that input stored. It reads nothing: only the host that bound
/// the run to that attempt holds the three together.
#[must_use]
pub fn brief_run_ceiling(
    run_id: EntityId,
    attempt: AttemptId,
    input: &AgentDispatchInput,
) -> BriefRunCeiling {
    BriefRunCeiling {
        run_id,
        attempt,
        branch: BriefBranchBound::of_dispatch(input.scope.as_ref()),
        context: BriefContextBound::of_dispatch(input.context_spec.as_ref()),
    }
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

/// The credential ceiling of verified slip `proof`, beside the scope the
/// read key `read_key` its host admitted for the caller reads under and the
/// bounds of the registered connector the call arrived on, if one carries
/// it. It copies the slip's effective scope, record and channel bounds and
/// the read key's proof scope; it reads nothing.
#[must_use]
pub fn brief_credential_ceiling(
    proof: &VerifiedSlip,
    read_key: &ScopedReadActorKey,
    connector: Option<BriefConnectorCeiling>,
) -> BriefCredentialCeiling {
    BriefCredentialCeiling {
        scope: proof.scope().clone(),
        records: proof.claims().records.clone(),
        channels: proof.claims().channels.clone(),
        read_scope: read_key.authority_scope().cloned(),
        connector,
    }
}

/// One delegation ancestor's live bounds.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BriefParentBound {
    pub attempt: AttemptId,
    pub actor: EntityId,
    pub branch: BriefBranchBound,
    pub context: BriefContextBound,
    /// The approval ceiling the ancestor's live definition holds it at;
    /// `null` when its definition bounds no approval.
    pub approval: Option<PolicyCeiling>,
}

/// The parent ceiling: each delegation ancestor's live bounds, nearest
/// first. A root run has an empty list. It describes the chain; it is no
/// Gate verdict, and every write meets the chain live.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BriefParentCeiling {
    pub ancestors: Vec<BriefParentBound>,
}

/// One concrete class ceiling the resolved policy holds, or the live
/// definition ceiling, dated. It describes a configured row; it is no
/// verdict on any act.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BriefCeiling {
    pub class_or_effect: BriefCeilingTarget,
    pub posture: BriefCeilingPosture,
    /// The vault's authority instant the read observed, in Unix seconds.
    pub as_of_secs: u64,
    /// The resolved policy's frontier hash in the same read, lowercase hex:
    /// it names the policy state the row was read beside. It is no revision,
    /// and no row carries one of its own.
    pub policy_frontier: String,
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

/// The bound a class ceiling's row states.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BriefCeilingPosture {
    /// An approval ceiling.
    Approval { approval: PolicyCeiling },
    /// An act class's posture, and on a vault row what its holder rows may
    /// do; `null` `precedence` on a holder row, which names none.
    Act {
        posture: BriefActPosture,
        precedence: Option<BriefClassPrecedence>,
    },
    /// A wait class's window, and on a vault row what its holder rows may
    /// do; `null` `max_secs` when the row bounds no longest wait, `null`
    /// `precedence` on a holder row, which names none.
    Wait {
        min_secs: u64,
        max_secs: Option<u64>,
        precedence: Option<BriefClassPrecedence>,
    },
    /// A configured scoped policy grant row: the six-axis scope it reads
    /// under, its purpose-specific selectors and budget row as the manifest
    /// gives them, and whether a read under it needs a receipt.
    ConfiguredScopedGrant {
        scope: Scope,
        selectors: Option<PolicyGrantValue>,
        budget: Option<PolicyGrantValue>,
        receipt_required: bool,
    },
}
