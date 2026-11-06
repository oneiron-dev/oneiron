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

use std::collections::BTreeSet;

use crate::attempt_queue::AttemptId;
use crate::context_projection::ContextSpec;
use crate::entity_id::EntityId;
use crate::federation::{Scope, ScopeAxis, ScopeId};
use crate::policy_manifest_doors::PolicyCeiling;

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

/// The run ceiling: the bounds the run's admitted dispatch attempt stored.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BriefRunCeiling {
    pub run_id: EntityId,
    pub attempt: AttemptId,
    pub branch: BriefBranchBound,
    pub context: BriefContextBound,
}

/// The credential ceiling: the bounds of the verified credential the caller
/// presented.
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
    /// The registered connector's own bounds; `null` for a credential that is
    /// no registered connector's.
    pub connector: Option<BriefConnectorCeiling>,
}

/// A registered connector's bounds beside its credential's.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BriefConnectorCeiling {
    pub world_ref: Option<EntityId>,
    /// The facet the connector's writes are born in.
    pub facet_ref: Option<EntityId>,
    /// The facets the connector reads.
    pub facets: ScopeAxis<ScopeId>,
    /// The registered bound-verb ceiling; `null` when the registration names
    /// none.
    pub bound_verbs: Option<BTreeSet<String>>,
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

/// The parent ceiling: each delegation ancestor's live bounds, in lineage
/// order. A root run has an empty list.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BriefParentCeiling {
    pub ancestors: Vec<BriefParentBound>,
}

/// One concrete class ceiling the resolved policy holds, dated. It describes
/// a configured row; it is no verdict on any act.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BriefCeiling {
    pub class_or_effect: BriefCeilingTarget,
    pub posture: BriefCeilingPosture,
    /// The vault's authority instant the read observed, in Unix seconds.
    pub as_of_secs: u64,
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

/// The bound a class ceiling's row states.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BriefCeilingPosture {
    /// An approval ceiling.
    Approval { approval: PolicyCeiling },
    /// An act class's posture.
    Act { posture: BriefActPosture },
    /// A wait class's window; `null` `max_secs` when the vault bounds no
    /// longest wait.
    Wait {
        min_secs: u64,
        max_secs: Option<u64>,
    },
    /// A configured scoped policy grant row: the six-axis scope it reads
    /// under, its purpose-specific selectors and budget row as the manifest
    /// gives them, and whether a read under it needs a receipt.
    ConfiguredScopedGrant {
        scope: Scope,
        selectors: Option<BriefPolicyValue>,
        budget: Option<BriefPolicyValue>,
        receipt_required: bool,
    },
}

/// A policy row's MessagePack value in a lossless JSON form: integers as
/// text, floats as their exact big-endian bits, map entries in their order
/// with their own keys.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum BriefPolicyValue {
    Nil,
    Boolean(bool),
    Integer(String),
    Float32([u8; 4]),
    Float64([u8; 8]),
    String(String),
    /// A complete encoded MessagePack string, its header included, for a
    /// string that is not valid UTF-8.
    RawString(Vec<u8>),
    Binary(Vec<u8>),
    Array(Vec<BriefPolicyValue>),
    /// Entries keep their order, duplicate keys and non-string keys.
    Map(Vec<BriefPolicyMapEntry>),
    Extension(BriefPolicyExtension),
}

/// One entry of a [`BriefPolicyValue::Map`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BriefPolicyMapEntry {
    pub key: BriefPolicyValue,
    pub value: BriefPolicyValue,
}

/// A MessagePack extension value.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BriefPolicyExtension {
    pub tag: i8,
    pub data: Vec<u8>,
}
