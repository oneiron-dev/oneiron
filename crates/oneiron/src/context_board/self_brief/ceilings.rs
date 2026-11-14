//! The ceilings a brief describes (Engine rulings GRANT and CLASSES, 21:47).
//!
//! The run's, the credential's and the delegation parents' bounds are three
//! separate typed descriptions, and none of them is a Grant. The policy's
//! concrete class ceilings are dated descriptions of configured rows, with
//! no verdict: the per-class verdicts beside them are their own lines
//! (`class_verdicts`, FIX 20734). Execution rechecks every one of them, and
//! nothing here is read back as authority.
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
//! [`crate::Vault::self_brief_class_reads`]). None of them writes anything.

use std::collections::BTreeSet;

use crate::agent_dispatch::AgentDispatchInput;
use crate::attempt_queue::AttemptId;
use crate::authority::VerifiedSlip;
use crate::claim::ScopedReadActorKey;
use crate::context_projection::ContextSpec;
use crate::entity_id::EntityId;
use crate::federation::{Scope, ScopeAxis, ScopeId};
use crate::policy_manifest_doors::{PolicyCeiling, PolicyGrantValue};

#[doc(hidden)]
pub use oneiron_records::context_board::self_brief::ceilings::{
    BriefActPosture, BriefBranchBound, BriefCeilingTarget, BriefClassPrecedence,
    BriefConnectorCeiling, BriefContextBound, BriefCredentialCeiling, BriefRunCeiling,
};

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
