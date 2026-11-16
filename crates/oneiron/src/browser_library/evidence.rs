//! Solved-run evidence (CUA E8a; DESIGN-2 "The Coach", row E8): a browser
//! run's span whose checks met on the page it reached, kept as ONE
//! caller-scoped `browser.solved_run` claim whose body is the
//! [`SolvedRunEvidence`]. Side rows hold only its refs, digests and
//! counters (the index); none holds the body again.
//!
//! The caller's own door writes it (`Memory::capture_browser_solved_run`):
//! the claim under the caller's envelope, its group ref, its group's dirty
//! generation and its source authority's reference, in one write. A source
//! with no recorded task type, or whose checks were not read on the page,
//! captures nothing: no group is made up for it.
//!
//! A group is exact ([`ScopedSolvedGroupKey`]): the caller's scope, then the
//! site, the origin, the recorded task type and the subgoal's exact bytes.
//! Its digest is length-delimited over each part, never a joined string.

use oneiron_browser::{DraftOutput, ExpectInput, SecretParam};
use serde::{Deserialize, Serialize};

use crate::authority::InvocationSlipBinding;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::learning::TypeRef;
use crate::runtime_hooks::InvocationId;
use crate::runtime_hooks::verb::VerbAskCredentialRef;

pub use crate::memory::browser_capture::SOLVED_RUN_PREDICATE;

pub use crate::memory::browser_capture::WORKFLOW_FILING_PREDICATE;

#[doc(hidden)]
pub(super) use oneiron_records::browser_library::evidence::digest;
#[doc(hidden)]
pub use oneiron_records::browser_library::evidence::{
    FiledScope, SOLVED_CAPTURE_VERSION, SOLVED_GROUP_DOMAIN, SOLVED_RUN_DOMAIN,
    SOLVED_SCOPE_DOMAIN, SolvedRunScope, SolvedSource, WORKFLOW_FILING_DOMAIN, workflow_filing_id,
};

pub use crate::dreamer_runner::maintenance::browser_candidate::CANDIDATE_DOMAIN;

/// A solved group's semantic key (CUA E8a): exact site, origin, recorded
/// task type and subgoal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolvedGroupKey {
    pub site: String,
    pub origin: String,
    pub type_ref: TypeRef,
    pub subgoal: String,
}

/// A solved group within its caller's scope (CUA E8a): runs group only
/// with runs of the same scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedSolvedGroupKey {
    pub scope: SolvedRunScope,
    pub group: SolvedGroupKey,
}

impl ScopedSolvedGroupKey {
    /// The group's digest: every part length-delimited, in
    /// [`SOLVED_GROUP_DOMAIN`].
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let scope = &self.scope;
        let group = &self.group;
        let authority = scope.authority.unwrap_or_default();
        let held = [u8::from(scope.authority.is_some())];
        digest(
            SOLVED_GROUP_DOMAIN,
            &[
                scope.actor.as_bytes(),
                &[scope.actor_class],
                &held,
                &authority,
                group.site.as_bytes(),
                group.origin.as_bytes(),
                group.type_ref.node_id.as_bytes(),
                &group.type_ref.tree_version.to_be_bytes(),
                group.subgoal.as_bytes(),
            ],
        )
    }
}

/// One filed program's anchor (FIX 10513): the body of its
/// `browser.workflow.filing` claim. It carries only the program, the
/// group it covers, and that group's origin, task type and subgoal:
/// the filing association a reader reads through [`ScopedRead`] before
/// dereferencing the program, never a second program or proof body.
///
/// [`ScopedRead`]: crate::claim::ScopedRead
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowFiling {
    /// The filed program the anchor names.
    pub workflow: EntityId,
    /// The digest of the solved group the filing covers.
    pub group: [u8; 32],
    /// The group's admitted origin.
    pub origin: String,
    /// The group's recorded task type.
    pub type_ref: TypeRef,
    /// The group's subgoal, exact.
    pub subgoal: String,
}

impl WorkflowFiling {
    /// Program `workflow`'s filing in the group `key` names.
    #[must_use]
    pub fn of(key: &ScopedSolvedGroupKey, workflow: EntityId) -> Self {
        Self {
            workflow,
            group: key.digest(),
            origin: key.group.origin.clone(),
            type_ref: key.group.type_ref.clone(),
            subgoal: key.group.subgoal.clone(),
        }
    }

    /// The anchor claim's id.
    ///
    /// # Errors
    ///
    /// A claim body that does not encode (as the evidence ids').
    pub fn id(&self) -> Result<EntityId> {
        workflow_filing_id(&self.workflow, &self.group)
    }
}

/// What a source door captured, before its caller's door scopes it.
#[derive(Debug, Clone)]
pub struct SolvedRunCapture {
    pub run_id: EntityId,
    /// The logical verb call it was captured at, when its door had one.
    pub call_id: Option<InvocationId>,
    pub site: String,
    pub origin: String,
    pub type_ref: TypeRef,
    pub subgoal: String,
    /// The checks as a program keeps them, every one met on the page.
    pub checks: Vec<ExpectInput>,
    /// The span's durable draft: no secret slot's argument, no handle.
    pub draft: DraftOutput,
    /// The secret slots the draft names, by name and kind.
    pub secret_slots: Vec<SecretParam>,
    /// Whether the draft replays as it is; a solved page whose secrets need
    /// binding again is still solved, but not replay-ready.
    pub replay_ready: bool,
    pub source: SolvedSource,
    pub captured_at_ms: u64,
}

/// One solved run's evidence: the body of its `browser.solved_run` claim
/// (CUA E8a).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolvedRunEvidence {
    pub id: EntityId,
    pub run_id: EntityId,
    pub call_id: Option<InvocationId>,
    pub scope: SolvedRunScope,
    pub site: String,
    pub origin: String,
    pub type_ref: TypeRef,
    pub subgoal: String,
    pub checks: Vec<ExpectInput>,
    pub draft: DraftOutput,
    pub secret_slots: Vec<SecretParam>,
    pub replay_ready: bool,
    pub source: SolvedSource,
    pub version: u32,
    pub captured_at_ms: u64,
}

impl SolvedRunEvidence {
    /// `capture` within `scope`, its id hashed in [`SOLVED_RUN_DOMAIN`].
    ///
    /// # Errors
    ///
    /// A body that does not encode.
    pub fn new(scope: SolvedRunScope, capture: SolvedRunCapture) -> Result<Self> {
        let body = serde_json::to_vec(&(
            &capture.checks,
            &capture.draft,
            &capture.secret_slots,
            &capture.source,
        ))
        .map_err(|_| Error::InvalidClaimBody("solved run evidence"))?;
        let call = capture.call_id.map(|call| call.0).unwrap_or_default();
        let group = ScopedSolvedGroupKey {
            scope: scope.clone(),
            group: SolvedGroupKey {
                site: capture.site.clone(),
                origin: capture.origin.clone(),
                type_ref: capture.type_ref.clone(),
                subgoal: capture.subgoal.clone(),
            },
        }
        .digest();
        let id = crate::codebase::entity_id_from_hash_material(
            SOLVED_RUN_DOMAIN,
            &[
                &group,
                capture.run_id.as_bytes(),
                &[u8::from(capture.call_id.is_some())],
                &call,
                &capture.draft.after_seq.to_be_bytes(),
                &capture.draft.through_seq.to_be_bytes(),
                &body,
            ],
        )?;
        Ok(Self {
            id,
            run_id: capture.run_id,
            call_id: capture.call_id,
            scope,
            site: capture.site,
            origin: capture.origin,
            type_ref: capture.type_ref,
            subgoal: capture.subgoal,
            checks: capture.checks,
            draft: capture.draft,
            secret_slots: capture.secret_slots,
            replay_ready: capture.replay_ready,
            source: capture.source,
            version: SOLVED_CAPTURE_VERSION,
            captured_at_ms: capture.captured_at_ms,
        })
    }

    /// The scoped group this run is evidence in.
    #[must_use]
    pub fn group(&self) -> ScopedSolvedGroupKey {
        ScopedSolvedGroupKey {
            scope: self.scope.clone(),
            group: SolvedGroupKey {
                site: self.site.clone(),
                origin: self.origin.clone(),
                type_ref: self.type_ref.clone(),
                subgoal: self.subgoal.clone(),
            },
        }
    }
}

/// The source authority a solved run was captured under (CUA E8a), kept
/// beside its evidence and never in it. The credential reference names the
/// exact instrument and door; the witness is the signed binding the request
/// was admitted on (CUA E8b), kept as a queued turn action keeps its slip:
/// never logged, never in a receipt, gone with the row's erase, and dropped
/// once an admission job that used it ends. The witness digest is its
/// BLAKE3, kept after the binding is dropped. A later use verifies the
/// binding again against current authority and revalidates the credential
/// then; this row is no authority of its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedBrowserCaller {
    pub scope: SolvedRunScope,
    /// The digest of the evidence's scoped group.
    pub group: [u8; 32],
    pub run_id: EntityId,
    pub call_id: Option<InvocationId>,
    pub credential: Option<VerbAskCredentialRef>,
    pub witness_digest: Option<[u8; 32]>,
    /// The binding itself, until an admission job that used it ends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness: Option<InvocationSlipBinding>,
}

pub use crate::memory::browser_capture::{SolvedCaptureGap, SolvedCaptureReceipt};
