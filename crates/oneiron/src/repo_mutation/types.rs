//! Repository mutation requests requiring document-operation provenance.

use crate::codebase::RepoRef;
use crate::entity_id::EntityId;

pub use crate::store::repo_mutation_record::{
    REPO_MUTATION_ALLOWED_OPERATION_KINDS, REPO_MUTATION_FORBIDDEN_GIT_COMMANDS, RepoBundleFile,
    RepoCommitProvenance, RepoConflictClaim, RepoConflictResolutionClaim, RepoForkHash,
    RepoMutationOperation, RepoMutationOplogEntry, RepoMutationOutcome, RepoMutationStatus,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepoMutationRequest {
    pub repo_ref: RepoRef,
    pub actor_id: Option<EntityId>,
    /// The actor's class when the host stamped a real writer (FIX 6867): a
    /// run's proposal. `None` keeps the trusted and owner call contract.
    pub actor_class: Option<crate::edge::EdgeActorClass>,
    pub session_id: Option<EntityId>,
    pub provenance_claim_id: Option<EntityId>,
    /// The authoring turn, activity, intent and model the reviewed document
    /// operation records. Absent fields stay unrecorded.
    pub op_provenance: crate::code_document::CodeOpProvenance,
    pub operation: RepoMutationOperation,
}

impl RepoMutationRequest {
    #[must_use]
    pub fn new(repo_ref: RepoRef, operation: RepoMutationOperation) -> Self {
        Self {
            repo_ref,
            actor_id: None,
            actor_class: None,
            session_id: None,
            provenance_claim_id: None,
            op_provenance: crate::code_document::CodeOpProvenance::default(),
            operation,
        }
    }

    #[must_use]
    pub fn with_actor_id(mut self, actor_id: EntityId) -> Self {
        self.actor_id = Some(actor_id);
        self
    }

    /// The actor a stored proposal records: none once that actor was erased
    /// (FIX 3520), and the queue then refuses to run it.
    #[must_use]
    pub(super) fn with_recorded_actor(mut self, actor_id: Option<EntityId>) -> Self {
        self.actor_id = actor_id;
        self
    }

    /// The writer a host stamped (FIX 6867): its actor and its class.
    #[must_use]
    pub(crate) fn with_write_actor(mut self, actor: crate::WriteActor) -> Self {
        self.actor_id = Some(actor.entity_ref());
        self.actor_class = Some(actor.actor_class());
        self
    }

    /// The class a stored proposal records beside its actor.
    #[must_use]
    pub(super) fn with_recorded_class(
        mut self,
        actor_class: Option<crate::edge::EdgeActorClass>,
    ) -> Self {
        self.actor_class = actor_class;
        self
    }

    #[must_use]
    pub fn with_session_id(mut self, session_id: EntityId) -> Self {
        self.session_id = Some(session_id);
        self
    }

    #[must_use]
    pub fn with_provenance_claim_id(mut self, claim_id: EntityId) -> Self {
        self.provenance_claim_id = Some(claim_id);
        self
    }

    #[must_use]
    pub fn with_op_provenance(
        mut self,
        provenance: crate::code_document::CodeOpProvenance,
    ) -> Self {
        self.op_provenance = provenance;
        self
    }
}
