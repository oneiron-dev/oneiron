//! The single-writer landing: apply path, per-ref publication fan-out, and
//! wire-outcome mapping.

use std::path::Path;

use crate::code_snapshot::repo_ref::RepoRef;
use crate::git_wire::ids::GitOid;
use crate::git_wire::ids::GitRefName;
use crate::git_wire::record::GitWireCommitOutcome;
use crate::git_wire::record::GitWireReceipt;
use crate::git_wire::repo::GitWireRepo;
use crate::git_wire::repo::lock_repository;
use crate::origin::lfs::pointer::LfsPointerIntent;
use crate::origin::publication::publication_types::OriginPublicationAnswer;
use crate::origin::publication::publication_types::OriginPublicationReceipt;
use crate::origin::publication::publication_types::OriginPublicationRequest;
use crate::origin::publication::publication_types::OriginPublicationStatus;
use crate::origin::residence::OriginAuthorityStamp;
use crate::origin::smart_http::paths::ORIGIN_REF_UPDATE_BATCH;
use crate::origin::smart_http::paths::now_secs;
use crate::origin::smart_http::paths::serve_failed;
use oneiron_base::error::CodeError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::temporal::TimeRange;

/// Attribution from the durable receive-pack observer. The landing verifies
/// the local producer receipt and the actor/repository/operation binding.
#[derive(Debug, Clone, Copy)]
pub struct ReceivePackAttribution {
    /// Server-derived authenticated principal, not an origin-local stand-in.
    pub actor_id: EntityId,
    /// Durable observed-outcome claim written by this module's serve path.
    /// Landing reads it; caller-supplied active claims are not source proof.
    pub provenance_claim_id: EntityId,
}

/// The durable record of one landing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivePackLanding {
    /// What certified the first ref. A multi-ref landing is not atomic;
    /// success means every ref certified, but failure never rolls earlier refs back.
    pub receipt: ReceivePackCertificate,
    /// Whether a durable terminal record answered without re-running git.
    pub replayed: bool,
}

/// What certified one landed ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceivePackCertificate {
    /// The journaled ref effect the landing drove or replayed.
    Wire(GitWireReceipt),
    /// The `Published` publication that had already made this ref's move.
    /// The backend left the ref at its value, its proof covers the push, and
    /// no ref effect ran for it: the push's own outcome stays its record.
    ResolvedToOwner {
        /// The owner's publication id.
        publication_id: EntityId,
    },
}

/// The receipt and replay flag of one journaled ref effect, or a refusal.
pub fn landed_wire_outcome(
    outcome: GitWireCommitOutcome,
) -> Result<(ReceivePackCertificate, bool)> {
    match outcome {
        GitWireCommitOutcome::Applied(receipt) => {
            Ok((ReceivePackCertificate::Wire(receipt), false))
        }
        GitWireCommitOutcome::Replayed(receipt) => {
            Ok((ReceivePackCertificate::Wire(receipt), true))
        }
        GitWireCommitOutcome::Rejected { reason, .. } => {
            Err(Error::Code(CodeError::ReceivePackLandingRefused {
                reason: format!("{reason:?}"),
            }))
        }
    }
}
