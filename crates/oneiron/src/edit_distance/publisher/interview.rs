//! Agent-conducted interview digests on ED-00/ED-01's doors.

use serde::{Deserialize, Serialize};

use super::{PublisherResult, put_meta};
use crate::Vault;
#[cfg(feature = "sync")]
use crate::edit_distance::proposal_text::ProposalTextArtifact;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
#[cfg(feature = "sync")]
use crate::write_envelope::WriteActor;

/// Where an interview digest stands (ARCH-0056 §9 rung 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InterviewState {
    /// The user's own agent is still drafting the digest.
    #[default]
    Drafting,
    /// Surfaced to the user, who may edit it before it settles.
    UserReview,
    /// Frozen — the digest's edit window is closed and its Δ is measurable.
    Settled,
}

impl InterviewState {
    /// Every arm.
    pub const ALL: [Self; 3] = [Self::Drafting, Self::UserReview, Self::Settled];

    /// The pinned on-disk token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Drafting => "drafting",
            Self::UserReview => "user_review",
            Self::Settled => "settled",
        }
    }

    /// Parses a pinned token.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|arm| arm.as_str() == value)
    }
}

/// One interview: the publisher-sourced topic, the digest artifact the user's
/// agent drafts against it, and where that digest stands.
///
/// The digest is an ORDINARY proposal-text artifact. That is the whole point of
/// rung 3's "the edit loop applies to the digest itself — free": the user's
/// edits are recorded by ED-00's window and measured by ED-01's Δ lanes, so
/// this module computes no edit distance of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterviewSession {
    /// The publisher-sourced topic this interview answers.
    pub topic_ref: EntityId,
    /// The proposal-text artifact holding the digest body.
    pub digest_artifact: EntityId,
    /// Where the digest stands.
    pub state: InterviewState,
}

const INTERVIEW_KEY_PREFIX: &[u8] = b"edit_distance/interview_session/v1\0";

/// On-disk shape of a session, keyed by its digest artifact.
#[derive(Serialize, Deserialize)]
struct InterviewRow {
    schema_version: u8,
    topic_ref: String,
    state: String,
}

const INTERVIEW_SCHEMA_VERSION: u8 = 1;

fn interview_corrupt() -> Error {
    Error::CorruptedIndex("interview session record")
}

fn interview_key(digest_artifact: EntityId) -> Vec<u8> {
    let mut key = INTERVIEW_KEY_PREFIX.to_vec();
    key.extend_from_slice(digest_artifact.as_bytes());
    key
}

fn put_interview(vault: &Vault, session: InterviewSession) -> Result<()> {
    let row = InterviewRow {
        schema_version: INTERVIEW_SCHEMA_VERSION,
        topic_ref: session.topic_ref.to_hex(),
        state: session.state.as_str().to_owned(),
    };
    let value = crate::llm::canonical_json_bytes(&row)
        .map_err(|_| Error::InvariantViolation("interview session encode"))?;
    put_meta(vault, &interview_key(session.digest_artifact), &value)
}

/// Reads the session recorded against `digest_artifact`.
///
/// # Errors
///
/// Storage errors, and [`Error::CorruptedIndex`] on a row this engine did not
/// write.
pub fn interview_session(
    vault: &Vault,
    digest_artifact: EntityId,
) -> PublisherResult<Option<InterviewSession>> {
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, &interview_key(digest_artifact))?
    else {
        return Ok(None);
    };
    let row: InterviewRow = serde_json::from_slice(&raw).map_err(|_| interview_corrupt())?;
    if row.schema_version != INTERVIEW_SCHEMA_VERSION {
        return Err(interview_corrupt().into());
    }
    Ok(Some(InterviewSession {
        topic_ref: EntityId::from_hex(&row.topic_ref).map_err(|_| interview_corrupt())?,
        digest_artifact,
        state: InterviewState::parse(&row.state).ok_or_else(interview_corrupt)?,
    }))
}

/// Moves a drafted digest in front of the user.
///
/// # Errors
///
/// Storage errors; [`PublisherError::SignatureNotFound`] is not raised here —
/// an unknown digest simply has no session, which surfaces as `Ok(None)` from
/// [`interview_session`].
pub fn submit_interview_for_review(
    vault: &Vault,
    session: InterviewSession,
) -> PublisherResult<InterviewSession> {
    let session = InterviewSession {
        state: InterviewState::UserReview,
        ..session
    };
    put_interview(vault, session)?;
    Ok(session)
}

/// Opens an interview: mints the digest as an ordinary proposal-text artifact
/// through ED-00's public door, binds `actor` to the artifact's Loro peer so
/// the user's later edits attribute to them, and records the session.
///
/// Returns the artifact alongside the session because ED-00's edit door lives
/// on the artifact value — the caller cannot reach the edit loop without it
/// (worklog D2).
///
/// # Errors
///
/// Whatever ED-00's door raises, plus storage errors.
#[cfg(feature = "sync")]
pub fn open_interview(
    vault: &Vault,
    topic: &EntityId,
    actor: &WriteActor,
    draft: &str,
) -> PublisherResult<(InterviewSession, ProposalTextArtifact)> {
    let digest = ProposalTextArtifact::open(draft, actor, Some(*topic))?;
    // Without the binding ED-00 refuses the stamp and every later edit
    // attributes to the device peer instead of the human doing the reviewing.
    super::register_peer_actor(vault, digest.peer_id(), actor)?;
    let session = InterviewSession {
        topic_ref: *topic,
        digest_artifact: digest.artifact_ref().entity_id(),
        state: InterviewState::Drafting,
    };
    put_interview(vault, session)?;
    Ok((session, digest))
}

/// Settles the digest: closes ED-00's edit window through
/// [`ProposalTextArtifact::finalize`] and records the session as
/// [`InterviewState::Settled`].
///
/// The user's amendments become a Δ the ordinary way — the finalized record is
/// persisted by `finalize`, so
/// [`delta_from_recorded_ops`](super::delta::delta_from_recorded_ops) over
/// [`finalized_proposal_text`](super::finalized_proposal_text) yields it. No
/// edit distance is computed here; that is ED-01's job and reusing it is the
/// point of rung 3.
///
/// The FINALIZED artifact's own ref keys the settled row — the session records
/// what was actually frozen, not what the caller believed it was holding. In
/// every flow through [`open_interview`] the two are the same value.
///
/// # Errors
///
/// Whatever ED-00's finalize raises, plus storage errors.
#[cfg(feature = "sync")]
pub fn settle_interview_digest(
    vault: &Vault,
    session: InterviewSession,
    digest: ProposalTextArtifact,
) -> PublisherResult<EntityId> {
    let finalized = digest.finalize(vault)?;
    let digest_artifact = finalized.artifact_ref.entity_id();
    put_interview(
        vault,
        InterviewSession {
            digest_artifact,
            state: InterviewState::Settled,
            ..session
        },
    )?;
    Ok(digest_artifact)
}
