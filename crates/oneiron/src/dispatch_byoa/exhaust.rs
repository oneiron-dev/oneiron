//! Exhaust types, terminal receipts, artifact and result-ref addressing, and capture helpers.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptRecord, AttemptResultRef, AttemptState};
use crate::blob_artifact::{
    BlobArtifactBody, BlobVersionProvenance, read_blob_artifact_head_in_txn,
};
use crate::codebase::entity_id_from_hash_material;
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;
use crate::git_wire::{GitRefName, GitWire, GitWireRepo};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

use super::connector::{
    BYOA_ATTEMPT_KIND, BYOA_CONNECTOR_SCHEMA_VERSION, BYOA_EXHAUST_ARTIFACT_ID_DOMAIN,
    BYOA_RESULT_REF_PREFIX, BYOA_RUNTIME_ACTOR_DOMAIN, ByoaAttemptPayload,
    MAX_EXHAUST_ENCODED_BYTES, MAX_STOP_REASON_LEN, decode_byoa_attempt_payload,
};
use super::error::{
    ByoaError, ByoaResult, ERR_ARTIFACT_COLLISION, ERR_ATTEMPT_KIND, ERR_CAPTURE_CONFLICT,
    ERR_DISPOSITION, ERR_EXHAUST_ENCODE, ERR_EXHAUST_TOO_LARGE, ERR_PAYLOAD_SCHEMA,
    ERR_RESULT_REF_SHAPE, ERR_RUNTIME_ACTOR_COLLISION, ERR_STOP_REASON_EMPTY,
    ERR_STOP_REASON_TOO_LONG, invalid,
};
use super::validate::validate_exhaust;
use crate::error::ArtifactError;
/// The proof that one network reach crossed the injected egress port.
///
/// Scope, expiry, and audit reference all live on the lease so the guarantee
/// stays inspectable after the fact: a reviewer can tell what was reachable,
/// until when, and which audit row authorized it, without re-deriving any of
/// it from policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByoaEgressLease {
    pub lease_id: [u8; 16],
    pub profile_ref: String,
    /// Host suffixes this lease admits. Matching is label-boundary aware, so
    /// `example.com` never admits `notexample.com`.
    pub allowed_hosts: Vec<String>,
    pub expires_at: u64,
    pub audit_ref: EntityId,
}

impl ByoaEgressLease {
    /// True when this lease is still live at `now` and admits `host`.
    #[must_use]
    pub fn permits_host(&self, host: &str, now: u64) -> bool {
        if now >= self.expires_at {
            return false;
        }
        let host = host.trim().trim_matches('.').to_lowercase();
        if host.is_empty() {
            return false;
        }
        self.allowed_hosts.iter().any(|allowed| {
            let allowed = allowed.trim().trim_matches('.').to_lowercase();
            !allowed.is_empty()
                && (host == allowed
                    || host
                        .strip_suffix(&allowed)
                        .is_some_and(|head| head.ends_with('.')))
        })
    }
}

/// The injected door every foreign network reach must cross.
///
/// This is an adapter seam over the host's credential-egress boundary
/// (allowlist enforcement plus resolve-and-inject). It is a TRAIT because the
/// dispatcher must be unable to reach the network on its own: with no port
/// injected there is no code path here that opens a socket.
pub trait ByoaEgressPort {
    /// Opens a lease for `profile_ref` on behalf of `intent_ref`.
    ///
    /// # Errors
    ///
    /// Returns [`ByoaError::EgressDenied`] when the profile grants nothing for
    /// this intent.
    fn open(&mut self, profile_ref: &str, intent_ref: &str) -> ByoaResult<ByoaEgressLease>;
}

/// The transcript and side-channel output one foreign agent left behind.
///
/// Every field is optional-or-empty because a foreign agent cooperates only as
/// much as it chooses to; what is NOT optional is that SOMETHING durable was
/// captured — an entirely empty exhaust is refused at the capture door, because
/// an abandonment pointing at nothing is not auditable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByoaExhaust {
    #[serde(default)]
    pub transcript: Option<Vec<u8>>,
    #[serde(default)]
    pub stdout: Vec<u8>,
    #[serde(default)]
    pub stderr: Vec<u8>,
    #[serde(default)]
    pub diff_bundle: Option<Vec<u8>>,
    /// Checkpoint refs as `name@oid`, read through the git seam.
    #[serde(default)]
    pub checkpoint_frontier: Vec<String>,
}

impl ByoaExhaust {
    /// True when nothing durable was captured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.transcript.as_ref().is_none_or(Vec::is_empty)
            && self.stdout.is_empty()
            && self.stderr.is_empty()
            && self.diff_bundle.as_ref().is_none_or(Vec::is_empty)
            && self.checkpoint_frontier.is_empty()
    }
}

/// How a foreign executor stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum ByoaTerminalDisposition {
    Completed,
    Failed,
    Cancelled,
    /// Stopped carrying the work without delivering, and without anyone
    /// stopping it.
    Abandoned,
}

impl ByoaTerminalDisposition {
    /// Stable wire label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Abandoned => "abandoned",
        }
    }
}

impl From<ByoaTerminalDisposition> for String {
    fn from(disposition: ByoaTerminalDisposition) -> Self {
        disposition.as_str().to_owned()
    }
}

impl TryFrom<String> for ByoaTerminalDisposition {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "abandoned" => Ok(Self::Abandoned),
            _ => Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                ERR_DISPOSITION,
            ))),
        }
    }
}

/// A request to fold one terminated executor's exhaust into its artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureByoaExhaust {
    pub attempt_id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub disposition: ByoaTerminalDisposition,
    pub exhaust: ByoaExhaust,
    /// Why the executor stopped. Failed and abandoned captures use a default
    /// when omitted; a supplied reason must satisfy the queue's reason bounds.
    /// Retries must match the stored reason after applying that default.
    /// Advisory for the other dispositions.
    pub reason: Option<String>,
    pub now: u64,
}

/// What one capture produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByoaTerminalReceipt {
    pub attempt: AttemptRecord,
    pub artifact_id: EntityId,
    pub artifact_version: u64,
    pub result_ref: AttemptResultRef,
}

/// The canonical body one exhaust artifact version holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ByoaExhaustEnvelope {
    pub(super) schema_version: u8,
    pub(super) attempt_id: [u8; 16],
    // Retained after settlement clears the row's live owner. Terminal retries
    // must present the same fence rather than borrowing generic no-op semantics.
    // Old exhaust remains readable, but missing fence evidence cannot authorize a retry.
    #[serde(default)]
    pub(super) lease_owner: String,
    #[serde(default)]
    pub(super) attempt_count: u32,
    pub(super) disposition: ByoaTerminalDisposition,
    pub(super) exhaust: ByoaExhaust,
}

/// Stamped on a failure whose caller supplied no reason.
pub const BYOA_DEFAULT_FAILURE_REASON: &str = "foreign executor failed";

/// Stamped on an abandonment whose caller supplied no reason.
pub const BYOA_DEFAULT_ABANDON_REASON: &str = "foreign executor stopped without delivering";

pub(super) fn normalize_capture_reason(
    disposition: ByoaTerminalDisposition,
    reason: Option<String>,
) -> ByoaResult<String> {
    let reason = match disposition {
        ByoaTerminalDisposition::Failed => {
            reason.unwrap_or_else(|| BYOA_DEFAULT_FAILURE_REASON.to_owned())
        }
        ByoaTerminalDisposition::Abandoned => {
            reason.unwrap_or_else(|| BYOA_DEFAULT_ABANDON_REASON.to_owned())
        }
        ByoaTerminalDisposition::Completed | ByoaTerminalDisposition::Cancelled => {
            return Ok(String::new());
        }
    };
    // Match queue admission on every request, including read-only retries.
    if reason.is_empty() {
        return Err(ByoaError::Store(Error::Artifact(
            ArtifactError::InvalidAttemptQueueRecord(ERR_STOP_REASON_EMPTY),
        )));
    }
    if reason.len() > MAX_STOP_REASON_LEN {
        return Err(ByoaError::Store(Error::Artifact(
            ArtifactError::InvalidAttemptQueueRecord(ERR_STOP_REASON_TOO_LONG),
        )));
    }
    Ok(reason)
}

/// The one artifact every capture for this attempt appends to.
///
/// Derived from the attempt id rather than minted per capture: that is what
/// makes "one canonical artifact per terminal attempt" a property of the
/// address, not of caller discipline.
///
/// # Errors
///
/// Returns [`ByoaError::Store`] when no non-reserved id can be derived.
pub fn byoa_exhaust_artifact_id(attempt_id: AttemptId) -> ByoaResult<EntityId> {
    Ok(entity_id_from_hash_material(
        BYOA_EXHAUST_ARTIFACT_ID_DOMAIN,
        &[attempt_id.as_bytes()],
    )?)
}

/// Builds the `blob-artifact:<id>@<version>` reference for one artifact
/// version.
///
/// # Errors
///
/// Returns [`ByoaError::Store`] when the reference fails the attempt-queue
/// result-reference door.
pub fn byoa_result_ref(artifact_id: &EntityId, version: u64) -> ByoaResult<AttemptResultRef> {
    Ok(AttemptResultRef::new(format!(
        "{BYOA_RESULT_REF_PREFIX}{}@{version}",
        artifact_id.to_hex()
    ))?)
}

/// Splits a BYOA result reference back into the artifact and version it names.
///
/// # Errors
///
/// Returns [`ByoaError::Store`] when the reference is not this module's shape.
pub fn parse_byoa_result_ref(result_ref: &AttemptResultRef) -> ByoaResult<(EntityId, u64)> {
    let shape = || {
        ByoaError::Store(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            ERR_RESULT_REF_SHAPE,
        )))
    };
    let body = result_ref
        .as_str()
        .strip_prefix(BYOA_RESULT_REF_PREFIX)
        .ok_or_else(shape)?;
    // Split from the RIGHT: the version is the tail, and an artifact id is
    // fixed-width hex that can never contain the delimiter.
    let (id_hex, version) = body.rsplit_once('@').ok_or_else(shape)?;
    let artifact_id = EntityId::from_hex(id_hex).map_err(|_| shape())?;
    let version: u64 = version.parse().map_err(|_| shape())?;
    Ok((artifact_id, version))
}

/// Reads a checkpoint frontier for one checkout through the typed git seam.
///
/// READ-ONLY by construction: it calls only the wire's read constructors, and
/// a ref whose tip object is not actually present is omitted rather than
/// reported, so a frontier never names an object a reader could not resolve.
///
/// # Errors
///
/// Returns [`ByoaError::Store`] on any git-seam refusal.
pub fn read_checkpoint_frontier(
    wire: &GitWire<'_>,
    repo: &GitWireRepo,
    names: &[GitRefName],
) -> ByoaResult<Vec<String>> {
    let mut frontier = Vec::new();
    for observed in wire.read_refs(repo, names)? {
        let Some(oid) = observed.oid else {
            continue;
        };
        if !wire.object_exists(repo, &oid)? {
            continue;
        }
        frontier.push(format!("{}@{}", observed.name.as_str(), oid.as_str()));
    }
    Ok(frontier)
}

/// The stable host-runtime identity that authors exhaust artifact writes.
///
/// Content-free and derived, not minted: the WRITE is performed by this
/// runtime on a foreign agent's behalf, and stamping a fresh actor per capture
/// would scatter one durable responsibility across unrelated ids.
pub(super) fn byoa_runtime_actor() -> ByoaResult<WriteActor> {
    Ok(WriteActor::new(
        entity_id_from_hash_material(BYOA_RUNTIME_ACTOR_DOMAIN, &[])?,
        EdgeActorClass::Agent,
    ))
}

/// Materializes the stable actor before the blob-version claim references it.
/// Only the canonical PERSON body may own this id; admitting the Agent class
/// alone does not establish runtime identity. Check and create share a transaction.
pub(super) fn ensure_byoa_runtime_actor(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    occurred: TimeRange,
    learned_at: u64,
) -> ByoaResult<WriteActor> {
    let actor = byoa_runtime_actor()?;
    if let Some(entity_type) = vault.get_entity_type_in_txn(wtxn, &actor.entity_ref())? {
        crate::provenance::validate_actor_class(entity_type, actor.actor_class())?;
        let raw = vault
            .get_raw_in(wtxn, &actor.entity_ref())?
            .ok_or_else(|| invalid(ERR_RUNTIME_ACTOR_COLLISION))?;
        if entity_type != crate::registry::ENTITY_TYPE_PERSON
            || raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
                != Some(BYOA_RUNTIME_ACTOR_DOMAIN)
        {
            return Err(invalid(ERR_RUNTIME_ACTOR_COLLISION));
        }
    } else {
        vault
            .batch_in()
            .put(
                &actor.entity_ref(),
                crate::registry::ENTITY_TYPE_PERSON,
                occurred,
                learned_at,
                BYOA_RUNTIME_ACTOR_DOMAIN,
            )
            .apply(wtxn)?;
    }
    Ok(actor)
}

pub(super) fn decode_byoa_record(record: &AttemptRecord) -> ByoaResult<ByoaAttemptPayload> {
    if record.kind != BYOA_ATTEMPT_KIND {
        return Err(invalid(ERR_ATTEMPT_KIND));
    }
    decode_byoa_attempt_payload(&record.payload)
}

pub(super) fn disposition_matches_state(
    disposition: ByoaTerminalDisposition,
    state: AttemptState,
) -> bool {
    matches!(
        (disposition, state),
        (ByoaTerminalDisposition::Completed, AttemptState::Completed)
            | (ByoaTerminalDisposition::Failed, AttemptState::Failed)
            | (ByoaTerminalDisposition::Cancelled, AttemptState::Cancelled)
            | (ByoaTerminalDisposition::Abandoned, AttemptState::Abandoned)
    )
}

pub(super) fn validate_canonical_capture(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    artifact_id: &EntityId,
    body: &BlobArtifactBody,
    provenance: &BlobVersionProvenance,
    requested: &ByoaExhaustEnvelope,
) -> ByoaResult<()> {
    if vault.get_blob_artifact_in_txn(wtxn, artifact_id)?.as_ref() != Some(body) {
        return Err(invalid(ERR_ARTIFACT_COLLISION));
    }
    let head = read_blob_artifact_head_in_txn(&vault.store, wtxn, artifact_id)?
        .ok_or_else(|| invalid(ERR_ARTIFACT_COLLISION))?;
    if head.version != 1 || &head.provenance != provenance {
        return Err(invalid(ERR_ARTIFACT_COLLISION));
    }
    let bytes = vault
        .read_blob_artifact_version_in_txn(wtxn, artifact_id, 1)?
        .ok_or_else(|| invalid(ERR_ARTIFACT_COLLISION))?;
    if blake3::hash(&bytes).as_bytes() != &head.content_hash {
        return Err(invalid(ERR_ARTIFACT_COLLISION));
    }
    let stored = decode_exhaust_envelope(&bytes)?;
    if stored.attempt_id != requested.attempt_id
        || stored.lease_owner != requested.lease_owner
        || stored.attempt_count != requested.attempt_count
        || stored.disposition != requested.disposition
        || (stored.disposition != ByoaTerminalDisposition::Abandoned
            && stored.exhaust != requested.exhaust)
    {
        return Err(invalid(ERR_CAPTURE_CONFLICT));
    }
    Ok(())
}

pub(super) fn byoa_exhaust_artifact_name(attempt_id: AttemptId) -> String {
    format!(
        "{BYOA_ATTEMPT_KIND}/{}",
        bytes_to_hex_lower(attempt_id.as_bytes())
    )
}

pub(super) fn encode_exhaust_envelope(envelope: &ByoaExhaustEnvelope) -> ByoaResult<Vec<u8>> {
    validate_exhaust(&envelope.exhaust)?;
    rmp_serde::to_vec_named(envelope).map_err(|_| {
        ByoaError::Store(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            ERR_EXHAUST_ENCODE,
        )))
    })
}

/// Decodes one exhaust artifact version body.
///
/// # Errors
///
/// Returns [`ByoaError::Store`] when the bytes are not an exhaust envelope of
/// a schema version this build understands.
pub fn decode_byoa_exhaust(
    bytes: &[u8],
) -> ByoaResult<(AttemptId, ByoaTerminalDisposition, ByoaExhaust)> {
    let envelope = decode_exhaust_envelope(bytes)?;
    let attempt_id = AttemptId::from_bytes(&envelope.attempt_id)?;
    Ok((attempt_id, envelope.disposition, envelope.exhaust))
}

fn decode_exhaust_envelope(bytes: &[u8]) -> ByoaResult<ByoaExhaustEnvelope> {
    if bytes.len() > MAX_EXHAUST_ENCODED_BYTES {
        return Err(invalid(ERR_EXHAUST_TOO_LARGE));
    }
    let envelope: ByoaExhaustEnvelope = rmp_serde::from_slice(bytes).map_err(|_| {
        ByoaError::Store(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            ERR_EXHAUST_ENCODE,
        )))
    })?;
    if envelope.schema_version != BYOA_CONNECTOR_SCHEMA_VERSION {
        return Err(ByoaError::Store(Error::Artifact(
            ArtifactError::InvalidAgentDispatchInput(ERR_PAYLOAD_SCHEMA),
        )));
    }
    validate_exhaust(&envelope.exhaust)?;
    Ok(envelope)
}
