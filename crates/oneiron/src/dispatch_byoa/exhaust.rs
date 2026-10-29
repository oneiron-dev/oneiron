//! Exhaust types, terminal receipts, artifact and result-ref addressing, and capture helpers.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptRecord, AttemptResultRef, AttemptState};
use crate::blob_artifact::{
    BlobArtifactBody, BlobArtifactVersion, BlobVersionProvenance, read_blob_artifact_head_in_txn,
};
use crate::codebase::entity_id_from_hash_material;
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;
use crate::git_wire::{GitRefName, GitWire, GitWireRepo};
use crate::limit_ask::EngineLimit;
use crate::secret_lease::SecretTaintRef;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

use super::connector::{
    BYOA_ATTEMPT_KIND, BYOA_CONNECTOR_SCHEMA_VERSION, BYOA_EXHAUST_ARTIFACT_ID_DOMAIN,
    BYOA_RESULT_REF_PREFIX, BYOA_RUNTIME_ACTOR_DOMAIN, ByoaAttemptPayload, MAX_STOP_REASON_LEN,
    decode_byoa_attempt_payload,
};
use super::error::{
    ByoaError, ByoaResult, ERR_ARTIFACT_COLLISION, ERR_ATTEMPT_KIND, ERR_CAPTURE_CONFLICT,
    ERR_DISPOSITION, ERR_EXHAUST_ENCODE, ERR_PAYLOAD_SCHEMA, ERR_RESULT_REF_SHAPE,
    ERR_RUNTIME_ACTOR_COLLISION, ERR_STOP_REASON_EMPTY, ERR_STOP_REASON_TOO_LONG, invalid,
};
use super::seat::SkippedRunnerSeat;
use super::validate::validate_exhaust;
use crate::error::ArtifactError;

use super::stream::{ByoaStream, ByoaStreamWire};

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
    /// The secrets the host injected into traffic under this lease, as its
    /// injection receipts reported them. Every run that used the lease
    /// carries these refs into its exhaust, so the captured output exports
    /// redacted.
    pub secret_taint_refs: Vec<SecretTaintRef>,
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
/// an abandonment pointing at nothing is not auditable. Each stream is held
/// whole ([`ByoaStream`]) and is never refused for its size.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ByoaExhaust {
    pub transcript: Option<ByoaStream>,
    pub stdout: ByoaStream,
    pub stderr: ByoaStream,
    pub diff_bundle: Option<ByoaStream>,
    /// Checkpoint refs as `name@oid`, read through the git seam.
    pub checkpoint_frontier: Vec<String>,
    /// The secrets injected while this output was produced. Empty is
    /// untainted.
    pub secret_taint_refs: Vec<SecretTaintRef>,
}

impl ByoaExhaust {
    /// True when nothing durable was captured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.streams().all(ByoaStream::is_empty) && self.checkpoint_frontier.is_empty()
    }

    /// The streams this exhaust carries.
    fn streams(&self) -> impl Iterator<Item = &ByoaStream> {
        [
            self.transcript.as_ref(),
            Some(&self.stdout),
            Some(&self.stderr),
            self.diff_bundle.as_ref(),
        ]
        .into_iter()
        .flatten()
    }

    /// This exhaust's envelope form, its longer streams stored by `append`.
    fn to_wire(
        &self,
        append: &mut impl FnMut(&[u8]) -> ByoaResult<u64>,
    ) -> ByoaResult<ByoaExhaustWire> {
        Ok(ByoaExhaustWire {
            transcript: self
                .transcript
                .as_ref()
                .map(|stream| stream.to_wire(append))
                .transpose()?,
            stdout: self.stdout.to_wire(append)?,
            stderr: self.stderr.to_wire(append)?,
            diff_bundle: self
                .diff_bundle
                .as_ref()
                .map(|stream| stream.to_wire(append))
                .transpose()?,
            checkpoint_frontier: self.checkpoint_frontier.clone(),
            secret_taint_refs: self.secret_taint_refs.clone(),
        })
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
    /// Fallback seats a NextSeat route passed over, each with why, in the
    /// owner's order. Empty for every other capture. A moved-on replay reads
    /// the head hop's durable list (FIX 9242).
    pub skipped_seats: Vec<SkippedRunnerSeat>,
}

/// The canonical body an exhaust artifact's head version holds. A capture
/// builds it over the runtime exhaust; the stored form carries the wire one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ByoaExhaustEnvelope<E = ByoaExhaustWire> {
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
    pub(super) exhaust: E,
}

/// How an exhaust rides its envelope: each stream within the inline budget
/// whole, a longer one as the manifest of its chunk versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ByoaExhaustWire {
    #[serde(default)]
    transcript: Option<ByoaStreamWire>,
    stdout: ByoaStreamWire,
    stderr: ByoaStreamWire,
    #[serde(default)]
    diff_bundle: Option<ByoaStreamWire>,
    #[serde(default)]
    checkpoint_frontier: Vec<String>,
    /// Empty is untainted and is not serialized.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    secret_taint_refs: Vec<SecretTaintRef>,
}

impl ByoaExhaustWire {
    /// Whether `exhaust` is the exhaust this form names, its chunked streams
    /// read back in `rtxn` and checked against their manifests.
    fn matches(
        &self,
        vault: &Vault,
        rtxn: &heed::RoTxn<'_>,
        artifact_id: &EntityId,
        exhaust: &ByoaExhaust,
    ) -> ByoaResult<bool> {
        let matches =
            |wire: Option<&ByoaStreamWire>, stream: Option<&ByoaStream>| match (wire, stream) {
                (None, None) => Ok(true),
                (Some(wire), Some(stream)) => wire.matches(vault, rtxn, artifact_id, stream),
                _ => Ok(false),
            };
        Ok(self.checkpoint_frontier == exhaust.checkpoint_frontier
            && self.secret_taint_refs == exhaust.secret_taint_refs
            && matches(self.transcript.as_ref(), exhaust.transcript.as_ref())?
            && matches(Some(&self.stdout), Some(&exhaust.stdout))?
            && matches(Some(&self.stderr), Some(&exhaust.stderr))?
            && matches(self.diff_bundle.as_ref(), exhaust.diff_bundle.as_ref())?)
    }

    /// The exhaust this form names, its chunked streams read back in `rtxn`.
    fn resolve(
        self,
        vault: &Vault,
        rtxn: &heed::RoTxn<'_>,
        artifact_id: &EntityId,
    ) -> ByoaResult<ByoaExhaust> {
        let resolve = |stream: ByoaStreamWire| stream.resolve(vault, rtxn, artifact_id);
        Ok(ByoaExhaust {
            transcript: self.transcript.map(resolve).transpose()?,
            stdout: resolve(self.stdout)?,
            stderr: resolve(self.stderr)?,
            diff_bundle: self.diff_bundle.map(resolve).transpose()?,
            checkpoint_frontier: self.checkpoint_frontier,
            secret_taint_refs: self.secret_taint_refs,
        })
    }
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

/// The head version a canonical capture's result ref names: `None` unless
/// `result_ref` is `artifact_id`'s, spelled as [`byoa_result_ref`] spells it.
pub(super) fn canonical_result_version(
    result_ref: &AttemptResultRef,
    artifact_id: &EntityId,
) -> Option<u64> {
    let (named, version) = parse_byoa_result_ref(result_ref).ok()?;
    (named == *artifact_id && byoa_result_ref(artifact_id, version).ok()? == *result_ref)
        .then_some(version)
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
    version: u64,
    body: &BlobArtifactBody,
    provenance: &BlobVersionProvenance,
    requested: &ByoaExhaustEnvelope<ByoaExhaust>,
) -> ByoaResult<()> {
    let stored_body = vault
        .get_blob_artifact_in_txn(wtxn, artifact_id)?
        .ok_or_else(|| invalid(ERR_ARTIFACT_COLLISION))?;
    let head = read_blob_artifact_head_in_txn(&vault.store, wtxn, artifact_id)?
        .ok_or_else(|| invalid(ERR_ARTIFACT_COLLISION))?;
    if head.version != version || &head.provenance != provenance {
        return Err(invalid(ERR_ARTIFACT_COLLISION));
    }
    let bytes = vault
        .read_blob_artifact_version_in_txn(wtxn, artifact_id, version)?
        .ok_or_else(|| invalid(ERR_ARTIFACT_COLLISION))?;
    if blake3::hash(&bytes).as_bytes() != &head.content_hash {
        return Err(invalid(ERR_ARTIFACT_COLLISION));
    }
    let stored = decode_exhaust_envelope(&bytes)?;
    // An abandoned retry answers with the first capture, so the metadata
    // must still carry the first capture's taint, read from its immutable
    // envelope, whatever the retry's exhaust carries.
    let expected = if requested.disposition == ByoaTerminalDisposition::Abandoned {
        body.clone()
            .with_secret_taint_refs(stored.exhaust.secret_taint_refs.clone())
    } else {
        body.clone()
    };
    if stored_body != expected {
        return Err(invalid(ERR_ARTIFACT_COLLISION));
    }
    if stored.attempt_id != requested.attempt_id
        || stored.lease_owner != requested.lease_owner
        || stored.attempt_count != requested.attempt_count
        || stored.disposition != requested.disposition
        || (stored.disposition != ByoaTerminalDisposition::Abandoned
            && !stored
                .exhaust
                .matches(vault, wtxn, artifact_id, &requested.exhaust)?)
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

/// Adds `refs` to `into`, one ref per secret at the lowest generation seen,
/// in name order. The lowest generation is the fail-closed choice: a rotation
/// past it still reads as stale taint.
pub(super) fn union_taint_refs(into: &mut Vec<SecretTaintRef>, refs: &[SecretTaintRef]) {
    for r in refs {
        match into.iter_mut().find(|held| held.secret_ref == r.secret_ref) {
            Some(held) => held.generation = held.generation.min(r.generation),
            None => into.push(r.clone()),
        }
    }
    into.sort_by(|a, b| a.secret_ref.cmp(&b.secret_ref));
}

/// Stores one capture in its artifact: each stream past the inline budget as
/// budget-sized chunk versions, in order, then the envelope naming them, whose
/// version is the head the result ref names. The longest stream is measured
/// against the engine's text row, and the frontier and taint counts traced;
/// no stream is refused for its length, nor a frontier or taint set for its
/// count.
pub(super) fn append_exhaust_envelope(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    artifact_id: &EntityId,
    envelope: &ByoaExhaustEnvelope<ByoaExhaust>,
    provenance: &BlobVersionProvenance,
    actor: WriteActor,
    now: u64,
) -> ByoaResult<BlobArtifactVersion> {
    let longest = envelope
        .exhaust
        .streams()
        .map(ByoaStream::len)
        .max()
        .unwrap_or_default();
    let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, longest);
    // Counts observed, never refused: every frontier entry and taint ref is
    // kept whole.
    tracing::debug!(
        checkpoint_frontier = envelope.exhaust.checkpoint_frontier.len(),
        secret_taint_refs = envelope.exhaust.secret_taint_refs.len(),
        "byoa capture: checkpoint frontier and taint ref counts"
    );
    let occurred = TimeRange {
        start: now,
        end: now,
    };
    let mut append = |bytes: &[u8]| -> ByoaResult<u64> {
        Ok(vault
            .append_blob_artifact_version_in_txn(
                wtxn,
                artifact_id,
                bytes,
                provenance,
                actor,
                occurred,
                now,
            )?
            .version)
    };
    let exhaust = envelope.exhaust.to_wire(&mut append)?;
    let bytes = encode_exhaust_envelope(&ByoaExhaustEnvelope {
        schema_version: envelope.schema_version,
        attempt_id: envelope.attempt_id,
        lease_owner: envelope.lease_owner.clone(),
        attempt_count: envelope.attempt_count,
        disposition: envelope.disposition,
        exhaust,
    })?;
    Ok(vault.append_blob_artifact_version_in_txn(
        wtxn,
        artifact_id,
        &bytes,
        provenance,
        actor,
        occurred,
        now,
    )?)
}

pub(super) fn encode_exhaust_envelope(envelope: &ByoaExhaustEnvelope) -> ByoaResult<Vec<u8>> {
    rmp_serde::to_vec_named(envelope).map_err(|_| {
        ByoaError::Store(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            ERR_EXHAUST_ENCODE,
        )))
    })
}

/// Decodes the capture an exhaust artifact's head version holds, reading back
/// the chunk versions its longer streams were stored in. A read: no stream is
/// measured or refused for its length.
///
/// # Errors
///
/// Returns [`ByoaError::Store`] when `version` is not the artifact's head,
/// when its bytes are not an exhaust envelope of a schema version this build
/// understands, or when a stream's chunks do not hold the bytes it names.
pub fn decode_byoa_exhaust(
    vault: &Vault,
    artifact_id: &EntityId,
    version: u64,
) -> ByoaResult<(AttemptId, ByoaTerminalDisposition, ByoaExhaust)> {
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    // Only the head holds an envelope; every version before it is a chunk.
    if read_blob_artifact_head_in_txn(&vault.store, &rtxn, artifact_id)?
        .is_none_or(|head| head.version != version)
    {
        return Err(invalid(ERR_CAPTURE_CONFLICT));
    }
    let bytes = vault
        .read_blob_artifact_version_in_txn(&rtxn, artifact_id, version)?
        .ok_or_else(|| invalid(ERR_CAPTURE_CONFLICT))?;
    let envelope = decode_exhaust_envelope(&bytes)?;
    let attempt_id = AttemptId::from_bytes(&envelope.attempt_id)?;
    let exhaust = envelope.exhaust.resolve(vault, &rtxn, artifact_id)?;
    validate_exhaust(&exhaust)?;
    Ok((attempt_id, envelope.disposition, exhaust))
}

fn decode_exhaust_envelope(bytes: &[u8]) -> ByoaResult<ByoaExhaustEnvelope> {
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
    Ok(envelope)
}
