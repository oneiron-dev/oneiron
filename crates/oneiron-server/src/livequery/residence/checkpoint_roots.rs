//! `residence.authority.checkpoint.{roots,attest,countersign}` (FIX 4882):
//! the home's half of checkpoint root attestations with a machine that
//! dials it. `roots` names this home's head image, the roots it awaits and
//! the roots this home signs as. `attest` takes one root's attestation of a
//! kept image through the host intake
//! ([`oneiron::Vault::import_device_checkpoint_attestation`]). `countersign`
//! takes the machine's own image a part at a time
//! ([`oneiron::Vault::stage_countersign_part`]), has this home's root attest
//! it once this home's fold rebuilds it
//! ([`oneiron::Vault::countersign_authority_checkpoint_for`]), and answers
//! what it made, on the last part, for the machine's intake. The staged bytes
//! are charged to the server's retained-memory line while held, and go when
//! the stage idles out or its socket closes (FIX 5111); the rebuild and the
//! signature run off the runtime worker (FIX 5110). Each serves a live
//! linked machine of the vault only; any other looks missing or refused.
//! Nothing a machine sends chooses its trust: every root comes from this
//! vault's own policy, and the home's root signs only what its own fold
//! rebuilds.

use std::sync::Arc;

use base64::Engine;
use oneiron::authority::{
    AUTHORITY_CHECKPOINT_COUNTERSIGN_PART_MAX, AuthorityCheckpointAttestation,
    CheckpointAttestationIntake, CountersignStageCharge, CountersignStaged, HostSlipIssuer,
    PeerMachine, RootCheckpointAttest,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Answer, AppError, one_hash};
use crate::byte_line::{ByteLine, HeldBytes};
use crate::server::SyncServer;
use crate::wire_telemetry::LimitQuestions;

/// No parameters.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootsRequest {}

/// One root's attestation of the kept image whose id is `checkpoint`, in
/// base64.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestRequest {
    checkpoint: String,
    attestation: AuthorityCheckpointAttestation,
}

/// One part of the machine's own image: the image's id in base64, its whole
/// length, the part's offset and the part's bytes in base64.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CountersignRequest {
    checkpoint: String,
    total: u64,
    offset: u64,
    part: String,
}

/// Runs `with` on the root this home signs as: the managed issuer, or the
/// one its configured host secret derives, as the checkpoint upkeep takes
/// it; `None` for a home with neither.
fn with_host_root<T>(
    server: &SyncServer,
    with: impl FnOnce(Option<&HostSlipIssuer>) -> Result<T, AppError>,
) -> Result<T, AppError> {
    if let Some(issuer) = server.managed_issuer.as_ref() {
        return with(Some(issuer));
    }
    let derived = match server
        .config
        .auth_secret
        .as_deref()
        .filter(|secret| !secret.is_empty())
    {
        Some(secret) => Some(
            HostSlipIssuer::from_secret(secret.as_bytes())
                .map_err(|_| AppError::internal_server_error("host root unavailable"))?,
        ),
        None => None,
    };
    with(derived.as_ref())
}

fn unavailable() -> AppError {
    AppError::internal_server_error("authority checkpoint unavailable")
}

/// A countersign stage's charge on this server's retained-memory line, the
/// one the residence index cache is charged to (FIX 5111).
struct StageCharge {
    line: Arc<ByteLine>,
    held: HeldBytes,
    questions: Arc<LimitQuestions>,
}

impl CountersignStageCharge for StageCharge {
    fn resize(&mut self, bytes: usize) -> bool {
        self.line.try_resize(&mut self.held, bytes, &self.questions)
    }
}

fn stage_charge(server: &SyncServer) -> Box<dyn CountersignStageCharge> {
    Box::new(StageCharge {
        held: server.retained.empty(),
        line: Arc::clone(&server.retained),
        questions: Arc::clone(server.wire_telemetry.limit_questions()),
    })
}

pub(super) fn roots(
    server: &SyncServer,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let RootsRequest {} = serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let status = server
        .vault
        .authority_checkpoint_roots_for(peer)
        .map_err(|_| AppError::not_found("authority checkpoint", None))?;
    let signs: Vec<_> = with_host_root(server, |issuer| {
        Ok(issuer.map(HostSlipIssuer::public_key).into_iter().collect())
    })?;
    let (checkpoint, awaiting): (Option<String>, Vec<_>) = match &status {
        Some(status) => (
            Some(base64::engine::general_purpose::STANDARD.encode(status.image)),
            status.awaited().cloned().collect(),
        ),
        None => (None, Vec::new()),
    };
    let awaiting = serde_json::to_value(awaiting).map_err(|_| unavailable())?;
    let signs = serde_json::to_value(signs).map_err(|_| unavailable())?;
    Ok((
        json!({ "checkpoint": checkpoint, "awaiting": awaiting, "signs": signs }),
        Some(Vec::new()),
    ))
}

pub(super) fn attest(
    server: &SyncServer,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: AttestRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let image = one_hash(&input.checkpoint)?;
    let attested = match server
        .vault
        .import_device_checkpoint_attestation(peer, image, &input.attestation)
        .map_err(|_| AppError::bad_request("checkpoint attestation refused", Some("attestation")))?
    {
        CheckpointAttestationIntake::Kept { attested }
        | CheckpointAttestationIntake::AlreadyKept { attested } => attested,
    };
    Ok((json!({ "attested": attested }), Some(Vec::new())))
}

pub(super) fn countersign(
    server: &SyncServer,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: CountersignRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let id = one_hash(&input.checkpoint)?;
    if input.part.len() > AUTHORITY_CHECKPOINT_COUNTERSIGN_PART_MAX.div_ceil(3) * 4 {
        return Err(AppError::invalid_params());
    }
    let part = base64::engine::general_purpose::STANDARD
        .decode(input.part)
        .map_err(|_| AppError::invalid_params())?;
    let attestations = with_host_root(server, |issuer| {
        // A home with no root countersigns nothing, and holds no part.
        let Some(issuer) = issuer else {
            return Ok(Vec::new());
        };
        let staged = server
            .vault
            .stage_countersign_part(peer, id, input.total, input.offset, &part, || {
                stage_charge(server)
            })
            .map_err(|_| AppError::bad_request("countersign part refused", Some("part")))?;
        // The whole image stays charged until it is countersigned.
        let (image, _charge) = match staged {
            CountersignStaged::Held => return Ok(Vec::new()),
            CountersignStaged::NoRoom => return Err(AppError::memory_floor()),
            CountersignStaged::Whole { image, charge } => (image, charge),
        };
        // FIX 5110: the fold rebuild and the SLH-DSA signature run off the
        // runtime worker. This socket waits for them before it answers, so
        // its replies keep their order.
        let made = crate::server::blocking(|| {
            server
                .vault
                .countersign_authority_checkpoint_for(peer, &image, issuer)
        })
        .map_err(|_| AppError::bad_request("authority checkpoint image refused", Some("part")))?;
        Ok(match made {
            RootCheckpointAttest::Attested { image, attestation } if image == id => {
                vec![*attestation]
            }
            RootCheckpointAttest::Attested { .. } | RootCheckpointAttest::Waiting(_) => Vec::new(),
        })
    })?;
    let attestations = serde_json::to_value(attestations).map_err(|_| unavailable())?;
    Ok((json!({ "attestations": attestations }), Some(Vec::new())))
}
