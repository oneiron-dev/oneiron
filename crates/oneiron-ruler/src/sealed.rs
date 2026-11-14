//! The sealed-once markers: one sealed run per experiment (RESEARCH-0651 Tier 0).
//!
//! A Promote on held_out earns exactly ONE run on the sealed slice. The claim
//! is spent before the sealed slice is opened, so a crash spends it. The
//! sealed run is a check that can withdraw the proposal: worse beyond
//! tolerance on any Primary or Floor axis withdraws it.

use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::pack::sha256_hex;
use crate::scorecard::Scorecard;

/// The contract string every sealed-once marker carries.
pub const SEALED_ONCE_CONTRACT: &str = "oneiron.retrieval_ruler_sealed_once.v1";

/// Experiment identity (RESEARCH-0651:101).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentIdentity {
    /// The engine commit.
    pub engine_commit: String,
    /// 64 lowercase hex: the digest of the parameter set.
    pub params_digest: String,
    /// The pack digest of the graded manifest.
    pub pack_digest: String,
}

impl ExperimentIdentity {
    /// The identity of the run a scorecard grades.
    pub fn of_scorecard(scorecard: &Scorecard) -> Self {
        Self {
            engine_commit: scorecard.engine_commit.clone(),
            params_digest: scorecard.params_digest.clone(),
            pack_digest: scorecard.pack_digest.clone(),
        }
    }

    /// sha256 (lowercase hex) of the RFC 8785 canonical JSON of the identity (serde_json_canonicalizer::to_vec).
    pub fn digest(&self) -> Result<String, SealedError> {
        let bytes = serde_json_canonicalizer::to_vec(self)
            .map_err(|error| SealedError::Canonical(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }
}

/// A claimed marker: where it is and which identity digest it spends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedClaim {
    /// The marker file.
    pub path: PathBuf,
    /// The identity digest the marker spends.
    pub identity_digest: String,
}

/// Every way a sealed claim can fail.
#[derive(Debug, Error)]
pub enum SealedError {
    /// A ledger file could not be read or written.
    #[error("io error at {path:?}: {source}")]
    Io {
        /// The file path.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// A marker is not valid JSON for this shape.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// The identity has no canonical JSON form.
    #[error("canonical JSON error: {0}")]
    Canonical(String),
    /// The identity already spent its one sealed run.
    #[error("sealed run already spent: {path:?}")]
    AlreadySpent {
        /// The existing marker.
        path: PathBuf,
    },
    /// The campaign already measured its incumbent on sealed.
    #[error("incumbent already measured for campaign: {campaign_id}")]
    IncumbentAlreadyMeasured {
        /// The campaign.
        campaign_id: String,
    },
    /// The campaign id is empty.
    #[error("campaign id is empty")]
    EmptyCampaignId,
}

/// Spends the identity's one sealed run BEFORE the sealed slice is opened.
///
/// This reuses the rule of `measure_once`
/// (crates/oneiron/src/autoreason_campaign/beam_promotion.rs:134-135): "Marks
/// the candidate spent BEFORE any external measurement. A crash or error
/// consumes the shot". The rule is reused, not called: the marker file is
/// created (and never rewritten) before any sealed measurement may run.
pub fn claim_sealed_once(
    ledger_dir: &Path,
    identity: &ExperimentIdentity,
) -> Result<SealedClaim, SealedError> {
    let identity_digest = identity.digest()?;
    let dir = ledger_dir.join("sealed-once");
    std::fs::create_dir_all(&dir).map_err(|source| SealedError::Io {
        path: dir.clone(),
        source,
    })?;
    let path = dir.join(format!("{identity_digest}.json"));
    let marker = SealedMarker {
        contract: SEALED_ONCE_CONTRACT.to_owned(),
        identity: identity.clone(),
        state: "spent".to_owned(),
    };
    let mut bytes = serde_json::to_vec_pretty(&marker)?;
    bytes.push(b'\n');
    if !write_claim(&dir, &path, &bytes)? {
        return Err(SealedError::AlreadySpent { path });
    }
    Ok(SealedClaim {
        path,
        identity_digest,
    })
}

/// Spends a campaign's one incumbent sealed run (the shipped incumbent gets one at bootstrap), then the identity's.
pub fn claim_incumbent_once(
    ledger_dir: &Path,
    campaign_id: &str,
    identity: &ExperimentIdentity,
) -> Result<SealedClaim, SealedError> {
    if campaign_id.is_empty() {
        return Err(SealedError::EmptyCampaignId);
    }
    let dir = ledger_dir.join("incumbent-once");
    std::fs::create_dir_all(&dir).map_err(|source| SealedError::Io {
        path: dir.clone(),
        source,
    })?;
    let digest = sha256_hex(campaign_id.as_bytes());
    let path = dir.join(format!("{digest}.json"));
    let marker = IncumbentMarker {
        contract: SEALED_ONCE_CONTRACT.to_owned(),
        campaign_id: campaign_id.to_owned(),
        identity: identity.clone(),
    };
    let mut bytes = serde_json::to_vec_pretty(&marker)?;
    bytes.push(b'\n');
    if !write_claim(&dir, &path, &bytes)? {
        return Err(SealedError::IncumbentAlreadyMeasured {
            campaign_id: campaign_id.to_owned(),
        });
    }
    claim_sealed_once(ledger_dir, identity)
}

/// The sealed-once marker file body.
#[derive(Serialize)]
struct SealedMarker {
    /// Must equal [`SEALED_ONCE_CONTRACT`].
    contract: String,
    /// The identity the marker spends.
    identity: ExperimentIdentity,
    /// Always "spent".
    state: String,
}

/// The incumbent-once marker file body.
#[derive(Serialize)]
struct IncumbentMarker {
    /// Must equal [`SEALED_ONCE_CONTRACT`].
    contract: String,
    /// The campaign the incumbent run belongs to.
    campaign_id: String,
    /// The measured incumbent identity.
    identity: ExperimentIdentity,
}

/// Creates, writes and syncs one claim file: Ok(true) when written, Ok(false) when it already existed.
fn write_claim(dir: &Path, path: &Path, bytes: &[u8]) -> Result<bool, SealedError> {
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(file) => file,
        Err(source) if source.kind() == ErrorKind::AlreadyExists => return Ok(false),
        Err(source) => {
            return Err(SealedError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    file.write_all(bytes).map_err(|source| SealedError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| SealedError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let handle = std::fs::File::open(dir).map_err(|source| SealedError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    handle.sync_all().map_err(|source| SealedError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    Ok(true)
}
