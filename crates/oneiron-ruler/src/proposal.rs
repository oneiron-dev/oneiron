//! Write-once proposal records: the held_out Promote, the sealed check, the owner's stamp (RESEARCH-0651 Tier 0).
//!
//! A Promote on held_out earns exactly ONE run on the sealed slice (spent
//! before it is measured, so a crash spends it). The sealed run is a check
//! that can withdraw the proposal: worse beyond tolerance on any Primary or
//! Floor axis withdraws it. Owner clause (Engine RULING 05:20, verbatim): "a
//! withdrawn proposal stays listed to the owner with both scorecards and the
//! reason. His stamp may still promote it; the stamp records that it overrode
//! the sealed check." Nothing in this crate ever refuses the owner's stamp.
//! This crate only stores and judges; it reads no wall clock (every time is a
//! caller argument).
//!
//! Store layout under a proposals root: `<root>/<proposal_id>/held_out.json`,
//! `sealed.json`, `stamp.json`. Every file is published once, whole or not at
//! all (a synced temporary file moved into place without replacing anything),
//! and never rewritten; status is derived from which files exist. A crash or a
//! full disk during a write leaves at most a stray `.<name>.*.tmp` file, which
//! no read opens, so the write can be retried.

use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::axes::{AxisComparison, AxisRole};
use crate::bootstrap::AxisBound;
use crate::pack::{Slice, sha256_hex};
use crate::scorecard::Scorecard;
use crate::sealed::ExperimentIdentity;

/// The contract string every held_out proposal carries.
pub const PROPOSAL_CONTRACT: &str = "oneiron.retrieval_ruler_proposal.v1";
/// The contract string every sealed outcome carries.
pub const SEALED_OUTCOME_CONTRACT: &str = "oneiron.retrieval_ruler_sealed_outcome.v1";
/// The contract string every stamp carries.
pub const STAMP_CONTRACT: &str = "oneiron.retrieval_ruler_stamp.v1";

/// sha256 hex of the canonical JSON of {"campaign_id", "incumbent", "candidate"} (field names exactly these).
pub fn proposal_id(
    campaign_id: &str,
    incumbent: &ExperimentIdentity,
    candidate: &ExperimentIdentity,
) -> Result<String, ProposalError> {
    let body = serde_json::json!({
        "campaign_id": campaign_id,
        "incumbent": incumbent,
        "candidate": candidate,
    });
    let bytes = serde_json_canonicalizer::to_vec(&body)
        .map_err(|error| ProposalError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// The held_out Promote that makes a proposal (written by `scorecard compare` on exit 0).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldOutProposal {
    /// Must equal [`PROPOSAL_CONTRACT`].
    pub contract: String,
    /// Must equal proposal_id(campaign_id, incumbent, candidate).
    pub proposal_id: String,
    /// The campaign the proposal belongs to.
    pub campaign_id: String,
    /// The incumbent experiment.
    pub incumbent: ExperimentIdentity,
    /// The candidate experiment.
    pub candidate: ExperimentIdentity,
    /// The candidate's resolved parameter file (oneiron.retrieval_eval_params.v1), so a stamp can name what to pin.
    pub candidate_params: serde_json::Value,
    /// sha256 of each held_out scorecard FILE's bytes (the store keeps the files; a parsed float may be 1 ULP off).
    pub incumbent_scorecard_sha256: String,
    /// sha256 of the candidate held_out scorecard file's bytes.
    pub candidate_scorecard_sha256: String,
    /// The judged axes.
    pub axes: Vec<AxisComparison>,
    /// The held_out bootstraps.
    pub bootstrap: Vec<AxisBound>,
    /// Unix seconds, given by the caller.
    pub decided_at: u64,
}

/// The sealed check's verdict on a proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedVerdict {
    /// No Primary or Floor axis lost beyond tolerance.
    Passed,
    /// At least one Primary or Floor axis lost beyond tolerance.
    Withdrawn,
}

/// The one sealed check of a proposal (written by `scorecard compare --sealed`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedOutcome {
    /// Must equal [`SEALED_OUTCOME_CONTRACT`].
    pub contract: String,
    /// The proposal the check judges.
    pub proposal_id: String,
    /// The verdict.
    pub verdict: SealedVerdict,
    /// Set exactly when Withdrawn: every loss, in axis order, joined by "; ".
    pub reason: Option<String>,
    /// Every judged loss, in axis order.
    pub losses: Vec<AxisComparison>,
    /// The incumbent's sealed scorecard, in full (owner clause).
    pub incumbent_sealed: Scorecard,
    /// The candidate's sealed scorecard, in full (owner clause).
    pub candidate_sealed: Scorecard,
    /// Unix seconds, given by the caller.
    pub judged_at: u64,
}

/// Judge the sealed axes: every Primary or Floor axis worse beyond its tolerance is a loss; Cost axes are not judged.
/// Any loss -> Withdrawn with the reason; none -> Passed with no reason.
pub fn judge_sealed(
    axes: &[AxisComparison],
) -> Result<(SealedVerdict, Vec<AxisComparison>, Option<String>), ProposalError> {
    let mut losses = Vec::new();
    let mut reasons: Vec<String> = Vec::new();
    for axis in axes {
        if !axis.incumbent.is_finite() || !axis.candidate.is_finite() || !axis.tolerance.is_finite()
        {
            return Err(ProposalError::BadAxis {
                axis: axis.axis.clone(),
            });
        }
        if axis.tolerance < 0.0 {
            return Err(ProposalError::BadAxis {
                axis: axis.axis.clone(),
            });
        }
        if axis.role == AxisRole::Cost {
            continue;
        }
        if axis.is_worse_beyond_tolerance() {
            let name = axis.axis.as_str();
            let loss = -axis.delta();
            let tolerance = axis.tolerance;
            let incumbent = axis.incumbent;
            let candidate = axis.candidate;
            reasons.push(format!(
                "{name} worse by {loss} beyond tolerance {tolerance} (incumbent {incumbent}, candidate {candidate})"
            ));
            losses.push(axis.clone());
        }
    }
    if losses.is_empty() {
        Ok((SealedVerdict::Passed, losses, None))
    } else {
        Ok((SealedVerdict::Withdrawn, losses, Some(reasons.join("; "))))
    }
}

/// What the sealed check said when the owner stamped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedCheck {
    /// The sealed check passed.
    Passed,
    /// The sealed check withdrew the proposal; the stamp overrode it.
    Overridden,
    /// No sealed check ran before the stamp.
    NotRun,
}

/// The record of the owner's stamp. sealed_check is computed by the store from sealed.json, never by the caller.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stamp {
    /// Must equal [`STAMP_CONTRACT`].
    pub contract: String,
    /// The stamped proposal.
    pub proposal_id: String,
    /// What the sealed check said when the owner stamped.
    pub sealed_check: SealedCheck,
    /// Unix seconds, given by the caller.
    pub stamped_at: u64,
    /// The owner's note.
    pub note: String,
}

/// One proposal's status, derived from which files exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    /// The proposal waits for its sealed run.
    AwaitingSealed,
    /// The sealed check passed.
    Proposed,
    /// The sealed check withdrew the proposal.
    Withdrawn,
}

/// One proposal as the owner's list shows it: a withdrawn proposal stays listed with both sealed scorecards and its reason.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalListing {
    /// The proposal.
    pub proposal_id: String,
    /// The status, derived from which files exist.
    pub status: ProposalStatus,
    /// The sealed outcome's reason, copied when Withdrawn.
    pub reason: Option<String>,
    /// The held_out Promote that made the proposal.
    pub held_out: HeldOutProposal,
    /// The sealed check, when it ran.
    pub sealed: Option<SealedOutcome>,
    /// The owner's stamp, when stamped.
    pub stamp: Option<Stamp>,
}

/// The write-once proposal store under a proposals root.
#[derive(Clone, Debug)]
pub struct ProposalStore {
    /// The proposals root.
    root: PathBuf,
}

impl ProposalStore {
    /// Opens (creating) the proposals root.
    pub fn open(root: &Path) -> Result<Self, ProposalError> {
        std::fs::create_dir_all(root).map_err(|source| ProposalError::Io {
            path: root.to_path_buf(),
            source,
        })?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// Stores the held_out Promote that makes a proposal; refuses a second one.
    pub fn put_held_out(&self, proposal: &HeldOutProposal) -> Result<PathBuf, ProposalError> {
        if proposal.contract != PROPOSAL_CONTRACT {
            return Err(ProposalError::WrongContract {
                found: proposal.contract.clone(),
            });
        }
        check_proposal_id(&proposal.proposal_id)?;
        let computed = proposal_id(
            &proposal.campaign_id,
            &proposal.incumbent,
            &proposal.candidate,
        )?;
        if computed != proposal.proposal_id {
            return Err(ProposalError::ProposalIdMismatch);
        }
        check_digest(
            &proposal.incumbent_scorecard_sha256,
            "incumbent_scorecard_sha256",
        )?;
        check_digest(
            &proposal.candidate_scorecard_sha256,
            "candidate_scorecard_sha256",
        )?;
        if proposal.candidate.pack_digest != proposal.incumbent.pack_digest {
            return Err(ProposalError::PackMismatch);
        }
        let dir = self.root.join(&proposal.proposal_id);
        std::fs::create_dir_all(&dir).map_err(|source| ProposalError::Io {
            path: dir.clone(),
            source,
        })?;
        sync_dir(&self.root)?;
        let path = dir.join("held_out.json");
        let mut bytes = serde_json::to_vec_pretty(proposal)?;
        bytes.push(b'\n');
        if !write_new(&dir, "held_out.json", &bytes)? {
            return Err(ProposalError::ProposalExists {
                proposal_id: proposal.proposal_id.clone(),
            });
        }
        Ok(path)
    }

    /// Stores the one sealed check of a proposal; refuses a second one.
    pub fn put_sealed(&self, outcome: &SealedOutcome) -> Result<PathBuf, ProposalError> {
        if outcome.contract != SEALED_OUTCOME_CONTRACT {
            return Err(ProposalError::WrongContract {
                found: outcome.contract.clone(),
            });
        }
        check_proposal_id(&outcome.proposal_id)?;
        let dir = self.root.join(&outcome.proposal_id);
        let held_path = dir.join("held_out.json");
        let held: Option<HeldOutProposal> = read_optional(&held_path)?;
        let held = match held {
            Some(held) => held,
            None => {
                return Err(ProposalError::UnknownProposal {
                    proposal_id: outcome.proposal_id.clone(),
                });
            }
        };
        if outcome.incumbent_sealed.slice != Slice::Sealed
            || outcome.candidate_sealed.slice != Slice::Sealed
        {
            return Err(ProposalError::NotSealedSlice);
        }
        if outcome.incumbent_sealed.pack_digest != outcome.candidate_sealed.pack_digest {
            return Err(ProposalError::PackMismatch);
        }
        if outcome.candidate_sealed.engine_commit != held.candidate.engine_commit
            || outcome.candidate_sealed.params_digest != held.candidate.params_digest
        {
            return Err(ProposalError::IdentityMismatch {
                side: "candidate".to_owned(),
            });
        }
        if outcome.incumbent_sealed.params_digest != held.incumbent.params_digest {
            return Err(ProposalError::IdentityMismatch {
                side: "incumbent".to_owned(),
            });
        }
        let withdrawn = outcome.verdict == SealedVerdict::Withdrawn;
        if withdrawn == outcome.losses.is_empty() || withdrawn != outcome.reason.is_some() {
            return Err(ProposalError::InconsistentOutcome);
        }
        let path = dir.join("sealed.json");
        let mut bytes = serde_json::to_vec_pretty(outcome)?;
        bytes.push(b'\n');
        if !write_new(&dir, "sealed.json", &bytes)? {
            return Err(ProposalError::SealedOutcomeExists {
                proposal_id: outcome.proposal_id.clone(),
            });
        }
        Ok(path)
    }

    /// Records the owner's stamp. It never refuses because of the sealed verdict (owner clause).
    pub fn put_stamp(
        &self,
        proposal_id: &str,
        stamped_at: u64,
        note: &str,
    ) -> Result<Stamp, ProposalError> {
        let listing = self.get(proposal_id)?;
        let sealed_check = match listing.sealed.as_ref() {
            None => SealedCheck::NotRun,
            Some(outcome) => match outcome.verdict {
                SealedVerdict::Passed => SealedCheck::Passed,
                SealedVerdict::Withdrawn => SealedCheck::Overridden,
            },
        };
        let stamp = Stamp {
            contract: STAMP_CONTRACT.to_owned(),
            proposal_id: proposal_id.to_owned(),
            sealed_check,
            stamped_at,
            note: note.to_owned(),
        };
        let mut bytes = serde_json::to_vec_pretty(&stamp)?;
        bytes.push(b'\n');
        let dir = self.root.join(proposal_id);
        if !write_new(&dir, "stamp.json", &bytes)? {
            return Err(ProposalError::StampExists {
                proposal_id: proposal_id.to_owned(),
            });
        }
        Ok(stamp)
    }

    /// Reads one proposal as the owner's list shows it.
    pub fn get(&self, proposal_id: &str) -> Result<ProposalListing, ProposalError> {
        check_proposal_id(proposal_id)?;
        let dir = self.root.join(proposal_id);
        let held: Option<HeldOutProposal> = read_optional(&dir.join("held_out.json"))?;
        let held = match held {
            Some(held) => held,
            None => {
                return Err(ProposalError::UnknownProposal {
                    proposal_id: proposal_id.to_owned(),
                });
            }
        };
        check_record(
            &held.contract,
            PROPOSAL_CONTRACT,
            &held.proposal_id,
            proposal_id,
        )?;
        let sealed: Option<SealedOutcome> = read_optional(&dir.join("sealed.json"))?;
        if let Some(outcome) = &sealed {
            check_record(
                &outcome.contract,
                SEALED_OUTCOME_CONTRACT,
                &outcome.proposal_id,
                proposal_id,
            )?;
        }
        let stamp: Option<Stamp> = read_optional(&dir.join("stamp.json"))?;
        if let Some(stamp) = &stamp {
            check_record(
                &stamp.contract,
                STAMP_CONTRACT,
                &stamp.proposal_id,
                proposal_id,
            )?;
        }
        let (status, reason) = match &sealed {
            None => (ProposalStatus::AwaitingSealed, None),
            Some(outcome) => match outcome.verdict {
                SealedVerdict::Passed => (ProposalStatus::Proposed, None),
                SealedVerdict::Withdrawn => (ProposalStatus::Withdrawn, outcome.reason.clone()),
            },
        };
        Ok(ProposalListing {
            proposal_id: proposal_id.to_owned(),
            status,
            reason,
            held_out: held,
            sealed,
            stamp,
        })
    }

    /// Every proposal with a held_out record, sorted by proposal_id.
    pub fn list(&self) -> Result<Vec<ProposalListing>, ProposalError> {
        let mut names = Vec::new();
        let entries = std::fs::read_dir(&self.root).map_err(|source| ProposalError::Io {
            path: self.root.clone(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| ProposalError::Io {
                path: self.root.clone(),
                source,
            })?;
            let name = match entry.file_name().into_string() {
                Ok(name) => name,
                Err(_) => continue,
            };
            if !is_sha256_hex(&name) {
                continue;
            }
            if !entry.path().join("held_out.json").is_file() {
                continue;
            }
            names.push(name);
        }
        names.sort_unstable();
        let mut out = Vec::with_capacity(names.len());
        for name in &names {
            out.push(self.get(name)?);
        }
        Ok(out)
    }
}

/// Every way a proposal record can fail to store, judge or read.
#[derive(Debug, Error)]
pub enum ProposalError {
    /// A proposal id is not 64 lowercase hex.
    #[error("bad proposal id")]
    BadProposalId,
    /// A file names another contract.
    #[error("wrong contract: {found}")]
    WrongContract {
        /// The contract the file carries.
        found: String,
    },
    /// A proposal id does not match its contents (or its directory).
    #[error("proposal id mismatch")]
    ProposalIdMismatch,
    /// A digest field is not 64 lowercase hex.
    #[error("bad digest in {field}")]
    BadDigest {
        /// Which field is bad.
        field: String,
    },
    /// Two scorecards (or identities) name different packs.
    #[error("pack mismatch")]
    PackMismatch,
    /// A sealed scorecard names another slice.
    #[error("not the sealed slice")]
    NotSealedSlice,
    /// A sealed scorecard names another experiment than the proposal.
    #[error("identity mismatch on the {side} side")]
    IdentityMismatch {
        /// Which side mismatches: "candidate" or "incumbent".
        side: String,
    },
    /// Verdict, losses and reason disagree.
    #[error("inconsistent sealed outcome")]
    InconsistentOutcome,
    /// An axis value is non-finite or its tolerance is negative.
    #[error("bad sealed axis: {axis}")]
    BadAxis {
        /// The bad axis.
        axis: String,
    },
    /// The proposal already has a held_out record.
    #[error("proposal already exists: {proposal_id}")]
    ProposalExists {
        /// The proposal.
        proposal_id: String,
    },
    /// No held_out record names this proposal.
    #[error("unknown proposal: {proposal_id}")]
    UnknownProposal {
        /// The proposal.
        proposal_id: String,
    },
    /// The proposal already has a sealed outcome.
    #[error("sealed outcome already exists: {proposal_id}")]
    SealedOutcomeExists {
        /// The proposal.
        proposal_id: String,
    },
    /// The proposal is already stamped.
    #[error("stamp already exists: {proposal_id}")]
    StampExists {
        /// The proposal.
        proposal_id: String,
    },
    /// A proposal file could not be read or written.
    #[error("io error at {path:?}: {source}")]
    Io {
        /// The file path.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// A proposal file is not valid JSON for this shape.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// A proposal body has no canonical JSON form.
    #[error("canonical JSON error: {0}")]
    Canonical(String),
}

/// True for 64 lowercase hex digits.
fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Refuses a proposal id that is not 64 lowercase hex, before it is joined to a path.
fn check_proposal_id(value: &str) -> Result<(), ProposalError> {
    if is_sha256_hex(value) {
        Ok(())
    } else {
        Err(ProposalError::BadProposalId)
    }
}

/// Refuses a scorecard digest that is not 64 lowercase hex.
fn check_digest(value: &str, field: &str) -> Result<(), ProposalError> {
    if is_sha256_hex(value) {
        Ok(())
    } else {
        Err(ProposalError::BadDigest {
            field: field.to_owned(),
        })
    }
}

/// Checks one stored record's contract and proposal id against its directory.
fn check_record(
    contract: &str,
    expected: &str,
    id: &str,
    proposal_id: &str,
) -> Result<(), ProposalError> {
    if contract != expected {
        return Err(ProposalError::WrongContract {
            found: contract.to_owned(),
        });
    }
    if id != proposal_id {
        return Err(ProposalError::ProposalIdMismatch);
    }
    Ok(())
}

/// Reads one optional record file: None when absent.
fn read_optional<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>, ProposalError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(source) => Err(ProposalError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Publishes one proposal file `<dir>/<name>` once, whole or not at all: Ok(true) when written, Ok(false) when it
/// already existed.
///
/// The bytes go to a new temporary file in `dir`, which is synced and then moved to `name` with `persist_noclobber`
/// (a rename that refuses an existing target, or a hard link then an unlink): the move never replaces a record. A
/// failed write drops the temporary file; a crash leaves it as a stray `.<name>.*.tmp` that no read opens. Either
/// way no truncated record is ever published, and the write can be retried. `dir` is synced after the move so the
/// new entry survives a power loss.
fn write_new(dir: &Path, name: &str, bytes: &[u8]) -> Result<bool, ProposalError> {
    let prefix = format!(".{name}.");
    let mut temp = tempfile::Builder::new()
        .prefix(&prefix)
        .suffix(".tmp")
        .tempfile_in(dir)
        .map_err(|source| ProposalError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
    let temp_path = temp.path().to_path_buf();
    temp.write_all(bytes).map_err(|source| ProposalError::Io {
        path: temp_path.clone(),
        source,
    })?;
    temp.as_file()
        .sync_all()
        .map_err(|source| ProposalError::Io {
            path: temp_path,
            source,
        })?;
    if let Err(error) = temp.persist_noclobber(dir.join(name)) {
        if error.error.kind() == ErrorKind::AlreadyExists {
            return Ok(false);
        }
        return Err(ProposalError::Io {
            path: dir.join(name),
            source: error.error,
        });
    }
    sync_dir(dir)?;
    Ok(true)
}

/// Syncs a directory, so a new entry in it survives a power loss.
fn sync_dir(dir: &Path) -> Result<(), ProposalError> {
    let handle = std::fs::File::open(dir).map_err(|source| ProposalError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    handle.sync_all().map_err(|source| ProposalError::Io {
        path: dir.to_path_buf(),
        source,
    })
}
