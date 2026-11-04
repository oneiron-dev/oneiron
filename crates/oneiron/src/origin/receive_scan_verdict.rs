//! The verdict of a pushed pack's pre-receive scan, and the lift advice a
//! refused push carries back. The credential door (`credential_door`) scans
//! the pack and decides; the smart-HTTP receive path reads the verdict.

use crate::receive_scan::ReceiveScanHit;
use crate::store::code_snapshot::RepoRef;

/// The verdict of a pre-receive scan. A verdict is a scan OUTCOME: an
/// unscannable blob is not a verdict, it is an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DoorScanVerdict {
    /// Every added line scanned, nothing matched.
    Clean,
    /// The push is refused; each proposal names one offending path.
    Rejected {
        /// One proposal per offending blob.
        proposals: Vec<CheckoutSecretLiftProposal>,
        /// The value-free hits the proposals were made from, one each.
        hits: Vec<ReceiveScanHit>,
    },
    /// The push is admitted with each hit marked (FIX 7608): the transport
    /// carries the hits to the admitted intent, whose transaction writes
    /// their marks or refuses the push whole.
    AdmitMarked {
        /// The value-free hits to mark.
        hits: Vec<ReceiveScanHit>,
    },
}

/// "Lift this into the vault instead" — the door's advice when a push carries
/// secret-shaped bytes.
///
/// Path, detector reason, and a suggested NAME. Never the matched line, never
/// the token, never any value bytes: the proposal travels back to whoever
/// pushed, and it must be safe to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckoutSecretLiftProposal {
    /// The offending blob's path.
    pub(crate) path: String,
    /// The detector's reason code (e.g. `gate.secret_scan.github_token`).
    pub(crate) reason: &'static str,
    /// A suggested custody name for the lifted secret, derived from the repo
    /// and path only.
    pub(crate) suggested_secret_name: String,
}

impl CheckoutSecretLiftProposal {
    /// Builds a proposal from non-secret addressing data only.
    pub(crate) fn new(repo: &RepoRef, path: &str, reason: &'static str) -> Self {
        Self {
            path: path.to_owned(),
            reason,
            suggested_secret_name: format!("{}.{}", repo_slug(repo), path_slug(path)),
        }
    }
}

/// A short, name-shaped slug for the repository.
fn repo_slug(repo: &RepoRef) -> String {
    match repo {
        RepoRef::LocalFolder { path, .. } => path_slug(path.rsplit('/').next().unwrap_or(path)),
        RepoRef::GitHubAtCommit { owner, repo, .. } => {
            format!("{}_{}", path_slug(owner), path_slug(repo))
        }
    }
}

/// Lowercases and folds everything that is not `[a-z0-9]` into `_` so a
/// suggested name is a name and carries no path punctuation.
fn path_slug(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        "unnamed".to_owned()
    } else {
        trimmed.to_owned()
    }
}
