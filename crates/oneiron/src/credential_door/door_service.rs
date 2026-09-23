//! CredentialDoorService: checkout admission and pre-receive scanning.

use std::net::IpAddr;
use std::sync::Arc;

use super::door_credential::DoorCredential;
use super::door_policy::{DoorEffector, DoorPolicy};
use super::door_types::{
    CredentialDoorError, DOOR_MAX_OID_BYTES, DOOR_MAX_PATH_BYTES, DOOR_RECEIVE_PACK_EFFECTOR,
    DOOR_VERB_RECEIVE_PACK, DoorDenyReason, DoorResult, DoorScanVerdict, PushedBlob,
    SecretLiftProposal, UNUSABLE_PATH, custody, repo_record,
};
use crate::batch::secret_scan::scan_file_content;
use crate::codebase::RepoRef;
use crate::secret_lease::VaultInstant;
use crate::vault::Vault;

#[cfg(test)]
use super::scan_fault_hook;

/// A named effector admitted under the door policy at one vault instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AdmittedScope {
    effector: DoorEffector,
    at: VaultInstant,
}

impl AdmittedScope {
    /// The door's scope check, and the ONLY way to obtain the proof: the
    /// effector must be one this door knows AND one the resolved dial still
    /// admits. An empty effector fails the first half, so there is no unscoped
    /// door operation to construct.
    fn admit(policy: DoorPolicy, effector: &str, at: VaultInstant) -> DoorResult<Self> {
        let admitted = DoorEffector::parse(effector)
            .filter(|proved| policy.dial.admits(*proved))
            .ok_or_else(|| CredentialDoorError::LeaseScopeRefused {
                effector: effector.to_owned(),
                reason: "not a door effector the resolved dial admits",
            })?;
        Ok(Self {
            effector: admitted,
            at,
        })
    }

    /// The PROVED effector. Door operations bind their scope to this, never to
    /// the string the caller handed in.
    pub(crate) fn effector(&self) -> DoorEffector {
        self.effector
    }

    /// The single vault reading this operation authorizes and stamps under.
    pub(crate) fn instant(&self) -> VaultInstant {
        self.at
    }
}

/// The credential door over one landed vault.
///
/// It holds no secret state of its own: the vault owns custody, the authority
/// log owns grants, and the detector owns detection. What lives here is the
/// composition and its refusals.
pub(crate) struct CredentialDoorService {
    vault: Arc<Vault>,
}

impl CredentialDoorService {
    /// Binds the door to a vault.
    pub(crate) fn new(vault: Arc<Vault>) -> Self {
        Self { vault }
    }

    /// The vault this door composes over.
    pub(crate) fn vault(&self) -> &Arc<Vault> {
        &self.vault
    }

    /// Resolves the current catastrophe dial from stored policy manifests.
    pub(crate) fn door_policy(&self) -> DoorResult<DoorPolicy> {
        let rtxn = self.vault.store.env.read_txn().map_err(custody)?;
        DoorPolicy::resolve(&self.vault.store, &rtxn)
    }

    /// The ONE instant a door operation authorizes and stamps under.
    ///
    /// Read from the vault's own seam ([`Vault::instant_in_txn`]) inside a
    /// read transaction — the authority plane's persisted-floor monotone
    /// observation, the same clock the fold makes widen-maturity decisions on.
    /// It is not a parameter, it is not a trait a caller may implement, and it
    /// is not the raw wall clock.
    ///
    /// Every door operation calls this EXACTLY once and threads the reading
    /// through: the lifetime check, the remaining-validity ceiling, the
    /// absolute lease bound, and the stamped `granted_at` are then all one
    /// observation. Reading twice would reintroduce, inside this module, the
    /// very gap removing the caller's `now` closed.
    pub(super) fn door_instant(&self) -> DoorResult<VaultInstant> {
        let rtxn = self.vault.store.env.read_txn().map_err(custody)?;
        self.vault.instant_in_txn(&rtxn).map_err(custody)
    }

    /// Authenticates a receive-pack attempt.
    ///
    /// `peer_addr` is transport context the caller already has; it is
    /// deliberately NOT an authorization input, and the leading underscore is
    /// the proof that no branch reads it. A loopback push authenticates
    /// exactly like any other push, because "localhost" describes a route and
    /// never a principal.
    ///
    /// The catastrophe dial applies HERE too. Receive-pack is a door effector
    /// like any other, so the resolved dial is admitted before the push
    /// authenticates: a manifest that narrows `secret.door.allowed_effectors`
    /// away from [`DOOR_RECEIVE_PACK_EFFECTOR`] shuts the receive-pack door
    /// itself, not merely the leases and injections taken through it. Without
    /// that check the one row an operator would reach for in a catastrophe —
    /// an empty effector set — would leave the push path wide open while
    /// closing everything downstream of it. The credential is still evaluated
    /// unconditionally; the dial only ever narrows.
    pub(crate) fn authenticate_receive_pack(
        &self,
        presented: Option<&DoorCredential>,
        repo: &RepoRef,
        _peer_addr: IpAddr,
    ) -> DoorResult<()> {
        let Some(credential) = presented else {
            return Err(CredentialDoorError::UnauthorizedPrincipal {
                reason: DoorDenyReason::CredentialAbsent,
            });
        };
        let now = self.door_instant()?;
        let admitted = self.admit_scope(DOOR_RECEIVE_PACK_EFFECTOR, now)?;
        self.authorize(
            credential,
            DOOR_VERB_RECEIVE_PACK,
            &repo_record(repo),
            admitted.effector().as_str(),
            admitted.instant(),
        )
    }

    /// The pre-receive verdict over a push's added lines.
    ///
    /// Unconditional ([`DOOR_SCAN_ALWAYS_ON`]): there is no credential, dial,
    /// or caveat argument that could turn it off, because none is accepted.
    /// Unscannable input never passes — binary content and scanner failure
    /// both leave through the error surface, not through a verdict.
    pub(crate) fn pre_receive_scan(
        &self,
        repo: &RepoRef,
        blobs: &[PushedBlob],
    ) -> DoorResult<DoorScanVerdict> {
        let mut proposals = Vec::new();
        for blob in blobs {
            if let Some(reason) = scan_one_blob(blob)? {
                proposals.push(SecretLiftProposal::new(repo, &blob.path, reason));
            }
        }
        if proposals.is_empty() {
            Ok(DoorScanVerdict::Clean)
        } else {
            Ok(DoorScanVerdict::Rejected { proposals })
        }
    }
}

impl CredentialDoorService {
    /// A door operation is always scoped, and the scope check is where the
    /// operation's AUTHORITY becomes a value.
    ///
    /// One resolved dial, one proved effector, one witnessed instant, one
    /// [`AdmittedScope`]. Everything downstream reads that proof instead of
    /// re-deriving any part of it: the evaluator's channel argument, the TTL
    /// ceiling, the absolute bound, and the re-admission the stamping
    /// transaction takes. The `()` this used to return left the dial, the
    /// effector and the instant lying around as three separate values that
    /// nothing tied together — which is how they came apart.
    pub(super) fn admit_scope(
        &self,
        effector: &str,
        at: VaultInstant,
    ) -> DoorResult<AdmittedScope> {
        AdmittedScope::admit(self.door_policy()?, effector, at)
    }
}

/// Scans one blob's added lines, returning the detector reason on a hit.
///
/// Order is load-bearing: seam validation, then the binary check over EVERY
/// added line, and only then the detector. The landed scanner is
/// intentionally lossy (it classifies over `from_utf8_lossy`), so asking it
/// about binary bytes would be asking a question it cannot answer — the door
/// answers it first, and the answer is always rejection.
fn scan_one_blob(blob: &PushedBlob) -> DoorResult<Option<&'static str>> {
    validate_seam_fields(blob)?;
    #[cfg(test)]
    {
        if scan_fault_hook::take_scanner_failure() {
            return Err(CredentialDoorError::ScanFailure {
                path: blob.path.clone(),
                reason: "scanner unavailable",
            });
        }
    }
    for line in &blob.added_lines {
        reject_unscannable(&blob.path, line)?;
    }
    for line in &blob.added_lines {
        if let Some(reason) = scan_file_content(&blob.path, line) {
            return Ok(Some(reason));
        }
    }
    Ok(None)
}

/// Binary is rejected, never skipped: a NUL byte or invalid UTF-8 anywhere in
/// the added bytes ends the push. Entropy, magic bytes, and size do not enter
/// — there is no allowlist to be wrong about.
fn reject_unscannable(path: &str, line: &[u8]) -> DoorResult<()> {
    if line.contains(&0) || std::str::from_utf8(line).is_err() {
        return Err(CredentialDoorError::BinaryContentRejected {
            path: path.to_owned(),
        });
    }
    Ok(())
}

/// Seam input the door cannot use is a scanner failure, which is a rejection.
/// An unnamed or unaddressable blob must never become a quiet pass.
fn validate_seam_fields(blob: &PushedBlob) -> DoorResult<()> {
    if blob.path.is_empty()
        || blob.path.len() > DOOR_MAX_PATH_BYTES
        || blob.path.chars().any(char::is_control)
    {
        return Err(CredentialDoorError::ScanFailure {
            path: UNUSABLE_PATH.to_owned(),
            reason: "pushed blob path is empty, oversized, or carries control bytes",
        });
    }
    if blob.oid.is_empty()
        || blob.oid.len() > DOOR_MAX_OID_BYTES
        || !blob.oid.as_bytes().iter().all(u8::is_ascii_hexdigit)
    {
        return Err(CredentialDoorError::ScanFailure {
            path: blob.path.clone(),
            reason: "pushed blob oid is empty, oversized, or not hexadecimal",
        });
    }
    Ok(())
}
