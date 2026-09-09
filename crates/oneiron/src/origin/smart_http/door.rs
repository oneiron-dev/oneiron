//! The door seam: admission stamp, the always-present hook trait with its noop
//! default and landed wiring, and the catastrophe-dial effector check.

use std::net::IpAddr;

use super::paths::door_refused;
use crate::codebase::RepoRef;
use crate::credential_door::{
    CredentialDoorError, CredentialDoorService, DOOR_RECEIVE_PACK_EFFECTOR, DoorCredential,
    DoorScanVerdict, PushedBlob,
};
use crate::entity_id::EntityId;
use crate::error::Result;

/// A derived admission record — NOT an identity type and NOT a credential
/// store.
///
/// It is minted from the canonical `DoorCredential` when a capability slip is
/// presented, and otherwise from the registered principal the transport already
/// proved. There is no `DoorActor` anywhere in this surface: nothing here mints
/// a second identity, and the stamp holds no token material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoorAdmissionStamp {
    pub(super) principal_ref: String,
    pub(super) credential_fingerprint: Option<String>,
    pub(super) method: &'static str,
    pub(super) admitted_at: u64,
    pub(super) operation_id: EntityId,
}

impl DoorAdmissionStamp {
    /// The admission a transport-proved principal carries when Phase A presents
    /// no capability slip (Edge #2: the serving plane mints no origin
    /// credential and gates on nothing in the secret stack).
    pub(super) fn from_principal(principal_ref: &str, admitted_at: u64) -> Self {
        Self {
            principal_ref: principal_ref.to_owned(),
            credential_fingerprint: None,
            method: "bearer+registered-principal",
            admitted_at,
            operation_id: EntityId::now(),
        }
    }

    /// The admission a presented slip carries, fingerprinted from the canonical
    /// credential's own identifiers. The fingerprint is a digest, never the
    /// slip: `DoorCredential` holds no token material to begin with.
    fn from_credential(credential: &DoorCredential, principal_ref: &str, admitted_at: u64) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron:origin:door-admission:v1");
        hasher.update(credential.slip_id().as_bytes());
        hasher.update(b"\x00");
        hasher.update(credential.holder_ref().as_bytes());
        Self {
            principal_ref: principal_ref.to_owned(),
            credential_fingerprint: Some(hasher.finalize().to_hex().to_string()),
            method: "door-credential+registered-principal",
            admitted_at,
            operation_id: EntityId::now(),
        }
    }

    /// The request identity. After `serve` admits the request, this also names
    /// its durable admission claim. Allocating this id alone is not evidence.
    #[must_use]
    pub const fn operation_id(&self) -> EntityId {
        self.operation_id
    }

    /// The registered principal this admission was stamped for.
    #[must_use]
    pub fn principal_ref(&self) -> &str {
        &self.principal_ref
    }

    /// The canonical credential fingerprint, when a slip was presented.
    #[must_use]
    pub fn credential_fingerprint(&self) -> Option<&str> {
        self.credential_fingerprint.as_deref()
    }

    /// How the admission was established.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        self.method
    }

    /// When the admission was stamped, in unix seconds.
    #[must_use]
    pub const fn admitted_at(&self) -> u64 {
        self.admitted_at
    }
}

/// The door seam — always present.
///
/// Crate-visible on purpose: its methods name the canonical door types, which
/// `credential_door.rs` publishes to this crate and to no one else. The
/// transport reaches the seam through [`serve`], never by holding a door type.
pub(super) trait DoorHook: Send + Sync {
    /// Admits an authenticated receive-pack.
    ///
    /// `presented` is the capability slip the caller carried, or `None` in
    /// Phase A, where the serving plane presents none. `peer_addr` is transport
    /// context, never an authorization input: a loopback push is admitted
    /// exactly like any other push.
    fn admit_receive_pack(
        &self,
        presented: Option<&DoorCredential>,
        principal_ref: &str,
        repo: &RepoRef,
        peer_addr: IpAddr,
        now: u64,
    ) -> Result<DoorAdmissionStamp>;

    /// The pre-receive verdict over a push's added lines, taken while the
    /// objects are still quarantined.
    fn pre_receive_scan(&self, repo: &RepoRef, blobs: &[PushedBlob]) -> Result<DoorScanVerdict>;
}

/// The seam's no-op default: it stamps the admission the transport already
/// proved and returns a clean verdict. It scans nothing and refuses nothing, so
/// the seam is present without adding behavior.
pub(super) struct NoopDoorHook;

impl DoorHook for NoopDoorHook {
    fn admit_receive_pack(
        &self,
        presented: Option<&DoorCredential>,
        principal_ref: &str,
        _repo: &RepoRef,
        _peer_addr: IpAddr,
        now: u64,
    ) -> Result<DoorAdmissionStamp> {
        Ok(match presented {
            Some(credential) => DoorAdmissionStamp::from_credential(credential, principal_ref, now),
            None => DoorAdmissionStamp::from_principal(principal_ref, now),
        })
    }

    fn pre_receive_scan(&self, _repo: &RepoRef, _blobs: &[PushedBlob]) -> Result<DoorScanVerdict> {
        Ok(DoorScanVerdict::Clean)
    }
}

/// The wiring block onto the landed credential door.
///
/// Both legs delegate; neither restates a door rule. A presented slip is
/// evaluated by the door's own `authenticate_receive_pack` before any stamp
/// exists, the catastrophe dial is the door's own resolved policy either way,
/// and the scan is the door's unconditional call.
impl DoorHook for CredentialDoorService {
    fn admit_receive_pack(
        &self,
        presented: Option<&DoorCredential>,
        principal_ref: &str,
        repo: &RepoRef,
        peer_addr: IpAddr,
        now: u64,
    ) -> Result<DoorAdmissionStamp> {
        let Some(credential) = presented else {
            // Phase A presents no slip. The door has nothing to evaluate, so it
            // stamps the registered principal the transport proved instead of
            // pretending a credential was checked — the stamp carries no
            // fingerprint, and that absence is the honest record.
            //
            // The catastrophe dial is not part of that evaluation, so it is
            // consulted here on its own. Receive-pack is a door effector like
            // any other, and reaching the dial ONLY through
            // `authenticate_receive_pack` would leave it unreachable on exactly
            // the path that carries no slip — which is every production push.
            // An operator who empties `secret.door.allowed_effectors` would
            // then close every lease and injection downstream while leaving the
            // push door itself wide open.
            admit_receive_pack_effector(self)?;
            return Ok(DoorAdmissionStamp::from_principal(principal_ref, now));
        };
        self.authenticate_receive_pack(Some(credential), repo, peer_addr)
            .map_err(|error| door_refused(&error))?;
        Ok(DoorAdmissionStamp::from_credential(
            credential,
            principal_ref,
            now,
        ))
    }

    fn pre_receive_scan(&self, repo: &RepoRef, blobs: &[PushedBlob]) -> Result<DoorScanVerdict> {
        // Inherent before trait: this dispatches to the door's own
        // `CredentialDoorService::pre_receive_scan`, which is the unconditional
        // scan. The seam carries the verdict; it never restates the rule.
        self.pre_receive_scan(repo, blobs)
            .map_err(|error| door_refused(&error))
    }
}

/// The catastrophe dial's verdict on the receive-pack effector, asked WITHOUT a
/// credential.
///
/// It restates no door rule and reads no door internal. The dial is resolved by
/// the door's own [`CredentialDoorService::door_policy`] and admitted by the
/// door's own `DoorPolicy::admits_effector` — the same two steps
/// [`CredentialDoorService::authenticate_receive_pack`] takes before it
/// evaluates a slip, and the refusal it raises is that same call's
/// `LeaseScopeRefused` with that same wording. What differs is only the way in:
/// no slip is required to reach it, because Phase A presents none and the dial
/// was never a statement about a credential.
///
/// Fail-closed in both directions. A dial that cannot be RESOLVED is a refusal
/// too: a push admitted because nobody could read the dial is a push nobody
/// checked.
fn admit_receive_pack_effector(door: &CredentialDoorService) -> Result<()> {
    let policy = door.door_policy().map_err(|error| door_refused(&error))?;
    if policy.admits_effector(DOOR_RECEIVE_PACK_EFFECTOR) {
        return Ok(());
    }
    Err(door_refused(&CredentialDoorError::LeaseScopeRefused {
        effector: DOOR_RECEIVE_PACK_EFFECTOR.to_owned(),
        reason: "not a door effector the resolved dial admits",
    }))
}

/// Which door implementation a serve invocation binds.
///
/// Both arms are real. `Noop` is the seam's always-present no-op default;
/// `Landed` binds the credential door that ships in this vault.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DoorSeam {
    /// The no-op default: the seam is present, the verdict is always clean.
    Noop,
    /// The landed credential door: its pre-receive scan is unconditional.
    /// This is what a serve invocation binds unless something names otherwise.
    #[default]
    Landed,
}
