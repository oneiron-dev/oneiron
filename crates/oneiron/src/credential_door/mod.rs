//! ARCH-0068 RC4 — the credential door (CSTDY-02).
//!
//! One organ owns what a repository push has to survive before anything it
//! carries becomes durable, and what a credential may buy at that boundary:
//!
//! 1. **T0 remote-at-door injection** — the value is resolved and handed to
//!    the egress INSIDE [`Vault::inject_secret_at_door`]; the caller receives
//!    a [`DoorInjectionReceipt`] and never the bytes.
//! 2. **T1 lease tickets** — the landed bounded materialization is the ONE
//!    materializing call (it writes the lease row and its receipt before the
//!    value returns, and clamps the lease against the credential's absolute
//!    expiry using the same instant that authorized it); this module composes
//!    over it and never mints a second, unmarked materialization path.
//! 3. **A catastrophe-class dial** — `secret.door.*` rows in the vault's
//!    POLICY_MANIFEST bodies, resolved locally with the same fail-closed,
//!    most-restrictive-wins idiom [`crate::secret_custody::SecretCustodyFloor`]
//!    uses. The dial NARROWS ONLY, it covers EVERY door effector including
//!    receive-pack itself, and it fails closed on any indexed declaration this
//!    door cannot read.
//! 4. **A pre-receive secret-shaped diff verdict** — every added line of every
//!    pushed blob goes through [`scan_file_content`] (the detector stays
//!    single-homed in `batch::secret_scan`; this door is a read-only consumer).
//! 5. **Authenticated receive-pack** — loopback is a network fact, never an
//!    identity, so the credential checks run unconditionally, under the same
//!    resolved effector dial every other door operation answers to.
//! 6. **A one-shot redemption hatch** — consumed by move, single-use caveat,
//!    lifetime capped, named secret and named effector only.
//!
//! # Floors are constants, not dials
//!
//! [`DOOR_SCAN_ALWAYS_ON`], [`DOOR_MAX_LEASE_TTL_SECS`] and
//! [`DOOR_ONE_SHOT_MAX_LIFETIME_SECS`] sit OUTSIDE the policy lattice. No
//! policy row, verb, caveat, attenuation, or scope may name or disable one:
//! naming a floor from inside the lattice is itself a fail-closed refusal
//! ([`CredentialDoorError::FloorNamed`]), because the only thing a "floor
//! switch" can ever be is an off switch for a catastrophe guard.
//!
//! # The clock is the vault's, not the caller's
//!
//! No door operation takes a `now`. Every one of them reads a
//! [`VaultInstant`] from [`CredentialDoorService::door_instant`] — the vault's
//! authority-plane observation clock — and that single reading answers the
//! credential's lifetime, sizes its remaining validity, bounds the ticket it
//! may buy, and stamps the lease.
//!
//! A caller-supplied `now: u64` was an authorization input wearing a
//! timestamp's clothes: whoever passed it decided whether the presented slip
//! was inside its own window and how much of that window was left. `now =
//! issued_at` revives a credential that died an hour ago and hands it a
//! full-length ticket, and no amount of default-deny elsewhere in the
//! evaluator can refuse it, because by then the lie has already been told.
//! [`VaultInstant`] has no `From<u64>` and no public constructor, so that
//! argument is not merely absent from these signatures — it cannot be
//! reintroduced by a caller at all.
//!
//! # Admission is a VALUE, taken inside the transaction that stamps
//!
//! The dial is not a bag of numbers this module reads twice. What resolving it
//! yields is [`PolicyFloors`] — the dial-narrowable catastrophe floors, each in
//! its lattice form — and an [`EffectorDial`], a subset of [`DOOR_EFFECTORS`]
//! BY CONSTRUCTION, because a [`DoorEffector`] cannot be built from a name that
//! is not one of this door's own constants. What the scope check PRODUCES is an
//! [`AdmittedScope`]: proof that one named effector was admitted, carrying the
//! resolved dial it was admitted under and the single [`VaultInstant`] the
//! operation authorized at. Sizing a ticket against that proof yields an
//! [`AdmittedLease`], and that ONE value is the entire argument list of
//! [`Vault::materialize_admitted_lease`]. No raw `max_lease_ttl_secs: u64` and
//! no caller-supplied effector set survives anywhere on the path to a stamp, so
//! there is exactly one admission shape and no second way to reach the mint.
//!
//! The gap that closes is not a type error, it is a TIME-OF-CHECK gap. The door
//! used to resolve the dial in one read transaction while the vault stamped the
//! lease in a different write transaction, so the dial that ADMITTED a request
//! was never the dial the row COMMITTED under: a dial narrowed — emptied, even
//! — in between still minted a ticket at the stale wide reading, and the one
//! row an operator reaches for in a catastrophe lost every race it was in.
//! [`AdmittedLease::reaffirm_in_txn`] re-resolves the dial INSIDE the write
//! transaction that stamps, refuses on any disagreement with the admission, and
//! is the FIRST thing that transaction does — before the record is read, before
//! the custody floor is resolved, and long before a value byte is touched.
//!
//! The witnessed instant is the one thing threaded IN rather than re-derived
//! there. A second reading inside the write transaction could disagree with the
//! lifetime check that already passed, which would put the credential's window
//! and the lease's dates back on two different clocks — exactly the split the
//! typed instant exists to prevent. So the proof carries the reading, and the
//! lifetime check, the ceiling, the absolute bound and `granted_at` stay one
//! observation.
//!
//! # What this module deliberately does NOT do
//!
//! It owns the VERDICT, never the transport. There is no receive-pack
//! protocol code, no hook implementation, no git invocation, and no server
//! adapter here; the wire side consumes this seam later (ONE-1908). The
//! quarantine extraction that fills a [`PushedBlob`] is likewise the
//! transport owner's work — [`PushedBlob`] is the seam boundary, not the
//! mechanism.
//!
//! # The credential
//!
//! One credential = one presented capability slip. This tree carries no slip
//! struct yet, so [`DoorCredential`] is the smallest honest holder-view the
//! crate-private seam needs: non-secret identifiers plus the verbs, records,
//! channels and lifetime the holder's slip bounds. It carries NO token
//! material, it is not `Clone` (single-use redemption is consumption by
//! move), and it is not constructible from a caller-supplied string: the
//! constructor's contract is that holder proof was already verified by the
//! verifier that produced the view. The production verifier arrives with the
//! transport adapter; this module ships the seam and its fail-closed
//! evaluation.
//!
//! # The one-shot mint STOP
//!
//! There is no landed authority-log surface that admits slip-mint bodies, and
//! inventing an `AuthorityOp` variant or a door-local ledger is forbidden. So
//! [`CredentialDoorService::mint_one_shot`] exists for API closure and fails
//! closed with [`CredentialDoorError::MintUnavailable`]. Redemption is the
//! landed half: it consumes the credential by move, refuses a single-use
//! caveat it cannot witness against the authority log, and writes no ledger
//! of its own.
// The door is created before its first production consumer: the transport
// adapter that calls these surfaces is a later ticket, and until it lands the
// module's own tests are what exercise them.
#![cfg_attr(not(test), allow(dead_code))]

mod door_credential;
mod door_policy;
mod door_service;
mod door_types;

pub(crate) use self::door_credential::DoorCredential;
pub(crate) use self::door_service::{AdmittedLease, CredentialDoorService};
pub(crate) use self::door_types::{
    CredentialDoorError, DOOR_RECEIVE_PACK_EFFECTOR, DoorResult, DoorScanVerdict, PushedBlob,
};

#[cfg(test)]
use self::{door_policy::*, door_service::*, door_types::*};
#[cfg(test)]
use crate::codebase::RepoRef;
#[cfg(test)]
use crate::secret_lease::VaultInstant;
#[cfg(test)]
use crate::store::Store;
#[cfg(test)]
use crate::vault::Vault;
#[cfg(test)]
use rmpv::Value;
#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
mod scan_fault_hook {
    //! One-shot test-only fault injection on the scan, proving the
    //! fail-closed arm: a scan that could not run is a rejection, never a
    //! pass.

    use std::cell::Cell;

    thread_local! {
        static SCANNER_FAILURE: Cell<bool> = const { Cell::new(false) };
    }

    /// Arms a one-shot scanner failure on the current thread.
    pub(super) fn arm_scanner_failure() {
        SCANNER_FAILURE.with(|cell| cell.set(true));
    }

    /// Returns and clears the armed flag (one-shot).
    pub(super) fn take_scanner_failure() -> bool {
        SCANNER_FAILURE.with(|cell| cell.replace(false))
    }
}

#[cfg(test)]
mod authority_log_fault_hook {
    //! One-shot test-only fault injection on the single-use witness, proving
    //! that a verifier which cannot reach the authority log refuses the
    //! caveat instead of assuming it holds.

    use std::cell::Cell;

    thread_local! {
        static LOG_UNREACHABLE: Cell<bool> = const { Cell::new(false) };
    }

    /// Arms a one-shot unreachable authority log on the current thread.
    pub(super) fn arm_log_unreachable() {
        LOG_UNREACHABLE.with(|cell| cell.set(true));
    }

    /// Returns and clears the armed flag (one-shot).
    pub(super) fn take_log_unreachable() -> bool {
        LOG_UNREACHABLE.with(|cell| cell.replace(false))
    }
}

#[cfg(test)]
mod tests;
