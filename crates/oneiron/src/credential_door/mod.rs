//! Checkout receive-pack admission, catastrophe policy, and secret-shaped diff scanning.
//!
//! Loopback is a network fact, never an identity. Checkout credentials are
//! re-witnessed under the writer that authorizes a receive-pack operation.
//!
//! The dial NARROWS ONLY, it covers EVERY door effector including
//! receive-pack itself, and it fails closed on any indexed declaration this
//! door cannot read.
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
//! [`VaultInstant`] has no `From<u64>` and no public constructor, so callers
//! cannot choose the clock that decides credential expiry.
//!
mod checkout_ticket;
mod door_authority;
mod door_consent;
mod door_credential;
mod door_policy;
mod door_service;
mod door_types;
mod verb_class;

pub(crate) use self::door_credential::DoorCredential;
pub(crate) use self::door_service::CredentialDoorService;
pub(crate) use self::door_types::{
    CredentialDoorError, DOOR_ONE_SHOT_MAX_LIFETIME_SECS, DOOR_RECEIVE_PACK_EFFECTOR,
    DoorScanVerdict, PushedBlob, names_a_floor,
};

#[cfg(test)]
use self::{door_policy::*, door_types::*};
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
mod tests;
