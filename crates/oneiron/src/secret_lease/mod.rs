//! ARCH-0069 secret custody — SECRET-02 (ONE-1920): the T0/T1/T2
//! materialization rungs behind a single admission gate.
//!
//! The honest dividing line is memory (S3): a value that enters workspace
//! memory is T1 minimum. The three rungs:
//!
//! * **T0 doored** — [`Vault::inject_secret_at_door`] resolves a secret ref
//!   and hands the value to a closure that runs INSIDE the door and returns
//!   only `()`: the bytes cannot come back through the closure's return
//!   type. The caller receives only a [`DoorInjectionReceipt`].
//! * **T1 leased** — [`Vault::materialize_secret_lease`] admits the request,
//!   then writes the [`SecretLease`] row and its
//!   [`SecretMaterializationReceipt`] durable BEFORE the value returns
//!   (receipt-at-materialization, S3 — environment reads are not
//!   interceptable, so the receipt is stamped at the mint). The value
//!   returns wrapped in [`Zeroizing`]. Expiry is lazy (checked at use) plus
//!   the [`Vault::expire_secret_leases`] maintenance sweep; the engine owns
//!   no timers (ARCH-0026).
//! * **T2 local-registered** — [`Vault::register_secret_local`]
//!   materializes the value to a manifest-declared local path under a live
//!   lease and records a [`LocalRegistration`] so unlease can clean the
//!   file and SECRET-03 (ONE-1921) can exclude the path. Recovery is
//!   re-materialization from the vault (S4), never from a snapshot.
//!
//! # The one admission rule (cap-only, stated once)
//!
//! A request is admitted iff ALL of:
//!
//! 1. the record has a [`SecretBinding`] for `(secret_ref, effector)` —
//!    otherwise [`Error::SecretBindingDenied`] (ONE-1919's binding
//!    discipline, regression-checked here);
//! 2. `requested_tier <= floor.band_for(class).max` against the live vault
//!    floor resolved per ONE-1919 — otherwise [`Error::SecretTierDenied`];
//! 3. `requested_tier <= binding.tier_ceiling` (exposure order
//!    `T0 < T1 < T2`) — otherwise [`Error::SecretTierDenied`].
//!
//! No minimum-exposure rule exists anywhere: floors and ceilings only ever
//! CAP exposure. ONE-1919's keystone makes the band's `min` informational
//! (floors narrow the MAX, never force exposure), so rule (2) is a pure
//! upper cap — a request for a SAFER tier than the band's `min` admits and
//! is never forced upward (K3 disposition of SOL-1920-01: the blueprint's
//! "set-membership" phrase lost to the keystone and to this ticket's own
//! no-minimum-exposure sentence). [`tier_admission`] is the pure function
//! at the rule's center; the doors add only the record lookup and the
//! binding resolution
//! (the binding is resolved from the record, never caller-invented). The
//! custody principal behind the effector string is the host-minted
//! capability slip (OF-452 D1/D7/D10); see [`crate::secret_custody`] module
//! docs — this module does not pretend otherwise either.
//!
//! # The door's admission travels INSIDE the stamping transaction
//!
//! That custody rule is about the RECORD. The credential door adds a second,
//! independent admission over the same mint — its narrow-only `secret.door.*`
//! dial — and `Vault::materialize_admitted_lease` is where the two meet. It
//! takes one `AdmittedLease` (the door's whole proof: proved effector, named
//! secret, admitted TTL, absolute bound, witnessed instant), RE-RESOLVES the
//! door dial under the write transaction that is about to stamp, and refuses on
//! any disagreement — before the record read, the custody floor, or any value
//! byte. The door resolving its dial in an earlier read transaction is what
//! made the dial that admitted a request different from the dial the row
//! committed under; both now happen under the one transaction that writes.
//!
//! `Vault::materialize_secret_lease_at` — the raw `(effector, ttl_secs, now,
//! not_after)` shape — is module-private for that reason: with two ways to
//! reach a stamp, "the door's admission is atomic with the stamp" would only be
//! true of whichever one the door happened to call.
//!
//! # Teardown honesty (S3/S6)
//!
//! [`Vault::revoke_secret_lease`] and expiry flip the lease status, revoke
//! door-side use, and — for T2 — remove the registered local file
//! (best-effort, recorded: a failed removal retains the registration row
//! with the error recorded, so a path whose file may still hold the value
//! stays in SECRET-03's exclusion set). Caller-held process memory is out
//! of the vault's reach by construction; that is the ratified lease-scoped
//! contract, not a gap to paper over — there is deliberately no fake
//! "scrub the returned buffer" machinery. Revocation of the SECRET itself
//! (SECRET-04, ONE-1922) is the only path that force-kills leases.
//!
//! A lease minted at rotation generation N remains valid after the record
//! rotates to N+1 (S6): staleness is OBSERVABLE via
//! [`SecretLease::value_generation`], never force-killed here. SECRET-04
//! owns rotation and attaches exhaust taint from
//! [`DoorInjectionReceipt::taint_token`].
//!
//! # Receipt residence
//!
//! The RS1 receipt-family discriminator ([`crate::receipt::ReceiptKind`])
//! is `#[non_exhaustive]` and pinned by OF-367 — an OPEN family set this
//! ticket has no authority to extend — so materialization receipts are
//! generic self-describing receipt bodies: `vault_meta` rows under
//! [`SECRET_MATERIALIZATION_RECEIPT_PREFIX`] carrying
//! `kind = "secret_materialization"`. They never carry value bytes.
//!
//! # Storage
//!
//! Lease rows live in `vault_meta` under [`SECRET_LEASE_KEY_PREFIX`], local
//! registrations under [`SECRET_LOCAL_REGISTRATION_PREFIX`] — the
//! [`crate::secret_custody`] name-index idiom, mirroring the device-lease
//! registry's shape ([`crate::sync::lease`], a different noun, never
//! overloaded). `vault_meta` is local-only: custody records never
//! replicate, so leases minted over them never do either.

mod admission;
mod codec;
mod doors;
mod files;
mod storage;
mod types;

pub use self::admission::tier_admission;
pub(crate) use self::codec::{decode_local_registration_body, decode_secret_lease_body};
pub(crate) use self::storage::{teardown_local_registration_in_txn, write_secret_lease_in_txn};
pub(crate) use self::types::VaultInstant;
pub use self::types::{
    DoorInjectionReceipt, LocalRegistration, SECRET_LEASE_KEY_PREFIX,
    SECRET_LOCAL_REGISTRATION_PREFIX, SECRET_MATERIALIZATION_RECEIPT_KIND,
    SECRET_MATERIALIZATION_RECEIPT_PREFIX, SecretLease, SecretLeaseMaterialization,
    SecretLeaseStatus, SecretMaterializationReceipt, SecretTaintRef,
};

#[cfg(test)]
pub(crate) use self::files::file_write_fault_hook;
#[cfg(test)]
pub(crate) use self::storage::{receipt_fault_hook, registration_fault_hook};

#[cfg(test)]
mod tests;

#[cfg(test)]
use self::{codec::*, storage::*};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Error;
#[cfg(test)]
use crate::secret_custody::{
    CustodyClass, CustodyTier, SecretBinding, SecretCustodyFloor, SecretCustodyStatus,
};
#[cfg(test)]
use crate::unix_seconds_now;
#[cfg(test)]
use crate::vault::Vault;
#[cfg(test)]
use std::path::PathBuf;
