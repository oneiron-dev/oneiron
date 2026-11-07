//! Optional authenticator-app step-up, using the same slip-bound record
//! and Admin witness as passkeys (MFA-1 A; FIX 17552).

use crate::store::totp_custody::{self as custody, SEED_BYTES};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::{
    RECORDS, STEP_UP_CHALLENGE_TTL_SECS, STEP_UP_REQUIRED, StepUpDone, StepUpFactor, StepUpRecord,
    VerifiedSlip, authority_refused, challenge_key, stale, webauthn,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

use oneiron_crypto::totp::{TOTP_DIGITS, TOTP_PERIOD_SECS};

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const REFUSED: &str = "step_up_totp_refused: the code did not verify or its step was already spent";

/// A fresh provisioning secret, returned only to the enrolling person.
/// It has no Debug or Clone; its seed text is wiped on drop. Do not log it.
#[derive(Serialize)]
pub struct TotpEnrollment {
    pub enrollment_id: String,
    /// RFC 4648 base32, without padding; for an otpauth provisioning URI.
    pub secret: String,
    pub algorithm: &'static str,
    pub digits: usize,
    pub period_secs: u64,
    /// On the authority clock, like a passkey enrollment challenge.
    pub expires_at: u64,
}

impl Drop for TotpEnrollment {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// The first code confirms enrollment; subsequent codes step up a slip.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpCode {
    pub enrollment_id: String,
    pub code: String,
}

impl Drop for TotpCode {
    fn drop(&mut self) {
        self.code.zeroize();
    }
}

/// An enrolled authenticator's public metadata. Never its seed or seal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnrolledTotp {
    pub enrollment_id: String,
    pub enrolled_at: u64,
    pub last_used_at: u64,
}

/// Owner reset names only the person's TOTP factors, not their passkeys.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StepUpTotpResetRequest {
    pub person: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StepUpTotpReset {
    pub person: String,
    pub removed: usize,
}

#[derive(Serialize, Deserialize)]
struct PendingTotp {
    slip_id: [u8; 32],
    key_ref: [u8; 32],
    sealed_seed: Vec<u8>,
    expires_at: u64,
}

#[derive(Serialize, Deserialize)]
struct StoredTotp {
    key_ref: [u8; 32],
    sealed_seed: Vec<u8>,
    enrolled_at: u64,
    last_used_at: u64,
    /// The actual matched RFC 6238 step, including a drift-window match.
    spent_step: u64,
}

const PENDING: SideTable<(EntityId, [u8; 32]), PendingTotp, Named> =
    SideTable::new(&side_table::STEP_UP_TOTP_PENDING);
const ENROLLED: SideTable<(EntityId, [u8; 32]), StoredTotp, Named> =
    SideTable::new(&side_table::STEP_UP_TOTP);

fn refused() -> crate::error::Error {
    authority_refused(REFUSED)
}

fn base32(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut bits = 0u32;
    let mut available = 0u32;
    for byte in bytes {
        bits = (bits << 8) | u32::from(*byte);
        available += 8;
        while available >= 5 {
            available -= 5;
            encoded.push(char::from(BASE32[((bits >> available) & 31) as usize]));
        }
    }
    if available != 0 {
        encoded.push(char::from(
            BASE32[((bits << (5 - available)) & 31) as usize],
        ));
    }
    bits.zeroize();
    encoded
}

fn matched_step(vault: &Vault, seed: &[u8], code: &str) -> Result<u64> {
    oneiron_crypto::totp::matching_totp_step(seed, code, vault.store.clock.wall_now())
        .ok_or_else(refused)
}

pub(super) fn has_enrolled(vault: &Vault, txn: &RoTxn<'_>, person: EntityId) -> Result<bool> {
    Ok(ENROLLED
        .scan_from(&vault.store, txn, person.as_bytes())?
        .iter()
        .any(|((holder, _), _)| *holder == person))
}

pub(super) fn stands(
    vault: &Vault,
    txn: &RoTxn<'_>,
    person: EntityId,
    enrollment: &[u8; 32],
) -> Result<bool> {
    let Some(stored) = ENROLLED.get(&vault.store, txn, &(person, *enrollment))? else {
        return Ok(false);
    };
    custody::live(&vault.store, txn, person, enrollment, &stored.key_ref)
}

fn drop_records(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    person: EntityId,
    enrollment: &[u8; 32],
) -> Result<()> {
    for (key, record) in RECORDS.scan(&vault.store, txn)? {
        if record.holder == person
            && record.factor == StepUpFactor::Totp
            && record.credential == *enrollment
        {
            RECORDS.delete(&vault.store, txn, &key)?;
        }
    }
    Ok(())
}

pub(crate) fn erase_step_up_totp_actor_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    person: &EntityId,
) -> Result<()> {
    for (key, _) in PENDING.scan_from(&vault.store, txn, person.as_bytes())? {
        if key.0 == *person {
            PENDING.delete(&vault.store, txn, &key)?;
        }
    }
    for (key, _) in ENROLLED.scan_from(&vault.store, txn, person.as_bytes())? {
        if key.0 == *person {
            ENROLLED.delete(&vault.store, txn, &key)?;
            drop_records(vault, txn, *person, &key.1)?;
        }
    }
    custody::retire_person(&vault.store, txn, *person)
}

impl Vault {
    /// Begins a pending enrollment on the person's own live slip. An
    /// existing factor requires a current step-up, just as adding a passkey
    /// does. A pending seed never replaces a working authenticator.
    pub fn begin_step_up_totp(&self, request: &VerifiedSlip) -> Result<TotpEnrollment> {
        let mut txn = self.store.env.write_txn()?;
        let person = self.step_up_holder_in_txn(&txn, request)?;
        self.require_step_up_for_factor_change(&txn, request, person)?;
        let now = self.instant_in_write_txn(&mut txn)?.secs();
        for (key, pending) in PENDING.scan_from(&self.store, &txn, person.as_bytes())? {
            if key.0 == person && now >= pending.expires_at {
                custody::retire(&self.store, &mut txn, person, &key.1, &pending.key_ref)?;
                PENDING.delete(&self.store, &mut txn, &key)?;
            }
        }
        let mut enrollment = [0u8; 32];
        crate::world_keys::os_fill(&mut enrollment)?;
        let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
        crate::world_keys::os_fill(&mut *seed)?;
        let (key_ref, sealed_seed) =
            custody::seal(&self.store, &mut txn, person, &enrollment, &*seed)?;
        let expires_at = now.saturating_add(STEP_UP_CHALLENGE_TTL_SECS);
        PENDING.put(
            &self.store,
            &mut txn,
            &(person, enrollment),
            &PendingTotp {
                slip_id: request.claims().slip_id,
                key_ref,
                sealed_seed,
                expires_at,
            },
        )?;
        let secret = base32(&*seed);
        let result = TotpEnrollment {
            enrollment_id: webauthn::to_b64url(&enrollment),
            secret,
            algorithm: "SHA1",
            digits: TOTP_DIGITS,
            period_secs: TOTP_PERIOD_SECS,
            expires_at,
        };
        txn.commit()?;
        Ok(result)
    }

    fn require_step_up_for_factor_change(
        &self,
        txn: &RoTxn<'_>,
        request: &VerifiedSlip,
        person: EntityId,
    ) -> Result<()> {
        if self.has_step_up_factor_in_txn(txn, person)?
            && self
                .step_up_standing_in_txn(txn, request, person)?
                .is_none()
        {
            return Err(authority_refused(STEP_UP_REQUIRED));
        }
        Ok(())
    }

    /// Confirms a pending seed with its first code, consumes the actual
    /// matched step, and records step-up on this same slip, all in one writer.
    pub fn confirm_step_up_totp(
        &self,
        request: &VerifiedSlip,
        input: &TotpCode,
    ) -> Result<StepUpDone> {
        let enrollment = challenge_key(&input.enrollment_id)?;
        let mut txn = self.store.env.write_txn()?;
        let person = self.step_up_holder_in_txn(&txn, request)?;
        self.require_step_up_for_factor_change(&txn, request, person)?;
        let now = self.instant_in_write_txn(&mut txn)?.secs();
        let pending = PENDING
            .get(&self.store, &txn, &(person, enrollment))?
            .ok_or_else(stale)?;
        if pending.slip_id != request.claims().slip_id || now >= pending.expires_at {
            return Err(stale());
        }
        let seed = custody::open(
            &self.store,
            &txn,
            person,
            &enrollment,
            &pending.key_ref,
            &pending.sealed_seed,
        )?;
        let spent_step = matched_step(self, &seed, &input.code)?;
        ENROLLED.put(
            &self.store,
            &mut txn,
            &(person, enrollment),
            &StoredTotp {
                key_ref: pending.key_ref,
                sealed_seed: pending.sealed_seed,
                enrolled_at: now,
                last_used_at: now,
                spent_step,
            },
        )?;
        PENDING.delete(&self.store, &mut txn, &(person, enrollment))?;
        self.record_totp_step_up(&mut txn, request, person, enrollment, now)?;
        txn.commit()?;
        Ok(totp_done(enrollment, now))
    }

    /// Verifies a code and consumes its actual matched step globally for
    /// this enrollment before recording step-up on the exact admitted slip.
    pub fn step_up_with_totp(
        &self,
        request: &VerifiedSlip,
        input: &TotpCode,
    ) -> Result<StepUpDone> {
        let enrollment = challenge_key(&input.enrollment_id)?;
        let mut txn = self.store.env.write_txn()?;
        let person = self.step_up_holder_in_txn(&txn, request)?;
        let key = (person, enrollment);
        let mut stored = ENROLLED.get(&self.store, &txn, &key)?.ok_or_else(refused)?;
        let seed = custody::open(
            &self.store,
            &txn,
            person,
            &enrollment,
            &stored.key_ref,
            &stored.sealed_seed,
        )?;
        let step = matched_step(self, &seed, &input.code)?;
        if step <= stored.spent_step {
            return Err(refused());
        }
        let now = self.instant_in_write_txn(&mut txn)?.secs();
        stored.spent_step = step;
        stored.last_used_at = now;
        ENROLLED.put(&self.store, &mut txn, &key, &stored)?;
        self.record_totp_step_up(&mut txn, request, person, enrollment, now)?;
        txn.commit()?;
        Ok(totp_done(enrollment, now))
    }

    fn record_totp_step_up(
        &self,
        txn: &mut RwTxn<'_>,
        request: &VerifiedSlip,
        holder: EntityId,
        credential: [u8; 32],
        stepped_up_at: u64,
    ) -> Result<()> {
        RECORDS.put(
            &self.store,
            txn,
            &request.claims().slip_id,
            &StepUpRecord {
                holder,
                factor: StepUpFactor::Totp,
                credential,
                stepped_up_at,
            },
        )
    }

    /// The person's enrolled authenticator metadata, oldest first; no seed.
    pub fn step_up_totp_enrollments(&self, request: &VerifiedSlip) -> Result<Vec<EnrolledTotp>> {
        let txn = self.store.env.read_txn()?;
        let person = self.step_up_holder_in_txn(&txn, request)?;
        let mut rows: Vec<_> = ENROLLED
            .scan_from(&self.store, &txn, person.as_bytes())?
            .into_iter()
            .filter(|((holder, _), _)| *holder == person)
            .map(|((_, id), stored)| EnrolledTotp {
                enrollment_id: webauthn::to_b64url(&id),
                enrolled_at: stored.enrolled_at,
                last_used_at: stored.last_used_at,
            })
            .collect();
        rows.sort_by_key(|row| row.enrolled_at);
        Ok(rows)
    }

    /// Removes an enrolled or pending authenticator and its exact factor's
    /// step-ups. A different factor's records remain untouched.
    pub fn remove_step_up_totp(&self, request: &VerifiedSlip, enrollment_id: &str) -> Result<bool> {
        let enrollment = challenge_key(enrollment_id)?;
        let mut txn = self.store.env.write_txn()?;
        let person = self.step_up_holder_in_txn(&txn, request)?;
        self.require_step_up_for_factor_change(&txn, request, person)?;
        let key = (person, enrollment);
        let enrolled = ENROLLED.get(&self.store, &txn, &key)?;
        let pending = PENDING.get(&self.store, &txn, &key)?;
        let key_ref = enrolled
            .as_ref()
            .map(|row| &row.key_ref)
            .or_else(|| pending.as_ref().map(|row| &row.key_ref));
        let removed = key_ref.is_some();
        if let Some(key_ref) = key_ref {
            custody::retire(&self.store, &mut txn, person, &enrollment, key_ref)?;
        }
        ENROLLED.delete(&self.store, &mut txn, &key)?;
        PENDING.delete(&self.store, &mut txn, &key)?;
        drop_records(self, &mut txn, person, &enrollment)?;
        txn.commit()?;
        Ok(removed)
    }

    /// Explicit owner recovery for lost authenticator apps. Passkey
    /// enrollment and passkey-derived step-ups are not reset by this call.
    pub fn reset_step_up_totp_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        person: EntityId,
    ) -> Result<StepUpTotpReset> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let removed = ENROLLED
            .scan_from(&self.store, &txn, person.as_bytes())?
            .iter()
            .filter(|((holder, _), _)| *holder == person)
            .count();
        erase_step_up_totp_actor_in_txn(self, &mut txn, &person)?;
        txn.commit()?;
        Ok(StepUpTotpReset {
            person: person.to_hex(),
            removed,
        })
    }
}

fn totp_done(enrollment: [u8; 32], stepped_up_at: u64) -> StepUpDone {
    StepUpDone {
        factor: StepUpFactor::Totp,
        credential_id: webauthn::to_b64url(&enrollment),
        stepped_up_at,
    }
}
