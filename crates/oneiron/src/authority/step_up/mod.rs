//! MFA step-up on a person's own request instrument (MFA-1 A, ruled
//! 2026-10-09; FIX 11694, the remainder of FIX 9431).
//!
//! Canon: MFA is optional for a person, a passkey comes first and an
//! authenticator app second, and an org Admin cannot skip it because any one
//! Admin can act alone (ARCH-0043). This module is the trusted verifier that
//! contract names. A person enrolls a passkey on this vault (its public key
//! only; no secret is kept), then steps up on one live slip they hold by
//! signing a fresh engine challenge with it. The engine checks the WebAuthn
//! response itself ([`webauthn`]) and records that step-up against that
//! exact slip. [`Vault::admin_step_up`] is the one producer of the weave
//! Admin's [`AdminStepUp`] witness: it reads that record for the request's
//! own slip, so a caller's word that a step-up happened is never enough.
//!
//! An authenticator app is the optional second choice ([`totp`]); its seed
//! rests sealed under its enrollment's erasable custody key. Both factors
//! record the same slip-bound step-up and produce the same Admin witness.
//!
//! A step-up stands while its slip stays live and its factor stays
//! enrolled; it adds no clock of its own (CALLS `FIX 11694 step-up life`).
//! A person's first passkey is enrolled on their live slip alone; adding or
//! removing one after that needs a current step-up with an enrolled one
//! (CALLS `FIX 11694 first passkey`). The vault owner may reset a person's
//! passkeys, so a person who lost every one can enroll again
//! ([`Vault::reset_step_up_passkeys_as_owner`]). An erase of the person
//! drops every row here with them.

mod admin_inputs;
mod erase;
mod totp;
mod webauthn;

pub(crate) use totp::erase_step_up_totp_actor_in_txn;
pub use totp::{EnrolledTotp, StepUpTotpReset, StepUpTotpResetRequest, TotpCode, TotpEnrollment};

pub use admin_inputs::{
    WeaveAdminDigestRequest, WeaveAdminItemWrongRequest, WeaveAdminLensRequest,
    WeaveAdminLinkWrongRequest, WeaveAdminReportRequest,
};
use erase::drop_step_ups_with_passkey_in_txn;
pub(crate) use erase::{
    erase_step_up_challenges_actor_in_txn, erase_step_up_passkeys_actor_in_txn,
    erase_step_up_records_actor_in_txn,
};

use heed::RwTxn;
use serde::{Deserialize, Serialize};

use super::{AdminStepUp, VerifiedSlip, authority_refused};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// How long a ceremony's challenge may be answered, on the authority clock
/// (CALLS `FIX 11694 challenge life`): WebAuthn's own default ceremony
/// timeout.
pub const STEP_UP_CHALLENGE_TTL_SECS: u64 = 300;

/// The request cannot step up: it is not a live slip of this vault held by
/// its own live person.
pub const STEP_UP_NOT_HOLDER: &str =
    "step_up_not_holder: step up on your own live credential, as the person who holds it";
/// No passkey is enrolled for this person.
pub const STEP_UP_NO_PASSKEY: &str = "step_up_no_passkey: enroll a passkey first";
/// Adding or removing a passkey once one is enrolled needs a current
/// step-up with an enrolled one.
pub const STEP_UP_REQUIRED: &str =
    "step_up_required: step up with a factor you already enrolled, then try again";
/// The ceremony's challenge is unknown, expired, already answered, or
/// another request's or another ceremony's.
pub const STEP_UP_CHALLENGE_STALE: &str = "step_up_challenge_stale: the ceremony's challenge is not open for this credential; start it again";
/// The passkey response did not verify: wrong challenge, origin, RP id,
/// key, signature or counter, or the authenticator did not verify the
/// person.
pub const STEP_UP_REFUSED: &str = "step_up_refused: the passkey response did not verify";

/// The kind of factor a step-up used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepUpFactor {
    /// A user-verified passkey or security key (WebAuthn).
    Passkey,
    /// An enrolled authenticator app (RFC 6238).
    Totp,
}

/// The two WebAuthn ceremonies a challenge opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepUpCeremony {
    /// `navigator.credentials.create`: enroll a passkey.
    Enroll,
    /// `navigator.credentials.get`: step up with an enrolled passkey.
    Assert,
}

/// One enrolled passkey as a ceremony's client names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PasskeyDescriptor {
    /// The credential id, base64url.
    pub credential_id: String,
    /// The RP id it was enrolled under.
    pub rp_id: String,
}

/// What a client needs to run one ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StepUpChallenge {
    /// The 32 challenge bytes, base64url: the client passes them as the
    /// ceremony's `challenge` and names them again in its answer.
    pub challenge: String,
    pub ceremony: StepUpCeremony,
    /// When the challenge closes, on the authority clock (seconds).
    pub expires_at: u64,
    /// The person's id bytes, base64url: `user.id` for `create`.
    pub user_id: String,
    /// The person's id, 32 hex: `user.name` for `create`.
    pub user_name: String,
    /// The person's enrolled passkeys: `excludeCredentials` for `create`,
    /// `allowCredentials` for `get`.
    pub credentials: Vec<PasskeyDescriptor>,
    /// The COSE algorithms an enrollment may use, in preference order.
    pub algorithms: Vec<i64>,
}

/// A passkey enrollment's answer, as the client read it from
/// `navigator.credentials.create` (every byte field base64url).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyRegistration {
    /// The challenge [`StepUpChallenge`] handed out for this enrollment.
    pub challenge: String,
    /// The RP id the client passed to `create` (its own effective domain).
    pub rp_id: String,
    pub credential_id: String,
    /// `response.clientDataJSON`.
    pub client_data_json: String,
    /// `response.getAuthenticatorData()`.
    pub authenticator_data: String,
    /// `response.getPublicKey()`: the SubjectPublicKeyInfo DER.
    pub public_key: String,
    /// `response.getPublicKeyAlgorithm()`: -7 (ES256) or -8 (EdDSA).
    pub algorithm: i64,
    /// The person's own name for this passkey.
    #[serde(default)]
    pub label: Option<String>,
}

/// A step-up's answer, as the client read it from
/// `navigator.credentials.get` (every byte field base64url).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyAssertion {
    /// The challenge [`StepUpChallenge`] handed out for this step-up.
    pub challenge: String,
    pub credential_id: String,
    /// `response.clientDataJSON`.
    pub client_data_json: String,
    /// `response.authenticatorData`.
    pub authenticator_data: String,
    /// `response.signature`.
    pub signature: String,
}

/// One enrolled passkey, as its person lists it. Holds no key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnrolledPasskey {
    pub credential_id: String,
    pub label: Option<String>,
    pub rp_id: String,
    pub origin: String,
    /// The COSE algorithm.
    pub algorithm: i64,
    pub enrolled_at: u64,
    pub last_used_at: Option<u64>,
}

/// The receipt of a completed step-up on one slip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StepUpDone {
    pub factor: StepUpFactor,
    /// The passkey that verified, base64url.
    pub credential_id: String,
    /// When, on the authority clock (seconds).
    pub stepped_up_at: u64,
}

/// `vault.step_up.passkeys.reset`'s input: the person whose passkeys the
/// owner resets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StepUpPasskeysResetRequest {
    /// The person (32 hex).
    pub person: String,
}

/// The receipt of an owner's reset of one person's passkeys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StepUpPasskeysReset {
    /// The person (32 hex).
    pub person: String,
    /// How many enrolled passkeys were removed.
    pub removed: usize,
}

/// A stored passkey. Key: (person, SHA-256 of the credential id).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredPasskey {
    credential_id: Vec<u8>,
    algorithm: i64,
    /// The raw key: a 65-byte SEC1 point (ES256) or 32 bytes (EdDSA).
    public_key: Vec<u8>,
    rp_id: String,
    origin: String,
    sign_count: u32,
    label: Option<String>,
    enrolled_at: u64,
    last_used_at: Option<u64>,
}

/// An open ceremony. Key: the challenge bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingChallenge {
    holder: EntityId,
    slip_id: [u8; 32],
    ceremony: StepUpCeremony,
    expires_at: u64,
}

/// A completed step-up. Key: the slip id it was made on.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StepUpRecord {
    holder: EntityId,
    factor: StepUpFactor,
    /// Passkey credential hash, or the TOTP enrollment id, as `factor` names it.
    credential: [u8; 32],
    stepped_up_at: u64,
}

const PASSKEYS: SideTable<(EntityId, [u8; 32]), StoredPasskey, Named> =
    SideTable::new(&side_table::STEP_UP_PASSKEY);
const CHALLENGES: SideTable<[u8; 32], PendingChallenge, Named> =
    SideTable::new(&side_table::STEP_UP_CHALLENGE);
const RECORDS: SideTable<[u8; 32], StepUpRecord, Named> =
    SideTable::new(&side_table::STEP_UP_RECORD);

/// The longest passkey label kept, in characters; a longer one is cut.
const MAX_LABEL_CHARS: usize = 128;

fn not_holder() -> crate::error::Error {
    authority_refused(STEP_UP_NOT_HOLDER)
}

fn refused() -> crate::error::Error {
    authority_refused(STEP_UP_REFUSED)
}

fn stale() -> crate::error::Error {
    authority_refused(STEP_UP_CHALLENGE_STALE)
}

fn challenge_key(text: &str) -> Result<[u8; 32]> {
    webauthn::from_b64url(text)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
        .ok_or_else(stale)
}

fn descriptor(stored: &StoredPasskey) -> PasskeyDescriptor {
    PasskeyDescriptor {
        credential_id: webauthn::to_b64url(&stored.credential_id),
        rp_id: stored.rp_id.clone(),
    }
}

impl Vault {
    /// The person `request` stands for, judged in `txn`: a live,
    /// untransferred slip of this vault with no delegation, held by its own
    /// live PERSON.
    fn step_up_holder_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        request: &VerifiedSlip,
    ) -> Result<EntityId> {
        let claims = request.claims();
        if request.is_transferred() || claims.delegation.is_some() {
            return Err(not_holder());
        }
        let holder = EntityId::from_hex(&claims.holder_ref).map_err(|_| not_holder())?;
        if !self.capability_slip_is_live_in_txn(txn, request)?
            || !crate::consent::person_is_live_in_txn(self, txn, &holder)?
        {
            return Err(not_holder());
        }
        Ok(holder)
    }

    fn step_up_passkeys_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        holder: EntityId,
    ) -> Result<Vec<StoredPasskey>> {
        Ok(PASSKEYS
            .scan_from(&self.store, txn, holder.as_bytes())?
            .into_iter()
            .filter(|((owner, _), _)| *owner == holder)
            .map(|(_, stored)| stored)
            .collect())
    }

    /// The step-up recorded on `request`'s slip for `holder`, while the
    /// factor it used is still enrolled.
    fn step_up_standing_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        request: &VerifiedSlip,
        holder: EntityId,
    ) -> Result<Option<StepUpRecord>> {
        let Some(record) = RECORDS.get(&self.store, txn, &request.claims().slip_id)? else {
            return Ok(None);
        };
        if record.holder != holder || !self.step_up_factor_stands_in_txn(txn, &record)? {
            return Ok(None);
        }
        Ok(Some(record))
    }

    /// Whether the step-up an Admin witness names still stands in `txn`: its
    /// slip's record is that same step-up, by `holder` at `stepped_up_at`,
    /// and the factor it used is still enrolled. A reset, a removed factor
    /// or a newer step-up on the slip ends it.
    pub(crate) fn step_up_record_stands_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        holder: EntityId,
        slip_id: &[u8; 32],
        stepped_up_at: u64,
    ) -> Result<bool> {
        let Some(record) = RECORDS.get(&self.store, txn, slip_id)? else {
            return Ok(false);
        };
        Ok(record.holder == holder
            && record.stepped_up_at == stepped_up_at
            && self.step_up_factor_stands_in_txn(txn, &record)?)
    }

    fn has_step_up_factor_in_txn(&self, txn: &heed::RoTxn<'_>, holder: EntityId) -> Result<bool> {
        Ok(!self.step_up_passkeys_in_txn(txn, holder)?.is_empty()
            || totp::has_enrolled(self, txn, holder)?)
    }

    fn step_up_factor_stands_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        record: &StepUpRecord,
    ) -> Result<bool> {
        match record.factor {
            StepUpFactor::Passkey => {
                PASSKEYS.contains(&self.store, txn, &(record.holder, record.credential))
            }
            StepUpFactor::Totp => totp::stands(self, txn, record.holder, &record.credential),
        }
    }

    /// Takes the open challenge `challenge` for `ceremony` on `request`'s
    /// slip and `holder`, and removes it: one answer per challenge, right or
    /// wrong.
    fn take_step_up_challenge(
        &self,
        txn: &mut RwTxn<'_>,
        challenge: &[u8; 32],
        request: &VerifiedSlip,
        holder: EntityId,
        ceremony: StepUpCeremony,
        now: u64,
    ) -> Result<()> {
        let pending = CHALLENGES.get(&self.store, txn, challenge)?;
        if pending.is_some() {
            CHALLENGES.delete(&self.store, txn, challenge)?;
        }
        match pending {
            Some(pending)
                if pending.holder == holder
                    && pending.slip_id == request.claims().slip_id
                    && pending.ceremony == ceremony
                    && now < pending.expires_at =>
            {
                Ok(())
            }
            _ => Err(stale()),
        }
    }

    /// Opens a `ceremony` for the person who holds `request`: a fresh
    /// challenge bound to that person and that exact slip. An enrollment
    /// when the person has a passkey already needs a current step-up on
    /// this slip; a step-up needs an enrolled passkey.
    ///
    /// # Errors
    /// `AuthorityRefused` with [`STEP_UP_NOT_HOLDER`], [`STEP_UP_REQUIRED`]
    /// or [`STEP_UP_NO_PASSKEY`]; a storage fault as itself.
    pub fn open_step_up_ceremony(
        &self,
        request: &VerifiedSlip,
        ceremony: StepUpCeremony,
    ) -> Result<StepUpChallenge> {
        let mut txn = self.store.env.write_txn()?;
        let holder = self.step_up_holder_in_txn(&txn, request)?;
        let passkeys = self.step_up_passkeys_in_txn(&txn, holder)?;
        match ceremony {
            StepUpCeremony::Assert if passkeys.is_empty() => {
                return Err(authority_refused(STEP_UP_NO_PASSKEY));
            }
            StepUpCeremony::Enroll
                if self.has_step_up_factor_in_txn(&txn, holder)?
                    && self
                        .step_up_standing_in_txn(&txn, request, holder)?
                        .is_none() =>
            {
                return Err(authority_refused(STEP_UP_REQUIRED));
            }
            _ => {}
        }
        let now = self.instant_in_txn(&txn)?.secs();
        // Closed ceremonies leave nothing behind.
        for (key, pending) in CHALLENGES.scan(&self.store, &txn)? {
            if now >= pending.expires_at {
                CHALLENGES.delete(&self.store, &mut txn, &key)?;
            }
        }
        let mut challenge = [0u8; 32];
        crate::world_keys::os_fill(&mut challenge)?;
        let expires_at = now.saturating_add(STEP_UP_CHALLENGE_TTL_SECS);
        CHALLENGES.put(
            &self.store,
            &mut txn,
            &challenge,
            &PendingChallenge {
                holder,
                slip_id: request.claims().slip_id,
                ceremony,
                expires_at,
            },
        )?;
        txn.commit()?;
        Ok(StepUpChallenge {
            challenge: webauthn::to_b64url(&challenge),
            ceremony,
            expires_at,
            user_id: webauthn::to_b64url(holder.as_bytes()),
            user_name: holder.to_hex(),
            credentials: passkeys.iter().map(descriptor).collect(),
            algorithms: vec![webauthn::COSE_ES256, webauthn::COSE_EDDSA],
        })
    }

    /// Enrolls the passkey `registration` answers for the person who holds
    /// `request`, under the challenge [`Self::open_step_up_ceremony`] handed
    /// out for an enrollment on this slip. The client data must be a
    /// `webauthn.create` over that challenge from a secure origin on the RP
    /// id, the authenticator must have verified the person, and the
    /// attested credential id must be the one named. Enrolling the same
    /// credential again replaces its row.
    ///
    /// # Errors
    /// `AuthorityRefused` with [`STEP_UP_NOT_HOLDER`], [`STEP_UP_REQUIRED`],
    /// [`STEP_UP_CHALLENGE_STALE`] or [`STEP_UP_REFUSED`]; a storage fault
    /// as itself.
    pub fn enroll_step_up_passkey(
        &self,
        request: &VerifiedSlip,
        registration: &PasskeyRegistration,
    ) -> Result<EnrolledPasskey> {
        let challenge = challenge_key(&registration.challenge)?;
        let mut txn = self.store.env.write_txn()?;
        let holder = self.step_up_holder_in_txn(&txn, request)?;
        let now = self.instant_in_txn(&txn)?.secs();
        self.take_step_up_challenge(
            &mut txn,
            &challenge,
            request,
            holder,
            StepUpCeremony::Enroll,
            now,
        )?;
        // The challenge is spent whatever follows.
        txn.commit()?;
        let mut txn = self.store.env.write_txn()?;
        if self.step_up_holder_in_txn(&txn, request)? != holder {
            return Err(not_holder());
        }
        if self.has_step_up_factor_in_txn(&txn, holder)?
            && self
                .step_up_standing_in_txn(&txn, request, holder)?
                .is_none()
        {
            return Err(authority_refused(STEP_UP_REQUIRED));
        }
        let stored = verified_registration(registration, &challenge, now).ok_or_else(refused)?;
        let key = (holder, webauthn::sha256(&stored.credential_id));
        // A step-up an earlier enrollment of this credential id verified
        // never stands with this one.
        drop_step_ups_with_passkey_in_txn(self, &mut txn, holder, &key.1)?;
        PASSKEYS.put(&self.store, &mut txn, &key, &stored)?;
        txn.commit()?;
        Ok(enrolled(&stored))
    }

    /// Steps up the slip `request` with the passkey `assertion` answers,
    /// under the challenge [`Self::open_step_up_ceremony`] handed out for a
    /// step-up on this slip. The client data must be a `webauthn.get` over
    /// that challenge from the origin the passkey was enrolled at, the
    /// authenticator data must name its RP id with the person verified, the
    /// signature must verify under its key, and a counting authenticator's
    /// counter must have moved forward. The step-up is then recorded on
    /// this exact slip.
    ///
    /// # Errors
    /// `AuthorityRefused` with [`STEP_UP_NOT_HOLDER`],
    /// [`STEP_UP_CHALLENGE_STALE`] or [`STEP_UP_REFUSED`]; a storage fault
    /// as itself.
    pub fn step_up_with_passkey(
        &self,
        request: &VerifiedSlip,
        assertion: &PasskeyAssertion,
    ) -> Result<StepUpDone> {
        let challenge = challenge_key(&assertion.challenge)?;
        let mut txn = self.store.env.write_txn()?;
        let holder = self.step_up_holder_in_txn(&txn, request)?;
        let now = self.instant_in_txn(&txn)?.secs();
        self.take_step_up_challenge(
            &mut txn,
            &challenge,
            request,
            holder,
            StepUpCeremony::Assert,
            now,
        )?;
        // The challenge is spent whatever follows.
        txn.commit()?;
        let mut txn = self.store.env.write_txn()?;
        if self.step_up_holder_in_txn(&txn, request)? != holder {
            return Err(not_holder());
        }
        let credential_id = webauthn::from_b64url(&assertion.credential_id).ok_or_else(refused)?;
        let credential = webauthn::sha256(&credential_id);
        let key = (holder, credential);
        let Some(mut stored) = PASSKEYS.get(&self.store, &txn, &key)? else {
            return Err(refused());
        };
        let sign_count = verified_assertion(&stored, assertion, &challenge).ok_or_else(refused)?;
        // A counting authenticator moves its counter on every use; one that
        // did not may be a copy (WebAuthn L2 §6.1.1).
        if (sign_count != 0 || stored.sign_count != 0) && sign_count <= stored.sign_count {
            return Err(refused());
        }
        stored.sign_count = sign_count;
        stored.last_used_at = Some(now);
        PASSKEYS.put(&self.store, &mut txn, &key, &stored)?;
        RECORDS.put(
            &self.store,
            &mut txn,
            &request.claims().slip_id,
            &StepUpRecord {
                holder,
                factor: StepUpFactor::Passkey,
                credential,
                stepped_up_at: now,
            },
        )?;
        txn.commit()?;
        Ok(StepUpDone {
            factor: StepUpFactor::Passkey,
            credential_id: webauthn::to_b64url(&credential_id),
            stepped_up_at: now,
        })
    }

    /// The passkeys the person who holds `request` has enrolled, oldest
    /// first. No key material.
    ///
    /// # Errors
    /// `AuthorityRefused(STEP_UP_NOT_HOLDER)`; a storage fault as itself.
    pub fn step_up_passkeys(&self, request: &VerifiedSlip) -> Result<Vec<EnrolledPasskey>> {
        let txn = self.store.env.read_txn()?;
        let holder = self.step_up_holder_in_txn(&txn, request)?;
        let mut passkeys: Vec<EnrolledPasskey> = self
            .step_up_passkeys_in_txn(&txn, holder)?
            .iter()
            .map(enrolled)
            .collect();
        passkeys.sort_by_key(|passkey| passkey.enrolled_at);
        Ok(passkeys)
    }

    /// Removes the person's passkey `credential_id` (base64url), after a
    /// current step-up on `request`. Every step-up that used it goes with
    /// it, so a later enrollment of the same credential id revives none.
    /// `false` when no such passkey is enrolled.
    ///
    /// # Errors
    /// `AuthorityRefused` with [`STEP_UP_NOT_HOLDER`] or
    /// [`STEP_UP_REQUIRED`]; a storage fault as itself.
    pub fn remove_step_up_passkey(
        &self,
        request: &VerifiedSlip,
        credential_id: &str,
    ) -> Result<bool> {
        let mut txn = self.store.env.write_txn()?;
        let holder = self.step_up_holder_in_txn(&txn, request)?;
        if self
            .step_up_standing_in_txn(&txn, request, holder)?
            .is_none()
        {
            return Err(authority_refused(STEP_UP_REQUIRED));
        }
        let Some(credential_id) = webauthn::from_b64url(credential_id) else {
            return Ok(false);
        };
        let key = (holder, webauthn::sha256(&credential_id));
        let removed = PASSKEYS.delete(&self.store, &mut txn, &key)?;
        drop_step_ups_with_passkey_in_txn(self, &mut txn, holder, &key.1)?;
        txn.commit()?;
        Ok(removed)
    }

    /// The vault owner removes every passkey `person` enrolled, and every
    /// step-up they made with one (FIX 17553): the way back for a person
    /// who lost each passkey, since adding one needs a current step-up. The
    /// person then enrolls a first passkey again on their own live slip.
    /// The owner proof is revalidated in the writer that removes them.
    ///
    /// # Errors
    /// The owner proof's refusal when it no longer holds; a storage fault as
    /// itself.
    pub fn reset_step_up_passkeys_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        person: EntityId,
    ) -> Result<StepUpPasskeysReset> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let removed = PASSKEYS
            .scan_from(&self.store, &txn, person.as_bytes())?
            .into_iter()
            .filter(|((holder, _), _)| *holder == person)
            .count();
        erase_step_up_passkeys_actor_in_txn(self, &mut txn, &person)?;
        erase::erase_step_up_passkey_records_actor_in_txn(self, &mut txn, &person)?;
        txn.commit()?;
        Ok(StepUpPasskeysReset {
            person: person.to_hex(),
            removed,
        })
    }

    /// The weave Admin's step-up witness for `request` (OF-499 A3): the
    /// [`AdminStepUp`] the step-up recorded on this exact slip left, while
    /// the slip is a live one of its own live person and the factor that
    /// stepped up is still enrolled. `None` when no such step-up stands.
    /// The only producer of the witness; the Admin proof binds it to the
    /// slip's holder and the slip and revalidates both on every read.
    ///
    /// # Errors
    /// A storage fault.
    pub fn admin_step_up(&self, request: &VerifiedSlip) -> Result<Option<AdminStepUp>> {
        let txn = self.store.env.read_txn()?;
        let holder = match self.step_up_holder_in_txn(&txn, request) {
            Ok(holder) => holder,
            Err(crate::error::Error::Record(crate::error::RecordError::AuthorityRefused(_))) => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        Ok(self
            .step_up_standing_in_txn(&txn, request, holder)?
            .map(|record| AdminStepUp::after_step_up(holder, request, record.stepped_up_at)))
    }
}

/// The stored passkey a registration enrolls, when every check holds.
fn verified_registration(
    registration: &PasskeyRegistration,
    challenge: &[u8; 32],
    now: u64,
) -> Option<StoredPasskey> {
    let credential_id = webauthn::from_b64url(&registration.credential_id)?;
    if credential_id.is_empty() || credential_id.len() > webauthn::MAX_CREDENTIAL_ID_LEN {
        return None;
    }
    let client_data_json = webauthn::from_b64url(&registration.client_data_json)?;
    let client = webauthn::client_data(&client_data_json)?;
    if client.kind != "webauthn.create"
        || client.challenge.as_slice() != challenge.as_slice()
        || client.cross_origin
        || !webauthn::origin_admits_rp_id(&client.origin, &registration.rp_id)
    {
        return None;
    }
    let authenticator_data = webauthn::from_b64url(&registration.authenticator_data)?;
    let auth = webauthn::auth_data(&authenticator_data)?;
    if auth.rp_id_hash != webauthn::sha256(registration.rp_id.as_bytes())
        || !auth.user_verified()
        || auth.attested_credential_id()? != credential_id.as_slice()
    {
        return None;
    }
    let spki = webauthn::from_b64url(&registration.public_key)?;
    let public_key = webauthn::spki_public_key(registration.algorithm, &spki)?;
    Some(StoredPasskey {
        credential_id,
        algorithm: registration.algorithm,
        public_key,
        rp_id: registration.rp_id.clone(),
        origin: client.origin,
        sign_count: auth.sign_count,
        label: registration
            .label
            .as_deref()
            .map(str::trim)
            .filter(|label| !label.is_empty())
            .map(|label| label.chars().take(MAX_LABEL_CHARS).collect()),
        enrolled_at: now,
        last_used_at: None,
    })
}

/// The authenticator's new counter, when `assertion` verifies for `stored`.
fn verified_assertion(
    stored: &StoredPasskey,
    assertion: &PasskeyAssertion,
    challenge: &[u8; 32],
) -> Option<u32> {
    let client_data_json = webauthn::from_b64url(&assertion.client_data_json)?;
    let client = webauthn::client_data(&client_data_json)?;
    if client.kind != "webauthn.get"
        || client.challenge.as_slice() != challenge.as_slice()
        || client.cross_origin
        || client.origin != stored.origin
    {
        return None;
    }
    let authenticator_data = webauthn::from_b64url(&assertion.authenticator_data)?;
    let auth = webauthn::auth_data(&authenticator_data)?;
    if auth.rp_id_hash != webauthn::sha256(stored.rp_id.as_bytes()) || !auth.user_verified() {
        return None;
    }
    let signature = webauthn::from_b64url(&assertion.signature)?;
    webauthn::signature_verifies(
        stored.algorithm,
        &stored.public_key,
        &authenticator_data,
        &client_data_json,
        &signature,
    )
    .then_some(auth.sign_count)
}

fn enrolled(stored: &StoredPasskey) -> EnrolledPasskey {
    EnrolledPasskey {
        credential_id: webauthn::to_b64url(&stored.credential_id),
        label: stored.label.clone(),
        rp_id: stored.rp_id.clone(),
        origin: stored.origin.clone(),
        algorithm: stored.algorithm,
        enrolled_at: stored.enrolled_at,
        last_used_at: stored.last_used_at,
    }
}
