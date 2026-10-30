//! Receiver freshness for the own-receive pin (FIX 4294).
//!
//! The own-receive exchange (`history_pin_exchange`) reads the candidate's
//! own signed challenge as an issuance label, so a receiver cannot tell the
//! tip it pinned from an older one. This exchange adds that proof. The
//! receiver issues a fresh random challenge bound to its vault, its own
//! machine and the target, and keeps it. The home answers with a signed
//! response naming the handoff it holds pinned for the target (its content
//! hash and heads), the signer's authority anchor, and the challenge.
//!
//! The receiver accepts a response only when it names this device's own
//! outstanding, unexpired challenge, its signature verifies, and its signer
//! passes the rule the own-receive pin applies to a tip's signer: a live
//! owner root in this device's fold, at an authority head the fold holds,
//! whose host context passes at a head the response's head equals or
//! precedes. A challenge answers once. A response that does not verify
//! spends nothing, so a forged or stray answer cannot use up a challenge.
//!
//! The proof is a status beside the pin, never a gate: the exchange, the
//! pin and every read behave as before, and a receiver with no answer reads
//! [`MachineHistoryPinFreshness::Unproven`]. Challenges and proofs live in
//! this vault's memory only.
//!
//! CALLS (L02, open): "FIX 4294 freshness challenge lifetime", "FIX 4294 one
//! outstanding challenge per target", "FIX 4294 proofs in memory".

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use rand_core::RngCore;

use crate::authority::{AuthorityKey, AuthoritySignature, ROLE_OWNER, verify_authority_signature};
use crate::error::{ClaimError, Error, Result};
use crate::{EntityId, Vault};

use super::ClaimHistoryHandoff;
use super::history_projection::pin_key;

/// Signature domain of a freshness response, distinct from the handoff's.
pub const MACHINE_HISTORY_FRESHNESS_DOMAIN: &[u8] = b"oneiron/machine-history-freshness/v1";
/// The leading byte of an encoded challenge and of an encoded response.
pub const MACHINE_HISTORY_FRESHNESS_VERSION: u8 = 1;
/// How long an issued challenge waits for its answer. CALLS: "FIX 4294
/// freshness challenge lifetime".
pub const MACHINE_HISTORY_FRESHNESS_CHALLENGE_LIFETIME: Duration = Duration::from_secs(120);
/// The most heads a response names: a handoff packet's own bound.
const MAX_FRESHNESS_HEADS: usize = 1024 + 4096;
const CHALLENGE_LEN: usize = 1 + 32 + 16 + 16 + 32;

/// What a receiver asks the home: the vault, the target and this device's
/// own machine it is bound to, and a random nonce it keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineHistoryFreshnessChallenge {
    pub vault_id: [u8; 32],
    pub target: EntityId,
    pub machine: EntityId,
    pub nonce: [u8; 32],
}

impl MachineHistoryFreshnessChallenge {
    /// Fixed-width wire encoding: version, vault, target, machine, nonce.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CHALLENGE_LEN);
        out.push(MACHINE_HISTORY_FRESHNESS_VERSION);
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(self.target.as_bytes());
        out.extend_from_slice(self.machine.as_bytes());
        out.extend_from_slice(&self.nonce);
        out
    }

    /// A challenge [`Self::encode`] wrote; `None` for anything else.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut cursor = Cursor { bytes, at: 0 };
        let challenge = cursor.challenge()?;
        (cursor.at == bytes.len()).then_some(challenge)
    }
}

/// The home's signed answer to one challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineHistoryFreshnessResponse {
    pub challenge: MachineHistoryFreshnessChallenge,
    /// Content hash of the handoff the home holds pinned for the target.
    pub tip: [u8; 32],
    /// That handoff's heads, sorted and unique.
    pub heads: Vec<[u8; 32]>,
    /// The signer's causal authority anchor at the home when it answered.
    pub authority_head: [u8; 32],
    pub signer: AuthorityKey,
    pub signature: [u8; 64],
}

impl MachineHistoryFreshnessResponse {
    fn body(&self) -> Option<Vec<u8>> {
        if self.heads.len() > MAX_FRESHNESS_HEADS
            || !self.heads.windows(2).all(|pair| pair[0] < pair[1])
        {
            return None;
        }
        let mut out = self.challenge.encode();
        out.extend_from_slice(&self.tip);
        out.extend_from_slice(&u16::try_from(self.heads.len()).ok()?.to_be_bytes());
        for head in &self.heads {
            out.extend_from_slice(head);
        }
        out.extend_from_slice(&self.authority_head);
        match &self.signer {
            AuthorityKey::Ed25519(bytes) => {
                out.push(1);
                out.extend_from_slice(bytes);
            }
            AuthorityKey::P256(bytes) => {
                out.push(2);
                out.extend_from_slice(bytes);
            }
        }
        Some(out)
    }

    /// Exact bytes to sign: the domain, the body's length, the body. The
    /// signature is excluded; every other field is bound.
    #[must_use]
    pub fn transcript(&self) -> Option<Vec<u8>> {
        let body = self.body()?;
        let mut out = Vec::with_capacity(MACHINE_HISTORY_FRESHNESS_DOMAIN.len() + 4 + body.len());
        out.extend_from_slice(MACHINE_HISTORY_FRESHNESS_DOMAIN);
        out.extend_from_slice(&u32::try_from(body.len()).ok()?.to_be_bytes());
        out.extend_from_slice(&body);
        Some(out)
    }

    /// Deterministic wire encoding, the fixed-width signature last.
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        let mut out = self.body()?;
        out.extend_from_slice(&self.signature);
        Some(out)
    }

    /// A response [`Self::encode`] wrote; `None` for anything else: no
    /// trailing bytes, unsorted heads or unknown signer suite.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut cursor = Cursor { bytes, at: 0 };
        let challenge = cursor.challenge()?;
        let tip = cursor.take()?;
        let count = usize::from(u16::from_be_bytes(cursor.take()?));
        if count > MAX_FRESHNESS_HEADS {
            return None;
        }
        let mut heads = Vec::with_capacity(count);
        for _ in 0..count {
            heads.push(cursor.take()?);
        }
        let authority_head = cursor.take()?;
        let signer = match cursor.take::<1>()?[0] {
            1 => AuthorityKey::Ed25519(cursor.take()?),
            2 => AuthorityKey::P256(cursor.take::<33>()?.to_vec()),
            _ => return None,
        };
        let signature = cursor.take()?;
        if cursor.at != bytes.len() || !heads.windows(2).all(|pair| pair[0] < pair[1]) {
            return None;
        }
        Some(Self {
            challenge,
            tip,
            heads,
            authority_head,
            signer,
            signature,
        })
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let end = self.at.checked_add(N)?;
        let taken = self.bytes.get(self.at..end)?.try_into().ok()?;
        self.at = end;
        Some(taken)
    }

    fn challenge(&mut self) -> Option<MachineHistoryFreshnessChallenge> {
        if self.take::<1>()?[0] != MACHINE_HISTORY_FRESHNESS_VERSION {
            return None;
        }
        Some(MachineHistoryFreshnessChallenge {
            vault_id: self.take()?,
            target: EntityId::from_bytes(self.take()?).ok()?,
            machine: EntityId::from_bytes(self.take()?).ok()?,
            nonce: self.take()?,
        })
    }
}

/// What this device can say of its own-receive pin's freshness for one
/// target. Times are recorded seconds on this device's clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineHistoryPinFreshness {
    /// No home answer to this device's challenge is held: the pin proves
    /// what the own-receive exchange proves, and no freshness.
    Unproven,
    /// The home, answering this device's own challenge, named the handoff
    /// this device holds pinned as the one it holds pinned: the tip was the
    /// home's at some time from `challenged_at` to `answered_at`.
    Latest {
        tip: [u8; 32],
        challenged_at: u64,
        answered_at: u64,
    },
    /// The home named another handoff than the one this device holds pinned
    /// (`held`, `None` when none is): the pin is not shown to be the
    /// home's latest.
    HomeNamedOther {
        held: Option<[u8; 32]>,
        home_tip: [u8; 32],
        challenged_at: u64,
        answered_at: u64,
    },
}

/// A challenge this device issued and keeps for its answer.
#[derive(Debug, Clone, Copy)]
struct Outstanding {
    challenge: MachineHistoryFreshnessChallenge,
    issued: Instant,
    issued_at: u64,
}

/// The last answer this device accepted for a target.
#[derive(Debug, Clone, Copy)]
struct Proof {
    home_tip: [u8; 32],
    challenged_at: u64,
    answered_at: u64,
}

/// This vault's freshness challenges and proofs, in memory only.
#[derive(Debug, Default)]
pub(crate) struct FreshnessLedger {
    /// One outstanding challenge per target; a new one replaces it. CALLS:
    /// "FIX 4294 one outstanding challenge per target".
    challenges: BTreeMap<EntityId, Outstanding>,
    proofs: BTreeMap<EntityId, Proof>,
}

fn ledger(slot: &Mutex<FreshnessLedger>) -> MutexGuard<'_, FreshnessLedger> {
    slot.lock().unwrap_or_else(PoisonError::into_inner)
}

fn invalid() -> Error {
    Error::Claim(ClaimError::InvalidMachineClaimProof)
}

fn freshness_of(held: Option<[u8; 32]>, proof: Option<Proof>) -> MachineHistoryPinFreshness {
    match proof {
        None => MachineHistoryPinFreshness::Unproven,
        Some(proof) if held == Some(proof.home_tip) => MachineHistoryPinFreshness::Latest {
            tip: proof.home_tip,
            challenged_at: proof.challenged_at,
            answered_at: proof.answered_at,
        },
        Some(proof) => MachineHistoryPinFreshness::HomeNamedOther {
            held,
            home_tip: proof.home_tip,
            challenged_at: proof.challenged_at,
            answered_at: proof.answered_at,
        },
    }
}

impl Vault {
    /// The content hash of the handoff this vault holds pinned for `target`.
    fn pinned_handoff_hash(
        &self,
        txn: &heed::RoTxn<'_>,
        target: EntityId,
    ) -> Result<Option<[u8; 32]>> {
        self.store
            .vault_meta
            .get(txn, &pin_key(target))?
            .map(|raw| {
                ClaimHistoryHandoff::decode(&raw)
                    .and_then(|pin| pin.content_hash())
                    .map_err(|_| invalid())
            })
            .transpose()
    }

    /// Issues a fresh challenge for `target`'s machine history, bound to this
    /// vault, this device's machine and the target, and keeps it for its
    /// answer; it replaces any earlier one for the target. `None` before this
    /// device has a folded vault id or a machine id.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn issue_machine_history_freshness_challenge(
        &self,
        target: EntityId,
    ) -> Result<Option<MachineHistoryFreshnessChallenge>> {
        let txn = self.store.env.read_txn()?;
        let Some(vault_id) = self.authority_view_readonly_in_txn(&txn)?.vault_id else {
            return Ok(None);
        };
        let Some(machine) = crate::identity::read_machine_id_in_txn(self, &txn)? else {
            return Ok(None);
        };
        drop(txn);
        let mut nonce = [0; 32];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let challenge = MachineHistoryFreshnessChallenge {
            vault_id,
            target,
            machine,
            nonce,
        };
        let issued_at = self.store.clock.now_recorded_at();
        ledger(&self.store.machine_history_runtime.freshness)
            .challenges
            .insert(
                target,
                Outstanding {
                    challenge,
                    issued: Instant::now(),
                    issued_at,
                },
            );
        Ok(Some(challenge))
    }

    /// The home's answer to `challenge`, signed with `issuer`: the handoff
    /// this vault holds pinned for the target, its heads, and the issuer's
    /// causal authority anchor here. `None` when this vault cannot answer:
    /// the challenge names another vault, no pin is held for the target, or
    /// `issuer` is not a live owner root here.
    ///
    /// # Errors
    ///
    /// Storage errors, and a stored pin that does not decode.
    pub fn answer_machine_history_freshness(
        &self,
        challenge: &MachineHistoryFreshnessChallenge,
        issuer: &crate::authority::HostSlipIssuer,
    ) -> Result<Option<MachineHistoryFreshnessResponse>> {
        let signer = issuer.public_key();
        let txn = self.store.env.read_txn()?;
        let (vault_id, authority_head) = match crate::authority::machine_history_host_context(
            &self.store,
            self.privacy_posture(),
            &txn,
            &signer,
        ) {
            Ok(context) => context,
            Err(Error::Claim(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        if challenge.vault_id != vault_id {
            return Ok(None);
        }
        let Some(raw) = self
            .store
            .vault_meta
            .get(&txn, &pin_key(challenge.target))?
        else {
            return Ok(None);
        };
        let pin = ClaimHistoryHandoff::decode(&raw).map_err(|_| invalid())?;
        let tip = pin.content_hash().map_err(|_| invalid())?;
        drop(txn);
        let mut response = MachineHistoryFreshnessResponse {
            challenge: *challenge,
            tip,
            heads: pin.heads,
            authority_head,
            signer,
            signature: [0; 64],
        };
        let Some(transcript) = response.transcript() else {
            return Ok(None);
        };
        response.signature = issuer.sign_claim_handoff(&transcript);
        Ok(Some(response))
    }

    /// Accepts the home's `response` to this device's outstanding challenge
    /// and returns the pin's freshness now. `None` when it is not accepted:
    /// it names no outstanding, unexpired challenge of this device's, its
    /// signature does not verify, or its signer fails the own-receive pin's
    /// signer rule (module doc). A response not accepted spends nothing.
    ///
    /// # Errors
    ///
    /// Storage errors, and a stored pin that does not decode.
    pub fn accept_machine_history_freshness(
        &self,
        response: &MachineHistoryFreshnessResponse,
    ) -> Result<Option<MachineHistoryPinFreshness>> {
        let challenge = response.challenge;
        let slot = &self.store.machine_history_runtime.freshness;
        let issued_at = match ledger(slot).challenges.get(&challenge.target) {
            Some(outstanding)
                if outstanding.challenge == challenge
                    && outstanding.issued.elapsed()
                        <= MACHINE_HISTORY_FRESHNESS_CHALLENGE_LIFETIME =>
            {
                outstanding.issued_at
            }
            _ => return Ok(None),
        };
        let Some(transcript) = response.transcript() else {
            return Ok(None);
        };
        let signature = AuthoritySignature {
            suite: response.signer.suite(),
            public_key: response.signer.clone(),
            signature: response.signature.to_vec(),
        };
        if !verify_authority_signature(&signature, &transcript) {
            return Ok(None);
        }
        let txn = self.store.env.read_txn()?;
        if crate::identity::read_machine_id_in_txn(self, &txn)? != Some(challenge.machine) {
            return Ok(None);
        }
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        if fold.vault_id != Some(challenge.vault_id)
            || !fold.valid_entries.contains(&response.authority_head)
            || !fold
                .roster
                .get(&response.signer)
                .is_some_and(|root| !root.revoked && root.roles & ROLE_OWNER != 0)
        {
            return Ok(None);
        }
        let (host_vault, current_head) = match crate::authority::machine_history_host_context(
            &self.store,
            self.privacy_posture(),
            &txn,
            &response.signer,
        ) {
            Ok(context) => context,
            Err(Error::Claim(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        if host_vault != challenge.vault_id
            || (response.authority_head != current_head
                && !crate::authority::machine_history_authority_descends(
                    &self.store,
                    &txn,
                    &response.authority_head,
                    &current_head,
                )?)
        {
            return Ok(None);
        }
        let held = self.pinned_handoff_hash(&txn, challenge.target)?;
        drop(txn);
        let proof = Proof {
            home_tip: response.tip,
            challenged_at: issued_at,
            answered_at: self.store.clock.now_recorded_at(),
        };
        let mut book = ledger(slot);
        // The challenge answers once: it is spent here, if still the same.
        if book
            .challenges
            .get(&challenge.target)
            .is_none_or(|outstanding| outstanding.challenge != challenge)
        {
            return Ok(None);
        }
        book.challenges.remove(&challenge.target);
        book.proofs.insert(challenge.target, proof);
        Ok(Some(freshness_of(held, Some(proof))))
    }

    /// What this device can say of `target`'s pin freshness: the last
    /// accepted home answer, read against the handoff pinned now.
    ///
    /// # Errors
    ///
    /// Storage errors, and a stored pin that does not decode.
    pub fn machine_history_pin_freshness(
        &self,
        target: EntityId,
    ) -> Result<MachineHistoryPinFreshness> {
        let txn = self.store.env.read_txn()?;
        let held = self.pinned_handoff_hash(&txn, target)?;
        drop(txn);
        let proof = ledger(&self.store.machine_history_runtime.freshness)
            .proofs
            .get(&target)
            .copied();
        Ok(freshness_of(held, proof))
    }
}
