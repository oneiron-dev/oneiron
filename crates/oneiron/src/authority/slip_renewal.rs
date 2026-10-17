//! FIX 3377: a paired owner device renews its own credential (Engine ruling
//! rec a, 10-18; CALLS row "FIX 3377 device owner-credential renewal").
//!
//! The host mints a fresh parentless slip carrying the logged original's
//! claims and binding key; only the slip id, `issued_at`, `expires_at` and
//! `ttl_secs` change. It is no attenuation (it extends time, so it is never a
//! child of the old slip), no new enrolment, key or grant: the authority is
//! the pairing's own, held by a device that proves on one request both its
//! holder key and its enrolled machine's install key. The old slip is not
//! revoked. It runs out on its own, so a lost reply leaves the device the old
//! credential to retry with. An expired or revoked slip refuses, with no
//! grace: that device pairs again.
//!
//! Two policy hooks carry the ruling: [`renewal_eligible`] says which
//! credentials renew, and [`renewal_ttl_secs`] how long a replacement lives.

use ed25519_dalek::{Signature, VerifyingKey};

use super::slip_vault::{random_slip_id, require_host};
use super::*;
use crate::error::Result;
use crate::federation::Scope;
use crate::{EntityId, Vault};

/// The machine half of one renewal request: the slip token it presented,
/// the timestamp and nonce of the holder proof it rode
/// (`x-oneiron-binding`), and the machine and its install key's signature
/// over [`machine_connection_transcript`] for those exact values
/// ([`MACHINE_PROOF_HEADER`]). The existing machine-proof wire, carried
/// whole for the renewal writer to verify; not a credential of its own.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnerDeviceRenewalProof {
    pub token: String,
    pub timestamp: u64,
    pub nonce: String,
    pub machine: EntityId,
    pub signature: [u8; 64],
}

/// Hand-written so the token cannot reach a log through a derive.
impl std::fmt::Debug for OwnerDeviceRenewalProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerDeviceRenewalProof")
            .field("timestamp", &self.timestamp)
            .field("machine", &self.machine)
            .finish_non_exhaustive()
    }
}

/// What the renewal writer found for one request, in its own snapshot.
struct RenewalFacts<'a> {
    /// The logged mint's claims: what the host signed, never the verifier's
    /// view, whose TTL is already clipped to the time left.
    original: &'a SlipClaims,
    /// No caveat narrowed the presented slip or moved it to another key.
    unattenuated: bool,
    /// The holder, when `holder_ref` is a canonical PERSON id.
    holder: Option<EntityId>,
    /// The holder is a live PERSON who owns this vault now.
    holder_is_live_owner: bool,
    /// The slip's `grant_ref` is the holder's own-device grant, live and
    /// conferring now. Never created or revived here.
    own_device_grant_stands: bool,
    /// The accepted profile of the machine that signed this request's
    /// machine proof, as it stands here now; `None` when none did.
    machine: Option<&'a MachineProfile>,
}

/// Policy hook (FIX 3377, Engine ruling rec a): who may renew. An
/// unattenuated, parentless, owner-grade human slip with no org or
/// invitation, held by a live owner, naming their own-device grant that
/// still stands, on a request a live machine signed whose accepted profile
/// the holder owns with an `Owned(..)` answer (yours, work/school and rented
/// alike). An agent's, a host root's, a hosted or execution node's and a
/// removed machine's request never renews.
fn renewal_eligible(facts: &RenewalFacts<'_>) -> bool {
    let slip = facts.original;
    facts.unattenuated
        && slip.parent_id.is_none()
        && slip.scope == Scope::top()
        && slip.records.is_empty()
        && slip.channels.is_empty()
        && !slip.single_use
        && slip.org_ref.is_none()
        && slip.invitation_ref.is_none()
        && slip.actor_class.as_deref() == Some(ACTOR_CLASS_HUMAN)
        && facts.holder_is_live_owner
        && facts.own_device_grant_stands
        && facts.machine.is_some_and(|profile| {
            facts.holder == Some(profile.owner) && matches!(profile.role, MachineRole::Owned(_))
        })
}

/// Policy hook (FIX 3377, Engine ruling rec a): the replacement's lifetime.
/// The least of the original's logged `ttl_secs` (the duration it was minted
/// for, not what remains of it), the vault's `initial_owner_secs` ceiling now,
/// and the caller's optional request. A renewal never outlasts the duration
/// the device was first paired for.
fn renewal_ttl_secs(
    original_ttl_secs: u64,
    initial_owner_secs: u64,
    requested: Option<u64>,
) -> u64 {
    original_ttl_secs
        .min(initial_owner_secs)
        .min(requested.unwrap_or(u64::MAX))
}

/// The profile a machine stands on here, read as
/// [`AuthorityFold::machine_proof_key`] reads its key: its trusted identity
/// under this install's pin, else its live roster revision. A removed,
/// conflicted, stale or held chain gives none.
fn accepted_machine_profile(fold: &AuthorityFold, machine: EntityId) -> Option<&MachineProfile> {
    match fold.trusted_machine(machine) {
        Some(trusted) => Some(trusted.profile),
        None => fold
            .machine(machine)?
            .roster
            .as_ref()
            .filter(|roster| roster.is_live())
            .map(|roster| &roster.profile),
    }
}

/// The accepted profile of the machine `device` names, when its install key
/// signed this request's token, timestamp and nonce.
fn proving_machine<'f>(
    fold: &'f AuthorityFold,
    device: &OwnerDeviceRenewalProof,
) -> Option<&'f MachineProfile> {
    let vault_id = fold.vault_id?;
    let profile = accepted_machine_profile(fold, device.machine)?;
    let key = VerifyingKey::from_bytes(&profile.machine_key).ok()?;
    let transcript = machine_connection_transcript(
        &vault_id,
        device.machine,
        &device.token,
        device.timestamp,
        &device.nonce,
    );
    key.verify_strict(&transcript, &Signature::from_bytes(&device.signature))
        .ok()?;
    Some(profile)
}

impl Vault {
    /// Renews the credential of a paired owner device (FIX 3377): mints,
    /// under `issuer`, a fresh parentless slip with `current`'s logged claims
    /// and binding key, living [`renewal_ttl_secs`]. `current` is the slip
    /// this request's transport admitted; `device` is that request's machine
    /// proof, mandatory. In one writer: the presented token is `current`,
    /// verified again against its logged mint (live, unexpired on the
    /// authority clock, its grant and invitation references standing); the
    /// request's holder proof is fresh and was admitted for the slip's key;
    /// the machine proof verifies under a live machine's accepted profile;
    /// and [`renewal_eligible`] holds. `requested_secs` can only shorten the
    /// lifetime; zero refuses. The old slip is left to run out.
    pub fn renew_owner_device_slip(
        &self,
        issuer: &HostSlipIssuer,
        current: &VerifiedSlip,
        device: &OwnerDeviceRenewalProof,
        requested_secs: Option<u64>,
    ) -> Result<CapabilitySlip> {
        if requested_secs == Some(0) {
            return Err(invalid_authority());
        }
        let mut txn = self.store.env.write_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        require_host(&fold, issuer)?;
        let now = self.instant_in_txn(&txn)?.secs();
        // The token the machine signed is the slip the transport admitted,
        // as the host minted it, and still live in this snapshot.
        let presented = CapabilitySlip::from_token(&device.token)?;
        let mint = fold
            .slips
            .mints
            .get(&presented.claims.slip_id)
            .ok_or_else(invalid_authority)?;
        let rechecked = presented.verify_authority(&mint.signer, &fold, now)?;
        self.require_live_slip_refs_in_txn(&txn, rechecked.claims(), now)?;
        if current.claims().slip_id != presented.claims.slip_id
            || current.claims().vault_id != mint.action.claims.vault_id
        {
            return Err(invalid_authority());
        }
        let original = mint.action.claims.clone();
        // The machine proof rides this exact request: its holder proof is
        // fresh and was admitted, once, for this slip's key.
        super::slip_replay::request_challenge(
            device.timestamp,
            device.nonce.as_bytes(),
            super::slip_replay::request_now_in_txn(self, &txn)?,
        )?;
        if !super::slip_replay::nonce_admitted_in_txn(
            self,
            &txn,
            &original.binding_key,
            device.nonce.as_bytes(),
            device.timestamp,
        )? {
            return Err(invalid_authority());
        }
        let holder = EntityId::from_hex(&original.holder_ref)
            .ok()
            .filter(|holder| holder.to_hex() == original.holder_ref);
        let holder_is_live_owner = match holder {
            Some(holder) => {
                crate::consent::person_is_live_in_txn(self, &txn, &holder)?
                    && crate::policy_model::is_live_vault_owner_in_txn(self, &txn, &holder)?
            }
            None => false,
        };
        let own_device_grant_stands = match original.grant_ref.as_deref().map(EntityId::from_hex) {
            Some(Ok(grant)) => {
                self.own_device_grant_stands_in_txn(&txn, grant, &original.holder_ref, now)?
            }
            _ => false,
        };
        let facts = RenewalFacts {
            original: &original,
            unattenuated: presented.caveats.is_empty()
                && current.is_unattenuated()
                && !current.is_transferred(),
            holder,
            holder_is_live_owner,
            own_device_grant_stands,
            machine: proving_machine(&fold, device),
        };
        if !renewal_eligible(&facts) {
            return Err(invalid_authority());
        }
        let ceiling = crate::gate::resolve_credential_lifetimes(&self.store, &txn)?;
        let ttl_secs = renewal_ttl_secs(
            original.ttl_secs,
            ceiling.initial_owner_secs,
            requested_secs,
        );
        if ttl_secs == 0 {
            return Err(invalid_authority());
        }
        let claims = SlipClaims {
            slip_id: random_slip_id(),
            parent_id: None,
            issued_at: now,
            expires_at: now.checked_add(ttl_secs).ok_or_else(invalid_authority)?,
            ttl_secs,
            single_use: false,
            ..original
        };
        let slip = self.mint_slip_in_txn(&mut txn, issuer, claims)?;
        txn.commit()?;
        Ok(slip)
    }
}
