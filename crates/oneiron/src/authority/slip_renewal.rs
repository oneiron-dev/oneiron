//! FIX 3377: a paired owner device renews its own credential (Engine ruling
//! rec a, 10-18; CALLS row "FIX 3377 device owner-credential renewal").
//!
//! The host mints a fresh parentless slip carrying the logged original's
//! claims and binding key; only the slip id, `issued_at`, `expires_at` and
//! `ttl_secs` change. It is no attenuation (it extends time, so it is never a
//! child of the old slip), but its logged mint names the slip it renews
//! (FIX 5481), so the credential lineage a proposal freezes follows it. It is
//! no new enrolment, key or grant: the authority is the pairing's own, held
//! by a device that proves on one request both its holder key and its
//! enrolled machine's install key. The old slip is not
//! revoked. It runs out on its own, so a lost reply leaves the device the old
//! credential to retry with. An expired or revoked slip refuses, with no
//! grace: that device pairs again.
//!
//! Two policy hooks carry the ruling: [`renewal_refusal`] says which
//! credentials renew, and [`renewal_ttl_secs`] how long a replacement lives.
//! Each refusal names its reason (mesh PR2-renewal, PR2-reasons); none echoes
//! a token or key. There is no delegated renewal: an agent's, a support
//! slip's or an attenuated credential's renewal is a fresh owner mint (K04).

use ed25519_dalek::{Signature, VerifyingKey};

use super::slip_vault::{random_slip_id, require_host};
use super::*;
use crate::error::Result;
use crate::federation::Scope;
use crate::{EntityId, Vault};

/// K04, authority: the credential is not a live owner's own unattenuated,
/// parentless human device credential. Each `RENEWAL_*` reason is public so
/// a transport can name its refusal (FIX 4651).
pub const RENEWAL_K04: &str = "only a live owner's unattenuated parentless human device credential may renew; agent, \
     support and attenuated credentials require a fresh owner mint";
/// Authority and key possession: the holder's own-device Grant does not
/// stand, or no enrolled machine of the holder's proved this request.
pub const RENEWAL_GRANT_AND_DEVICE: &str = "renewal requires this owner's live own-device Grant \
                                            and the enrolled device's proof for the original \
                                            credential";
/// Integrity: the presented credential is not the admitted, live, logged one,
/// or its holder proof is stale or was not admitted once for its key.
pub const RENEWAL_PROOF_NOT_FRESH: &str =
    "renewal proof is not fresh or admitted for this credential";
/// The lifetime bound: positive, and never past the original paired duration
/// or the owner's current ceiling.
pub const RENEWAL_LIFETIME: &str = "renewal lifetime must be positive and cannot exceed the \
                                    original paired duration or the current owner ceiling";

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

/// Policy hook (FIX 3377, Engine ruling rec a): who may renew, as the reason
/// a request may not, or `None` when it may. An unattenuated, parentless,
/// owner-grade human slip with no org or invitation, held by a live owner
/// (else [`RENEWAL_K04`]), naming their own-device grant that still stands,
/// on a request a live machine signed whose accepted profile the holder owns
/// with an `Owned(..)` answer, yours, work/school and rented alike (else
/// [`RENEWAL_GRANT_AND_DEVICE`]). An agent's, a host root's, a hosted or
/// execution node's and a removed machine's request never renews: a hosted
/// or execution node's profile is no human renewal credential.
fn renewal_refusal(facts: &RenewalFacts<'_>) -> Option<&'static str> {
    let slip = facts.original;
    let human_owner_device = facts.unattenuated
        && slip.parent_id.is_none()
        && slip.scope == Scope::top()
        && slip.records.is_empty()
        && slip.channels.is_empty()
        && !slip.single_use
        && slip.org_ref.is_none()
        && slip.invitation_ref.is_none()
        // A support slip (OF-606) never renews: more time is a fresh owner mint.
        && slip.delegation.is_none()
        && slip.actor_class.as_deref() == Some(ACTOR_CLASS_HUMAN)
        && facts.holder_is_live_owner;
    if !human_owner_device {
        return Some(RENEWAL_K04);
    }
    let enrolled = facts.own_device_grant_stands
        && facts.machine.is_some_and(|profile| {
            facts.holder == Some(profile.owner) && matches!(profile.role, MachineRole::Owned(_))
        });
    (!enrolled).then_some(RENEWAL_GRANT_AND_DEVICE)
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
pub(super) fn accepted_machine_profile(
    fold: &AuthorityFold,
    machine: EntityId,
) -> Option<&MachineProfile> {
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
    /// and [`renewal_refusal`] finds none. `requested_secs` can only shorten
    /// the lifetime; zero refuses. The old slip is left to run out. Each
    /// refusal is a typed `AuthorityRefused` naming its reason.
    pub fn renew_owner_device_slip(
        &self,
        issuer: &HostSlipIssuer,
        current: &VerifiedSlip,
        device: &OwnerDeviceRenewalProof,
        requested_secs: Option<u64>,
    ) -> Result<CapabilitySlip> {
        // The lifetime bound: a zero request asks for no credential.
        if requested_secs == Some(0) {
            return Err(authority_refused(RENEWAL_LIFETIME));
        }
        let mut txn = self.store.env.write_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        require_host(&fold, issuer)?;
        let now = self.instant_in_txn(&txn)?.secs();
        // Integrity: the token the machine signed is the slip the transport
        // admitted, as the host minted it, and still live in this snapshot
        // (an expired or revoked slip refuses, with no grace).
        let not_fresh = || authority_refused(RENEWAL_PROOF_NOT_FRESH);
        let presented = CapabilitySlip::from_token(&device.token)
            .map_err(authority_refusal_as(RENEWAL_PROOF_NOT_FRESH))?;
        let mint = fold
            .slips
            .mints
            .get(&presented.claims.slip_id)
            .ok_or_else(not_fresh)?;
        let rechecked = presented
            .verify_authority(&mint.signer, &fold, now)
            .map_err(authority_refusal_as(RENEWAL_PROOF_NOT_FRESH))?;
        self.require_live_slip_refs_in_txn(&txn, rechecked.claims(), now)
            .map_err(authority_refusal_as(RENEWAL_PROOF_NOT_FRESH))?;
        if current.claims().slip_id != presented.claims.slip_id
            || current.claims().vault_id != mint.action.claims.vault_id
        {
            return Err(not_fresh());
        }
        let original = mint.action.claims.clone();
        // Integrity (replay and freshness): the machine proof rides this exact
        // request; its holder proof is fresh and was admitted, once, for this
        // slip's key.
        super::slip_replay::request_challenge(
            device.timestamp,
            device.nonce.as_bytes(),
            super::slip_replay::request_now_in_txn(self, &txn)?,
        )
        .map_err(authority_refusal_as(RENEWAL_PROOF_NOT_FRESH))?;
        if !super::slip_replay::nonce_admitted_in_txn(
            self,
            &txn,
            &original.binding_key,
            device.nonce.as_bytes(),
            device.timestamp,
        )? {
            return Err(not_fresh());
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
        let own_device_grant = match original.grant_ref.as_deref().map(EntityId::from_hex) {
            Some(Ok(grant)) => self
                .own_device_grant_stands_in_txn(&txn, grant, &original.holder_ref, now)?
                .then_some(grant),
            // FIX 3393: a device paired before its holder became an Owner
            // names no grant; it renews under the holder's own-device grant.
            None if holder_is_live_owner => match holder {
                Some(holder) => self.own_device_grant_in_txn(&txn, holder, now)?,
                None => None,
            },
            _ => None,
        };
        let own_device_grant_stands = own_device_grant.is_some();
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
        // K04 (authority) or the own-device Grant and enrolled machine
        // (authority, key possession): the policy hook names which.
        if let Some(reason) = renewal_refusal(&facts) {
            return Err(authority_refused(reason));
        }
        let ceiling = crate::gate::resolve_credential_lifetimes(&self.store, &txn)?;
        let ttl_secs = renewal_ttl_secs(
            original.ttl_secs,
            ceiling.initial_owner_secs,
            requested_secs,
        );
        // The lifetime bound: a positive lifetime within the original paired
        // duration and the owner's current ceiling.
        let lifetime = || authority_refused(RENEWAL_LIFETIME);
        if ttl_secs == 0 {
            return Err(lifetime());
        }
        // FIX 5481: the mint names the slip it renews, so the replacement
        // stays in the original's lineage; still parentless, it narrows
        // nothing and no revocation of the old slip reaches it.
        let renews = Some(original.slip_id);
        let claims = SlipClaims {
            slip_id: random_slip_id(),
            parent_id: None,
            issued_at: now,
            expires_at: now.checked_add(ttl_secs).ok_or_else(lifetime)?,
            ttl_secs,
            single_use: false,
            grant_ref: original
                .grant_ref
                .clone()
                .or_else(|| own_device_grant.map(|grant| grant.to_hex())),
            ..original
        };
        let slip =
            self.mint_slip_action_in_txn(&mut txn, issuer, SlipMintAction { claims, renews })?;
        txn.commit()?;
        Ok(slip)
    }
}
