//! FIX 2907: a caller's request, forwarded by its device to the home
//! (Engine ruling 10-18, CALLS row "FIX 2907 caller-scoped home search
//! contract").
//!
//! The device never holds its caller's key, so it forwards the caller's own
//! holder proof: the slip token and the timestamp, nonce and signature the
//! caller sent the device (`x-oneiron-binding`). The device admitted that
//! proof and spent its nonce; it adds its install key's signature over the
//! forwarded request and that proof ([`forwarded_request_transcript`]). The
//! home verifies both halves ([`Vault::verify_forwarded_caller`]): the
//! signing machine is an `Owned` machine of a live owner whose own-device
//! grant stands and names the device's selector, and the caller's slip is
//! logged, live and unrevoked, its holder proof inside the freshness
//! window. The home does not spend the nonce again. It then reads under the
//! caller's own read key, and the device's selector stays the second
//! ceiling every hit must pass.

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::*;
use crate::claim::ScopedReadActorKey;
use crate::error::Result;
use crate::{EntityId, Vault};

const FORWARDED_REQUEST_DOMAIN: &[u8] = b"oneiron/forwarded-request/v1\0";

/// A caller's own holder proof, as its device forwards it: the slip token it
/// presented and the fields of the `x-oneiron-binding` header it signed,
/// unchanged. Not a credential of its own: the home verifies it again.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardedCallerProof {
    /// The caller's `v2.slip.` token.
    pub token: String,
    /// The holder proof's signed timestamp.
    pub timestamp: u64,
    /// The holder proof's nonce: 32 lowercase hex characters.
    pub nonce: String,
    /// The holder's Ed25519 signature, 128 lowercase hex characters.
    pub signature: String,
}

/// Hand-written so the token cannot reach a log through a derive.
impl std::fmt::Debug for ForwardedCallerProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForwardedCallerProof")
            .field("timestamp", &self.timestamp)
            .finish_non_exhaustive()
    }
}

/// The forwarding device's machine and its install key's signature over
/// [`forwarded_request_transcript`], in the [`MACHINE_PROOF_HEADER`] value's
/// encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardingMachineProof {
    /// The MACHINE id, canonical hex.
    pub machine: String,
    /// 128 lowercase hex characters.
    pub signature: String,
}

/// The request a device forwards: the RPC and its fields, in the order the
/// RPC defines, as the device sends them. The device signs exactly these, so
/// the home judges the caller for this request alone.
#[derive(Debug, Clone, Copy)]
pub struct ForwardedRequest<'a> {
    /// The RPC, e.g. `residence.search`.
    pub method: &'a str,
    pub fields: &'a [&'a [u8]],
}

/// The device the home received a forwarded request from.
#[derive(Debug, Clone, Copy)]
pub struct ForwardingDevice<'a> {
    /// The member the device's sync selector names: its paired owner.
    pub member_ref: &'a str,
    /// The device selector's grant: that owner's own-device grant.
    pub grant: EntityId,
    /// The machine the carrying connection proved, if any. A forwarding
    /// proof from another machine refuses.
    pub connection: PeerMachine,
}

/// A forwarded caller the home verified: what it may read under. It is
/// only the caller's authority; the device's selector stays a second
/// ceiling the reader applies to every hit.
#[derive(Debug, Clone)]
pub struct VerifiedForwardedCaller {
    caller: VerifiedSlip,
    read_key: ScopedReadActorKey,
    machine: EntityId,
}

impl VerifiedForwardedCaller {
    /// The caller's slip, verified here.
    #[must_use]
    pub const fn caller(&self) -> &VerifiedSlip {
        &self.caller
    }

    /// The caller's own read key ([`Vault::credential_read_key`]).
    #[must_use]
    pub const fn read_key(&self) -> &ScopedReadActorKey {
        &self.read_key
    }

    /// The `Owned` machine that forwarded the request.
    #[must_use]
    pub const fn machine(&self) -> EntityId {
        self.machine
    }
}

/// The bytes a forwarding device's install key signs: the vault, the
/// machine, and one digest over the request and the caller's whole proof,
/// each field length-prefixed.
#[must_use]
pub fn forwarded_request_transcript(
    vault_id: &[u8; 32],
    machine: EntityId,
    request: &ForwardedRequest<'_>,
    caller: &ForwardedCallerProof,
) -> Vec<u8> {
    let timestamp = caller.timestamp.to_be_bytes();
    let fields: Vec<&[u8]> = std::iter::once(request.method.as_bytes())
        .chain(request.fields.iter().copied())
        .chain([
            caller.token.as_bytes(),
            timestamp.as_slice(),
            caller.nonce.as_bytes(),
            caller.signature.as_bytes(),
        ])
        .collect();
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(fields.len() as u64).to_be_bytes());
    for field in fields {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    let mut bytes = FORWARDED_REQUEST_DOMAIN.to_vec();
    bytes.extend_from_slice(vault_id);
    bytes.extend_from_slice(machine.as_bytes());
    bytes.extend_from_slice(hasher.finalize().as_bytes());
    bytes
}

/// Exactly 128 lowercase hex characters, decoded.
fn signature_hex(text: &str) -> Option<[u8; 64]> {
    if text.len() != 128 {
        return None;
    }
    let mut bytes = [0; 64];
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).ok()?;
        if !pair
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return None;
        }
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(bytes)
}

fn signature_hex_string(signature: &[u8; 64]) -> String {
    signature.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Vault {
    /// The device half: this install's forwarding proof for `request`
    /// carrying `caller`, or `None` when it is no machine of this vault yet.
    /// The caller presented `caller` to this install and it was admitted
    /// here; the device signs nothing else.
    pub fn forwarding_machine_proof(
        &self,
        request: &ForwardedRequest<'_>,
        caller: &ForwardedCallerProof,
    ) -> Result<Option<ForwardingMachineProof>> {
        self.load_install_signing_if_minted()?;
        let txn = self.store.env.read_txn()?;
        let Some(machine) = crate::identity::read_machine_id_in_txn(self, &txn)? else {
            return Ok(None);
        };
        let Some(key) = crate::identity::read_machine_signing_key_in_txn(self, &txn)? else {
            return Ok(None);
        };
        let Some(vault_id) = self.authority_view_readonly_in_txn(&txn)?.vault_id else {
            return Ok(None);
        };
        let transcript = forwarded_request_transcript(&vault_id, machine, request, caller);
        Ok(Some(ForwardingMachineProof {
            machine: machine.to_hex(),
            signature: signature_hex_string(&key.sign(&transcript).to_bytes()),
        }))
    }

    /// The home half: verifies a request `device` forwarded for a caller,
    /// in one snapshot. The machine proof must verify under the accepted
    /// profile of an `Owned` machine (the connection's own, when it proved
    /// one) whose owner is a live vault owner, is the device selector's
    /// member, and holds `device.grant` as a standing own-device grant. The
    /// caller's slip must be logged, live and unrevoked, its references
    /// standing, reusable, and its holder proof inside the freshness window;
    /// its nonce is not spent again here. Any refusal is the one
    /// invalid-authority error: the reader omits the home's hits, never
    /// widens to the device's authority.
    pub fn verify_forwarded_caller(
        &self,
        caller: &ForwardedCallerProof,
        machine: &ForwardingMachineProof,
        request: &ForwardedRequest<'_>,
        device: &ForwardingDevice<'_>,
    ) -> Result<VerifiedForwardedCaller> {
        let txn = self.store.env.read_txn()?;
        self.verify_forwarded_caller_in_txn(&txn, caller, machine, request, device)
    }

    /// [`Self::verify_forwarded_caller`] in the caller's snapshot.
    pub(crate) fn verify_forwarded_caller_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        caller: &ForwardedCallerProof,
        machine: &ForwardingMachineProof,
        request: &ForwardedRequest<'_>,
        device: &ForwardingDevice<'_>,
    ) -> Result<VerifiedForwardedCaller> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let now = self.instant_in_txn(txn)?.secs();
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        // The device: an Owned machine signed this exact request and proof.
        let machine_id = EntityId::from_hex(&machine.machine)
            .ok()
            .filter(|id| id.to_hex() == machine.machine)
            .ok_or_else(invalid_authority)?;
        if let PeerMachine::Proven {
            machine: proved, ..
        } = device.connection
            && proved != machine_id
        {
            return Err(invalid_authority());
        }
        let profile = super::slip_renewal::accepted_machine_profile(&fold, machine_id)
            .ok_or_else(invalid_authority)?;
        let signature = signature_hex(&machine.signature).ok_or_else(invalid_authority)?;
        let key =
            VerifyingKey::from_bytes(&profile.machine_key).map_err(|_| invalid_authority())?;
        let transcript = forwarded_request_transcript(&vault_id, machine_id, request, caller);
        key.verify_strict(&transcript, &Signature::from_bytes(&signature))
            .map_err(|_| invalid_authority())?;
        let owner = profile.owner;
        if !matches!(profile.role, MachineRole::Owned(_))
            || device.member_ref != owner.to_hex()
            || !crate::consent::person_is_live_in_txn(self, txn, &owner)?
            || !crate::policy_model::is_live_vault_owner_in_txn(self, txn, &owner)?
            || !self.own_device_grant_stands_in_txn(txn, device.grant, device.member_ref, now)?
        {
            return Err(invalid_authority());
        }
        // The caller: its own logged slip and holder proof, fresh, its nonce
        // already spent on the device that admitted it.
        let slip = CapabilitySlip::from_token(&caller.token)?;
        let challenge = super::slip_replay::request_challenge(
            caller.timestamp,
            caller.nonce.as_bytes(),
            super::slip_replay::request_now_in_txn(self, txn)?,
        )?;
        let holder_signature = signature_hex(&caller.signature).ok_or_else(invalid_authority)?;
        let signer = &fold
            .slips
            .mints
            .get(&slip.claims.slip_id)
            .ok_or_else(invalid_authority)?
            .signer;
        let verified = slip.verify(signer, &fold, now, &challenge, &holder_signature)?;
        self.require_live_slip_refs_in_txn(txn, verified.claims(), now)?;
        if verified.claims().single_use || !self.capability_slip_is_live_in_txn(txn, &verified)? {
            return Err(invalid_authority());
        }
        let read_key = self
            .credential_read_key_in(txn, &verified)?
            .ok_or_else(invalid_authority)?;
        Ok(VerifiedForwardedCaller {
            caller: verified,
            read_key,
            machine: machine_id,
        })
    }
}
