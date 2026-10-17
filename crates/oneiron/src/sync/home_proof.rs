//! OF-534 G6/G7: the home names itself to the device that dials it.
//!
//! A device names its machine on each sync upgrade (`x-oneiron-machine`), so
//! the home judges what it sends for that machine. The home answers the
//! upgrade with its own proof in the same way: its install key's signature
//! over the request's own slip proof (token, timestamp, nonce), under a
//! domain of its own, so a device's request proof is never read back as the
//! home's. The device then judges what it sends the home for the machine the
//! home proved: a "my machines" world reaches a home that is one of the
//! owner's machines, and a home that proves nothing stays an unknown
//! destination.

use ed25519_dalek::{Signature, Signer, VerifyingKey};

use crate::Vault;
use crate::authority::PeerMachine;
use crate::entity_id::EntityId;
use crate::error::Result;

const HOME_CONNECTION_DOMAIN: &[u8] = b"oneiron/home-proof/v1\0";
/// The upgrade response header a home names itself in.
pub const HOME_PROOF_HEADER: &str = "x-oneiron-home-machine";

/// The bytes a home signs to answer one upgrade: the request's slip proof,
/// under the home's own domain.
fn home_connection_transcript(
    vault_id: &[u8; 32],
    machine: EntityId,
    token: &str,
    timestamp: u64,
    nonce: &str,
) -> Vec<u8> {
    let mut bytes = HOME_CONNECTION_DOMAIN.to_vec();
    bytes.extend_from_slice(vault_id);
    bytes.extend_from_slice(machine.as_bytes());
    bytes.extend_from_slice(blake3::hash(token.as_bytes()).as_bytes());
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(nonce.as_bytes());
    bytes
}

/// One upgrade's slip proof, kept by the device that signed it: the home's
/// answer must bind exactly this, never a tuple the answer supplies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::sync) struct UpgradeBinding {
    pub(in crate::sync) token: String,
    pub(in crate::sync) timestamp: u64,
    pub(in crate::sync) nonce: String,
}

impl Vault {
    /// The home half: this install's [`HOME_PROOF_HEADER`] value answering
    /// one upgrade whose slip proof is (`token`, `timestamp`, `nonce`), or
    /// `None` when it is not a machine of this vault yet.
    pub fn home_connection_proof(
        &self,
        token: &str,
        timestamp: u64,
        nonce: &str,
    ) -> Result<Option<String>> {
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
        let transcript = home_connection_transcript(&vault_id, machine, token, timestamp, nonce);
        let signature = key.sign(&transcript).to_bytes();
        Ok(Some(crate::authority::machine_proof_header_value(
            machine, &signature,
        )))
    }

    /// The device half: the machine a home's answer proves for `binding`,
    /// under the key that machine stands on here. Anything that does not
    /// verify is `Unknown`, never an error. A key only an untrusted chain
    /// names never proves it.
    fn verify_home_connection_proof(
        &self,
        machine: EntityId,
        signature: &[u8; 64],
        binding: &UpgradeBinding,
    ) -> Result<PeerMachine> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let (Some(vault_id), Some(machine_key)) = (fold.vault_id, fold.machine_proof_key(machine))
        else {
            return Ok(PeerMachine::Unknown);
        };
        let Ok(key) = VerifyingKey::from_bytes(&machine_key) else {
            return Ok(PeerMachine::Unknown);
        };
        let transcript = home_connection_transcript(
            &vault_id,
            machine,
            &binding.token,
            binding.timestamp,
            &binding.nonce,
        );
        Ok(
            if key
                .verify_strict(&transcript, &Signature::from_bytes(signature))
                .is_ok()
            {
                PeerMachine::Proven {
                    machine,
                    key: machine_key,
                }
            } else {
                PeerMachine::Unknown
            },
        )
    }
}

/// The home an upgrade response's `headers` prove for the upgrade the device
/// signed as `binding`, or `Unknown`: no binding, no header, a malformed one,
/// or one that does not verify here.
pub(in crate::sync) fn home_peer(
    vault: &Vault,
    headers: &tokio_tungstenite::tungstenite::http::HeaderMap,
    binding: Option<&UpgradeBinding>,
) -> PeerMachine {
    let Some(binding) = binding else {
        return PeerMachine::Unknown;
    };
    let Some(claim) = headers
        .get(HOME_PROOF_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
    else {
        return PeerMachine::Unknown;
    };
    let machine = claim
        .get("machine")
        .and_then(serde_json::Value::as_str)
        .and_then(|hex| EntityId::from_hex(hex).ok());
    let signature = claim
        .get("signature")
        .and_then(serde_json::Value::as_str)
        .and_then(parse_signature);
    let (Some(machine), Some(signature)) = (machine, signature) else {
        return PeerMachine::Unknown;
    };
    vault
        .verify_home_connection_proof(machine, &signature, binding)
        .unwrap_or(PeerMachine::Unknown)
}

/// An Ed25519 signature as 128 lowercase hex.
fn parse_signature(hex: &str) -> Option<[u8; 64]> {
    if hex.len() != 128
        || !hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let mut out = [0u8; 64];
    for (slot, pair) in out.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}
