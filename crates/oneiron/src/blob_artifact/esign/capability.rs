//! Session-less, high-entropy capabilities. Only SHA-256 digests persist here.
use super::{ledger::state_in, model::*, principals::verify_owner};
use crate::consent::AuthenticatedOwner;
use crate::{EntityId, Result, Vault};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
const TOKENS: &[u8] = b"esign.capability.v1/";
const RECIPIENT: &[u8] = b"esign.recipient_capability.v1/";

/// Intentionally not serializable and always redacted in Debug. The delivery
/// adapter may expose the raw value once, then retain it in its secret custody.
pub struct EsignCapability(String);
impl std::fmt::Debug for EsignCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EsignCapability([redacted])")
    }
}
impl EsignCapability {
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.len() != 64
            || !raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("invalid capability"));
        }
        Ok(Self(raw.into()))
    }
    pub fn expose_for_delivery(&self) -> &str {
        &self.0
    }
    fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_bytes()).into()
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CapabilityBinding {
    pub(super) document: String,
    pub(super) recipient: String,
    pub(super) hard_expires_at: u64,
    pub(super) revoked_at: Option<u64>,
}
pub(super) fn binding(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    token: &EsignCapability,
) -> Result<CapabilityBinding> {
    let key = [TOKENS, token.digest().as_slice()].concat();
    let raw = vault
        .store
        .vault_meta
        .get(txn, &key)?
        .ok_or_else(|| invalid("invalid capability"))?;
    serde_json::from_slice(&raw).map_err(|_| invalid("capability record"))
}
pub(super) fn require_recipient_capabilities(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    document: EntityId,
    state: &EsignState,
    now: u64,
) -> Result<()> {
    for recipient in &state.document.recipients {
        let key = [RECIPIENT, document.as_bytes(), recipient.id.as_bytes()].concat();
        let digest = vault
            .store
            .vault_meta
            .get(txn, &key)?
            .ok_or_else(|| invalid("mint recipient capabilities before send"))?;
        let raw = vault
            .store
            .vault_meta
            .get(txn, &[TOKENS, digest.as_ref()].concat())?
            .ok_or_else(|| invalid("missing recipient capability"))?;
        let cap: CapabilityBinding =
            serde_json::from_slice(&raw).map_err(|_| invalid("capability record"))?;
        if cap.document != document.to_hex()
            || cap.recipient != recipient.id
            || cap.revoked_at.is_some()
            || now >= cap.hard_expires_at
            || cap.hard_expires_at < state.document.expires_at
        {
            return Err(invalid("recipient capability is unavailable"));
        }
    }
    Ok(())
}

impl Vault {
    /// Mint missing recipients in DRAFT. Existing tokens are never rotated or
    /// returned again. An unchanged draft returns an empty list; re-sends reuse
    /// tokens held by the secret-aware delivery adapter.
    /// The caller passes raw tokens only to its secret-aware delivery adapter.
    pub fn issue_esign_capabilities(
        &self,
        owner: &AuthenticatedOwner,
        document: EntityId,
    ) -> Result<Vec<(String, EsignCapability)>> {
        self.with_write_txn(|txn| {
            verify_owner(self, txn, owner)?;
            let state = state_in(self, txn, document)?;
            if state.status != DocumentStatus::Draft {
                return Err(invalid("tokens are minted before send"));
            }
            let mut issued = Vec::new();
            for recipient in &state.document.recipients {
                let recipient_key =
                    [RECIPIENT, document.as_bytes(), recipient.id.as_bytes()].concat();
                if self.store.vault_meta.get(txn, &recipient_key)?.is_some() {
                    continue;
                }
                let mut entropy = [0u8; 32];
                OsRng
                    .try_fill_bytes(&mut entropy)
                    .map_err(|_| invalid("capability entropy unavailable"))?;
                let raw = crate::entity_id::bytes_to_hex_lower(&entropy);
                let token = EsignCapability(raw);
                let digest = token.digest();
                let key = [TOKENS, digest.as_slice()].concat();
                if self.store.vault_meta.get(txn, &key)?.is_some() {
                    return Err(invalid("capability collision"));
                }
                let row = CapabilityBinding {
                    document: document.to_hex(),
                    recipient: recipient.id.clone(),
                    hard_expires_at: state.document.expires_at,
                    revoked_at: None,
                };
                self.store.vault_meta.put(
                    txn,
                    &key,
                    &serde_json::to_vec(&row).map_err(|_| invalid("capability encoding"))?,
                )?;
                self.store.vault_meta.put(txn, &recipient_key, &digest)?;
                issued.push((recipient.id.clone(), token));
            }
            Ok(issued)
        })
    }
    pub fn revoke_esign_capability(
        &self,
        owner: &AuthenticatedOwner,
        token: &EsignCapability,
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            verify_owner(self, txn, owner)?;
            let mut row = binding(self, txn, token)?;
            row.revoked_at = Some(crate::unix_seconds_now());
            self.store.vault_meta.put(
                txn,
                &[TOKENS, token.digest().as_slice()].concat(),
                &serde_json::to_vec(&row).map_err(|_| invalid("capability encoding"))?,
            )?;
            Ok(())
        })
    }
}
