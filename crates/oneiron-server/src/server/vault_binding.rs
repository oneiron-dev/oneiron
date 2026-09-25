//! Hosted API and socket binding to one local vault and one registered device key.
use crate::{error::ApiError, server::SyncServer};
use axum::http::HeaderMap;
use oneiron::sync::lease::{require_vault_lease, verify_lease_pop};
#[derive(Clone, Debug)]
pub(crate) struct VaultBinding {
    pub vault_id: u64,
    pub client_id: u64,
    pub pubkey: [u8; 32],
}
impl VaultBinding {
    pub(crate) fn live(&self, vault: &oneiron::Vault) -> bool {
        require_vault_lease(vault, self.vault_id, self.client_id, &self.pubkey).is_ok()
    }
}
pub(crate) fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut bytes = [0; N];
    for (dest, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let text = std::str::from_utf8(pair).ok()?;
        *dest = u8::from_str_radix(text, 16).ok()?;
    }
    Some(bytes)
}
impl SyncServer {
    pub(crate) fn require_vault_binding(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<VaultBinding>, ApiError> {
        if self.config.lease_vault_id == 0 {
            return Ok(None);
        }
        let parse = || -> Option<VaultBinding> {
            let value = |name| headers.get(name)?.to_str().ok();
            let vault_id = u64::from_be_bytes(decode_hex(value("x-oneiron-vault")?)?);
            let client_id = u64::from_be_bytes(decode_hex(value("x-oneiron-client")?)?);
            let pubkey = decode_hex(value("x-oneiron-key")?)?;
            let signature = decode_hex(value("x-oneiron-proof")?)?;
            if vault_id != self.config.lease_vault_id
                || !verify_lease_pop(client_id, &pubkey, &signature)
            {
                return None;
            }
            Some(VaultBinding {
                vault_id,
                client_id,
                pubkey,
            })
        };
        let binding = parse().ok_or_else(ApiError::unauthorized)?;
        if !binding.live(self.vault()) {
            return Err(ApiError::unauthorized());
        }
        Ok(Some(binding))
    }
}
