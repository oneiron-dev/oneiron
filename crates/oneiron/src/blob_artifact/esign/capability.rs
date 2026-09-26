//! Session-less, high-entropy capabilities. Only SHA-256 digests persist here.
use super::{ledger::state_in, model::*, principals::verify_owner};
use crate::consent::AuthenticatedOwner;
use crate::side_table::{self, LegacyJson, Raw, SideTable};
use crate::{EntityId, Result, Vault};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Signing capability row. Key: bytes32 (digest).
const TOKENS: SideTable<[u8; 32], CapabilityBinding, LegacyJson> =
    SideTable::new(&side_table::ESIGN_CAPABILITY_TOKEN);
/// Recipient live capability index. Key: id16 (document) + string (recipient id).
const RECIPIENT: SideTable<(EntityId, String), [u8; 32], Raw> =
    SideTable::new(&side_table::ESIGN_RECIPIENT_CAPABILITY_INDEX);

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
    let cap = TOKENS
        .get(&vault.store, txn, &token.digest())?
        .ok_or_else(|| invalid("invalid capability"))?;
    // Event history and sealed artifacts survive erasure, but bearer authority does not.
    let document = EntityId::from_hex(&cap.document)?;
    if vault.get_blob_artifact_in_txn(txn, &document)?.is_none() {
        return Err(invalid("invalid capability"));
    }
    Ok(cap)
}
impl CapabilityBinding {
    fn usable_until(&self, expires_at: u64, now: u64) -> bool {
        self.revoked_at.is_none()
            && now < self.hard_expires_at
            && expires_at <= self.hard_expires_at
    }
}
fn recipient_binding(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    document: EntityId,
    recipient: &str,
) -> Result<Option<([u8; 32], CapabilityBinding)>> {
    let Some(digest) = RECIPIENT.get(&vault.store, txn, &(document, recipient.to_owned()))? else {
        return Ok(None);
    };
    let cap = TOKENS
        .get(&vault.store, txn, &digest)?
        .ok_or_else(|| invalid("missing recipient capability"))?;
    if cap.document != document.to_hex() || cap.recipient != recipient {
        return Err(invalid("recipient capability binding"));
    }
    Ok(Some((digest, cap)))
}
pub(super) fn require_recipient_capabilities(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    document: EntityId,
    state: &EsignState,
    now: u64,
) -> Result<()> {
    for recipient in &state.document.recipients {
        let (_, cap) = recipient_binding(vault, txn, document, &recipient.id)?
            .ok_or_else(|| invalid("mint recipient capabilities before send"))?;
        if !cap.usable_until(state.document.expires_at, now) {
            return Err(invalid("recipient capability is unavailable"));
        }
    }
    Ok(())
}

impl Vault {
    /// Mint missing or unusable recipient capabilities in DRAFT. Live tokens
    /// covering the current deadline are never rotated or returned again.
    /// Replacements revoke the old digest; re-sends reuse tokens held by the
    /// secret-aware delivery adapter.
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
            let now = crate::unix_seconds_now();
            let mut issued = Vec::new();
            for recipient in &state.document.recipients {
                let recipient_key = (document, recipient.id.clone());
                if let Some((digest, mut prior)) =
                    recipient_binding(self, txn, document, &recipient.id)?
                {
                    if prior.usable_until(state.document.expires_at, now) {
                        continue;
                    }
                    prior.revoked_at.get_or_insert(now);
                    TOKENS.put(&self.store, txn, &digest, &prior)?;
                }
                let mut entropy = [0u8; 32];
                OsRng
                    .try_fill_bytes(&mut entropy)
                    .map_err(|_| invalid("capability entropy unavailable"))?;
                let raw = crate::entity_id::bytes_to_hex_lower(&entropy);
                let token = EsignCapability(raw);
                let digest = token.digest();
                if TOKENS.contains(&self.store, txn, &digest)? {
                    return Err(invalid("capability collision"));
                }
                let row = CapabilityBinding {
                    document: document.to_hex(),
                    recipient: recipient.id.clone(),
                    hard_expires_at: state.document.expires_at,
                    revoked_at: None,
                };
                TOKENS.put(&self.store, txn, &digest, &row)?;
                RECIPIENT.put(&self.store, txn, &recipient_key, &digest)?;
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
            TOKENS.put(&self.store, txn, &token.digest(), &row)?;
            Ok(())
        })
    }
}
