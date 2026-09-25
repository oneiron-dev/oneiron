//! Single-use pairing links bind a throwaway key and mint one log-backed slip.
use super::slip_vault::{random_slip_id, require_host};
use super::*;
use crate::Vault;
use crate::error::Result;
use crate::federation::{OrgAdminPolicy, OrgAdminPower, Scope, ScopeAxis};
use crate::side_table::{self, LegacyJson, SideTable};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// One outstanding single-use pairing/enrollment link. Key: hex64 (keyed hash of the code).
const PAIRING_PENDING: SideTable<String, PairingPending, LegacyJson> =
    SideTable::new(&side_table::AUTHORITY_PAIRING_PENDING);
/// Immutable one-time organization-administration power grant. Key: hex32 (org_ref).
const ORG_ADMIN_POLICY: SideTable<String, OrgAdminPolicy, LegacyJson> =
    SideTable::new(&side_table::ORG_ADMIN_POLICY);

/// Pairing descriptor is public liveness, not a credential or authority claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingDescriptor {
    pub protocol: String,
    pub slip_version: u8,
    pub binding: String,
    pub pairing_endpoint: String,
}
impl Default for PairingDescriptor {
    fn default() -> Self {
        Self {
            protocol: "oneiron-pairing".into(),
            slip_version: 2,
            binding: "ed25519".into(),
            pairing_endpoint: "/v1/core/pairing/redeem".into(),
        }
    }
}
/// A link/QR payload. The code is random and stored only as a keyed hash.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingLink {
    pub code: String,
    pub expires_at: u64,
}
/// Owner-approved identity constraints. Redemption can choose a connection key,
/// but cannot replace these claims or add organization authority.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingPrincipal {
    pub holder_ref: Option<String>,
    pub actor_class: Option<String>,
    pub org_ref: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairingPending {
    expires_at: u64,
    slip_lifetime_secs: u64,
    scope: Scope,
    host_key: [u8; 32],
    principal: PairingPrincipal,
}

/// Crockford base32: no `I`, `L`, `O` or `U`, so a code survives being read
/// aloud or typed from a screen.
const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_LEN: usize = 8;
const CODE_TTL_SECS: u64 = 60 * 60;
const CODE_HASH_CONTEXT: &str = "oneiron/pairing-code/v1/hash";

/// The one reader of a typed code: case-blind, with `O`, `I` and `L` read as
/// `0`, `1` and `1`.
fn normalize_code(code: &str) -> Result<String> {
    let normalized: String = code
        .chars()
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            upper => upper,
        })
        .collect();
    if normalized.len() != CODE_LEN || !normalized.bytes().all(|b| CODE_ALPHABET.contains(&b)) {
        return Err(invalid_authority());
    }
    Ok(normalized)
}
/// Keyed by the issuer secret, so a copied vault file alone cannot search the
/// 40-bit code space.
fn pairing_row_key(issuer: &HostSlipIssuer, code: &str) -> Result<String> {
    let key = blake3::derive_key(CODE_HASH_CONTEXT, issuer.secret());
    let hash = blake3::keyed_hash(&key, normalize_code(code)?.as_bytes());
    Ok(hash.to_hex().to_string())
}
/// Client signs this transcript with its newly generated connection key.
/// Code possession without that private key cannot authenticate the result.
pub fn pairing_binding_transcript(
    code: &str,
    binding_key: &[u8; 32],
    holder_ref: &str,
) -> Result<Vec<u8>> {
    let code = normalize_code(code)?;
    if holder_ref.is_empty() || holder_ref.len() > 256 {
        return Err(invalid_authority());
    }
    let mut msg = b"oneiron/pairing-binding/v2\0".to_vec();
    msg.extend_from_slice(code.as_bytes());
    msg.extend_from_slice(binding_key);
    msg.extend_from_slice(holder_ref.as_bytes());
    Ok(msg)
}
/// One string pairs on its own: the server origin, the code and the holder the
/// owner fixed. The code rides in the fragment, which a browser never sends to
/// a server, and the string is its own QR payload.
#[must_use]
pub fn format_pairing_link(origin: &str, code: &str, holder_ref: &str) -> String {
    format!("{}/pair#{code}.{holder_ref}", origin.trim_end_matches('/'))
}
/// The inverse of [`format_pairing_link`]: `(origin, code, holder_ref)`.
pub fn parse_pairing_link(link: &str) -> Result<(String, String, String)> {
    let (location, fragment) = link.split_once('#').ok_or_else(invalid_authority)?;
    let origin = location
        .strip_suffix("/pair")
        .filter(|origin| !origin.is_empty())
        .ok_or_else(invalid_authority)?;
    let (code, holder_ref) = fragment.split_once('.').ok_or_else(invalid_authority)?;
    let holder = crate::EntityId::from_hex(holder_ref).map_err(|_| invalid_authority())?;
    if holder.to_hex() != holder_ref {
        return Err(invalid_authority());
    }
    Ok((
        origin.to_owned(),
        normalize_code(code)?,
        holder_ref.to_owned(),
    ))
}
fn draw_code() -> String {
    use rand_core::{OsRng, RngCore};
    let bits = OsRng.next_u64();
    (0..CODE_LEN)
        .map(|at| char::from(CODE_ALPHABET[((bits >> (at * 5)) & 0x1f) as usize]))
        .collect()
}
impl Vault {
    /// Owner/host API: issue a one-hour enrollment link, scoped at creation.
    pub fn issue_pairing_link(
        &self,
        issuer: &HostSlipIssuer,
        scope: Scope,
        slip_lifetime_secs: u64,
    ) -> Result<PairingLink> {
        self.issue_pairing_link_for_principal(
            issuer,
            scope,
            slip_lifetime_secs,
            PairingPrincipal::default(),
        )
    }
    /// Owner/host enrollment with identity claims fixed before code delivery.
    /// Organization links require a registered admin and an explicit subset
    /// of the organization's immutable administration policy.
    pub fn issue_pairing_link_for_principal(
        &self,
        issuer: &HostSlipIssuer,
        scope: Scope,
        slip_lifetime_secs: u64,
        principal: PairingPrincipal,
    ) -> Result<PairingLink> {
        if slip_lifetime_secs == 0 || slip_lifetime_secs > 365 * 24 * 60 * 60 {
            return Err(invalid_authority());
        }
        let mut txn = self.store.env.write_txn()?;
        require_host(&self.authority_fold_readonly_in_txn(&txn)?, issuer)?;
        self.validate_pairing_principal_in_txn(&txn, &principal, &scope)?;
        let now = self.instant_in_txn(&txn)?.secs();
        let (code, row_key) = loop {
            let code = draw_code();
            let row_key = pairing_row_key(issuer, &code)?;
            let free = match PAIRING_PENDING.get(&self.store, &txn, &row_key) {
                Ok(Some(pending)) => now >= pending.expires_at,
                Ok(None) => true,
                Err(_) => false,
            };
            if free {
                break (code, row_key);
            }
        };
        let expires_at = now.saturating_add(CODE_TTL_SECS);
        let pending = PairingPending {
            expires_at,
            slip_lifetime_secs,
            scope,
            host_key: issuer.binding_key(),
            principal,
        };
        PAIRING_PENDING.put(&self.store, &mut txn, &row_key, &pending)?;
        txn.commit()?;
        Ok(PairingLink { code, expires_at })
    }
    /// No prior bearer is required. The link is the one-use enrollment grant;
    /// the binding signature proves possession of the receiving connection key.
    /// Consuming the link and appending SlipMint are one LMDB transaction.
    pub fn redeem_pairing_link(
        &self,
        issuer: &HostSlipIssuer,
        code: &str,
        holder_ref: &str,
        binding_key: [u8; 32],
        signature: &[u8],
    ) -> Result<CapabilitySlip> {
        let key = VerifyingKey::from_bytes(&binding_key).map_err(|_| invalid_authority())?;
        let signature = Signature::from_slice(signature).map_err(|_| invalid_authority())?;
        key.verify_strict(
            &pairing_binding_transcript(code, &binding_key, holder_ref)?,
            &signature,
        )
        .map_err(|_| invalid_authority())?;
        let mut txn = self.store.env.write_txn()?;
        let now = self.instant_in_txn(&txn)?.secs();
        let row_key = pairing_row_key(issuer, code)?;
        let pending = PAIRING_PENDING
            .get(&self.store, &txn, &row_key)
            .map_err(|_| invalid_authority())?
            .ok_or_else(invalid_authority)?;
        if now >= pending.expires_at || pending.host_key != issuer.binding_key() {
            return Err(invalid_authority());
        }
        if pending
            .principal
            .holder_ref
            .as_deref()
            .is_some_and(|intended| intended != holder_ref)
        {
            return Err(invalid_authority());
        }
        self.validate_pairing_principal_in_txn(&txn, &pending.principal, &pending.scope)?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        require_host(&fold, issuer)?;
        let claims = SlipClaims {
            slip_id: random_slip_id(),
            vault_id: fold.vault_id.ok_or_else(invalid_authority)?,
            parent_id: None,
            holder_ref: holder_ref.to_owned(),
            binding_key,
            scope: pending.scope,
            issued_at: now,
            expires_at: now.saturating_add(pending.slip_lifetime_secs),
            ttl_secs: pending.slip_lifetime_secs,
            single_use: false,
            records: Default::default(),
            channels: Default::default(),
            actor_class: pending.principal.actor_class,
            org_ref: pending.principal.org_ref,
        };
        let slip = self.mint_slip_in_txn(&mut txn, issuer, claims)?;
        PAIRING_PENDING.delete(&self.store, &mut txn, &row_key)?;
        txn.commit()?;
        Ok(slip)
    }
    fn validate_pairing_principal_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        principal: &PairingPrincipal,
        scope: &Scope,
    ) -> Result<()> {
        if principal
            .actor_class
            .as_deref()
            .is_some_and(|class| !matches!(class, "human" | "agent" | "system"))
        {
            return Err(invalid_authority());
        }
        let holder = principal
            .holder_ref
            .as_deref()
            .map(|holder| {
                let id = crate::EntityId::from_hex(holder).map_err(|_| invalid_authority())?;
                if id.to_hex() != holder {
                    return Err(invalid_authority());
                }
                Ok(id)
            })
            .transpose()?;
        let Some(org_ref) = principal.org_ref.as_deref() else {
            // All verbs without an org is a general root, not an org credential.
            if matches!(&scope.verbs, ScopeAxis::Some(verbs) if verbs.iter().any(|verb| verb.starts_with("org:")))
            {
                return Err(invalid_authority());
            }
            return Ok(());
        };
        let org = crate::EntityId::from_hex(org_ref).map_err(|_| invalid_authority())?;
        if org.to_hex() != org_ref {
            return Err(invalid_authority());
        }
        let admin = holder.ok_or_else(invalid_authority)?;
        if self.store.entities.get(txn, admin.as_bytes())?.is_none()
            || self.archive_tombstone_in_txn(txn, &admin)?.is_some()
        {
            return Err(invalid_authority());
        }
        let ScopeAxis::Some(verbs) = &scope.verbs else {
            return Err(invalid_authority());
        };
        if verbs.is_empty() {
            return Err(invalid_authority());
        }
        // Read the fixed setup in the same snapshot as the enrollment/mint.
        let policy = ORG_ADMIN_POLICY
            .get(&self.store, txn, &org.to_hex())
            .map_err(|_| invalid_authority())?
            .ok_or_else(invalid_authority)?;
        if policy.org_ref() != org {
            return Err(invalid_authority());
        }
        for verb in verbs {
            let power = OrgAdminPower::parse(verb).ok_or_else(invalid_authority)?;
            policy
                .authorize(admin, power)
                .map_err(|_| invalid_authority())?;
        }
        Ok(())
    }
}
