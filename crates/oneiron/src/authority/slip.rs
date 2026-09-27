//! Host-signed, log-backed capability slips with MAC-checked offline narrowing and holder proof.
use super::{
    AuthorityFold, AuthorityKey, AuthoritySignature, AuthoritySignatureSuite, invalid_authority,
    verify_authority_signature,
};
use crate::error::Result;
use crate::federation::Scope;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const MAX_CAVEATS: usize = 64;
const MAX_WIRE_BYTES: usize = 65_536;
const MAC_CONTEXT: &str = "oneiron/capability-slip/v2/mac";

/// The immutable, authority-log-committed part of a slip. No secret is stored here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlipClaims {
    pub slip_id: [u8; 32],
    pub vault_id: [u8; 32],
    pub parent_id: Option<[u8; 32]>,
    pub holder_ref: String,
    pub binding_key: [u8; 32],
    pub scope: Scope,
    pub issued_at: u64,
    pub expires_at: u64,
    pub ttl_secs: u64,
    pub single_use: bool,
    /// Exact named secret/repository bounds for credential-door operations.
    pub records: BTreeSet<String>,
    /// Exact named credential-door effectors. Empty means no door channel.
    pub channels: BTreeSet<String>,
    pub actor_class: Option<String>,
    pub org_ref: Option<String>,
}

/// A narrowing appended by a holder, without contacting the issuing host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlipCaveat {
    pub scope: Option<Scope>,
    pub expires_at: Option<u64>,
    pub ttl_secs: Option<u64>,
    pub single_use: bool,
    pub records: Option<BTreeSet<String>>,
    pub channels: Option<BTreeSet<String>>,
    #[serde(
        default,
        serialize_with = "serialize_pact",
        deserialize_with = "deserialize_pact"
    )]
    pub pact: Option<(crate::EntityId, crate::federation::FederationDirectionScope)>,
}

/// One serializable slip. The host signs the immutable mint; only the FINAL
/// caveat MAC travels, so a recipient cannot strip an upstream narrowing.
/// Debug deliberately omits signature and token material.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySlip {
    pub version: u8,
    pub claims: SlipClaims,
    pub caveats: Vec<SlipCaveat>,
    issuer_key: [u8; 32],
    host_signature: Vec<u8>,
    mac: [u8; 32],
}
impl std::fmt::Debug for CapabilitySlip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapabilitySlip")
            .field("version", &self.version)
            .field("slip_id", &self.claims.slip_id)
            .field("caveat_count", &self.caveats.len())
            .finish_non_exhaustive()
    }
}

/// The signed SlipMint payload. The MAC is not authority-log material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlipMintAction {
    pub claims: SlipClaims,
}
impl SlipMintAction {
    pub fn validate(&self) -> Result<()> {
        self.claims.validate()
    }
}
impl SlipClaims {
    pub fn validate(&self) -> Result<()> {
        if self.slip_id == [0; 32]
            || self.vault_id == [0; 32]
            || self.parent_id == Some(self.slip_id)
            || self.parent_id == Some([0; 32])
            || self.holder_ref.is_empty()
            || self.holder_ref.len() > 256
            || self.issued_at >= self.expires_at
            || self.ttl_secs == 0
            || self.ttl_secs > self.expires_at - self.issued_at
            || (self.single_use
                && self.expires_at - self.issued_at
                    > crate::credential_door::DOOR_ONE_SHOT_MAX_LIFETIME_SECS)
            || matches!(&self.scope.verbs, crate::federation::ScopeAxis::Some(verbs)
                if verbs.iter().any(|verb| crate::credential_door::names_a_floor(verb)))
            || VerifyingKey::from_bytes(&self.binding_key).is_err()
            || self
                .actor_class
                .as_deref()
                .is_some_and(|v| !super::ACTOR_BINDING_CLASSES.contains(&v))
            || self
                .org_ref
                .as_deref()
                .is_some_and(|v| crate::EntityId::from_hex(v).is_err())
            || self
                .records
                .iter()
                .chain(self.channels.iter())
                .any(|v| v.is_empty() || v.len() > 512 || crate::credential_door::names_a_floor(v))
            || canonical(self)?.len() > MAX_WIRE_BYTES / 2
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
    pub(super) fn narrows(&self, parent: &Self) -> bool {
        self.vault_id == parent.vault_id
            && self.scope.is_narrowing_of(&parent.scope)
            && self.issued_at >= parent.issued_at
            && self.expires_at <= parent.expires_at
            && self.ttl_secs <= parent.ttl_secs
            && (!parent.single_use || self.single_use)
            && self.binding_key == parent.binding_key
            && self.holder_ref == parent.holder_ref
            && self.actor_class == parent.actor_class
            && self.org_ref == parent.org_ref
            && (self.records == parent.records
                || (!self.records.is_empty()
                    && ((parent.records.is_empty() && parent.channels.is_empty())
                        || self.records.is_subset(&parent.records))))
            && (self.channels == parent.channels
                || (!self.channels.is_empty() && self.channels.is_subset(&parent.channels)))
    }
}

/// A verifier-produced effective view; fields cannot be assembled by callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSlip {
    claims: SlipClaims,
    pact: Option<(crate::EntityId, crate::federation::FederationDirectionScope)>,
    // Only the verifier can prove that no offline narrowing caveat was present.
    unattenuated: bool,
}
impl VerifiedSlip {
    #[must_use]
    pub fn pact(&self) -> Option<&(crate::EntityId, crate::federation::FederationDirectionScope)> {
        self.pact.as_ref()
    }
    pub(crate) fn witness_pact(&self, fold: &AuthorityFold) -> Result<()> {
        let Some((grant, requested)) = &self.pact else {
            return Ok(());
        };
        let pact = fold.pact_for_grant(grant).ok_or_else(invalid_authority)?;
        let effective = requested.intersect(&pact.effective_scope);
        if pact.status != super::FederationPactStatus::Active
            || fold
                .federation_grant_bindings
                .get(grant)
                .is_none_or(|ids| ids.len() != 1)
            || !requested.is_narrowing_of(&effective)
            || matches!(
                effective.worlds,
                crate::federation::FederationScopeWorlds::Bottom
            )
            || matches!(
                effective.facets,
                crate::federation::FederationScopeFacets::Bottom
            )
            || matches!(
                effective.bands,
                crate::federation::FederationScopeBands::Bottom
            )
        {
            return Err(invalid_authority());
        }
        Ok(())
    }

    #[must_use]
    pub fn claims(&self) -> &SlipClaims {
        &self.claims
    }
    /// A verified, unattenuated full-vault instrument, not merely `core:read`.
    #[must_use]
    pub fn is_full_vault_owner_grade(&self) -> bool {
        self.unattenuated
            && self.claims.scope == Scope::top()
            && self.claims.org_ref.is_none()
            && self.claims.records.is_empty()
            && self.claims.channels.is_empty()
            && !self.claims.single_use
    }
    #[must_use]
    pub fn scope(&self) -> &Scope {
        &self.claims.scope
    }
    #[must_use]
    pub fn allows_verb(&self, verb: &str) -> bool {
        self.claims.scope.verbs.contains(&verb.to_owned())
    }
}

impl CapabilitySlip {
    pub(super) fn mint(claims: SlipClaims, issuer: &super::HostSlipIssuer) -> Result<Self> {
        claims.validate()?;
        let key = blake3::derive_key(MAC_CONTEXT, issuer.secret());
        let mac = *blake3::keyed_hash(&key, &canonical(&claims)?).as_bytes();
        let issuer_key = issuer.binding_key();
        let host_signature = issuer.sign_slip(&host_transcript(2, &claims, &issuer_key, &mac)?);
        Ok(Self {
            version: 2,
            claims,
            caveats: Vec::new(),
            issuer_key,
            host_signature,
            mac,
        })
    }
    /// Appends one meet operation. A looser caveat never restores lost authority.
    pub fn attenuate(&mut self, caveat: SlipCaveat) -> Result<()> {
        if self.caveats.len() >= MAX_CAVEATS {
            return Err(invalid_authority());
        }
        let bytes = canonical(&caveat)?;
        if bytes.len() > MAX_WIRE_BYTES / 2 {
            return Err(invalid_authority());
        }
        let mac = *blake3::keyed_hash(&self.mac, &bytes).as_bytes();
        let mut narrowed = self.clone();
        narrowed.caveats.push(caveat);
        narrowed.mac = mac;
        if canonical(&narrowed)?.len() > MAX_WIRE_BYTES {
            return Err(invalid_authority());
        }
        *self = narrowed;
        Ok(())
    }
    /// Stable v2 framing around the one canonical JSON slip representation.
    pub fn to_token(&self) -> Result<String> {
        Ok(format!("v2.slip.{}", hex(&canonical(self)?)))
    }
    pub fn from_token(token: &str) -> Result<Self> {
        let bytes = unhex(
            token
                .strip_prefix("v2.slip.")
                .ok_or_else(invalid_authority)?,
        )?;
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(invalid_authority());
        }
        let slip: Self = serde_json::from_slice(&bytes).map_err(|_| invalid_authority())?;
        if canonical(&slip)? != bytes {
            return Err(invalid_authority());
        }
        Ok(slip)
    }
    /// Checks the host signature, private caveat MAC chain, live authority
    /// ancestry, and holder possession. The receiving door supplies `challenge`.
    pub fn verify(
        &self,
        secret: &[u8],
        fold: &AuthorityFold,
        now: u64,
        challenge: &[u8],
        holder_signature: &[u8],
    ) -> Result<VerifiedSlip> {
        let verified = self.verify_authority(secret, fold, now)?;
        self.verify_holder(challenge, holder_signature)?;
        Ok(verified)
    }
    /// Verify an uncaveated logged slip with ONLY the issuing host public key.
    /// Offline caveats need the private MAC root to prove that no narrowing was
    /// stripped; they fail closed here rather than granting the base scope.
    pub fn verify_with_host_key(
        &self,
        host_key: &AuthorityKey,
        fold: &AuthorityFold,
        now: u64,
        challenge: &[u8],
        holder_signature: &[u8],
    ) -> Result<VerifiedSlip> {
        if !self.caveats.is_empty() || now < self.claims.issued_at || now >= self.claims.expires_at
        {
            return Err(invalid_authority());
        }
        // The issuer signature commits to the INITIAL MAC as well as the
        // claims. A holder of an attenuated token cannot strip the caveats:
        // their final MAC differs and they do not know the signed initial MAC.
        self.verify_host_signature(host_key, fold, &self.mac)?;
        let mut claims = self.claims.clone();
        claims.ttl_secs = claims.ttl_secs.min(claims.expires_at - now);
        let verified = VerifiedSlip {
            claims,
            pact: None,
            unattenuated: true,
        };
        self.verify_holder(challenge, holder_signature)?;
        Ok(verified)
    }
    fn verify_holder(&self, challenge: &[u8], holder_signature: &[u8]) -> Result<()> {
        let key =
            VerifyingKey::from_bytes(&self.claims.binding_key).map_err(|_| invalid_authority())?;
        let signature = Signature::from_slice(holder_signature).map_err(|_| invalid_authority())?;
        key.verify_strict(&self.binding_transcript(challenge)?, &signature)
            .map_err(|_| invalid_authority())
    }
    /// The issuer in the token must be the signer of THIS mint in the
    /// fold-verified log, not merely another enrolled host key.
    fn verify_host_signature(
        &self,
        host_key: &AuthorityKey,
        fold: &AuthorityFold,
        base_mac: &[u8; 32],
    ) -> Result<()> {
        self.claims.validate()?;
        if self.version != 2
            || self.caveats.len() > MAX_CAVEATS
            || canonical(self)?.len() > MAX_WIRE_BYTES
            || fold.vault_id != Some(self.claims.vault_id)
            || *host_key != AuthorityKey::Ed25519(self.issuer_key)
        {
            return Err(invalid_authority());
        }
        let mint = fold
            .slips
            .mints
            .get(&self.claims.slip_id)
            .ok_or_else(invalid_authority)?;
        if mint.action.claims != self.claims
            || mint.signer != *host_key
            || !fold.slip_is_live(&self.claims.slip_id)
        {
            return Err(invalid_authority());
        }
        let signature = AuthoritySignature {
            suite: AuthoritySignatureSuite::Ed25519,
            public_key: host_key.clone(),
            signature: self.host_signature.clone(),
        };
        if !verify_authority_signature(
            &signature,
            &host_transcript(self.version, &self.claims, &self.issuer_key, base_mac)?,
        ) {
            return Err(invalid_authority());
        }
        Ok(())
    }
    /// Transcript to sign with the throwaway binding private key for this request.
    pub fn binding_transcript(&self, challenge: &[u8]) -> Result<Vec<u8>> {
        if challenge.is_empty() || challenge.len() > 8192 {
            return Err(invalid_authority());
        }
        let mut transcript = b"oneiron/slip-binding/v2\0".to_vec();
        transcript.extend_from_slice(blake3::hash(&canonical(self)?).as_bytes());
        transcript.extend_from_slice(&(challenge.len() as u64).to_be_bytes());
        transcript.extend_from_slice(challenge);
        Ok(transcript)
    }
    pub(super) fn verify_authority(
        &self,
        secret: &[u8],
        fold: &AuthorityFold,
        now: u64,
    ) -> Result<VerifiedSlip> {
        let key = blake3::derive_key(MAC_CONTEXT, secret);
        let mut mac = *blake3::keyed_hash(&key, &canonical(&self.claims)?).as_bytes();
        self.verify_host_signature(&AuthorityKey::Ed25519(self.issuer_key), fold, &mac)?;
        let mut effective = self.claims.clone();
        let mut pact: Option<(crate::EntityId, crate::federation::FederationDirectionScope)> = None;
        // An absent named-record bound is universal on generic record reads.
        // Once a caveat supplies a set, its empty meet is Bottom, never universal.
        let mut records_constrained =
            !effective.records.is_empty() || !effective.channels.is_empty();
        for caveat in &self.caveats {
            if caveat.scope.as_ref().is_some_and(|scope| {
                matches!(&scope.verbs, crate::federation::ScopeAxis::Some(verbs)
                    if verbs.iter().any(|verb| crate::credential_door::names_a_floor(verb)))
            }) || caveat
                .records
                .iter()
                .flatten()
                .chain(caveat.channels.iter().flatten())
                .any(|token| crate::credential_door::names_a_floor(token))
            {
                return Err(invalid_authority());
            }
            mac = *blake3::keyed_hash(&mac, &canonical(caveat)?).as_bytes();
            if let Some(scope) = &caveat.scope {
                effective.scope = effective.scope.meet(scope);
            }
            if let Some(expiry) = caveat.expires_at {
                effective.expires_at = effective.expires_at.min(expiry);
            }
            if let Some(ttl) = caveat.ttl_secs {
                effective.ttl_secs = effective.ttl_secs.min(ttl);
            }
            effective.single_use |= caveat.single_use;
            if let Some((grant, bound)) = &caveat.pact {
                bound.validate()?;
                pact = Some(match &pact {
                    Some((prior_grant, prior)) if prior_grant == grant => {
                        (*grant, prior.intersect(bound))
                    }
                    Some(_) => return Err(invalid_authority()),
                    None => (*grant, bound.clone()),
                });
            }
            if let Some(records) = &caveat.records {
                effective.records = if records_constrained {
                    effective.records.intersection(records).cloned().collect()
                } else {
                    records.clone()
                };
                records_constrained = true;
                if effective.records.is_empty() {
                    effective.scope = Scope::default();
                }
            }
            if let Some(channels) = &caveat.channels {
                effective.channels = effective.channels.intersection(channels).cloned().collect();
                // Empty channels carry no credential-door authority. A disjoint
                // meet must not turn a channel-bound slip into a generic reader.
                if effective.channels.is_empty() {
                    effective.scope = Scope::default();
                }
            }
        }
        // keyed_hash::Hash equality is constant time; no string-MAC comparisons.
        if blake3::Hash::from(mac) != blake3::Hash::from(self.mac)
            || now < effective.issued_at
            || now >= effective.expires_at
            || effective.ttl_secs == 0
        {
            return Err(invalid_authority());
        }
        effective.ttl_secs = effective
            .ttl_secs
            .min(effective.expires_at.saturating_sub(effective.issued_at));
        effective.validate()?;
        effective.ttl_secs = effective.ttl_secs.min(effective.expires_at - now);
        let verified = VerifiedSlip {
            claims: effective,
            pact,
            unattenuated: self.caveats.is_empty(),
        };
        verified.witness_pact(fold)?;
        Ok(verified)
    }
}

fn host_transcript(
    version: u8,
    claims: &SlipClaims,
    issuer_key: &[u8; 32],
    base_mac: &[u8; 32],
) -> Result<Vec<u8>> {
    let mut transcript = b"oneiron/capability-slip/host-signature/v2\0".to_vec();
    transcript.extend_from_slice(&canonical(&(version, issuer_key, claims, base_mac))?);
    Ok(transcript)
}

pub(super) fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| invalid_authority())
}
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(super) fn unhex(value: &str) -> Result<Vec<u8>> {
    if value.len() > MAX_WIRE_BYTES * 2
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid_authority());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            Ok(nibble(pair[0]) * 16 + nibble(pair[1]))
        })
        .collect()
}

#[cfg(test)]
#[path = "slip_tests.rs"]
mod tests;

fn serialize_pact<S: serde::Serializer>(
    pact: &Option<(crate::EntityId, crate::federation::FederationDirectionScope)>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    pact.as_ref()
        .map(|(grant, bound)| {
            super::encode_value(&crate::federation::federation_direction_scope_value(bound))
                .map(|bytes| (*grant, bytes))
        })
        .transpose()
        .map_err(serde::ser::Error::custom)?
        .serialize(serializer)
}

fn deserialize_pact<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<
    Option<(crate::EntityId, crate::federation::FederationDirectionScope)>,
    D::Error,
> {
    let wire = Option::<(crate::federation::ScopeId, Vec<u8>)>::deserialize(deserializer)?;
    wire.map(|(grant, bytes)| {
        let mut cursor = std::io::Cursor::new(&bytes);
        let value = rmpv::decode::read_value(&mut cursor).map_err(serde::de::Error::custom)?;
        let scope = crate::federation::decode_federation_direction_scope_value(&value)
            .map_err(serde::de::Error::custom)?;
        let canonical =
            super::encode_value(&crate::federation::federation_direction_scope_value(&scope))
                .map_err(serde::de::Error::custom)?;
        if canonical != bytes {
            return Err(serde::de::Error::custom("noncanonical pact bound"));
        }
        Ok((grant.0, scope))
    })
    .transpose()
}
