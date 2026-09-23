//! HTTP/session holder proof and projection of the single log-backed slip.
use super::*;
use oneiron::authority::{CapabilitySlip, VerifiedSlip};
use serde::Deserialize;

/// A short-lived proof bound to the whole slip and a caller-generated nonce.
/// TLS protects the proof in transit. It is not a replacement bearer token.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindingProof {
    pub timestamp: u64,
    pub nonce: String,
    pub signature: String,
}
impl BindingProof {
    pub(crate) fn from_headers(headers: &HeaderMap) -> Result<Self, ApiError> {
        let raw = headers
            .get("x-oneiron-binding")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(ApiError::unauthorized)?;
        serde_json::from_str(raw).map_err(|_| ApiError::unauthorized())
    }
    fn signature(&self) -> Result<Vec<u8>, ApiError> {
        if self.signature.len() != 128
            || !self
                .signature
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ApiError::unauthorized());
        }
        self.signature
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
                Ok(nibble(pair[0]) * 16 + nibble(pair[1]))
            })
            .collect()
    }
}
impl CoreAuth {
    pub(crate) fn from_slip_token(
        token: &str,
        proof: &BindingProof,
        config: &SyncServerConfig,
        vault: &dyn RevokedTokenJtis,
    ) -> Result<Self, ApiError> {
        let secret = config
            .auth_secret
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(ApiError::unauthorized)?;
        let slip = CapabilitySlip::from_token(token).map_err(|_| ApiError::unauthorized())?;
        let verified = vault
            .verify_slip(
                secret,
                &slip,
                proof.timestamp,
                proof.nonce.as_bytes(),
                &proof.signature()?,
            )
            .map_err(|_| ApiError::unauthorized())?;
        // These transports can call auth more than once per request; they must
        // not perform one-shot effects. The atomic consuming door owns those.
        if verified.claims().single_use {
            return Err(ApiError::unauthorized());
        }
        let mut auth = Self::from_verified(verified, slip.caveats.is_empty())?;
        auth.instrument = Some(*blake3::hash(token.as_bytes()).as_bytes());
        Ok(auth)
    }
    /// Admit a fresh transport binding once. Repeated authorization checks
    /// inside the admitted request keep using the read-only verifier.
    pub(crate) fn bind_transport_once(
        token: &str,
        proof: &BindingProof,
        config: &SyncServerConfig,
        vault: &oneiron::Vault,
    ) -> Result<Self, ApiError> {
        // This also refuses one-shot instruments before a consuming operation.
        let auth = Self::from_slip_token(token, proof, config, vault)?;
        let secret = config
            .auth_secret
            .as_deref()
            .ok_or_else(ApiError::unauthorized)?;
        let issuer = oneiron::authority::HostSlipIssuer::from_secret(secret.as_bytes())
            .map_err(|_| ApiError::unauthorized())?;
        let slip = CapabilitySlip::from_token(token).map_err(|_| ApiError::unauthorized())?;
        vault
            .authenticate_capability_slip(
                &issuer,
                &slip,
                proof.timestamp,
                &proof.signature()?,
                proof.nonce.as_bytes(),
            )
            .map_err(|_| ApiError::unauthorized())?;
        Ok(auth)
    }
    pub(super) fn from_verified(
        verified: VerifiedSlip,
        unattenuated: bool,
    ) -> Result<Self, ApiError> {
        use oneiron::federation::{OrgAdminPower, Scope, ScopeAxis};
        let claims = verified.claims();
        let principal_ref = if claims.holder_ref == "host" {
            None
        } else {
            Some(parse_principal_ref(&claims.holder_ref)?)
        };
        if claims.org_ref.is_some() {
            if principal_ref.is_none() {
                return Err(ApiError::unauthorized());
            }
            let ScopeAxis::Some(verbs) = &claims.scope.verbs else {
                return Err(ApiError::unauthorized());
            };
            if verbs.is_empty()
                || verbs
                    .iter()
                    .any(|verb| OrgAdminPower::parse(verb).is_none())
            {
                return Err(ApiError::unauthorized());
            }
        } else if matches!(&claims.scope.verbs, ScopeAxis::Some(verbs) if verbs.iter().any(|verb| verb.starts_with("org:")))
        {
            return Err(ApiError::unauthorized());
        }
        let scopes: BTreeSet<_> = CoreScope::all()
            .into_iter()
            .filter(|scope| {
                // A general root is not an organization credential. Organization
                // powers exist only in the explicit org-bound closed vocabulary.
                if matches!(scope, CoreScope::OrgAdmin(_)) && claims.org_ref.is_none() {
                    return false;
                }
                let class = match scope {
                    CoreScope::Read => "read",
                    CoreScope::Write => "write",
                    _ => scope.as_str(),
                };
                verified.allows_verb(class) || verified.allows_verb(scope.as_str())
            })
            .collect();
        let owner_grade = unattenuated
            && claims.scope == Scope::top()
            && claims.org_ref.is_none()
            && claims.records.is_empty()
            && claims.channels.is_empty()
            && !claims.single_use;
        Ok(Self {
            principal: format!("slip:{}", hex_id(&claims.slip_id)),
            principal_ref,
            scopes,
            implicit_all_scopes: owner_grade,
            jti: Some(hex_id(&claims.slip_id)),
            actor_class: claims.actor_class.clone(),
            org_ref: claims.org_ref.clone(),
            // Local host proofs have no caveats. Their logged mint id is stable.
            instrument: Some(claims.slip_id),
            verified_slip: Some(verified),
        })
    }
    /// An adapter without record-Scope enforcement cannot accept a narrowed
    /// record capability. Fail closed instead of dropping caveats at projection.
    pub(crate) fn require_unrestricted_record_scope(&self) -> Result<(), ApiError> {
        if let Some(proof) = self.verified_slip() {
            let mut required = oneiron::federation::Scope::top();
            required.verbs = proof.scope().verbs.clone();
            if !proof.claims().records.is_empty()
                || !proof.claims().channels.is_empty()
                || !required.is_narrowing_of(proof.scope())
            {
                return Err(ApiError::forbidden_scope("record-scope"));
            }
        }
        Ok(())
    }
    pub(crate) fn credential_is_live_in_write_txn(
        &self,
        vault: &oneiron::Vault,
        txn: &heed::RwTxn<'_>,
    ) -> bool {
        if let Some(verified) = &self.verified_slip {
            return vault
                .capability_slip_is_live_in_txn(txn, verified)
                .unwrap_or(false);
        }
        self.jti().is_none_or(|jti| {
            if jti.len() == 64 {
                return parse_slip_id(jti).is_ok_and(|id| {
                    vault
                        .capability_slip_id_is_live_in_txn(txn, &id)
                        .unwrap_or(false)
                });
            }
            vault
                .sync_state_get_in_write_txn(txn, &super::revoked_token_jti_key(jti))
                .is_ok_and(|row| row.is_none())
        })
    }

    /// Long-lived sessions refold liveness for their original verified mint.
    pub(crate) fn credential_is_live(&self, vault: &oneiron::Vault) -> bool {
        if let Some(verified) = &self.verified_slip {
            vault.capability_slip_is_live(verified).unwrap_or(false)
        } else {
            self.jti()
                .is_none_or(|jti| vault.is_revoked(jti).is_ok_and(|revoked| !revoked))
        }
    }
}
fn hex_id(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(super) fn parse_slip_id(value: &str) -> Result<[u8; 32], ApiError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ApiError::unauthorized());
    }
    let mut id = [0; 32];
    for (slot, pair) in id.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        *slot = nibble(pair[0]) * 16 + nibble(pair[1]);
    }
    Ok(id)
}
