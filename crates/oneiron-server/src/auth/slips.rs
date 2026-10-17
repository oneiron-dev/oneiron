//! HTTP/session holder proof and projection of the single log-backed slip.
use super::*;
use oneiron::authority::{CapabilitySlip, VerifiedSlip};
use serde::Deserialize;

/// The facade doors an invitee's own slip (FIX 1925) reaches: its
/// invitation's list, accept and decline. Anywhere else it holds no scope.
pub(crate) const INVITEE_DOORS: [&str; 3] = [
    "vault.members.invitations",
    "vault.members.accept",
    "vault.members.decline",
];

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
        parse_signature(&self.signature)
    }
}
/// An Ed25519 signature as 128 lowercase hex.
pub(crate) fn parse_signature(value: &str) -> Result<Vec<u8>, ApiError> {
    if value.len() != 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ApiError::unauthorized());
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
impl CoreAuth {
    pub(crate) fn from_slip_token(
        token: &str,
        proof: &BindingProof,
        vault: &dyn RevokedTokenJtis,
    ) -> Result<Self, ApiError> {
        let slip = CapabilitySlip::from_token(token).map_err(|_| ApiError::unauthorized())?;
        let signature = proof.signature()?;
        let nonce = proof.nonce.as_bytes();
        let verified = vault
            .verify_slip(&slip, proof.timestamp, nonce, &signature)
            .map_err(|()| {
                vault
                    .proof_clock_refusal(&slip, proof.timestamp, nonce, &signature)
                    .unwrap_or_else(ApiError::unauthorized)
            })?;
        // These transports can call auth more than once per request; they must
        // not perform one-shot effects. The atomic consuming door owns those.
        if verified.claims().single_use {
            return Err(ApiError::unauthorized());
        }
        let mut auth = Self::from_verified(verified, slip.caveats.is_empty())?;
        auth.instrument = Some(*blake3::hash(token.as_bytes()).as_bytes());
        // The work this request queues carries the slip it was admitted on,
        // judged again when that work runs. A registry that keeps none
        // leaves the request nothing to queue slip-bound work with.
        let challenge = oneiron::authority::holder_proof_challenge(proof.timestamp, &proof.nonce);
        auth.invocation_slip = vault
            .bind_invocation_slip(&slip, &challenge, &signature)
            .ok();
        auth.facets_owner_exempt = auth
            .verified_slip
            .as_ref()
            .is_some_and(|proof| vault.credential_facets_owner_exempt(proof));
        Ok(auth)
    }
    /// Admit a fresh transport binding once. Repeated authorization checks
    /// inside the admitted request keep using the read-only verifier.
    pub(crate) fn bind_transport_once(
        token: &str,
        proof: &BindingProof,
        vault: &oneiron::Vault,
    ) -> Result<Self, ApiError> {
        // This also refuses one-shot instruments before a consuming operation.
        let auth = Self::from_slip_token(token, proof, vault)?;
        let slip = CapabilitySlip::from_token(token).map_err(|_| ApiError::unauthorized())?;
        vault
            .admit_capability_slip_request(
                &slip,
                proof.timestamp,
                &proof.signature()?,
                proof.nonce.as_bytes(),
            )
            .map_err(|_| ApiError::unauthorized())?;
        // A fresh proof, used here once: the connection it came on is no
        // longer a stranger's. The read-only check above does not say so,
        // since a replay passes it and is refused only here.
        crate::http_listener::authenticated();
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
                // An invitee's slip holds no scope of its own; only its
                // invitation's doors grant one (`at_invitee_door`).
                if claims.invitation_ref.is_some() {
                    return false;
                }
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
            invocation_slip: None,
            locality: CallerLocality::OffDevice,
            facets_owner_exempt: false,
        })
    }
    /// An invitee's slip (FIX 1925) on the facade route of one of
    /// [`INVITEE_DOORS`] (`/v1/core/facade/<verb>`): the read and write
    /// scopes those rows require. Its door then admits the invitee's own
    /// invitation alone. Any other request keeps the slip's empty scope.
    pub(super) fn at_invitee_door(mut self, path: &str) -> Self {
        let invited = self
            .verified_slip
            .as_ref()
            .is_some_and(|slip| slip.claims().invitation_ref.is_some());
        let verb = path
            .strip_prefix("/v1/core/facade")
            .unwrap_or(path)
            .trim_start_matches('/');
        if invited && INVITEE_DOORS.contains(&verb) {
            self.scopes = BTreeSet::from([CoreScope::Read, CoreScope::Write]);
        }
        self
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
    /// A door that reads or writes around the credential's lane cannot honour
    /// a facet narrowing (owner ruling FACET-READ), so it refuses one, as MCP
    /// refuses a narrowed connector there. The owner's own narrower
    /// credential is no narrowing: facets never bind the owner, so this door
    /// admits it as the lane would. Any other bound keeps this door's own
    /// checks.
    pub(crate) fn require_unnarrowed_facets(&self) -> Result<(), ApiError> {
        if !self.facets_owner_exempt
            && self.verified_slip().is_some_and(|proof| {
                !matches!(proof.scope().facets, oneiron::federation::ScopeAxis::All)
            })
        {
            return Err(ApiError::forbidden_scope("record-scope"));
        }
        Ok(())
    }
    /// A door that reads only through the credential's lane, which honours a
    /// facet narrowing on every row (owner ruling FACET-READ), admits one. Any
    /// other narrowing, and any record or channel caveat, fails closed as in
    /// [`Self::require_unrestricted_record_scope`].
    pub(crate) fn require_lane_record_scope(&self) -> Result<(), ApiError> {
        let facets = self
            .verified_slip()
            .map_or(oneiron::federation::ScopeAxis::All, |proof| {
                proof.scope().facets.clone()
            });
        self.require_record_scope_carried(oneiron::federation::ScopeAxis::All, facets)
    }
    /// A write whose records are born at `worlds` and `facets` carries those
    /// two axes of the credential's record bounds and no other. The proof may
    /// narrow worlds and facets to cover them; any other narrowing, and any
    /// record or channel caveat, fails closed as in
    /// [`Self::require_unrestricted_record_scope`].
    pub(crate) fn require_record_scope_carried(
        &self,
        worlds: oneiron::federation::ScopeAxis<oneiron::federation::ScopeId>,
        facets: oneiron::federation::ScopeAxis<oneiron::federation::ScopeId>,
    ) -> Result<(), ApiError> {
        if let Some(proof) = self.verified_slip() {
            let mut required = oneiron::federation::Scope::top();
            required.verbs = proof.scope().verbs.clone();
            required.worlds = worlds;
            required.facets = facets;
            if !proof.claims().records.is_empty()
                || !proof.claims().channels.is_empty()
                || !required.is_narrowing_of(proof.scope())
            {
                return Err(ApiError::forbidden_scope("record-scope"));
            }
        }
        Ok(())
    }
    /// May this credential read `id`? A verified slip reads through the
    /// actor-scoped lane its own proof builds (the engine's one credential
    /// key), so its policy floor and relationship grants apply on every
    /// route. A credential with no verified slip is the owner's server secret
    /// and reads every entity, but for one a device-local world keeps from a
    /// caller off this device (DEC-0005).
    pub(crate) fn can_read_entity(
        &self,
        vault: &oneiron::Vault,
        id: &oneiron::EntityId,
    ) -> oneiron::Result<bool> {
        let Some(proof) = self.verified_slip() else {
            return Ok(self.locality == CallerLocality::OnDevice || !vault.device_local_keeps(id)?);
        };
        let Some(key) = vault.credential_read_key(proof)? else {
            return Ok(false);
        };
        vault
            .scoped_read(key.at(self.locality))
            .is_entity_readable(id)
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

pub(crate) fn parse_slip_id(value: &str) -> Result<[u8; 32], ApiError> {
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
