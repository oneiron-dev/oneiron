//! Host-signed capability slips with holder-signed offline narrowing and proof.
use super::{AuthorityFold, MAX_WIRE_BYTES, SlipClaims, canonical, invalid_authority};
use crate::error::Result as EngineResult;
use crate::federation::Scope;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

mod stored_read;
pub(crate) use stored_read::StoredReadProof;

const MAX_CAVEATS: usize = 64;
const MINT_CONTEXT: &[u8] = b"oneiron/capability-slip/v0/mint\0";
const CAVEAT_CONTEXT: &[u8] = b"oneiron/capability-slip/v0/caveat\0";

/// A narrowing appended by a holder, without contacting the issuing host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    #[schemars(with = "Option<(crate::federation::ScopeId, Vec<u8>)>")]
    pub pact: Option<(crate::EntityId, crate::federation::FederationDirectionScope)>,
    /// A lower comm reach (FIX 3899): the verifier meets it with the slip's,
    /// so a caveat only lowers whom the holder may message. A wider reach is
    /// a new owner mint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comm: Option<super::CommReach>,
}

/// A holder-signed narrowing, optionally transferring proof to a new holder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCaveat {
    pub caveat: SlipCaveat,
    pub next_binding_key: [u8; 32],
    signature: Vec<u8>,
}

/// Canonical, versioned credential. The host signs immutable claims; each
/// subsequent holder signs the prior wire image and the next narrower block.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySlip {
    pub version: u8,
    pub claims: SlipClaims,
    pub caveats: Vec<SignedCaveat>,
    signature: Vec<u8>,
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

/// A verifier-produced effective view; fields cannot be assembled by callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSlip {
    claims: SlipClaims,
    pact: Option<(crate::EntityId, crate::federation::FederationDirectionScope)>,
    // Only the verifier can prove that no offline narrowing caveat was present.
    unattenuated: bool,
    // Only the verifier knows whether a caveat moved the binding key off the
    // key the slip was minted to.
    transferred: bool,
}
impl VerifiedSlip {
    #[must_use]
    pub fn pact(&self) -> Option<&(crate::EntityId, crate::federation::FederationDirectionScope)> {
        self.pact.as_ref()
    }
    /// This view met with its guest grant's current effective scope (FIX
    /// 7929): only the Vault's admission, which read the grant's own row,
    /// asks for it.
    pub(in crate::authority) fn meet_current_scope(
        mut self,
        current: &crate::federation::FederationDirectionScope,
    ) -> Self {
        self.claims.scope = super::current_scope::clamp_scope(&self.claims.scope, current);
        self
    }
    pub(crate) fn witness_pact(&self, fold: &AuthorityFold) -> EngineResult<()> {
        let Some((grant, requested)) = &self.pact else {
            return Ok(());
        };
        witnessed_pact_scope(fold, grant, requested).map(drop)
    }

    #[must_use]
    pub fn claims(&self) -> &SlipClaims {
        &self.claims
    }
    /// Whether the slip is its mint, with no caveat narrowing it (a scope,
    /// a pact bound, a shorter lifetime, another key).
    #[must_use]
    pub(crate) fn is_unattenuated(&self) -> bool {
        self.unattenuated
    }
    /// A verified, unattenuated full-vault instrument, not merely `core:read`.
    /// A slip whose comm reach the owner capped below the vault's is not one
    /// (FIX 3899): it could otherwise mint itself a wider reach.
    #[must_use]
    pub fn is_full_vault_owner_grade(&self) -> bool {
        self.unattenuated
            && self.comm() == super::CommReach::Vault
            && self.claims.scope == Scope::top()
            && self.claims.org_ref.is_none()
            && self.claims.records.is_empty()
            && self.claims.channels.is_empty()
            && !self.claims.single_use
    }
    /// A caveat handed the slip to another key (`attenuate_to`): whoever
    /// proves it now is not the holder the mint names, whatever
    /// `holder_ref` says.
    #[must_use]
    pub fn is_transferred(&self) -> bool {
        self.transferred
    }
    #[must_use]
    pub fn scope(&self) -> &Scope {
        &self.claims.scope
    }
    /// Whom the slip lets its holder message, every caveat met (FIX 3899):
    /// the owner's mint-time ceiling, or the vault-wide reach when he set
    /// none.
    #[must_use]
    pub fn comm(&self) -> super::CommReach {
        super::effective_slip_comm(self.claims.comm)
    }
    #[must_use]
    pub fn allows_verb(&self, verb: &str) -> bool {
        self.claims.scope.verbs.contains(&verb.to_owned())
    }
}

impl CapabilitySlip {
    pub(super) fn mint(claims: SlipClaims, issuer: &super::HostSlipIssuer) -> EngineResult<Self> {
        claims.validate()?;
        let signature = issuer.sign_slip(&mint_transcript(&claims)?);
        Ok(Self {
            version: 2,
            claims,
            caveats: Vec::new(),
            signature,
        })
    }
    /// Appends a signed meet. The caller must own the current holder key; a
    /// recipient gets only the next key, so it cannot remove earlier blocks.
    pub fn attenuate_to(
        &mut self,
        caveat: SlipCaveat,
        holder: &SigningKey,
        next_binding_key: [u8; 32],
    ) -> EngineResult<()> {
        if self.caveats.len() >= MAX_CAVEATS {
            return Err(invalid_authority());
        }
        super::strong_ed25519_key(&next_binding_key)?;
        // A support slip (OF-606) stays with the support party's own key: it
        // narrows, but never passes to another holder.
        if self.current_binding_key() != holder.verifying_key().to_bytes()
            || (self.claims.delegation.is_some() && next_binding_key != self.current_binding_key())
        {
            return Err(invalid_authority());
        }
        let signature = holder
            .sign(&caveat_transcript(self, &caveat, &next_binding_key)?)
            .to_bytes()
            .to_vec();
        let mut narrowed = self.clone();
        narrowed.caveats.push(SignedCaveat {
            caveat,
            next_binding_key,
            signature,
        });
        if canonical(&narrowed)?.len() > MAX_WIRE_BYTES {
            return Err(invalid_authority());
        }
        *self = narrowed;
        Ok(())
    }
    /// Narrow without transferring the holder key (for a local holder).
    pub fn attenuate(&mut self, caveat: SlipCaveat, holder: &SigningKey) -> EngineResult<()> {
        self.attenuate_to(caveat, holder, holder.verifying_key().to_bytes())
    }
    pub(super) fn current_binding_key(&self) -> [u8; 32] {
        self.caveats
            .last()
            .map_or(self.claims.binding_key, |block| block.next_binding_key)
    }
    /// Stable v2 framing around the one canonical JSON slip representation.
    pub fn to_token(&self) -> EngineResult<String> {
        Ok(format!("v2.slip.{}", hex(&canonical(self)?)))
    }
    pub fn from_token(token: &str) -> EngineResult<Self> {
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
    /// Checks host and caveat signatures, authority ancestry and holder possession.
    /// `challenge` is supplied by the receiving door, never taken from the slip.
    pub fn verify(
        &self,
        host_public_key: &super::AuthorityKey,
        fold: &AuthorityFold,
        now: u64,
        challenge: &[u8],
        holder_signature: &[u8],
    ) -> EngineResult<VerifiedSlip> {
        let verified = self.verify_authority(host_public_key, fold, now)?;
        self.verify_holder(challenge, holder_signature)?;
        Ok(verified)
    }
    /// Verify with the minting host public key, including signed narrowing blocks.
    pub fn verify_with_host_key(
        &self,
        host_key: &super::AuthorityKey,
        fold: &AuthorityFold,
        now: u64,
        challenge: &[u8],
        holder_signature: &[u8],
    ) -> EngineResult<VerifiedSlip> {
        self.verify(host_key, fold, now, challenge, holder_signature)
    }
    /// Transcript to sign with the throwaway binding private key for this request.
    pub fn binding_transcript(&self, challenge: &[u8]) -> EngineResult<Vec<u8>> {
        if challenge.is_empty() || challenge.len() > 8192 {
            return Err(invalid_authority());
        }
        let mut transcript = b"oneiron/slip-binding/v2\0".to_vec();
        transcript.extend_from_slice(blake3::hash(&canonical(self)?).as_bytes());
        transcript.extend_from_slice(&(challenge.len() as u64).to_be_bytes());
        transcript.extend_from_slice(challenge);
        Ok(transcript)
    }
    /// Checks a proof the holder made at `signed_at`, as a read-time fold does
    /// for stored history: expiry is judged at that time, not the reader's
    /// clock, and a revoke of the slip or its minting host still refuses it.
    pub fn verify_history(
        &self,
        host_public_key: &super::AuthorityKey,
        fold: &AuthorityFold,
        signed_at: u64,
        challenge: &[u8],
        holder_signature: &[u8],
    ) -> EngineResult<VerifiedSlip> {
        let verified = self.verify_authority_with(host_public_key, fold, signed_at, true)?;
        self.verify_holder(challenge, holder_signature)?;
        Ok(verified)
    }
    /// Checks what a proof's bytes fix for good: the mint's claims equal this
    /// slip's, the host signed them, every caveat transfer is signed by the
    /// key before it, and the last binding key signed `challenge`. Standing
    /// (revocation, retirement, expiry, scope) is the reader's later check, so
    /// a row that passes here can still lose its authority.
    pub(crate) fn verify_origin(
        &self,
        fold: &AuthorityFold,
        challenge: &[u8],
        holder_signature: &[u8],
    ) -> EngineResult<()> {
        self.claims.validate()?;
        if self.version != 2
            || self.caveats.len() > MAX_CAVEATS
            || canonical(self)?.len() > MAX_WIRE_BYTES
            || fold.vault_id != Some(self.claims.vault_id)
        {
            return Err(invalid_authority());
        }
        let mint = fold
            .slips
            .mints
            .get(&self.claims.slip_id)
            .ok_or_else(invalid_authority)?;
        let super::AuthorityKey::Ed25519(host_key) = &mint.signer else {
            return Err(invalid_authority());
        };
        if mint.action.claims != self.claims {
            return Err(invalid_authority());
        }
        let host = VerifyingKey::from_bytes(host_key).map_err(|_| invalid_authority())?;
        let signature = Signature::from_slice(&self.signature).map_err(|_| invalid_authority())?;
        host.verify_strict(&mint_transcript(&self.claims)?, &signature)
            .map_err(|_| invalid_authority())?;
        let mut prefix = Self {
            version: self.version,
            claims: self.claims.clone(),
            caveats: Vec::new(),
            signature: self.signature.clone(),
        };
        let mut binding_key = self.claims.binding_key;
        for block in &self.caveats {
            let key = VerifyingKey::from_bytes(&binding_key).map_err(|_| invalid_authority())?;
            let signature =
                Signature::from_slice(&block.signature).map_err(|_| invalid_authority())?;
            key.verify_strict(
                &caveat_transcript(&prefix, &block.caveat, &block.next_binding_key)?,
                &signature,
            )
            .map_err(|_| invalid_authority())?;
            prefix.caveats.push(block.clone());
            binding_key = block.next_binding_key;
        }
        self.verify_holder(challenge, holder_signature)
    }
    fn verify_holder(&self, challenge: &[u8], holder_signature: &[u8]) -> EngineResult<()> {
        let key = VerifyingKey::from_bytes(&self.current_binding_key())
            .map_err(|_| invalid_authority())?;
        let signature = Signature::from_slice(holder_signature).map_err(|_| invalid_authority())?;
        key.verify_strict(&self.binding_transcript(challenge)?, &signature)
            .map_err(|_| invalid_authority())
    }
    pub(super) fn verify_authority(
        &self,
        host_public_key: &super::AuthorityKey,
        fold: &AuthorityFold,
        now: u64,
    ) -> EngineResult<VerifiedSlip> {
        self.verify_authority_with(host_public_key, fold, now, false)
    }
    fn verify_authority_with(
        &self,
        host_public_key: &super::AuthorityKey,
        fold: &AuthorityFold,
        now: u64,
        history: bool,
    ) -> EngineResult<VerifiedSlip> {
        self.claims.validate()?;
        if self.version != 2
            || self.caveats.len() > MAX_CAVEATS
            || canonical(self)?.len() > MAX_WIRE_BYTES
            || fold.vault_id != Some(self.claims.vault_id)
        {
            return Err(invalid_authority());
        }
        let mint = fold
            .slips
            .mints
            .get(&self.claims.slip_id)
            .ok_or_else(invalid_authority)?;
        if mint.action.claims != self.claims
            || &mint.signer != host_public_key
            || !(if history {
                fold.slip_authorized_history(&self.claims.slip_id)
            } else {
                fold.slip_is_live(&self.claims.slip_id)
            })
        {
            return Err(invalid_authority());
        }
        let super::AuthorityKey::Ed25519(host_key) = host_public_key else {
            return Err(invalid_authority());
        };
        let host = VerifyingKey::from_bytes(host_key).map_err(|_| invalid_authority())?;
        let signature = Signature::from_slice(&self.signature).map_err(|_| invalid_authority())?;
        host.verify_strict(&mint_transcript(&self.claims)?, &signature)
            .map_err(|_| invalid_authority())?;
        let mut prefix = Self {
            version: self.version,
            claims: self.claims.clone(),
            caveats: Vec::new(),
            signature: self.signature.clone(),
        };
        let mut binding_key = self.claims.binding_key;
        let mut effective = self.claims.clone();
        let mut pact: Option<(crate::EntityId, crate::federation::FederationDirectionScope)> = None;
        // An absent named-record bound is universal on generic record reads.
        // Once a caveat supplies a set, its empty meet is Bottom, never universal.
        let mut records_constrained =
            !effective.records.is_empty() || !effective.channels.is_empty();
        for block in &self.caveats {
            let caveat = &block.caveat;
            let key = VerifyingKey::from_bytes(&binding_key).map_err(|_| invalid_authority())?;
            let signature =
                Signature::from_slice(&block.signature).map_err(|_| invalid_authority())?;
            key.verify_strict(
                &caveat_transcript(&prefix, caveat, &block.next_binding_key)?,
                &signature,
            )
            .map_err(|_| invalid_authority())?;
            VerifyingKey::from_bytes(&block.next_binding_key).map_err(|_| invalid_authority())?;
            prefix.caveats.push(block.clone());
            binding_key = block.next_binding_key;
            meet_caveat(&mut effective, &mut pact, &mut records_constrained, caveat)?;
        }
        if now < effective.issued_at || now >= effective.expires_at || effective.ttl_secs == 0 {
            return Err(invalid_authority());
        }
        effective.ttl_secs = effective
            .ttl_secs
            .min(effective.expires_at.saturating_sub(effective.issued_at));
        effective.validate()?;
        effective.ttl_secs = effective.ttl_secs.min(effective.expires_at - now);
        effective.binding_key = binding_key;
        let verified = VerifiedSlip {
            claims: effective,
            pact,
            unattenuated: self.caveats.is_empty(),
            transferred: binding_key != self.claims.binding_key,
        };
        verified.witness_pact(fold)?;
        Ok(verified)
    }
}

/// A pact bound the caveats carry, as the meet folds it: one grant, its
/// bounds intersected.
type PactBound = Option<(crate::EntityId, crate::federation::FederationDirectionScope)>;

/// Meets one authenticated caveat into `effective`: the one meet live
/// verification and a transferred removal archive's bounds (FIX-LIST 8224)
/// both take. A caveat naming a floor, or a second pact, refuses.
fn meet_caveat(
    effective: &mut SlipClaims,
    pact: &mut PactBound,
    records_constrained: &mut bool,
    caveat: &SlipCaveat,
) -> EngineResult<()> {
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
    if let Some(comm) = caveat.comm {
        effective.comm = Some(super::effective_slip_comm(effective.comm).min(comm));
    }
    if let Some((grant, bound)) = &caveat.pact {
        bound.validate()?;
        *pact = Some(match pact.as_ref() {
            Some((prior_grant, prior)) if prior_grant == grant => (*grant, prior.intersect(bound)),
            Some(_) => return Err(invalid_authority()),
            None => (*grant, bound.clone()),
        });
    }
    if let Some(records) = &caveat.records {
        effective.records = if *records_constrained {
            effective.records.intersection(records).cloned().collect()
        } else {
            records.clone()
        };
        *records_constrained = true;
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
    Ok(())
}

/// `requested` met with `grant`'s pact while that pact holds in `fold`: it
/// is Active, its grant is bound once, `requested` lies inside its effective
/// scope and no axis of the meet is ⊥. A live slip's pact bound
/// ([`VerifiedSlip::witness_pact`]) and a transferred removal archive's, at
/// each serve (FIX 11860), are both witnessed so.
fn witnessed_pact_scope(
    fold: &AuthorityFold,
    grant: &crate::EntityId,
    requested: &crate::federation::FederationDirectionScope,
) -> EngineResult<crate::federation::FederationDirectionScope> {
    let pact = fold.pact_for_grant(grant).ok_or_else(invalid_authority)?;
    let effective = requested.intersect(&pact.effective_scope);
    if pact.status != super::FederationPactStatus::Active
        || fold
            .federation_grant_bindings
            .get(grant)
            .is_none_or(|ids| ids.len() != 1)
        || !crate::federation::Ceiling::new(requested.clone())
            .is_within(&crate::federation::Ceiling::new(effective.clone()))
        || effective.worlds.is_bottom()
        || effective.facets.is_bottom()
        || effective.bands.is_bottom()
    {
        return Err(invalid_authority());
    }
    Ok(effective)
}

/// The verb a transferred holder's bounds must carry to take any of a
/// removal archive (CALLS "REMOVAL_ARCHIVE_TRANSFER_VERB", accepted by the
/// Engine 10-22 05:3x): the scoped export's own.
pub(crate) const REMOVAL_ARCHIVE_TRANSFER_VERB: &str = "export";

/// What a transferred slip's authenticated caveats leave its holder of the
/// original mint (FIX-LIST 8224): the caveats met over the mint's claims,
/// the mint's own lifetime aside, which the removal already ended for its
/// recipient too. Live standing (revocation, retirement) is not consulted:
/// it ended with the removal, and a transfer's bounds never revive it. A
/// pact bound is the one standing read live, at each serve (FIX 11860).
#[derive(Debug, Clone)]
pub(crate) struct TransferredBounds {
    scope: Scope,
    /// The named-record bound, when one constrains.
    records: Option<BTreeSet<String>>,
    /// Whether the effective bounds name channels: an archived record
    /// carries none, so a channel-bound transfer takes nothing here.
    channel_bound: bool,
    deadline: u64,
    single_use: bool,
    /// The pact bound a caveat set: its grant and the scope it requested.
    pact: PactBound,
}

impl TransferredBounds {
    /// Whether the archived record `id`, which stood at `position` when the
    /// removal froze it, lies inside these bounds at `now`. A record frozen
    /// with no position is judged as if it stood everywhere: only bounds no
    /// caveat narrowed take it. A one-shot transfer is judged as any other:
    /// the archive doors take it once and spend it in the writer that serves
    /// it ([`Self::single_use`], FIX-LIST 10773). A pact-bound transfer takes
    /// only a record whose frozen position lies inside `served_pact`, the
    /// scope its pact still leaves it at this serve
    /// ([`Self::served_pact_scope`], FIX 11860), and nothing once that pact
    /// no longer holds. A channel-bound one takes nothing: an archived record
    /// stood on no channel, and this door is none.
    #[must_use]
    pub(crate) fn admits(
        &self,
        id: crate::EntityId,
        position: Option<&Scope>,
        now: u64,
        served_pact: Option<&crate::federation::FederationDirectionScope>,
    ) -> bool {
        if now >= self.deadline || self.channel_bound {
            return false;
        }
        let top = Scope::top();
        if self.pact.is_some()
            && !served_pact
                .is_some_and(|pact| super::current_scope::within(position.unwrap_or(&top), pact))
        {
            return false;
        }
        if self
            .records
            .as_ref()
            .is_some_and(|records| !records.contains(&id.to_hex()))
        {
            return false;
        }
        let mut record = crate::federation::record_scope::note_world::any_world_at(
            position.unwrap_or(&top),
            &self.scope.worlds,
        );
        record.verbs = crate::federation::ScopeAxis::Some(BTreeSet::from([
            REMOVAL_ARCHIVE_TRANSFER_VERB.to_owned(),
        ]));
        record.facets.is_narrowing_of(&self.scope.facets)
            && self
                .scope
                .admits(REMOVAL_ARCHIVE_TRANSFER_VERB, &record, &Scope::top())
    }

    /// Whether the mint or a caveat made the transfer one-shot: an archive
    /// door serves it once, and the first answer that takes anything spends
    /// the slip (FIX-LIST 10773).
    #[must_use]
    pub(crate) const fn single_use(&self) -> bool {
        self.single_use
    }

    /// The grant of the pact a caveat bound this transfer to, if one did.
    #[must_use]
    pub(crate) fn pact_grant(&self) -> Option<crate::EntityId> {
        self.pact.as_ref().map(|(grant, _)| *grant)
    }

    /// The scope a pact-bound transfer takes at this serve: its requested
    /// scope met with its pact's effective scope, while that pact holds in
    /// `fold` (FIX 11860); `None` with no pact bound, or once the pact ended,
    /// was suspended or no longer covers what the transfer requested.
    #[must_use]
    pub(crate) fn served_pact_scope(
        &self,
        fold: &AuthorityFold,
    ) -> Option<crate::federation::FederationDirectionScope> {
        let (grant, requested) = self.pact.as_ref()?;
        witnessed_pact_scope(fold, grant, requested).ok()
    }
}

impl CapabilitySlip {
    /// `None` while the mint's own binding key still proves this slip: the
    /// original recipient, whose retrieval stays byte-identical. Otherwise
    /// the bounds its caveats leave the holder, met by the same meet live
    /// verification takes, over a chain [`Self::verify_origin`] already
    /// authenticated; a caveat that meet refuses comes back as its error.
    pub(crate) fn transferred_bounds(&self) -> Option<EngineResult<TransferredBounds>> {
        if self.current_binding_key() == self.claims.binding_key {
            return None;
        }
        let mut effective = self.claims.clone();
        effective.expires_at = u64::MAX;
        effective.ttl_secs = u64::MAX;
        let mut pact = None;
        let mut records_constrained =
            !effective.records.is_empty() || !effective.channels.is_empty();
        for block in &self.caveats {
            if let Err(error) = meet_caveat(
                &mut effective,
                &mut pact,
                &mut records_constrained,
                &block.caveat,
            ) {
                return Some(Err(error));
            }
        }
        Some(Ok(TransferredBounds {
            deadline: effective
                .expires_at
                .min(effective.issued_at.saturating_add(effective.ttl_secs)),
            records: records_constrained.then_some(effective.records),
            channel_bound: !effective.channels.is_empty(),
            scope: effective.scope,
            single_use: effective.single_use,
            pact,
        }))
    }
}

/// What a slip's mint and signed caveats leave its holder, met as live
/// verification meets them, with no clock, liveness or holder proof judged
/// (FIX 6108): the bounds a rebind holds a successor instrument within.
pub(crate) struct SignedBounds {
    pub(crate) claims: SlipClaims,
    /// The mint or a caveat named a record or channel set, so an empty set
    /// here admits no record at all.
    pub(crate) records_bound: bool,
    /// The pact bound a caveat set: its grant and the scope it requested.
    pub(crate) pact: Option<(crate::EntityId, crate::federation::FederationDirectionScope)>,
}

impl CapabilitySlip {
    /// [`SignedBounds`] of this slip, over a chain [`Self::verify_origin`]
    /// already authenticated; a caveat the meet refuses comes back as its
    /// error.
    pub(crate) fn signed_bounds(&self) -> EngineResult<SignedBounds> {
        let mut claims = self.claims.clone();
        let mut pact = None;
        let mut records_bound = !claims.records.is_empty() || !claims.channels.is_empty();
        for block in &self.caveats {
            meet_caveat(&mut claims, &mut pact, &mut records_bound, &block.caveat)?;
        }
        Ok(SignedBounds {
            claims,
            records_bound,
            pact,
        })
    }
}

fn mint_transcript(claims: &SlipClaims) -> EngineResult<Vec<u8>> {
    let mut bytes = MINT_CONTEXT.to_vec();
    bytes.extend_from_slice(&canonical(claims)?);
    Ok(bytes)
}

fn caveat_transcript(
    prefix: &CapabilitySlip,
    caveat: &SlipCaveat,
    next_key: &[u8; 32],
) -> EngineResult<Vec<u8>> {
    let mut bytes = CAVEAT_CONTEXT.to_vec();
    bytes.extend_from_slice(&canonical(prefix)?);
    bytes.extend_from_slice(&canonical(caveat)?);
    bytes.extend_from_slice(next_key);
    Ok(bytes)
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(super) fn unhex(value: &str) -> EngineResult<Vec<u8>> {
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
