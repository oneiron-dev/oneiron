//! DoorCredential attenuation, lifetime math, and floor-naming evaluation.

use std::collections::BTreeSet;

use super::door_types::{
    CredentialDoorError, DoorCredentialStatus, DoorDenyReason, DoorResult, TtlCeiling,
    names_a_floor,
};
use crate::secret_lease::VaultInstant;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum DoorGrant {
    Capability(Box<crate::authority::VerifiedSlip>),
    Checkout {
        ticket: String,
        scope: crate::federation::Scope,
    },
    #[cfg(test)]
    Witnessed(crate::federation::Scope),
}

/// One presented capability slip, as the door sees it.
///
/// Deliberately NOT `Clone`: a one-shot is consumed by move, and a type that
/// can be duplicated cannot carry that guarantee. Deliberately without token
/// material: identifiers and bounds only, so `Debug` is safe by construction.
///
/// Every field is private and the constructor is the only door in. The
/// constructor does NOT verify anything — it records that verification
/// already happened upstream. A blank holder view therefore fails closed at
/// evaluation instead of pretending a caller-supplied string is proof.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DoorCredential {
    slip_id: String,
    holder_ref: String,
    pub(super) grant: DoorGrant,
    pub(super) records: BTreeSet<String>,
    pub(super) channels: BTreeSet<String>,
    issued_at: u64,
    expires_at: u64,
    status: DoorCredentialStatus,
    pub(super) single_use: bool,
    pub(super) ttl_cap: TtlCeiling,
}

impl DoorCredential {
    /// The capability constructor accepts only a MAC/log/binding-verified slip.
    pub(crate) fn from_verified_slip(verified: &crate::authority::VerifiedSlip) -> Self {
        let claims = verified.claims();
        Self {
            slip_id: claims.slip_id.iter().map(|b| format!("{b:02x}")).collect(),
            holder_ref: claims.holder_ref.clone(),
            grant: DoorGrant::Capability(Box::new(verified.clone())),
            records: claims.records.clone(),
            channels: claims.channels.clone(),
            issued_at: claims.issued_at,
            expires_at: claims.expires_at,
            status: DoorCredentialStatus::Active,
            single_use: claims.single_use,
            ttl_cap: TtlCeiling::default().meet_secs(claims.ttl_secs),
        }
    }
    pub(super) fn from_checkout(
        ticket: &str,
        lease: &crate::checkout::lease::CheckoutLeaseAct,
    ) -> Self {
        Self {
            slip_id: format!("checkout:{ticket}"),
            holder_ref: lease.holder_ref.clone(),
            grant: DoorGrant::Checkout {
                ticket: ticket.to_owned(),
                scope: super::verb_class::preset("door.push").unwrap_or_default(),
            },
            records: [super::door_types::repo_record(&lease.repo_ref)].into(),
            channels: [super::door_types::DOOR_RECEIVE_PACK_EFFECTOR.to_owned()].into(),
            issued_at: lease.claimed_at,
            expires_at: lease.lease_expires_at.unwrap_or(0),
            status: DoorCredentialStatus::Active,
            single_use: false,
            ttl_cap: TtlCeiling::default(),
        }
    }

    /// Unverified bounds are available outside this module only to fixtures.
    #[cfg(test)]
    pub(crate) fn verified(
        slip_id: impl Into<String>,
        holder_ref: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            slip_id: slip_id.into(),
            holder_ref: holder_ref.into(),
            grant: DoorGrant::Witnessed(crate::federation::Scope::default()),
            records: BTreeSet::new(),
            channels: BTreeSet::new(),
            issued_at,
            expires_at,
            status: DoorCredentialStatus::Active,
            single_use: false,
            ttl_cap: TtlCeiling::default(),
        }
    }

    /// The claims namespace is carried by provenance, never inferred from hex text.
    pub(super) fn capability_identity(&self) -> Option<([u8; 32], [u8; 32])> {
        match &self.grant {
            DoorGrant::Capability(verified) => {
                Some((verified.claims().slip_id, verified.claims().vault_id))
            }
            DoorGrant::Checkout { .. } => None,
            #[cfg(test)]
            DoorGrant::Witnessed(_) => None,
        }
    }

    /// Verbs the fixture grants.
    #[cfg(test)]
    pub(super) fn with_verbs<I, S>(mut self, verbs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if let DoorGrant::Witnessed(scope) = &mut self.grant {
            scope.verbs =
                crate::federation::ScopeAxis::Some(verbs.into_iter().map(Into::into).collect());
        }
        self
    }

    /// Records (repositories, secret names) the slip bounds.
    #[cfg(test)]
    pub(super) fn with_records<I, S>(mut self, records: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.records = records.into_iter().map(Into::into).collect();
        self
    }

    /// Channels (door effectors) the slip bounds.
    #[cfg(test)]
    pub(super) fn with_channels<I, S>(mut self, channels: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.channels = channels.into_iter().map(Into::into).collect();
        self
    }

    /// Records a DIRECT revocation.
    ///
    /// Monotone by construction: revocation is a join up the status order
    /// ([`DoorCredentialStatus::join`]), so it is idempotent, it survives any
    /// cascade that arrives later, and it has no inverse. There is deliberately
    /// no way back — `Revoked -> Active` is not an operation this type offers,
    /// so it is not a state machine the caller can be talked into.
    pub(crate) fn revoked(mut self) -> Self {
        self.status = self.status.join(DoorCredentialStatus::Revoked);
        self
    }

    /// Records a PARENT slip's revocation cascading down.
    ///
    /// The same join, one rank lower: it kills a live slip, and it leaves an
    /// already directly-revoked slip exactly as revoked as it was rather than
    /// rewriting the reason it died.
    pub(super) fn parent_revoked(mut self) -> Self {
        self.status = self.status.join(DoorCredentialStatus::ParentRevoked);
        self
    }

    /// Attaches the single-use caveat.
    #[cfg(test)]
    pub(super) fn with_single_use_caveat(mut self) -> Self {
        self.single_use = true;
        self
    }

    /// Slip-side attenuation of the lease TTL. Narrowing only: the effective
    /// ceiling is a minimum, so a slip asking for more than the floor gets the
    /// floor, never more.
    ///
    /// Attenuation is also narrowing with respect to ITSELF. A verifier may
    /// apply one TTL caveat per slip in the chain, and the caveats arrive in
    /// whatever order the chain is walked; storing the new value would let a
    /// later, looser caveat restore authority an earlier one had already
    /// given up. So the caveat is merged by [`TtlCeiling::meet`] — the lattice
    /// minimum — which makes repeated attenuation idempotent, monotone, and
    /// independent of caveat order, and leaves the tightest caveat in the
    /// chain standing however late the loosest one arrives.
    #[cfg(test)]
    pub(super) fn attenuate_lease_ttl(mut self, secs: u64) -> Self {
        self.ttl_cap = self.ttl_cap.meet_secs(secs);
        self
    }

    /// The non-secret slip identifier.
    pub(crate) fn slip_id(&self) -> &str {
        &self.slip_id
    }

    /// The non-secret holder reference.
    pub(crate) fn holder_ref(&self) -> &str {
        &self.holder_ref
    }

    /// Whether the single-use caveat is present.
    pub(super) fn is_single_use(&self) -> bool {
        self.single_use
    }

    /// The credential's declared lifetime in seconds.
    pub(super) fn lifetime_secs(&self) -> u64 {
        self.expires_at.saturating_sub(self.issued_at)
    }

    /// How much of the credential's validity is LEFT at `now`, in seconds.
    ///
    /// This is the bound every ticket the credential buys sits under: a lease
    /// that outlives the slip that bought it turns the slip's expiry into a
    /// suggestion, and a half-spent slip would otherwise buy a full-length
    /// ticket. `now` is the same vault-witnessed instant [`Self::evaluate`]
    /// admits against — the credential's `expires_at` is an external wire
    /// fact, and it is compared against the vault's reading rather than
    /// against anything the presenter chose.
    ///
    /// A DURATION is only half the bound, and it is deliberately the half that
    /// answers "may this be asked for". The absolute half — "when does the
    /// ticket die" — travels with the materialization request, derived from
    /// this same instant; see
    /// [`CredentialDoorService::issue_lease_ticket`].
    pub(super) fn remaining_secs(&self, now: VaultInstant) -> u64 {
        self.expires_at.saturating_sub(now.secs())
    }

    /// The ONE evaluator call: `verb ∈ slip ∧ record ⊑ slip ∧ record ⊑ channel`,
    /// under the slip's lifetime and revocation state.
    ///
    /// Nothing about the caller's network position enters here. That is the
    /// point: "localhost" is a route, not a principal.
    ///
    /// Nothing about the caller's CLOCK enters here either, for the same
    /// reason. `now` is a [`VaultInstant`] — a reading the vault took — so the
    /// lifetime arm below is a comparison of the slip's declared window
    /// against the engine's own observation, not against a number the
    /// presenter handed in alongside the slip.
    pub(super) fn evaluate(
        &self,
        verb: &str,
        record: &str,
        channel: &str,
        now: VaultInstant,
    ) -> DoorResult<()> {
        self.reject_floor_naming()?;
        let deny = |reason| Err(CredentialDoorError::UnauthorizedPrincipal { reason });

        if self.slip_id.is_empty() || self.holder_ref.is_empty() {
            return deny(DoorDenyReason::HolderUnverified);
        }
        match self.status {
            DoorCredentialStatus::Revoked => return deny(DoorDenyReason::Revoked),
            DoorCredentialStatus::ParentRevoked => return deny(DoorDenyReason::ParentRevoked),
            DoorCredentialStatus::Active => {}
        }
        let now_secs = now.secs();
        if now_secs < self.issued_at || now_secs >= self.expires_at {
            return deny(DoorDenyReason::Expired);
        }
        if record.is_empty() || !self.records.contains(record) {
            return deny(DoorDenyReason::RecordOutsideSlip);
        }
        if channel.is_empty() || !self.channels.contains(channel) {
            return deny(DoorDenyReason::ChannelOutsideSlip);
        }
        let admits = self.scope().verbs.contains(&verb.to_owned());
        if !admits {
            return deny(DoorDenyReason::VerbNotInSlip);
        }
        Ok(())
    }

    fn scope(&self) -> &crate::federation::Scope {
        match &self.grant {
            DoorGrant::Capability(verified) => verified.scope(),
            DoorGrant::Checkout { scope, .. } => scope,
            #[cfg(test)]
            DoorGrant::Witnessed(scope) => scope,
        }
    }

    /// A slip may not reach a floor either. Verbs, records and channels are
    /// lattice tokens; floors are not in the lattice.
    fn reject_floor_naming(&self) -> DoorResult<()> {
        let reject = |token: &String| {
            if names_a_floor(token) {
                Err(CredentialDoorError::FloorNamed {
                    site: "credential",
                    name: token.clone(),
                })
            } else {
                Ok(())
            }
        };
        if let crate::federation::ScopeAxis::Some(verbs) = &self.scope().verbs {
            for verb in verbs {
                reject(verb)?;
            }
        }
        for token in self.records.iter().chain(self.channels.iter()) {
            reject(token)?;
        }
        Ok(())
    }
}
