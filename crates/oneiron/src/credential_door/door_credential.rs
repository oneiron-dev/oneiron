//! DoorCredential attenuation, lifetime math, and floor-naming evaluation.

use std::collections::BTreeSet;

use super::door_types::{CredentialDoorError, DoorDenyReason, DoorResult, names_a_floor};
use crate::secret_lease::VaultInstant;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum DoorGrant {
    Checkout {
        ticket: String,
        scope: crate::federation::Scope,
    },
    #[cfg(test)]
    Witnessed(crate::federation::Scope),
}

/// A bounded checkout credential with no token material in its Debug view.
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
}

impl DoorCredential {
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

    /// The non-secret slip identifier.
    pub(crate) fn slip_id(&self) -> &str {
        &self.slip_id
    }

    /// The non-secret holder reference.
    pub(crate) fn holder_ref(&self) -> &str {
        &self.holder_ref
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
        let admits = super::verb_class::class_for_verb(verb).is_some()
            && self.scope().verbs.contains(&verb.to_owned());
        if !admits {
            return deny(DoorDenyReason::VerbNotInSlip);
        }
        Ok(())
    }

    fn scope(&self) -> &crate::federation::Scope {
        match &self.grant {
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
