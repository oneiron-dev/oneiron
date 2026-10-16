//! Channel-identity consume door with usage accounting.

use super::codec::invalid_grant;
use super::grant::StandingOutboundGrant;
use super::mint::standing_outbound_grant_in_txn;
use super::scope::StandingOutboundGrantScope;
use crate::Vault;
use crate::channel_identity_autonomy::ChannelIdentityEffectCandidate;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::Store;

/// One usage row per immutable envelope, shared by all grants naming it.
pub const CHANNEL_IDENTITY_GRANT_USAGE_PREFIX: &[u8] = b"outbound_grant:channel_identity_usage:v1:";

/// One envelope's usage window: the window start plus the spent
/// `(effect_key, fingerprint)` pairs. Keyed by the envelope id.
const USAGE: SideTable<EntityId, ChannelIdentityGrantUsage, Raw> =
    SideTable::new(&side_table::OUTBOUND_GRANT_CHANNEL_IDENTITY_USAGE);

#[derive(Clone, PartialEq, Eq)]
struct ChannelIdentityGrantUsage {
    started: u64,
    effects: Vec<([u8; 32], [u8; 32])>,
}

impl RawValue for ChannelIdentityGrantUsage {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut bytes = self.started.to_be_bytes().to_vec();
        bytes.extend_from_slice(&(self.effects.len() as u32).to_be_bytes());
        for (effect, fingerprint) in &self.effects {
            bytes.extend_from_slice(effect);
            bytes.extend_from_slice(fingerprint);
        }
        Ok(bytes)
    }

    fn from_raw(raw: &[u8]) -> std::result::Result<Self, CodecError> {
        if raw.len() < 12 || !(raw.len() - 12).is_multiple_of(64) {
            return Err(invalid_grant().into());
        }
        let started = u64::from_be_bytes(raw[..8].try_into().map_err(|_| invalid_grant())?);
        let used = u32::from_be_bytes(raw[8..12].try_into().map_err(|_| invalid_grant())?);
        if used as usize != (raw.len() - 12) / 64 {
            return Err(invalid_grant().into());
        }
        let mut effects = Vec::with_capacity(used as usize);
        for pair in raw[12..].chunks_exact(64) {
            effects.push((
                pair[..32].try_into().map_err(|_| invalid_grant())?,
                pair[32..].try_into().map_err(|_| invalid_grant())?,
            ));
        }
        Ok(Self { started, effects })
    }
}

impl Vault {
    /// Atomically authorizes and reserves an action using the engine clock.
    ///
    /// A true retry reuses the reservation; it is not permission to execute a
    /// second delivery. Dispatch must retain the same engine effect key. This
    /// door never reads a caller timestamp or delegates to `matches_effect`.
    pub fn authorize_and_consume_channel_identity_grant(
        &self,
        grant_ref: &EntityId,
        candidate: &ChannelIdentityEffectCandidate,
    ) -> Result<bool> {
        self.consume_channel_identity_grant_at(
            grant_ref,
            candidate,
            self.store.authorization_now()?,
        )
    }

    fn consume_channel_identity_grant_at(
        &self,
        grant_ref: &EntityId,
        candidate: &ChannelIdentityEffectCandidate,
        now: u64,
    ) -> Result<bool> {
        let mut txn = self.store.env.write_txn()?;
        let Some(reservation) =
            reserve_channel_identity_grant_in_txn(&self.store, &txn, grant_ref, candidate, now)?
        else {
            return Ok(false);
        };
        reservation.commit_in_txn(&self.store, &mut txn, now)?;
        txn.commit()?;
        Ok(true)
    }
}

/// One envelope slot proven on the caller's transaction and not yet spent.
/// [`Self::commit_in_txn`] spends it; dropping it spends nothing, so a caller
/// that holds, denies or aborts its effect leaves the window untouched.
pub(crate) struct ChannelIdentityGrantReservation {
    grant_ref: EntityId,
    grant: StandingOutboundGrant,
    envelope_ref: EntityId,
    /// The usage row this reservation was proven against.
    prior: Option<ChannelIdentityGrantUsage>,
    /// The window with this effect added, or `None` for an exact replay
    /// whose slot was spent when it was first reserved.
    next: Option<ChannelIdentityGrantUsage>,
}

impl ChannelIdentityGrantReservation {
    /// Spends the slot and touches the grant as used, in the caller's write
    /// txn. An exact replay writes nothing, so it is never charged twice.
    pub(crate) fn commit_in_txn(
        self,
        store: &Store,
        wtxn: &mut heed::RwTxn<'_>,
        now: u64,
    ) -> Result<()> {
        let Some(next) = self.next else {
            return Ok(());
        };
        // A second reservation of the same envelope inside one txn was proven
        // on the row this one is about to replace: fail the txn, never lose
        // a spent slot.
        if USAGE.get(store, &*wtxn, &self.envelope_ref)? != self.prior {
            return Err(Error::InvariantViolation(
                "channel identity envelope changed inside admission transaction",
            ));
        }
        USAGE.put(store, wtxn, &self.envelope_ref, &next)?;
        crate::ports::EntityStoreMaintenance::port_outbound_grant_touch(
            store,
            wtxn,
            &self.grant_ref,
            self.grant,
            now,
        )
    }
}

/// Authorizes one channel-identity action against its envelope on the
/// caller's transaction and returns the slot it would spend, without writing.
/// `None` is a denial: absent, revoked or mismatched authority, a spent
/// window, or a clock rollback. Structural/storage failures stay errors; no
/// error ever falls through to a less constrained dial.
pub(crate) fn reserve_channel_identity_grant_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    grant_ref: &EntityId,
    candidate: &ChannelIdentityEffectCandidate,
    now: u64,
) -> Result<Option<ChannelIdentityGrantReservation>> {
    use crate::channel_identity_autonomy::{AutonomyReader, ChannelIdentityAutonomyRung};

    let reader = AutonomyReader { store };
    let Some(grant) = standing_outbound_grant_in_txn(store, txn, grant_ref)? else {
        return Ok(None);
    };
    let StandingOutboundGrantScope::ChannelIdentityEnvelope {
        identity_ref,
        envelope_ref,
        verb_class,
    } = &grant.scope
    else {
        return Ok(None);
    };
    let envelope_ref = *envelope_ref;
    let verb = candidate.verb_class.trim().to_ascii_lowercase();
    if *identity_ref != candidate.identity_ref || *verb_class != verb {
        return Ok(None);
    }
    let envelope = match reader.validate_autonomy_action(txn, &grant, now) {
        Ok(envelope) => envelope,
        Err(Error::Gate(GateError::InvalidConsentBound(_))) => return Ok(None),
        Err(error) => return Err(error),
    };
    if envelope.relationship_context != candidate.relationship_context
        || envelope.counterparty_class != candidate.counterparty_class
    {
        return Ok(None);
    }
    let mode = match reader.autonomy_mode_in_txn(
        txn,
        candidate.identity_ref,
        candidate.relationship_context,
        now,
        now,
    ) {
        Ok(mode) => mode,
        Err(Error::Gate(GateError::InvalidConsentBound(_))) => return Ok(None),
        Err(error) => return Err(error),
    };
    if mode.action_grant_ref != Some(*grant_ref)
        || (verb == "mail.send"
            && mode.rung != ChannelIdentityAutonomyRung::AutonomousWithinEnvelope)
    {
        return Ok(None);
    }
    let prior = USAGE.get(store, txn, &envelope_ref)?;
    let mut started = now;
    let mut effects = Vec::<([u8; 32], [u8; 32])>::new();
    if let Some(usage) = prior.clone() {
        if usage.effects.len() as u32 > envelope.max_actions {
            return Err(invalid_grant());
        }
        started = usage.started;
        // Clock rollback cannot reset a window or spend a fresh slot.
        if now < started {
            return Ok(None);
        }
        if now - started < envelope.window_secs {
            effects = usage.effects;
        } else {
            started = now;
        }
    }
    let fingerprint = *blake3::hash(verb.as_bytes()).as_bytes();
    let reservation = |next| ChannelIdentityGrantReservation {
        grant_ref: *grant_ref,
        grant: grant.clone(),
        envelope_ref,
        prior: prior.clone(),
        next,
    };
    if let Some((_, stored)) = effects.iter().find(|(key, _)| *key == candidate.effect_key) {
        return Ok((*stored == fingerprint).then(|| reservation(None)));
    }
    if effects.len() >= envelope.max_actions as usize {
        return Ok(None);
    }
    effects.push((candidate.effect_key, fingerprint));
    Ok(Some(reservation(Some(ChannelIdentityGrantUsage { started, effects }))))
}
