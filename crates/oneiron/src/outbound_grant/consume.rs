//! Channel-identity consume door with usage accounting.

use super::codec::{encode_standing_outbound_grant_body, invalid_grant};
use super::mint::standing_outbound_grant_in_txn;
use super::scope::StandingOutboundGrantScope;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};

/// One usage row per immutable envelope, shared by all grants naming it.
pub const CHANNEL_IDENTITY_GRANT_USAGE_PREFIX: &[u8] = b"outbound_grant:channel_identity_usage:v1:";

impl Vault {
    /// Atomically authorizes and reserves an action using the engine clock.
    ///
    /// A true retry reuses the reservation; it is not permission to execute a
    /// second delivery. Dispatch must retain the same engine effect key. This
    /// door never reads a caller timestamp or delegates to `matches_effect`.
    pub fn authorize_and_consume_channel_identity_grant(
        &self,
        grant_ref: &EntityId,
        candidate: &crate::channel_identity_autonomy::ChannelIdentityEffectCandidate,
    ) -> Result<bool> {
        self.consume_channel_identity_grant_at(grant_ref, candidate, crate::unix_seconds_now())
    }

    fn consume_channel_identity_grant_at(
        &self,
        grant_ref: &EntityId,
        candidate: &crate::channel_identity_autonomy::ChannelIdentityEffectCandidate,
        now: u64,
    ) -> Result<bool> {
        use crate::channel_identity_autonomy::ChannelIdentityAutonomyRung;

        let mut txn = self.store.env.write_txn()?;
        let Some(grant) = standing_outbound_grant_in_txn(&self.store, &txn, grant_ref)? else {
            return Ok(false);
        };
        let StandingOutboundGrantScope::ChannelIdentityEnvelope {
            identity_ref,
            envelope_ref,
            verb_class,
        } = &grant.scope
        else {
            return Ok(false);
        };
        let verb = candidate.verb_class.trim().to_ascii_lowercase();
        if *identity_ref != candidate.identity_ref || *verb_class != verb {
            return Ok(false);
        }
        // Structural/storage failures stay errors. Absence/revocation/mismatch
        // are denials; no error ever falls through to a less constrained dial.
        let envelope = match self.validate_autonomy_action(&txn, &grant, now) {
            Ok(envelope) => envelope,
            Err(Error::Gate(GateError::InvalidConsentBound(_))) => return Ok(false),
            Err(error) => return Err(error),
        };
        if envelope.relationship_context != candidate.relationship_context
            || envelope.counterparty_class != candidate.counterparty_class
        {
            return Ok(false);
        }
        let mode = match self.autonomy_mode_in_txn(
            &txn,
            candidate.identity_ref,
            candidate.relationship_context,
            now,
        ) {
            Ok(mode) => mode,
            Err(Error::Gate(GateError::InvalidConsentBound(_))) => return Ok(false),
            Err(error) => return Err(error),
        };
        if mode.action_grant_ref != Some(*grant_ref)
            || (verb == "mail.send"
                && mode.rung != ChannelIdentityAutonomyRung::AutonomousWithinEnvelope)
        {
            return Ok(false);
        }
        let mut key = CHANNEL_IDENTITY_GRANT_USAGE_PREFIX.to_vec();
        key.extend_from_slice(envelope_ref.as_bytes());
        let mut started = now;
        let mut effects = Vec::<([u8; 32], [u8; 32])>::new();
        if let Some(raw) = self.store.vault_meta.get(&txn, &key)? {
            if raw.len() < 12 || (raw.len() - 12) % 64 != 0 {
                return Err(invalid_grant());
            }
            started = u64::from_be_bytes(raw[..8].try_into().map_err(|_| invalid_grant())?);
            let used = u32::from_be_bytes(raw[8..12].try_into().map_err(|_| invalid_grant())?);
            if used as usize != (raw.len() - 12) / 64 || used > envelope.max_actions {
                return Err(invalid_grant());
            }
            // Clock rollback cannot reset a window or spend a fresh slot.
            if now < started {
                return Ok(false);
            }
            if now - started < envelope.window_secs {
                for pair in raw[12..].chunks_exact(64) {
                    effects.push((
                        pair[..32].try_into().map_err(|_| invalid_grant())?,
                        pair[32..].try_into().map_err(|_| invalid_grant())?,
                    ));
                }
            } else {
                started = now;
            }
        }
        let fingerprint = *blake3::hash(verb.as_bytes()).as_bytes();
        if let Some((_, stored)) = effects.iter().find(|(key, _)| *key == candidate.effect_key) {
            return Ok(*stored == fingerprint);
        }
        if effects.len() >= envelope.max_actions as usize {
            return Ok(false);
        }
        effects.push((candidate.effect_key, fingerprint));
        let mut bytes = started.to_be_bytes().to_vec();
        bytes.extend_from_slice(&(effects.len() as u32).to_be_bytes());
        for (effect, fingerprint) in effects {
            bytes.extend_from_slice(&effect);
            bytes.extend_from_slice(&fingerprint);
        }
        self.store.vault_meta.put(&mut txn, &key, &bytes)?;
        let touched = grant.touched(now)?;
        self.apply_standing_outbound_grant_body(
            &mut txn,
            grant_ref,
            now,
            encode_standing_outbound_grant_body(&touched)?,
        )?;
        txn.commit()?;
        Ok(true)
    }
}
