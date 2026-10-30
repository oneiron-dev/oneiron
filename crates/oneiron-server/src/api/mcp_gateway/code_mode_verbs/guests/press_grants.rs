//! The press policy the vault's standing action grants set for a run's
//! browser and desktop sends, and its live read at each classified send.
//! `browser_send_policy` and `VaultPressGrants` are its call surface.

use super::*;
use oneiron_browser::PressGrants;

/// The press policy the vault's standing action grants set for one run's
/// browser: a grant naming a browser effect class covers it (no press),
/// and a budgeted grant covers that many sends as one reviewed batch.
/// No grant leaves the floor: a press per send.
pub(super) fn browser_send_policy(server: &SyncServer) -> SendPolicy {
    grants_policy(&server.vault)
}

/// The press policy `vault`'s standing action grants set now, as
/// [`browser_send_policy`] reads it; the floor where they cannot be read.
fn grants_policy(vault: &oneiron::Vault) -> SendPolicy {
    let mut policy = SendPolicy::default();
    let Ok(grants) = vault.active_standing_consent_grants() else {
        return policy;
    };
    for grant in &grants {
        let StandingConsentGrant::Action(_) = grant else {
            continue;
        };
        let bound = grant.bound();
        let BoundClass::Action(class) = bound.class() else {
            continue;
        };
        let class = class.as_str();
        if !EFFECT_CLASSES.contains(&class) || SendPolicy::person_only(class) {
            continue;
        }
        let budget = match bound.envelope() {
            BoundEnvelope::Action(envelope) => envelope.budget(),
            BoundEnvelope::Disclosure(_) => None,
        };
        match budget {
            Some(count) => {
                policy.modes.insert(class.to_owned(), PressMode::PerBatch);
                policy
                    .batch
                    .insert(class.to_owned(), u32::try_from(count).unwrap_or(u32::MAX));
            }
            None => {
                policy.modes.insert(class.to_owned(), PressMode::None);
            }
        }
    }
    policy
}

/// The vault's grants, read again at each classified browser send (FIX
/// 4613): a grant revoked during the run covers no later send.
pub(super) struct VaultPressGrants(pub(super) Arc<oneiron::Vault>);

impl PressGrants for VaultPressGrants {
    fn current(&self) -> SendPolicy {
        grants_policy(&self.0)
    }
}
