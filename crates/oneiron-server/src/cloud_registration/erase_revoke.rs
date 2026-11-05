//! The pinned registration client's one revoke-only erase consumer.

use oneiron::secret_custody::{CloudRegistrationEraseRevoke, CloudRegistrationEraseRevoker};

use super::discovery::discover;
use super::{CloudRegistration, Http, Revoke, TokenSet, revoke};

impl CloudRegistration {
    pub(crate) fn attach_erase_revoker(
        &self,
        vault: &oneiron::Vault,
    ) -> Option<CloudRegistrationEraseRevoker> {
        let pins = self.pins().ok()?;
        Some(vault.attach_cloud_registration_erase_revoker(&pins.issuer, &pins.audience))
    }

    pub(crate) fn revoke_after_owner_erase(&self, capture: CloudRegistrationEraseRevoke) {
        let Ok(pins) = self.pins() else {
            return;
        };
        if capture.issuer != pins.issuer || capture.audience != pins.audience {
            return;
        }
        // The same family serialization as logout and refresh, on this
        // blocking worker only. The erase has already committed.
        let _family = self.family();
        let Ok(http) = Http::new() else {
            tracing::warn!("cloud registration erase revoke transport was unavailable");
            return;
        };
        let Ok(endpoints) = discover(&http, pins) else {
            tracing::warn!("cloud registration erase revoke discovery failed");
            return;
        };
        capture.with_token_set_for_revoke(|bytes| {
            let Some(set) = TokenSet::decode(bytes) else {
                tracing::warn!("a cloud registration erase revoke token set did not decode");
                return;
            };
            match revoke(&http, &endpoints, &set.refresh_token) {
                Revoke::Accepted => tracing::debug!("cloud registration erase revoke accepted"),
                Revoke::Failed { .. } | Revoke::NotAttempted { .. } => {
                    // A provider's failure text could echo credential bytes.
                    tracing::warn!("cloud registration erase revoke failed");
                }
            }
        });
    }
}
