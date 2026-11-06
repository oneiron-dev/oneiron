//! A seat run's credential helper (FIX 10624 step 2; ARCH-0069 T1, the
//! credential-helper shim): begun before the CLI starts, ended once it is
//! done.
//!
//! The host binds helper destinations (`[runtime.helper_destinations]`); a
//! run reaches those whose secret its pinned manifest declares. For such a
//! run the host mints a seat-child slip under its issuer, for the claim's
//! own Agent PERSON and a key generated for the run, naming those secrets;
//! registers the destinations under the claim; and hands the CLI the slip,
//! the seed, the loopback origin and the git configuration that calls this
//! binary as the helper for each bound context. At the end it revokes the
//! slip, closes the registration, tears down every grant the helper took
//! and hands back their taint for the run's exhaust.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use oneiron::AttemptId;
use oneiron::authority::SeatClaimSlipBinding;
use oneiron::checkout::CheckoutLeaseAct;
use oneiron::dispatch_byoa::{
    ByoaExecutionFence, ByoaResult, pinned_secret_manifest, seat_child_holder,
};
use oneiron::edge::EdgeActorClass;
use oneiron::secret_lease::{SecretGrantCaller, SecretTaintRef};
use oneiron::{EntityId, Vault};
use zeroize::Zeroizing;

use super::super::{
    HelperDestination, HelperReplyDelivery, SeatHelperEnv, SeatHelperRun,
    is_helper_destination_name,
};
use crate::server::SyncServer;

/// One run's credential helper while its CLI runs.
pub(super) struct SeatHelper {
    attempt: AttemptId,
    holder: EntityId,
    slip_id: [u8; 32],
    registration: SeatHelperRun,
    env: SeatHelperEnv,
}

impl SeatHelper {
    /// Begins the helper of `fence`'s run over `checkout`, its slip ending
    /// `ttl_secs` from now, or `None` when the host binds no helper
    /// destination the run declares. A host that cannot serve one (no
    /// issuer, no loopback listener) begins none and says so.
    ///
    /// # Errors
    /// The pinned manifest's read, the holder's or the slip's mint: the run
    /// then fails before its CLI starts.
    pub(super) fn begin(
        server: &SyncServer,
        fence: &ByoaExecutionFence,
        checkout: &CheckoutLeaseAct,
        ttl_secs: u64,
    ) -> ByoaResult<Option<Self>> {
        let bound = &server.config.runtime.helper_destinations;
        if bound.is_empty() {
            return Ok(None);
        }
        let vault = server.vault();
        let Some(manifest) = pinned_secret_manifest(vault, checkout)? else {
            return Ok(None);
        };
        let declared: BTreeSet<&str> = manifest
            .secrets
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        let destinations: BTreeMap<String, HelperDestination> = bound
            .iter()
            .filter(|(name, destination)| {
                let plain = is_helper_destination_name(name) && destination.is_plain_context();
                if !plain {
                    tracing::warn!(
                        destination = %name,
                        "a helper destination's name or git context cannot ride git's config; it is not offered"
                    );
                }
                plain && declared.contains(destination.secret.as_str())
            })
            .map(|(name, destination)| (name.clone(), destination.clone()))
            .collect();
        if destinations.is_empty() {
            return Ok(None);
        }
        let (Some(issuer), Some(origin), Ok(program)) = (
            server.host_issuer(),
            server.loopback_api_origin(),
            std::env::current_exe(),
        ) else {
            tracing::warn!(
                "the seat host has no issuer, loopback listener or binary path; the run's credential helper is not offered"
            );
            return Ok(None);
        };
        let holder = seat_child_holder(
            vault,
            fence.attempt_id,
            &fence.lease_owner,
            fence.attempt_count,
        )?;
        let key = SigningKey::generate(&mut rand_core::OsRng);
        let claim = SeatClaimSlipBinding {
            attempt: *fence.attempt_id.as_bytes(),
            lease_owner: fence.lease_owner.clone(),
            attempt_count: fence.attempt_count,
        };
        let records = destinations
            .values()
            .map(|destination| destination.secret.clone())
            .collect();
        let slip = vault.mint_seat_child_slip(
            issuer,
            claim,
            holder,
            key.verifying_key().to_bytes(),
            records,
            ttl_secs,
        )?;
        let slip_id = slip.claims.slip_id;
        let token = match slip.to_token() {
            Ok(token) => Zeroizing::new(token),
            Err(error) => {
                revoke_slip(server, slip_id);
                return Err(error.into());
            }
        };
        let seed = Zeroizing::new(
            key.to_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        );
        let env = SeatHelperEnv::new(token, seed, origin, &program, &destinations);
        let registration = server.seat_helpers.register(
            fence.attempt_id,
            &fence.lease_owner,
            fence.attempt_count,
            destinations,
        );
        Ok(Some(Self {
            attempt: fence.attempt_id,
            holder,
            slip_id,
            registration,
            env,
        }))
    }

    /// The environment the run's CLI starts with.
    pub(super) fn env(&self) -> SeatHelperEnv {
        self.env.clone()
    }

    /// Ends the helper: the slip is revoked, the registration closed, every
    /// grant the helper took torn down, and their taint handed back for the
    /// run's exhaust. A grant that cannot be torn down now ends at its
    /// expiry.
    pub(super) fn end(self, server: &SyncServer) -> Vec<SecretTaintRef> {
        revoke_slip(server, self.slip_id);
        let end = server
            .seat_helpers
            .retire_own(self.attempt, &self.registration);
        if !end.grants.is_empty() {
            teardown(server.vault(), self.attempt, self.holder, &end.grants);
        }
        end.taints
    }
}

fn revoke_slip(server: &SyncServer, slip_id: [u8; 32]) {
    let Some(issuer) = server.host_issuer() else {
        return;
    };
    if let Err(error) = server.vault().revoke_capability_slip(issuer, slip_id) {
        tracing::warn!(%error, "a seat run's helper slip could not be revoked; it ends at its expiry or with its claim");
    }
}

fn teardown(vault: &Vault, attempt: AttemptId, holder: EntityId, grants: &[EntityId]) {
    let caller = match SecretGrantCaller::of(
        &vault.memory(holder, EdgeActorClass::Agent),
        Some(attempt),
    ) {
        Ok(caller) => caller,
        Err(error) => {
            tracing::warn!(%error, "a seat run's helper grants could not be torn down; they end at their expiry");
            return;
        }
    };
    for grant in grants {
        // The value went back to the helper; nothing of it stays here.
        let mut delivery = HelperReplyDelivery::new(attempt, String::new(), String::new());
        if let Err(error) = vault.teardown_secret_grant(&caller, grant, &mut delivery) {
            tracing::warn!(%error, "a seat run's helper grant could not be torn down; it ends at its expiry");
        }
    }
}
