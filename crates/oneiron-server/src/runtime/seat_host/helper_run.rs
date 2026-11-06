//! A seat run's credential helper (FIX 10624 step 2; ARCH-0069 T1, the
//! credential-helper shim) and model door (FIX 15702 slice 1; ARCH-0069
//! `#door-sign-loopback`): begun before the CLI starts, ended once it is
//! done.
//!
//! The host binds helper destinations (`[runtime.helper_destinations]`) and
//! model door slots (`[runtime.seat_model_providers]`); a run reaches those
//! whose secret its pinned manifest declares. For such a run the host mints
//! a seat-child slip under its issuer, for the claim's own Agent PERSON and
//! a key generated for the run, naming those secrets, with the model door's
//! channel when a slot is offered; registers the destinations and slots
//! under the claim; and hands the CLI the slip, the seed, the loopback
//! origin and the git configuration that calls this binary as the helper
//! for each bound context, and for the model door each slot's loopback URL
//! and a fresh reference to it. The model door presents the slip on the
//! run's behalf: the host admits it once with its own holder proof and
//! keeps the opaque credential, which every key release rechecks. At the
//! end it revokes the slip, closes the registration, tears down every grant
//! the helper took and hands back their taint, and the taint of every key
//! the model door released, for the run's exhaust.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ed25519_dalek::{Signer as _, SigningKey};
use oneiron::AttemptId;
use oneiron::authority::{
    CapabilitySlip, SeatChildCredential, SeatClaimSlipBinding, holder_proof_challenge,
};
use oneiron::checkout::CheckoutLeaseAct;
use oneiron::dispatch_byoa::{
    ByoaExecutionFence, ByoaResult, pinned_secret_manifest, seat_child_holder,
};
use oneiron::edge::EdgeActorClass;
use oneiron::secret_lease::{SecretGrantCaller, SecretTaintRef};
use oneiron::{EntityId, Vault};
use zeroize::Zeroizing;

use super::super::{
    HelperDestination, HelperReplyDelivery, SeatHelperEnv, SeatHelperRun, SeatModelBinding,
    SeatModelEnv, SeatModelProtocol, SeatModelSlot, is_helper_destination_name,
    is_seat_model_slot_name, mint_reference,
};
use crate::models::SeatModelMeter;
use crate::server::SyncServer;

/// One run's credential helper and model door while its CLI runs.
pub(super) struct SeatHelper {
    attempt: AttemptId,
    holder: EntityId,
    slip_id: [u8; 32],
    registration: SeatHelperRun,
    /// The claim's run its model door calls are admitted on, when a slot is
    /// offered (FIX 15702 slice 3).
    meter: Option<Arc<SeatModelMeter>>,
    env: Option<SeatHelperEnv>,
    model_env: Option<SeatModelEnv>,
}

/// A model door slot the host offers a run, before its reference is minted.
struct OfferedSlot {
    provider: String,
    secret: String,
    protocol: SeatModelProtocol,
    models: BTreeSet<String>,
}

impl SeatHelper {
    /// Begins the helper and model door of `fence`'s run over `checkout`,
    /// its slip ending `ttl_secs` from now, or `None` when the host binds no
    /// helper destination and no model door slot the run declares. A host
    /// that cannot serve them (no issuer, no loopback listener) begins none
    /// and says so; one with no binary path offers the model door alone.
    ///
    /// # Errors
    /// The pinned manifest's read, the holder's, the slip's mint or its
    /// admission for the model door: the run then fails before its CLI
    /// starts.
    pub(super) fn begin(
        server: &SyncServer,
        fence: &ByoaExecutionFence,
        checkout: &CheckoutLeaseAct,
        ttl_secs: u64,
    ) -> ByoaResult<Option<Self>> {
        let bound = &server.config.runtime.helper_destinations;
        let bound_slots = &server.config.runtime.seat_model_providers;
        if bound.is_empty() && bound_slots.is_empty() {
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
        let mut destinations: BTreeMap<String, HelperDestination> = bound
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
        let slots = offered_slots(server, bound_slots, &declared);
        if destinations.is_empty() && slots.is_empty() {
            return Ok(None);
        }
        let (Some(issuer), Some(origin)) = (server.host_issuer(), server.loopback_api_origin())
        else {
            tracing::warn!(
                "the seat host has no issuer or loopback listener; the run's credential helper and model door are not offered"
            );
            return Ok(None);
        };
        // Git runs this binary as the helper; the model door needs no path.
        let program = if destinations.is_empty() {
            None
        } else {
            match std::env::current_exe() {
                Ok(program) => Some(program),
                Err(_) => {
                    tracing::warn!(
                        "the seat host has no binary path; the run's credential helper is not offered"
                    );
                    destinations.clear();
                    None
                }
            }
        };
        if destinations.is_empty() && slots.is_empty() {
            return Ok(None);
        }
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
            .chain(slots.values().map(|slot| slot.secret.clone()))
            .collect();
        let slip = vault.mint_seat_child_slip(
            issuer,
            claim,
            holder,
            key.verifying_key().to_bytes(),
            records,
            !slots.is_empty(),
            ttl_secs,
        )?;
        let slip_id = slip.claims.slip_id;
        let prepared = prepare(
            vault,
            &slip,
            &key,
            &origin,
            program.as_deref(),
            &destinations,
            &slots,
        );
        let (env, credential) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                revoke_slip(server, slip_id);
                return Err(error.into());
            }
        };
        let mut presented = BTreeMap::new();
        let mut registered = BTreeMap::new();
        for (name, offered) in slots {
            let reference = mint_reference();
            registered.insert(
                name.clone(),
                SeatModelSlot::new(
                    offered.provider,
                    offered.secret,
                    offered.protocol,
                    offered.models,
                    &reference,
                ),
            );
            presented.insert(name, (offered.protocol, reference));
        }
        let model_env = (!presented.is_empty())
            .then(|| SeatModelEnv::new(&origin, &presented))
            .filter(|env| !env.is_empty());
        // Every model door call is a paid call of the claim's own run, on
        // the vault's budget policy for its agent and its spend scope.
        let meter = if registered.is_empty() {
            None
        } else {
            match SeatModelMeter::open(server, fence, holder) {
                Ok(meter) => Some(meter),
                Err(error) => {
                    revoke_slip(server, slip_id);
                    return Err(error.into());
                }
            }
        };
        let registration = server.seat_helpers.register(
            fence.attempt_id,
            &fence.lease_owner,
            fence.attempt_count,
            destinations,
            registered,
            credential,
            meter.clone(),
        );
        Ok(Some(Self {
            attempt: fence.attempt_id,
            holder,
            slip_id,
            registration,
            meter,
            env,
            model_env,
        }))
    }

    /// The credential-helper environment the run's CLI starts with, when a
    /// helper destination is offered.
    pub(super) fn env(&self) -> Option<SeatHelperEnv> {
        self.env.clone()
    }

    /// The model door environment the run's CLI starts with, when a slot is
    /// offered.
    pub(super) fn model_env(&self) -> Option<SeatModelEnv> {
        self.model_env.clone()
    }

    /// Ends the helper and model door: the slip is revoked, the registration
    /// closed (no reference to its slots is answered again), every grant the
    /// helper took torn down, and their taint and that of every key the door
    /// released handed back for the run's exhaust. A grant that cannot be
    /// torn down now ends at its expiry.
    pub(super) fn end(self, server: &SyncServer) -> Vec<SecretTaintRef> {
        revoke_slip(server, self.slip_id);
        let end = server
            .seat_helpers
            .retire_own(self.attempt, &self.registration);
        // What the claim's model calls spent and no look booked goes on its
        // spend scope; a call still settling books its own.
        if let Some(meter) = &self.meter {
            meter.book_rest();
        }
        if !end.grants.is_empty() {
            teardown(server.vault(), self.attempt, self.holder, &end.grants);
        }
        end.taints
    }
}

/// The slots of `bound` a run declaring `declared` is offered: each names a
/// provider this host's broker context sends through for the model door, its
/// key declared by the run, and at least one model.
fn offered_slots(
    server: &SyncServer,
    bound: &BTreeMap<String, SeatModelBinding>,
    declared: &BTreeSet<&str>,
) -> BTreeMap<String, OfferedSlot> {
    if bound.is_empty() {
        return BTreeMap::new();
    }
    let Some(context) = server.broker_context() else {
        tracing::warn!(
            "the seat host has no credential broker context; the run's model door is not offered"
        );
        return BTreeMap::new();
    };
    bound
        .iter()
        .filter_map(|(name, binding)| {
            let provider = context.seat_model_provider(&binding.provider);
            if !is_seat_model_slot_name(name) || provider.is_none() || binding.models.is_empty() {
                tracing::warn!(
                    slot = %name,
                    "a seat model slot's name, provider or model list cannot serve the model door; it is not offered"
                );
                return None;
            }
            let provider = provider?;
            declared
                .contains(provider.secret.as_str())
                .then(|| {
                    (
                        name.clone(),
                        OfferedSlot {
                            provider: binding.provider.clone(),
                            secret: provider.secret.clone(),
                            protocol: provider.protocol,
                            models: binding.models.clone(),
                        },
                    )
                })
        })
        .collect()
}

/// What the run's CLI is handed for its helper, and the credential the
/// model door presents for it: the slip admitted once, with a fresh holder
/// proof the host signs with the run's key, when a slot is offered.
fn prepare(
    vault: &Vault,
    slip: &CapabilitySlip,
    key: &SigningKey,
    origin: &str,
    program: Option<&std::path::Path>,
    destinations: &BTreeMap<String, HelperDestination>,
    slots: &BTreeMap<String, OfferedSlot>,
) -> oneiron::Result<(Option<SeatHelperEnv>, Option<SeatChildCredential>)> {
    let env = match program {
        Some(program) if !destinations.is_empty() => {
            let token = Zeroizing::new(slip.to_token()?);
            let seed = Zeroizing::new(
                key.to_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            );
            Some(SeatHelperEnv::new(
                token,
                seed,
                origin.to_owned(),
                program,
                destinations,
            ))
        }
        _ => None,
    };
    let credential = if slots.is_empty() {
        None
    } else {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = key.sign(&slip.binding_transcript(&challenge)?);
        Some(vault.admit_seat_child_slip_request(
            slip,
            timestamp,
            &signature.to_bytes(),
            nonce.as_bytes(),
        )?)
    };
    Ok((env, credential))
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
