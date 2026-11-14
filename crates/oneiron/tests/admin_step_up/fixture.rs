//! An org Admin's MFA step-up, for the integration tests (L7-17 PR 2): a
//! rooted vault whose host mints each person a live `human` credential, as
//! a transport verifies the slip a request presents, and a TOTP step-up on
//! that credential with the RFC 6238 code an authenticator app shows.
//!
//! A rooted vault's membership gate admits a writer only on a live binding,
//! and the host key holds one: [`bind_human_writer`] binds it to the person
//! about to act, and an owner acts again after
//! `oneiron::test_support::bind_host_owner`.
//!
//! One person steps up once per test: a person's second TOTP enrollment
//! needs a step-up already (`STEP_UP_REQUIRED`), and a code's 30-second
//! step is spent by its first use. Keep the stepped-up proof and reuse it.
#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::authority::{HostSlipIssuer, TotpCode, VerifiedSlip};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};

/// A vault whose host mints credentials: a device keystore, the engine's
/// machines, and the embedded owner bound to the host key. The owner.
pub(crate) fn rooted_vault(dir: &std::path::Path) -> (Vault, HostSlipIssuer, EntityId) {
    let vault = Vault::open(dir, VaultConfig::device()).expect("vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    (vault, issuer, owner)
}

/// Binds the host key to `person` at class `human`, as a served person's
/// own device binding does, so the rooted vault's membership gate admits
/// that person's writes. The owner, or whoever the key bound before, is
/// unbound until bound again.
pub(crate) fn bind_human_writer(vault: &Vault, issuer: &HostSlipIssuer, person: EntityId) {
    oneiron::test_support::bind_host_actor(vault, issuer, person, "human")
        .expect("the host key bound to the acting person");
}

/// A distinct slip id for each credential a test binary mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The live `human` credential the host mints `person`, verified as a
/// transport verifies the slip a request presents.
pub(crate) fn credential(vault: &Vault, issuer: &HostSlipIssuer, person: EntityId) -> VerifiedSlip {
    let root = vault
        .ensure_host_root_slip(issuer)
        .expect("the host root slip");
    let issued_at = vault.capability_slip_now().expect("slip clock");
    let mut claims = root.claims;
    claims.slip_id = next_slip_id();
    claims.holder_ref = person.to_hex();
    claims.actor_class = Some("human".into());
    claims.issued_at = issued_at;
    claims.expires_at = issued_at + 3_600;
    claims.ttl_secs = 3_600;
    let slip = vault
        .mint_capability_slip(issuer, claims)
        .expect("the person's credential");
    let challenge = b"org-admin-step-up";
    let proof = issuer
        .binding_proof(&slip, challenge)
        .expect("binding proof");
    vault
        .verify_capability_slip(&issuer.public_key(), &slip, challenge, &proof)
        .expect("a verified credential")
}

/// Steps `credential`'s holder up on it with an authenticator app: a new
/// TOTP enrollment whose first code confirms it and records the step-up on
/// this exact slip.
pub(crate) fn enroll_totp_and_step_up(vault: &Vault, credential: &VerifiedSlip) {
    let enrollment = vault
        .begin_step_up_totp(credential)
        .expect("a TOTP enrollment on the person's own credential");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("wall clock")
        .as_secs();
    let code = oneiron_crypto::totp::totp_code_for_secret(&enrollment.secret, now)
        .expect("a base32 provisioning secret");
    vault
        .confirm_step_up_totp(
            credential,
            &TotpCode {
                enrollment_id: enrollment.enrollment_id.clone(),
                code,
            },
        )
        .expect("the first code confirms the authenticator and steps up");
}

/// `person`'s proof, its request on `credential`, as a transport binds a
/// request's own slip.
pub(crate) fn proof_on(
    vault: &Vault,
    person: EntityId,
    credential: &VerifiedSlip,
) -> AuthenticatedOwner {
    let proof = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof");
    vault
        .bind_request_credential(proof, credential.clone())
        .expect("the request's own slip binds")
}

/// `person`'s proof on a fresh credential stepped up with TOTP: an org
/// Admin who passed MFA in this session.
pub(crate) fn stepped_up_proof(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    person: EntityId,
) -> AuthenticatedOwner {
    let credential = credential(vault, issuer, person);
    enroll_totp_and_step_up(vault, &credential);
    proof_on(vault, person, &credential)
}
