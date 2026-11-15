//! Restriction wave 1: the owner can raise the step-up challenge life, the mesh grant ceiling and
//! a pairing code's life; without a Setting row, their five-minute, one-year and one-hour defaults
//! do not move. A pairing code's life is held to one minute through one day.
//!
//! Red on the helper base 5f4c0fa1eda (main + the Setting primitive): no such key exists, so the
//! owner's change is refused (unknown key) and the lifetimes stay at five minutes, one year and one
//! hour.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test restriction_wave_1`.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActSurface, HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
    MachineDeviceClass, MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership,
    MachineRole, MeshAlpnGrant, MeshBindingIdentity, MeshEnrolment, PairingPrincipal, SlipClaims,
    StepUpCeremony, VerifiedSlip, machine_profile_proof_transcript,
    pairing_binding_transcript_pinned,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::Scope;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const FIVE_MINUTES: u64 = 300;
const FIFTEEN_MINUTES: u64 = 900;
const ONE_YEAR: u64 = 31_536_000;
const TWO_YEARS: u64 = 63_072_000;
const ONE_HOUR: u64 = 3_600;
const TWO_HOURS: u64 = 7_200;
const ONE_DAY: u64 = 86_400;
const ALPN: &[u8] = b"mesh/test";

struct Fixture {
    vault: Vault,
    issuer: HostSlipIssuer,
    person: EntityId,
    owner: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn rooted() -> Result<Self, Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        vault.prepare_install_signing()?;
        let issuer = vault.bootstrap_host_slip_issuer()?;
        vault.ensure_host_root_slip(&issuer)?;
        vault.provision_engine_machine_identities(&issuer)?;
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let person = vault.ensure_embedded_owner_actor()?;
        let owner =
            vault.authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())?;
        Ok(Self {
            vault,
            issuer,
            person,
            owner,
            _dir: dir,
        })
    }

    /// The embedded owner's live human slip, proved on the host root's binding key.
    fn person_slip(&self) -> Result<VerifiedSlip, Box<dyn std::error::Error>> {
        let root = self.vault.ensure_host_root_slip(&self.issuer)?;
        let now = self.vault.capability_slip_now()?;
        let mut claims = root.claims;
        claims.slip_id = [0x52; 32];
        claims.parent_id = None;
        claims.holder_ref = self.person.to_hex();
        claims.actor_class = Some("human".to_owned());
        claims.issued_at = now;
        claims.expires_at = now + 3_600;
        claims.ttl_secs = 3_600;
        let slip = self.vault.mint_capability_slip(&self.issuer, claims)?;
        let challenge = b"restriction-wave-1";
        let proof = self.issuer.binding_proof(&slip, challenge)?;
        Ok(self.vault.verify_capability_slip(
            &self.issuer.public_key(),
            &slip,
            challenge,
            &proof,
        )?)
    }

    /// Redeem a machine link with both mesh binding proofs. The mesh pairing is a separate
    /// slip from the link's session credential; only its lifetime caps the ALPN grant.
    fn enrol_mesh(&self) -> Result<MeshFixture, Box<dyn std::error::Error>> {
        let machine = self.vault.new_entity_id()?;
        let device = SigningKey::from_bytes(&[31; 32]);
        let transport = SigningKey::from_bytes(&[32; 32]);
        let machine_key = device.verifying_key().to_bytes();
        let endpoint_key = transport.verifying_key().to_bytes();
        let vault_id = self
            .vault
            .authority_vault_id()?
            .ok_or("FIXTURE: a rooted vault has an authority id")?;
        let device_class = MachineDeviceClass::Computer;
        // Shape-valid key material, as in authority/tests/machine_identity.rs::request_for;
        // this fixture never decrypts a world key with the enrolled machine.
        let encryption_key = MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
        };
        let machine_proof = device
            .sign(&machine_profile_proof_transcript(
                &vault_id,
                machine,
                &machine_key,
                device_class,
                &encryption_key,
            ))
            .to_bytes();
        let request = MachineEnrolmentRequest {
            vault_id,
            machine,
            machine_key,
            device_class,
            encryption_key,
            machine_proof,
        };
        let mut transcript = b"oneiron/mesh-machine-binding/v1\0".to_vec();
        transcript.extend_from_slice(machine.as_bytes());
        transcript.extend_from_slice(&endpoint_key);
        let identity = MeshBindingIdentity {
            machine,
            device_key: machine_key,
            endpoint_key,
            device_proof: device.sign(&transcript).to_bytes().to_vec(),
            transport_proof: transport.sign(&transcript).to_bytes().to_vec(),
        };
        let link = self.vault.issue_machine_pairing_link(
            &self.issuer,
            &self.owner,
            ActSurface::ThisInstall,
            Scope::top(),
            3_600,
            PairingPrincipal::default(),
            MachineOwnership::Yours,
        )?;
        let holder = machine.to_hex();
        let proof = device
            .sign(&pairing_binding_transcript_pinned(
                &link.code,
                &machine_key,
                &holder,
                link.pin.as_ref(),
            )?)
            .to_bytes();
        let before = self.vault.capability_slip_now()?;
        let redeemed = self.vault.redeem_pairing_link_with_mesh(
            &self.issuer,
            &link.code,
            &holder,
            machine_key,
            &proof,
            &request,
            None,
            (&identity, ALPN),
        )?;
        let after = self.vault.capability_slip_now()?;
        let mesh = redeemed
            .mesh
            .ok_or("FIXTURE: redemption returns a mesh result")?;
        assert!(
            matches!(mesh, MeshEnrolment::Bound { .. }),
            "FIXTURE: a fresh machine is mesh-bound, not {mesh:?}"
        );
        let MeshEnrolment::Bound {
            pairing_slip_id, ..
        } = mesh
        else {
            return Err("FIXTURE: no fresh mesh pairing".into());
        };
        let fold = self.vault.authority_fold()?;
        let pairing = fold
            .slips
            .mints
            .get(&pairing_slip_id)
            .ok_or("FIXTURE: the mesh pairing's mint is logged")?
            .action
            .claims
            .clone();
        assert!(
            (before..=after).contains(&pairing.issued_at),
            "FIXTURE: the pairing records its own enrolment instant"
        );
        Ok(MeshFixture {
            machine,
            endpoint_key,
            pairing,
        })
    }

    fn grant_alpn(&self, mesh: &MeshFixture) -> Result<SlipClaims, Box<dyn std::error::Error>> {
        let before = self.vault.authority_fold()?;
        self.vault.set_mesh_alpn_grant_as_owner(
            &self.issuer,
            &self.owner,
            MeshAlpnGrant {
                machine: mesh.machine,
                endpoint_key: mesh.endpoint_key,
                alpn: ALPN.to_vec(),
                allow: true,
            },
        )?;
        let after = self.vault.authority_fold()?;
        let mut minted = after.slips.mints.iter().filter(|(id, mint)| {
            !before.slips.mints.contains_key(*id)
                && mint.action.claims.binding_key == mesh.endpoint_key
                && mint.action.claims.holder_ref == mesh.machine.to_hex()
                && after.slip_is_live(id)
        });
        let (_, grant) = minted
            .next()
            .ok_or("the owner's ALPN grant has a live logged mint")?;
        assert!(
            minted.next().is_none(),
            "the owner mints exactly one new ALPN grant for this endpoint"
        );
        Ok(grant.action.claims.clone())
    }
}

struct MeshFixture {
    machine: EntityId,
    endpoint_key: [u8; 32],
    pairing: SlipClaims,
}

fn owner_change(key: &str, seconds: u64) -> SetSetting {
    SetSetting {
        key: key.to_owned(),
        item: None,
        scope: SettingScope::Vault,
        mode: SettingMode::Value,
        value: Some(json!(seconds)),
        expected_revision: None,
        why: None,
        check_in_ref: None,
    }
}

/// The authority clock advances monotonically even with a manual store clock. Bracket the
/// call, not SystemTime: these bounds encode exactly `expires_at = own_now + seconds`.
fn assert_lifetime(expires_at: u64, before: u64, after: u64, seconds: u64) {
    assert!(
        (before + seconds..=after + seconds).contains(&expires_at),
        "expiry {expires_at} must be exactly {seconds}s after the call's authority instant \
         in [{before}, {after}]"
    );
}

#[test]
fn a_raised_step_up_challenge_life_keeps_the_ceremony_open_longer() -> TestResult {
    let fx = Fixture::rooted()?;
    let changed = fx.vault.set_setting(
        SettingCaller::Owner(&fx.owner),
        owner_change("step_up.challenge.ttl_secs", FIFTEEN_MINUTES),
    )?;
    assert!(
        matches!(changed, SetSettingOutcome::Applied { .. }),
        "the owner raises the challenge life without an ask: {changed:?}"
    );
    let person = fx.person_slip()?;
    let before = fx.vault.capability_slip_now()?;
    let challenge = fx
        .vault
        .open_step_up_ceremony(&person, StepUpCeremony::Enroll)?;
    let after = fx.vault.capability_slip_now()?;
    assert_lifetime(challenge.expires_at, before, after, FIFTEEN_MINUTES);
    Ok(())
}

#[test]
fn a_step_up_ceremony_with_no_row_stays_open_five_minutes() -> TestResult {
    let fx = Fixture::rooted()?;
    let person = fx.person_slip()?;
    let before = fx.vault.capability_slip_now()?;
    let challenge = fx
        .vault
        .open_step_up_ceremony(&person, StepUpCeremony::Enroll)?;
    let after = fx.vault.capability_slip_now()?;
    assert_lifetime(challenge.expires_at, before, after, FIVE_MINUTES);
    Ok(())
}

#[test]
fn a_raised_mesh_grant_ceiling_lets_an_alpn_grant_run_past_one_year() -> TestResult {
    let fx = Fixture::rooted()?;
    let changed = fx.vault.set_setting(
        SettingCaller::Owner(&fx.owner),
        owner_change("mesh.grant.max_ttl_secs", TWO_YEARS),
    )?;
    assert!(
        matches!(changed, SetSettingOutcome::Applied { .. }),
        "the owner raises the mesh ceiling before enrolment: {changed:?}"
    );
    let mesh = fx.enrol_mesh()?;
    let grant = fx.grant_alpn(&mesh)?;
    assert_eq!(
        mesh.pairing.expires_at,
        mesh.pairing.issued_at + TWO_YEARS,
        "the raised ceiling also stretches the enrolment's pairing to two years"
    );
    assert_eq!(
        grant.expires_at,
        mesh.pairing.expires_at.min(grant.issued_at + TWO_YEARS),
        "the owner's ALPN grant gets two years, capped only by its pairing"
    );
    assert!(
        grant.expires_at > grant.issued_at + ONE_YEAR,
        "the raised grant really runs past one year after its own mint instant"
    );
    Ok(())
}

#[test]
fn a_mesh_alpn_grant_with_no_row_runs_one_year() -> TestResult {
    let fx = Fixture::rooted()?;
    let mesh = fx.enrol_mesh()?;
    let grant = fx.grant_alpn(&mesh)?;
    assert_eq!(
        mesh.pairing.expires_at,
        mesh.pairing.issued_at + ONE_YEAR,
        "without a Setting row, the enrolment's pairing runs exactly one year"
    );
    assert_eq!(
        grant.expires_at,
        mesh.pairing.expires_at.min(grant.issued_at + ONE_YEAR),
        "without a Setting row, the grant keeps the one-year ceiling and pairing cap"
    );
    assert_eq!(
        grant.expires_at, mesh.pairing.expires_at,
        "the earlier pairing's one-year expiry is the unchanged limiting instant"
    );
    Ok(())
}

#[test]
fn a_raised_step_up_challenge_life_stretches_authenticator_app_enrolment() -> TestResult {
    let fx = Fixture::rooted()?;
    let changed = fx.vault.set_setting(
        SettingCaller::Owner(&fx.owner),
        owner_change("step_up.challenge.ttl_secs", FIFTEEN_MINUTES),
    )?;
    assert!(
        matches!(changed, SetSettingOutcome::Applied { .. }),
        "the owner raises the authenticator enrolment life without an ask: {changed:?}"
    );
    let person = fx.person_slip()?;
    let before = fx.vault.capability_slip_now()?;
    let enrolment = fx.vault.begin_step_up_totp(&person)?;
    let after = fx.vault.capability_slip_now()?;
    assert_lifetime(enrolment.expires_at, before, after, FIFTEEN_MINUTES);
    Ok(())
}

#[test]
fn a_raised_pairing_code_life_keeps_a_link_redeemable_longer() -> TestResult {
    let fx = Fixture::rooted()?;
    let changed = fx.vault.set_setting(
        SettingCaller::Owner(&fx.owner),
        owner_change("pairing.code.ttl_secs", TWO_HOURS),
    )?;
    assert!(
        matches!(changed, SetSettingOutcome::Applied { .. }),
        "the owner raises the pairing code life without an ask: {changed:?}"
    );
    let before = fx.vault.capability_slip_now()?;
    let link = fx.vault.issue_pairing_link(&fx.issuer, Scope::top(), 600)?;
    let after = fx.vault.capability_slip_now()?;
    assert_lifetime(link.expires_at, before, after, TWO_HOURS);
    Ok(())
}

#[test]
fn a_pairing_code_with_no_row_lives_one_hour() -> TestResult {
    let fx = Fixture::rooted()?;
    let before = fx.vault.capability_slip_now()?;
    let link = fx.vault.issue_pairing_link(&fx.issuer, Scope::top(), 600)?;
    let after = fx.vault.capability_slip_now()?;
    assert_lifetime(link.expires_at, before, after, ONE_HOUR);
    Ok(())
}

#[test]
fn a_pairing_code_life_outside_one_minute_to_one_day_is_refused() -> TestResult {
    let fx = Fixture::rooted()?;
    for seconds in [0, 59, ONE_DAY + 1] {
        match fx.vault.set_setting(
            SettingCaller::Owner(&fx.owner),
            owner_change("pairing.code.ttl_secs", seconds),
        ) {
            Ok(outcome) => {
                return Err(
                    format!("a pairing code life of {seconds}s was taken: {outcome:?}").into(),
                );
            }
            Err(error) => assert!(
                error
                    .to_string()
                    .contains("a pairing code lives between 60 and 86400 seconds"),
                "a pairing code life of {seconds}s is refused by the key's own check, not as {error}"
            ),
        }
    }
    let longest = fx.vault.set_setting(
        SettingCaller::Owner(&fx.owner),
        owner_change("pairing.code.ttl_secs", ONE_DAY),
    )?;
    assert!(
        matches!(longest, SetSettingOutcome::Applied { .. }),
        "one day is the longest life the owner may give a pairing code: {longest:?}"
    );
    let before = fx.vault.capability_slip_now()?;
    let link = fx.vault.issue_pairing_link(&fx.issuer, Scope::top(), 600)?;
    let after = fx.vault.capability_slip_now()?;
    assert_lifetime(link.expires_at, before, after, ONE_DAY);
    Ok(())
}
