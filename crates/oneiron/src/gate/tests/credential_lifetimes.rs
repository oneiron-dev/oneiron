//! Credential expiry policies are trusted, restrictive and applied at mint.
use super::*;
use crate::authority::{HostSlipIssuer, PairingPrincipal};
use crate::federation::Scope;
use rmpv::Value;

fn policy(oauth: Value, owner: Value) -> Vec<u8> {
    encode_policy_manifest(vec![(
        Value::from(POLICY_CREDENTIAL_LIFETIMES_KEY),
        Value::Map(vec![
            (Value::from("oauth_exchange_secs"), oauth),
            (Value::from("initial_owner_secs"), owner),
        ]),
    )])
}
fn mint(
    vault: &crate::Vault,
    issuer: &HostSlipIssuer,
    jwt: u64,
    requested: Option<u64>,
) -> crate::Result<crate::authority::CapabilitySlip> {
    let mut claims = vault.ensure_host_root_slip(issuer)?.claims;
    claims.slip_id = *blake3::hash(&vault.new_entity_id()?.as_bytes()[..]).as_bytes();
    claims.holder_ref = "oauth-holder".to_owned();
    vault.mint_oauth_capability_slip(issuer, claims, jwt, requested)
}
fn pair(
    vault: &crate::Vault,
    issuer: &HostSlipIssuer,
    requested: u64,
) -> crate::Result<crate::authority::PairingLink> {
    vault.issue_pairing_link_for_principal(
        issuer,
        Scope::top(),
        requested,
        PairingPrincipal::default(),
    )
}
fn pending_lifetime(
    vault: &crate::Vault,
    issuer: &HostSlipIssuer,
    link: &crate::authority::PairingLink,
) -> crate::Result<u64> {
    use ed25519_dalek::{Signer, SigningKey};
    let holder = SigningKey::from_bytes(&[77; 32]);
    let pubkey = holder.verifying_key().to_bytes();
    let sig = holder
        .sign(&crate::authority::pairing_binding_transcript(
            &link.code,
            &pubkey,
            "test-holder",
        )?)
        .to_bytes();
    let slip = vault.redeem_pairing_link(issuer, &link.code, "test-holder", pubkey, &sig)?;
    Ok(slip.claims.ttl_secs)
}
#[test]
fn credential_lifetime_policy_defaults_and_trusted_narrowing_govern_both_mints() -> crate::Result<()>
{
    let dir = tempfile::tempdir()?;
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default())?;
    let issuer = HostSlipIssuer::from_secret(b"credential-policy-test")?;
    vault.ensure_host_root_slip(&issuer)?;
    assert_eq!(mint(&vault, &issuer, 10_000, None)?.claims.ttl_secs, 3600);
    assert_eq!(
        pending_lifetime(&vault, &issuer, &pair(&vault, &issuer, u64::MAX)?)?,
        365 * 24 * 60 * 60
    );
    assert_eq!(
        mint(&vault, &issuer, 120, None)?.claims.ttl_secs,
        120,
        "JWT remains an independent ceiling"
    );
    let outstanding = pair(&vault, &issuer, u64::MAX)?;
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::test_util::entity(0xB7),
        &policy(Value::from(45_u64), Value::from(600_u64)),
    )?;
    assert_eq!(
        mint(&vault, &issuer, 10_000, Some(100_000))?
            .claims
            .ttl_secs,
        45
    );
    assert_eq!(
        pending_lifetime(&vault, &issuer, &pair(&vault, &issuer, 100_000)?)?,
        600
    );
    assert_eq!(
        pending_lifetime(&vault, &issuer, &outstanding)?,
        600,
        "a policy narrowed after link issuance still binds the mint"
    );
    assert_eq!(mint(&vault, &issuer, 10_000, Some(5))?.claims.ttl_secs, 5);
    assert_eq!(
        pending_lifetime(&vault, &issuer, &pair(&vault, &issuer, 6)?)?,
        6
    );
    Ok(())
}
#[test]
fn malformed_trusted_lifetime_policy_refuses_both_mint_paths() -> crate::Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default())?;
    let issuer = HostSlipIssuer::from_secret(b"malformed-credential-policy")?;
    vault.ensure_host_root_slip(&issuer)?;
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::test_util::entity(0xB8),
        &policy(Value::from("not-seconds"), Value::from(600_u64)),
    )?;
    assert!(mint(&vault, &issuer, 300, None).is_err());
    assert!(pair(&vault, &issuer, 300).is_err());
    Ok(())
}

#[test]
fn trusted_lifetime_ceiling_meets_across_packs_and_ignores_untrusted_widening() -> crate::Result<()>
{
    for (first, second) in [(45_u64, 30_u64), (30, 45)] {
        let dir = tempfile::tempdir()?;
        let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default())?;
        let issuer = HostSlipIssuer::from_secret(b"ordered-lifetime-policy")?;
        vault.ensure_host_root_slip(&issuer)?;
        for (id, oauth, owner) in [(0xBA, first, 400_u64), (0xBB, second, 300_u64)] {
            crate::test_util::put_policy_manifest_bytes(
                &vault,
                crate::test_util::entity(id),
                &policy(Value::from(oauth), Value::from(owner)),
            )?;
        }
        assert_eq!(mint(&vault, &issuer, 10_000, None)?.claims.ttl_secs, 30);
        assert_eq!(
            pending_lifetime(&vault, &issuer, &pair(&vault, &issuer, u64::MAX)?)?,
            300
        );
        let row = policy(Value::from(1_u64), Value::from(1_u64));
        vault
            .batch()
            .put_replicated(
                &crate::test_util::entity(0xBC),
                crate::registry::ENTITY_TYPE_POLICY_MANIFEST,
                crate::TimeRange { start: 1, end: 1 },
                1,
                &row,
            )
            .commit()?;
        assert_eq!(mint(&vault, &issuer, 10_000, None)?.claims.ttl_secs, 30);
        assert_eq!(
            pending_lifetime(&vault, &issuer, &pair(&vault, &issuer, u64::MAX)?)?,
            300
        );
    }
    Ok(())
}
