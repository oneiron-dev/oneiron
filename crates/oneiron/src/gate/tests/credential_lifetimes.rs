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
            (
                Value::from("precedence"),
                Value::from("vault_ceiling_holder_narrows"),
            ),
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

#[test]
fn replacing_the_authoritative_default_can_set_a_longer_vault_ceiling() -> crate::Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default())?;
    let issuer = HostSlipIssuer::from_secret(b"owner-replaced-credential-policy")?;
    vault.ensure_host_root_slip(&issuer)?;
    // This local authored replacement uses the pinned default manifest ID,
    // rather than adding a second pack to meet against the old values.
    let id = crate::gate::default_policy_manifest_id()?;
    let mut cursor = std::io::Cursor::new(crate::gate::default_policy_manifest().unwrap());
    let Value::Map(mut entries) =
        rmpv::decode::read_value(&mut cursor).expect("decode fixture manifest")
    else {
        panic!("seeded manifest must be a map");
    };
    let (_, lifetime) = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some(POLICY_CREDENTIAL_LIFETIMES_KEY))
        .expect("seeded lifetime row");
    *lifetime = Value::Map(vec![
        (Value::from("oauth_exchange_secs"), Value::from(7200_u64)),
        (Value::from("initial_owner_secs"), Value::from(63072000_u64)),
        (
            Value::from("precedence"),
            Value::from("vault_ceiling_holder_narrows"),
        ),
    ]);
    let mut replacement = Vec::new();
    rmpv::encode::write_value(&mut replacement, &Value::Map(entries))
        .expect("encode fixture manifest");
    crate::test_util::put_policy_manifest_bytes(&vault, id, &replacement)?;
    assert_eq!(mint(&vault, &issuer, 15_000, None)?.claims.ttl_secs, 7200);
    assert_eq!(
        pending_lifetime(&vault, &issuer, &pair(&vault, &issuer, u64::MAX)?)?,
        63072000
    );
    assert_eq!(
        mint(&vault, &issuer, 900, None)?.claims.ttl_secs,
        900,
        "JWT still independently narrows the owner-expanded vault ceiling"
    );
    Ok(())
}
#[test]
fn manifest_without_lifetimes_does_not_restore_shipped_numeric_caps() -> crate::Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default())?;
    let issuer = HostSlipIssuer::from_secret(b"omitted-lifetime-policy")?;
    vault.ensure_host_root_slip(&issuer)?;
    let id = crate::gate::default_policy_manifest_id()?;
    let mut cursor = std::io::Cursor::new(crate::gate::default_policy_manifest().unwrap());
    let Value::Map(mut entries) =
        rmpv::decode::read_value(&mut cursor).expect("decode fixture manifest")
    else {
        panic!("seeded manifest must be a map");
    };
    entries.retain(|(key, _)| key.as_str() != Some(POLICY_CREDENTIAL_LIFETIMES_KEY));
    let mut replacement = Vec::new();
    rmpv::encode::write_value(&mut replacement, &Value::Map(entries))
        .expect("encode fixture manifest");
    crate::test_util::put_policy_manifest_bytes(&vault, id, &replacement)?;
    assert!(mint(&vault, &issuer, 300, None).is_err());
    assert!(pair(&vault, &issuer, 300).is_err());
    Ok(())
}

#[test]
fn invalid_precedence_refuses_issuance() -> crate::Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default())?;
    let issuer = HostSlipIssuer::from_secret(b"invalid-precedence-policy")?;
    vault.ensure_host_root_slip(&issuer)?;
    let mut rows = Vec::new();
    let mut cursor = std::io::Cursor::new(policy(Value::from(100_u64), Value::from(100_u64)));
    let Value::Map(entries) =
        rmpv::decode::read_value(&mut cursor).expect("decode fixture manifest")
    else {
        panic!("policy map");
    };
    for (key, value) in entries {
        if key.as_str() == Some(POLICY_CREDENTIAL_LIFETIMES_KEY) {
            let Value::Map(mut values) = value else {
                panic!("lifetime map");
            };
            values
                .iter_mut()
                .find(|(name, _)| name.as_str() == Some("precedence"))
                .expect("precedence")
                .1 = Value::from("holder_can_widen");
            rows.push((key, Value::Map(values)));
        } else {
            rows.push((key, value));
        }
    }
    let mut malformed = Vec::new();
    rmpv::encode::write_value(&mut malformed, &Value::Map(rows))
        .expect("encode malformed manifest");
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::test_util::entity(0xBD),
        &malformed,
    )?;
    assert!(mint(&vault, &issuer, 100, None).is_err());
    assert!(pair(&vault, &issuer, 100).is_err());
    Ok(())
}
