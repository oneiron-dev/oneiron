//! Hosted TTS policy rows: defaults, scope, precedence and strict decoding.
use super::*;
use crate::Vault;
use crate::gate::hosted_tts_policy::HostedTtsLimits;

fn table(rows: Vec<Value>, precedence: &str) -> (Value, Value) {
    (
        Value::from(POLICY_HOSTED_TTS_KEY),
        Value::Map(vec![
            (Value::from("precedence"), Value::from(precedence)),
            (Value::from("rows"), Value::Array(rows)),
        ]),
    )
}
fn row(provider: &str, scope: &str, holder: Option<EntityId>, text: u64, pcm: u64) -> Value {
    let mut fields = vec![
        (Value::from("provider"), Value::from(provider)),
        (Value::from("scope"), Value::from(scope)),
        (Value::from("max_text_bytes"), Value::from(text)),
        (Value::from("max_pcm_fragment_bytes"), Value::from(pcm)),
    ];
    if let Some(holder) = holder {
        fields.push((Value::from("holder_ref"), Value::from(holder.to_hex())));
    }
    Value::Map(fields)
}
fn put(vault: &Vault, id: u8, rows: Vec<Value>) -> Result<()> {
    put_policy_manifest_bytes(
        vault,
        test_id(id),
        &encode_policy_manifest(vec![table(rows, "nested_narrowing")]),
    )
}

#[test]
fn shipped_manifest_supplies_both_provider_defaults_and_no_implicit_holder_widening() -> Result<()>
{
    let _dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(_dir.path(), crate::VaultConfig::device()).expect("open seeded vault");
    let holder = test_id(0x51);
    let expected = HostedTtsLimits {
        max_text_bytes: 8_192,
        max_pcm_fragment_bytes: 2_097_152,
    };
    for provider in ["cartesia", "elevenlabs_flash"] {
        assert_eq!(vault.hosted_tts_limits(provider, holder)?, expected);
    }
    assert!(vault.hosted_tts_limits("other", holder).is_err());
    Ok(())
}

#[test]
fn trusted_rows_narrow_per_provider_and_holder_without_raising_vault_cap() -> Result<()> {
    let _dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(_dir.path(), crate::VaultConfig::device()).expect("open seeded vault");
    let alice = test_id(0x52);
    let bob = test_id(0x53);
    let before = resolve(&vault)?.read_frontier_hash()?;
    put(
        &vault,
        0x54,
        vec![
            row("cartesia", "vault", None, 6_000, 1_000),
            row("cartesia", "holder", Some(alice), 3_000, 900),
            row("elevenlabs_flash", "holder", Some(alice), 30_000, 3_000_000),
        ],
    )?;
    assert_ne!(resolve(&vault)?.read_frontier_hash()?, before);
    assert_eq!(
        vault.hosted_tts_limits("cartesia", alice)?,
        HostedTtsLimits {
            max_text_bytes: 3_000,
            max_pcm_fragment_bytes: 900
        }
    );
    assert_eq!(
        vault.hosted_tts_limits("cartesia", bob)?,
        HostedTtsLimits {
            max_text_bytes: 6_000,
            max_pcm_fragment_bytes: 1_000
        }
    );
    assert_eq!(
        vault.hosted_tts_limits("elevenlabs_flash", alice)?,
        HostedTtsLimits {
            max_text_bytes: 8_192,
            max_pcm_fragment_bytes: 2_097_152
        }
    );
    put(
        &vault,
        0x55,
        vec![row("cartesia", "holder", Some(alice), 2_000, 500)],
    )?;
    assert_eq!(
        vault.hosted_tts_limits("cartesia", alice)?,
        HostedTtsLimits {
            max_text_bytes: 2_000,
            max_pcm_fragment_bytes: 500
        }
    );
    Ok(())
}

#[test]
fn malformed_or_missing_policy_never_falls_back_to_adapter_literals() -> Result<()> {
    let holder = test_id(0x56);
    let (_dir, vault) = temp_vault(); // test fixture intentionally removes shipped manifest
    put_policy_manifest_bytes(&vault, test_id(0x57), &encode_policy_manifest(vec![]))?;
    assert!(vault.hosted_tts_limits("cartesia", holder).is_err());
    let (_dir, vault) = temp_vault();
    put(
        &vault,
        0x58,
        vec![row("cartesia", "holder", Some(holder), 100, 200)],
    )?;
    assert!(vault.hosted_tts_limits("cartesia", holder).is_err()); // no vault row
    for extra in [
        table(
            vec![row("cartesia", "vault", None, 0, 200)],
            "nested_narrowing",
        ),
        table(
            vec![row("cartesia", "vault", None, 100, 200)],
            "last_writer_wins",
        ),
        table(
            vec![row("cartesia", "vault", Some(holder), 100, 200)],
            "nested_narrowing",
        ),
        table(
            vec![
                row("cartesia", "vault", None, 100, 200),
                row("cartesia", "vault", None, 50, 100),
            ],
            "nested_narrowing",
        ),
    ] {
        let (_dir, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, test_id(0x59), &encode_policy_manifest(vec![extra]))?;
        assert!(resolve(&vault)?.is_fail_closed());
        assert!(vault.hosted_tts_limits("cartesia", holder).is_err());
    }
    Ok(())
}
