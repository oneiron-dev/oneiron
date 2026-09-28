//! Shipped PowerPoint limits and owner/holder policy precedence.

use super::*;
use crate::edit_roundtrip::pptx::PptxOperationalLimits;

fn owner_row(vault: &crate::Vault, seed: u8, limits: PptxOperationalLimits) -> Result<()> {
    put_policy_manifest_bytes(
        vault,
        test_id(seed),
        &encode_policy_manifest(vec![(
            Value::from(POLICY_PPTX_COMMENT_LIMITS_KEY),
            limits.policy_row(),
        )]),
    )
}

#[test]
fn fresh_vault_has_shipped_row_and_owner_can_adjust_it() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = crate::Vault::open(dir.path(), crate::test_util::embedding_test_config())?;
    assert_eq!(resolve(&vault)?.diagnostics().manifest_count, 1);
    let shipped = resolve(&vault)?.pptx_comment_limits().expect("shipped row");
    assert_eq!(shipped, PptxOperationalLimits::default());
    let original_hash = resolve(&vault)?.read_frontier_hash()?;
    let owner = PptxOperationalLimits {
        max_author_name_bytes: shipped.max_author_name_bytes + 10,
        max_patches: 5,
        ..shipped
    };
    owner_row(&vault, 0x30, owner)?;
    let resolved = resolve(&vault)?;
    assert_eq!(resolved.pptx_comment_limits(), Some(owner));
    assert_ne!(resolved.read_frontier_hash()?, original_hash);
    owner_row(
        &vault,
        0x31,
        PptxOperationalLimits {
            max_patches: 3,
            ..owner
        },
    )?;
    assert_eq!(
        resolve(&vault)?.pptx_comment_limits().unwrap().max_patches,
        3
    );
    Ok(())
}

#[test]
fn precedence_is_required_and_unknown_or_malformed_rows_fail_closed() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let limits = PptxOperationalLimits::default();
    for (key, value) in [
        ("precedence", Value::from("holder_wins")),
        ("max_patches", Value::from(0_u64)),
        ("unknown_budget", Value::from(10_u64)),
    ] {
        let Value::Map(mut row) = limits.policy_row() else {
            unreachable!()
        };
        if key == "unknown_budget" {
            row.push((Value::from(key), value));
        } else {
            row.iter_mut()
                .find(|(field, _)| field.as_str() == Some(key))
                .unwrap()
                .1 = value;
        }
        let manifest = encode_policy_manifest(vec![(
            Value::from(POLICY_PPTX_COMMENT_LIMITS_KEY),
            Value::Map(row),
        )]);
        assert!(
            decode_policy_manifest(&manifest).is_none(),
            "malformed {key}"
        );
    }
    put_policy_manifest_bytes(
        &vault,
        test_id(0x32),
        &encode_policy_manifest(vec![(
            Value::from(POLICY_PPTX_COMMENT_LIMITS_KEY),
            Value::from("not a row"),
        )]),
    )?;
    assert!(resolve(&vault)?.pptx_comment_limits().is_none());
    Ok(())
}

#[test]
fn missing_trusted_limits_row_refuses_instead_of_falling_back() -> Result<()> {
    let (_dir, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x33), &encode_policy_manifest(vec![]))?;
    assert!(resolve(&vault)?.pptx_comment_limits().is_none());
    Ok(())
}

#[test]
fn holder_override_only_narrows_vault_limits() {
    let vault = PptxOperationalLimits {
        max_patches: 5,
        ..PptxOperationalLimits::default()
    };
    let holder_wider = PptxOperationalLimits {
        max_patches: 50,
        ..vault
    };
    assert_eq!(vault.narrow(holder_wider).max_patches, 5);
    let holder_stricter = PptxOperationalLimits {
        max_patches: 2,
        ..holder_wider
    };
    assert_eq!(vault.narrow(holder_stricter).max_patches, 2);
}
