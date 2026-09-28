//! Docedit resource-policy decode, trusted fold and engine-to-organ factory.
use super::*;
use crate::Vault;
use crate::gate::decode::decode_docedit_resource::parse_docedit_resource_policy;
use crate::gate::docedit_resource::DoceditResourcePolicy;
use oneiron_docedit::retained_opc::{Editability, Package};

const KEY: &str = "docedit_resource_policy";
fn entry(row: Value) -> (Value, Value) {
    (Value::from(KEY), row)
}
fn row(fields: [(&str, u64); 6]) -> Value {
    Value::Map(
        fields
            .into_iter()
            .map(|(key, value)| (Value::from(key), Value::from(value)))
            .collect(),
    )
}
fn row_from(policy: DoceditResourcePolicy) -> Value {
    row([
        ("archive_bytes", policy.archive_bytes as u64),
        ("entries", policy.entries as u64),
        ("part_bytes", policy.part_bytes as u64),
        ("expanded_bytes", policy.expanded_bytes as u64),
        ("xml_depth", policy.xml_depth as u64),
        ("xml_nodes", policy.xml_nodes as u64),
    ])
}
fn write_policy(vault: &Vault, seed: u8, extra: Vec<(Value, Value)>) -> Result<()> {
    put_policy_manifest_bytes(vault, test_id(seed), &encode_policy_manifest(extra))
}

#[test]
fn shipped_manifest_and_absent_row_have_same_six_ceiling_values() -> Result<()> {
    let shipped = crate::gate::default_manifest::default_docedit_resource_row();
    let baseline = parse_docedit_resource_policy(&shipped).expect("shipped six limits");
    let decoded = crate::gate::decode::decode_policy_manifest(&default_policy_manifest())
        .expect("default manifest decodes");
    assert_eq!(decoded.docedit_resource_policy, Some(baseline));
    let (_tmp, vault) = temp_vault();
    write_policy(&vault, 0x30, vec![])?;
    let absent = resolve(&vault)?;
    assert_eq!(absent.docedit_resource_policy(), Some(baseline));
    assert_eq!(
        vault.docedit_package_limits()?.xml.max_depth,
        baseline.xml_depth
    );
    let hash = absent.read_frontier_hash()?;
    let (_tmp_explicit, explicit_vault) = temp_vault();
    write_policy(&explicit_vault, 0x30, vec![entry(row_from(baseline))])?;
    assert_eq!(hash, resolve(&explicit_vault)?.read_frontier_hash()?);
    Ok(())
}

#[test]
fn trusted_rows_restrict_every_ceiling_and_change_frontier_and_admission() -> Result<()> {
    let tighter = DoceditResourcePolicy {
        archive_bytes: 900,
        entries: 3,
        part_bytes: 256,
        expanded_bytes: 512,
        xml_depth: 2,
        xml_nodes: 3,
    };
    let (_tmp, vault) = temp_vault();
    write_policy(&vault, 0x30, vec![entry(row_from(tighter))])?;
    let resolved = resolve(&vault)?;
    assert_eq!(resolved.docedit_resource_policy(), Some(tighter));
    let bounds = vault.docedit_package_limits()?;
    assert_eq!(bounds.xml.max_depth, 2);
    let source = include_bytes!("../../../../oneiron-docedit/tests/fixtures/retained.docx");
    // The compact source fits archive but has four entries and thus refuses.
    assert!(Package::open(source, bounds).is_err());
    let mut wider = tighter;
    wider.archive_bytes = source.len() + 1;
    wider.entries = 4;
    wider.part_bytes = 2048;
    wider.expanded_bytes = 4096;
    let (_tmp2, permissive) = temp_vault();
    write_policy(&permissive, 0x30, vec![entry(row_from(wider))])?;
    let metadata = include_bytes!("fixtures/docedit_deep_metadata.zip");
    let mut package =
        Package::open(metadata, permissive.docedit_package_limits()?).expect("ZIP admitted");
    // Its XML metadata is parsed with the same max_depth and max_nodes; low
    // XML count makes metadata read-only while preserving no-op bytes.
    assert_eq!(package.editability(), Editability::MetadataUnsupported);
    assert_eq!(package.export().expect("no-op"), metadata);
    assert!(
        package
            .replace_text("word/document.xml", &["root", "item"], "old", "new")
            .is_err()
    );
    let deep = include_bytes!("fixtures/docedit_deep_document.zip");
    let mut document =
        Package::open(deep, permissive.docedit_package_limits()?).expect("ZIP admitted");
    assert_eq!(document.editability(), Editability::Unsigned);
    assert!(
        document
            .replace_text(
                "word/document.xml",
                &["root", "nested", "item"],
                "old",
                "new"
            )
            .is_err()
    );
    assert_eq!(document.export().expect("no-op"), deep);
    let hash = resolved.read_frontier_hash()?;
    assert_ne!(hash, resolve(&permissive)?.read_frontier_hash()?);
    assert_ne!(hash, baseline_hash()?);
    Ok(())
}
fn baseline_hash() -> Result<[u8; 32]> {
    let (_tmp, vault) = temp_vault();
    write_policy(&vault, 0x30, vec![])?;
    resolve(&vault)?.read_frontier_hash()
}

#[test]
fn bad_policy_rows_or_missing_manifest_fail_factory_closed() -> Result<()> {
    let baseline = DoceditResourcePolicy::shipped();
    let (_tmp_none, none) = temp_vault();
    assert!(matches!(
        none.docedit_package_limits(),
        Err(Error::InvalidConfig(_))
    ));
    for bad in [
        Value::Array(vec![]),
        row_from(DoceditResourcePolicy {
            part_bytes: u64::MAX as usize,
            ..baseline
        }),
        row_from(DoceditResourcePolicy {
            xml_depth: 0,
            ..baseline
        }),
        Value::Map(vec![(Value::from("archive_bytes"), Value::from(10u64))]),
        Value::Map(vec![(Value::from("archive_bytes"), Value::from(10u64)); 6]),
    ] {
        let (_tmp, vault) = temp_vault();
        write_policy(&vault, 0x30, vec![entry(bad)])?;
        assert!(matches!(
            vault.docedit_package_limits(),
            Err(Error::InvalidConfig(_))
        ));
    }
    let (_tmp_unknown, unknown) = temp_vault();
    let Value::Map(mut entries) = row_from(baseline) else {
        unreachable!()
    };
    entries[0].0 = Value::from("unknown");
    write_policy(&unknown, 0x30, vec![entry(Value::Map(entries))])?;
    assert!(matches!(
        unknown.docedit_package_limits(),
        Err(Error::InvalidConfig(_))
    ));
    Ok(())
}

#[test]
fn each_trusted_policy_ceiling_changes_frontier_and_real_admission() -> Result<()> {
    let base = DoceditResourcePolicy::shipped();
    let bytes = include_bytes!("../../../../oneiron-docedit/tests/fixtures/retained.docx");
    let baseline = baseline_hash()?;
    for dimension in 0..6 {
        let mut row = base;
        match dimension {
            0 => row.archive_bytes = bytes.len() - 1,
            1 => row.entries = 3,
            2 => row.part_bytes = 124,
            3 => row.expanded_bytes = 157,
            4 => row.xml_depth = 1,
            _ => row.xml_nodes = 1,
        }
        let (_tmp, vault) = temp_vault();
        write_policy(&vault, 0x30, vec![entry(row_from(row))])?;
        let resolution = resolve(&vault)?;
        assert_ne!(
            resolution.read_frontier_hash()?,
            baseline,
            "dimension {dimension}"
        );
        let limits = vault.docedit_package_limits()?;
        if dimension < 4 {
            assert!(
                Package::open(bytes, limits).is_err(),
                "ZIP dimension {dimension}"
            );
        } else {
            let mut package = Package::open(bytes, limits).expect("bounded ZIP admitted");
            assert!(
                package
                    .replace_text("word/document.xml", &["root", "item"], "old", "new")
                    .is_err()
            );
            assert_eq!(package.export().expect("no-op"), bytes);
        }
    }
    Ok(())
}

#[test]
fn duplicate_top_level_row_and_unsupported_schema_refuse_factory() -> Result<()> {
    let baseline = DoceditResourcePolicy::shipped();
    let (_tmp_dup, duplicate) = temp_vault();
    write_policy(
        &duplicate,
        0x30,
        vec![entry(row_from(baseline)), entry(row_from(baseline))],
    )?;
    assert!(matches!(
        duplicate.docedit_package_limits(),
        Err(Error::InvalidConfig(_))
    ));
    let (_tmp_schema, unsupported) = temp_vault();
    let mut wire = encode_policy_manifest(vec![entry(row_from(baseline))]);
    rewrite_policy_manifest_entries(&mut wire, |entries| {
        entries.retain(|(key, _)| key.as_str() != Some(POLICY_SCHEMA_VERSION_KEY));
    });
    put_policy_manifest_bytes(&unsupported, test_id(0x30), &wire)?;
    assert!(matches!(
        unsupported.docedit_package_limits(),
        Err(Error::InvalidConfig(_))
    ));
    Ok(())
}

#[test]
fn untrusted_manifest_cannot_widen_document_limits() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let tight = DoceditResourcePolicy {
        archive_bytes: 700,
        ..DoceditResourcePolicy::shipped()
    };
    write_policy(&vault, 0x30, vec![entry(row_from(tight))])?;
    let len = vault.docedit_package_limits()?.archive_bytes;
    let wide = DoceditResourcePolicy::shipped();
    let data = encode_policy_manifest(vec![entry(row_from(wide))]);
    vault
        .batch()
        .put_replicated(
            &test_id(0x31),
            crate::registry::ENTITY_TYPE_POLICY_MANIFEST,
            test_time(1),
            1,
            &data,
        )
        .commit()?;
    assert_eq!(vault.docedit_package_limits()?.archive_bytes, len);
    Ok(())
}

#[test]
fn two_trusted_manifest_rows_narrow_without_a_second_precedence() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let baseline = DoceditResourcePolicy::shipped();
    let first = DoceditResourcePolicy {
        archive_bytes: 1000,
        xml_depth: 5,
        ..baseline
    };
    let second = DoceditResourcePolicy {
        archive_bytes: 900,
        xml_nodes: 32,
        ..baseline
    };
    write_policy(&vault, 0x30, vec![entry(row_from(first))])?;
    write_policy(&vault, 0x31, vec![entry(row_from(second))])?;
    let resolved = resolve(&vault)?
        .docedit_resource_policy()
        .expect("trusted policy");
    assert_eq!(resolved, first.restrict(second));
    let from_host = vault.docedit_package_limits()?;
    assert_eq!(from_host.archive_bytes, 900);
    assert_eq!(from_host.xml.max_depth, 5);
    assert_eq!(from_host.xml.max_nodes, 32);
    Ok(())
}
