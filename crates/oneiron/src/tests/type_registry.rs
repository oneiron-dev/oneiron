//! Type-byte zones, structural-kind registry, entity-type validation on every write path.

use super::*;

/// Every presentation prefix names exactly one thing, across all three tables.
///
/// Canonical prefixes, retired prefixes, and non-entity namespaces share one
/// string space: a collision anywhere means one id resolves two ways, and the
/// resolver would pick by table order rather than by meaning.
#[test]
fn short_id_prefixes_are_globally_unique() {
    use crate::registry::{
        ENTITY_TYPE_REGISTRY, ID_NAMESPACE_REGISTRY, IdNamespaceTarget, VAULT_ID_NAMESPACE_PREFIX,
        id_namespace_for_prefix,
    };
    use std::collections::BTreeMap;

    let mut owners: BTreeMap<&str, String> = BTreeMap::new();
    let mut claim = |prefix: &'static str, owner: String| {
        if let Some(existing) = owners.insert(prefix, owner.clone()) {
            panic!("prefix {prefix:?} is claimed by both {existing} and {owner}");
        }
    };
    for entry in ENTITY_TYPE_REGISTRY {
        if let Some(prefix) = entry.short_id_prefix {
            claim(prefix, format!("{} (canonical)", entry.kind));
        }
        for legacy in entry.legacy_short_id_prefixes {
            claim(legacy, format!("{} (legacy)", entry.kind));
        }
    }
    for entry in ID_NAMESPACE_REGISTRY {
        claim(entry.prefix, format!("{:?} namespace", entry.target));
    }

    // `vt` is a first-class namespace that resolves to a VAULT, and no entity
    // type was invented to express it.
    assert_eq!(
        id_namespace_for_prefix(VAULT_ID_NAMESPACE_PREFIX).map(|entry| entry.target),
        Some(IdNamespaceTarget::Vault)
    );
    assert!(
        !ENTITY_TYPE_REGISTRY
            .iter()
            .any(|entry| entry.kind == "VAULT"),
        "vt names vaults through the namespace registry, never a fake entity kind"
    );

    // Entity-backed prefixes resolve through the same door, to their real byte.
    assert_eq!(
        id_namespace_for_prefix("mc").map(|entry| entry.target),
        Some(IdNamespaceTarget::EntityType(
            crate::registry::ENTITY_TYPE_MACHINE
        ))
    );
    // `mx` is the ticket's LEGACY sample, not a namespace. It must stay absent
    // from every canonical row and resolve only through an exact alias.
    assert_eq!(id_namespace_for_prefix("mx"), None);
    assert_eq!(id_namespace_for_prefix("zz"), None);
}

#[test]
fn type_byte_zone_allocation_matches_contract() {
    use crate::registry::{
        TYPE_BYTE_SEMANTIC, TYPE_BYTE_ZONE_COMPILED_PRODUCT_END,
        TYPE_BYTE_ZONE_COMPILED_PRODUCT_START, TYPE_BYTE_ZONE_CORE_END, TYPE_BYTE_ZONE_CORE_START,
        TYPE_BYTE_ZONE_ENGINE_EXPERIMENTAL_END, TYPE_BYTE_ZONE_ENGINE_EXPERIMENTAL_START,
        TYPE_BYTE_ZONE_SYSTEM_END, TYPE_BYTE_ZONE_SYSTEM_START, TypeByteZone,
        entity_type_registry_entry, is_structural_kind, validate_entity_type, zone_of,
    };

    // contracts.ts §1 typeByteBands — the v3 EIGHT-zone allocation, high bit
    // as the engine/pack boundary: 0 semantic / 1-63 CORE / 64-99 system /
    // 100-125 compiled product / 126-127 engine experimental /
    // 128-247 PackByteMap handles / 248-254 pack experimental / 255 sentinel.
    // Engine-half boundary constants pinned as literals so an off-by-one
    // allocation FAILS. The pack half has no boundary constants to pin — a
    // `const … : u8` naming one of its bytes is forbidden outright — so its
    // edges are pinned by the exhaustive `zone_of` sweep below instead, which
    // is the stronger check anyway.
    assert_eq!(TYPE_BYTE_SEMANTIC, 0);
    assert_eq!(TYPE_BYTE_ZONE_CORE_START, 1);
    assert_eq!(TYPE_BYTE_ZONE_CORE_END, 63);
    assert_eq!(TYPE_BYTE_ZONE_SYSTEM_START, 64);
    assert_eq!(TYPE_BYTE_ZONE_SYSTEM_END, 99);
    assert_eq!(TYPE_BYTE_ZONE_COMPILED_PRODUCT_START, 100);
    assert_eq!(TYPE_BYTE_ZONE_COMPILED_PRODUCT_END, 125);
    assert_eq!(TYPE_BYTE_ZONE_ENGINE_EXPERIMENTAL_START, 126);
    assert_eq!(TYPE_BYTE_ZONE_ENGINE_EXPERIMENTAL_END, 127);

    // zone_of is total over all 256 bytes. Expected values are written from
    // the contract's literal zone edges, independent of the implementation.
    for byte in u8::MIN..=u8::MAX {
        let expected = if byte == 0 {
            TypeByteZone::Semantic
        } else if byte <= 63 {
            TypeByteZone::Core
        } else if byte <= 99 {
            TypeByteZone::System
        } else if byte <= 125 {
            TypeByteZone::CompiledProduct
        } else if byte <= 127 {
            TypeByteZone::EngineExperimental
        } else if byte <= 247 {
            TypeByteZone::PackHandle
        } else if byte <= 254 {
            TypeByteZone::PackExperimental
        } else {
            TypeByteZone::Sentinel
        };
        assert_eq!(zone_of(byte), expected, "zone_of({byte})");
    }

    // is_structural_kind: false for the semantic byte 0 and for every
    // engine-authored system record; true for every REGISTERED core (1..=17,
    // AGENT_DEF being byte 17) and pack kind. Byte-space v3 moved the whole
    // maintenance family DOWN into 64-99 — these are canon values now, and the
    // pinned pre-v3 expectations were changed rather than preserved because
    // canon outranks the old test.
    assert!(!is_structural_kind(0), "CLAIM is NOT a StructuralKind");
    for (byte, name) in [
        (64_u8, "REDACTION_AUDIT"),
        (65, "MODEL"),
        (66, "AUTHORITY_LOG"),
        (67, "POLICY_MANIFEST"),
        (68, "FEDERATION_GRANT"),
        (69, "DIAGNOSTIC"),
        (70, "CONNECTOR_KEY"),
        (71, "PSYCH_PROFILE"),
        (73, "ACCESS_GRANT"),
        (76, "IDENTITY_TOPOLOGY_EVENT"),
        (77, "SECRET_CUSTODY"),
        (79, "CHANNEL_IDENTITY"),
        (80, "COUNTERPARTY_CONTACT"),
        (81, "OUTBOUND_GRANT"),
        (82, "PERSONA_SNAPSHOT_EXPORT"),
        (83, "COMM_RECORD"),
        (84, "SKILL_CONTENT_ANCHOR"),
    ] {
        assert!(
            !is_structural_kind(byte),
            "{name} ({byte}) is engine-authored, NOT a StructuralKind"
        );
    }
    for byte in 1..=17_u8 {
        assert!(is_structural_kind(byte), "core byte {byte}");
    }
    // COMPANION_REGISTER (78) shares the system zone with the records above and
    // is still a StructuralKind: classification, not zone, decides.
    for byte in [78_u8, 100, 101, 102, 103, 104, 105, 106] {
        assert!(is_structural_kind(byte), "pack byte {byte}");
    }

    // Unregistered bytes — including bytes INSIDE structural zones — are not
    // StructuralKinds, and the write-path gate still rejects them with the
    // same typed error.
    for byte in [63_u8, 72, 74, 75, 85, 99, 107, 125, 128, 247, 255] {
        assert!(!is_structural_kind(byte), "unregistered byte {byte}");
        assert!(
            matches!(
                validate_entity_type(byte),
                Err(Error::InvalidEntityType(rejected)) if rejected == byte
            ),
            "unregistered byte {byte} must stay rejected by validate_entity_type"
        );
    }

    // Canon reserves the engine has not built yet stay explicitly
    // unregistered rather than disappearing from the record. DIAGNOSTIC (69)
    // LEFT this list when ONE-1394 built its substrate — a reserve is a
    // promise to implement, not a permanent shelf.
    for (byte, name) in [
        (72_u8, "SUSPICIOUS_WAKE"),
        (74, "CLAIM_CLASS_DESCRIPTOR"),
        (75, "SKILL_HUB"),
    ] {
        assert!(
            entity_type_registry_entry(byte).is_none(),
            "{name} byte {byte} must stay reserved-unregistered"
        );
    }
}

/// Zone-driven validation is decided by the ZONE above the engine half, so no
/// registry row — static or persisted — can widen it. 255 is rejected in both
/// modes; the two experimental zones are the only mode-sensitive ones.
#[test]
fn validate_entity_type_zone_rules_are_mode_aware() {
    use crate::registry::validate_entity_type_for_mode;

    for byte in [126_u8, 127, 248, 254] {
        assert!(
            validate_entity_type_for_mode(byte, true).is_ok(),
            "development mode admits experimental byte {byte}"
        );
        assert!(
            matches!(
                validate_entity_type_for_mode(byte, false),
                Err(Error::InvalidEntityType(rejected)) if rejected == byte
            ),
            "production rejects experimental byte {byte}"
        );
    }

    // PackByteMap is deliberately not built here: 128-247 fails in BOTH modes.
    for byte in [128_u8, 200, 247] {
        for dev in [true, false] {
            assert!(
                matches!(
                    validate_entity_type_for_mode(byte, dev),
                    Err(Error::InvalidEntityType(rejected)) if rejected == byte
                ),
                "pack-handle byte {byte} must fail (dev={dev})"
            );
        }
    }

    // The sentinel is never admissible.
    for dev in [true, false] {
        assert!(
            matches!(
                validate_entity_type_for_mode(255, dev),
                Err(Error::InvalidEntityType(255))
            ),
            "sentinel 255 must fail (dev={dev})"
        );
    }

    // Registered engine-zone kinds pass in both modes; unregistered ones do not.
    for dev in [true, false] {
        assert!(validate_entity_type_for_mode(0, dev).is_ok());
        assert!(validate_entity_type_for_mode(64, dev).is_ok());
        assert!(validate_entity_type_for_mode(100, dev).is_ok());
        assert!(validate_entity_type_for_mode(107, dev).is_err());
    }
}

#[test]
fn structural_kind_registration_vets_zones_and_collisions_transactionally() -> Result<()> {
    use crate::registry::{TypeByteZone, entity_type_registry_entry};

    let (_dir, vault) = open_test_vault();

    // Byte-space v3 narrows dynamic registration to ONE zone: compiled-product
    // 100-125. The system zone is engine-authored and the pack half belongs to
    // PackByteMap, so admitting either would make register_structural_kind an
    // accidental PackByteMap — the exact hole ONE-1754 closes.
    for (byte, zone, why) in [
        (
            0_u8,
            TypeByteZone::Semantic,
            "the semantic byte is reserved",
        ),
        (63, TypeByteZone::Core, "CORE bytes are reserved"),
        (
            90,
            TypeByteZone::System,
            "the system zone is engine-authored",
        ),
        (
            200,
            TypeByteZone::PackHandle,
            "128-247 belongs to PackByteMap",
        ),
        (
            250,
            TypeByteZone::PackExperimental,
            "the pack half is never registrable",
        ),
        (255, TypeByteZone::Sentinel, "255 is the reserved sentinel"),
    ] {
        let err = vault
            .register_structural_kind(byte, "cx", zone, "bad-zone")
            .expect_err(why);
        assert_eq!(
            err.kind(),
            ErrorKind::StructuralKindZoneViolation,
            "byte {byte}: {why}"
        );
    }
    // A declared zone that disagrees with the byte is rejected before any
    // zone-admissibility question is even asked.
    let err = vault
        .register_structural_kind(110, "cx", TypeByteZone::System, "wrong-zone")
        .expect_err("byte 110 is compiled-product, not system");
    assert_eq!(err.kind(), ErrorKind::StructuralKindZoneViolation);
    assert!(
        vault_meta_rows_with_prefix(&vault, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)?.is_empty(),
        "rejected zone claims must not persist registry rows"
    );

    // Statically-claimed compiled-product bytes stay closed.
    let err = vault
        .register_structural_kind(
            ENTITY_TYPE_TASK_LIST,
            "np",
            TypeByteZone::CompiledProduct,
            "notes-pack",
        )
        .expect_err("TASK_LIST's byte is statically reserved");
    assert_eq!(err.kind(), ErrorKind::StructuralKindCollision);
    assert_matches!(err, Error::StructuralKindTypeByteCollision(byte) if byte == ENTITY_TYPE_TASK_LIST);
    assert!(
        vault_meta_rows_with_prefix(&vault, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)?.is_empty(),
        "static-byte rejection must not persist registry rows"
    );

    let registered =
        vault.register_structural_kind(110, "np", TypeByteZone::CompiledProduct, "notes-pack")?;
    assert_eq!(registered.type_byte, 110);
    assert_eq!(registered.short_id_prefix, "np");
    assert_eq!(registered.zone, TypeByteZone::CompiledProduct);
    assert!(entity_type_registry_entry(registered.type_byte).is_none());

    vault.register_structural_kind(
        111,
        "pd",
        TypeByteZone::CompiledProduct,
        "productivity-pack",
    )?;
    vault.register_structural_kind(112, "cm", TypeByteZone::CompiledProduct, "crm-pack")?;

    let before = vault_meta_rows_with_prefix(&vault, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)?;
    let err = vault
        .register_structural_kind(110, "nx", TypeByteZone::CompiledProduct, "duplicate-byte")
        .expect_err("duplicate type byte must be rejected");
    assert_eq!(err.kind(), ErrorKind::StructuralKindCollision);
    assert_matches!(err, Error::StructuralKindTypeByteCollision(110));
    assert_eq!(
        vault_meta_rows_with_prefix(&vault, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)?,
        before,
        "duplicate-byte rejection must not mutate vault_meta"
    );

    let err = vault
        .register_structural_kind(113, "np", TypeByteZone::CompiledProduct, "duplicate-prefix")
        .expect_err("duplicate dynamic prefix must be rejected");
    assert_eq!(err.kind(), ErrorKind::StructuralKindCollision);
    assert_matches!(err, Error::StructuralKindPrefixCollision(ref prefix) if prefix == "np");
    assert_eq!(
        vault_meta_rows_with_prefix(&vault, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)?,
        before,
        "duplicate-prefix rejection must not mutate vault_meta"
    );

    for static_prefix in ["tn", "cr"] {
        let err = vault
            .register_structural_kind(
                113,
                static_prefix,
                TypeByteZone::CompiledProduct,
                "static-prefix",
            )
            .expect_err("static short-id prefixes must not be reused");
        assert_eq!(err.kind(), ErrorKind::StructuralKindCollision);
        assert_matches!(
            err,
            Error::StructuralKindPrefixCollision(ref prefix) if prefix == static_prefix
        );
        assert_eq!(
            vault_meta_rows_with_prefix(&vault, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)?,
            before,
            "static-prefix rejection must not mutate vault_meta"
        );
    }

    Ok(())
}

#[test]
fn structural_kind_registry_handles_legacy_dynamic_companion_byte() -> Result<()> {
    use crate::companion::{COMPANION_REGISTER_PACK_ID, COMPANION_REGISTER_SHORT_ID_PREFIX};

    // The row is written at COMPANION_REGISTER's byte with the SYSTEM zone
    // code (2): byte-space v3 moved the kind from 64 to 78, and the re-key
    // rewrites any surviving legacy row onto the new byte, so tolerance is
    // owned at the new byte — nothing legitimate is left at 64. The record
    // itself is CURRENT-version: the vault under test is a v3 vault, and the
    // re-key is what leaves legacy registrations in the current record format.
    fn legacy_row(prefix: &str, pack: &str) -> Vec<u8> {
        let mut raw = vec![
            STRUCTURAL_KIND_REGISTRY_RECORD_VERSION,
            ENTITY_TYPE_COMPANION_REGISTER,
            2,
            2,
        ];
        raw.extend_from_slice(
            &u16::try_from(pack.len())
                .expect("test pack length fits u16")
                .to_le_bytes(),
        );
        raw.extend_from_slice(prefix.as_bytes());
        raw.extend_from_slice(pack.as_bytes());
        raw
    }

    let compatible_dir = tempfile::tempdir()?;
    {
        let vault = Vault::open(compatible_dir.path(), test_config())?;
        let key = structural_kind_registry_key(ENTITY_TYPE_COMPANION_REGISTER);
        let raw = legacy_row(
            COMPANION_REGISTER_SHORT_ID_PREFIX,
            COMPANION_REGISTER_PACK_ID,
        );

        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(&mut wtxn, &key, &raw)?;
        wtxn.commit()?;
    }
    let compatible = Vault::open(compatible_dir.path(), test_config())?;
    assert!(
        compatible
            .structural_kind_registration(ENTITY_TYPE_COMPANION_REGISTER)
            .is_none(),
        "compatible legacy row must be ignored so the static registry owns the byte"
    );

    let incompatible_dir = tempfile::tempdir()?;
    {
        let vault = Vault::open(incompatible_dir.path(), test_config())?;
        let key = structural_kind_registry_key(ENTITY_TYPE_COMPANION_REGISTER);
        let raw = legacy_row("np", "legacy-pack");

        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(&mut wtxn, &key, &raw)?;
        wtxn.commit()?;
    }

    let err = match Vault::open(incompatible_dir.path(), test_config()) {
        Ok(_) => panic!("incompatible legacy companion-register row must fail closed"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), ErrorKind::CorruptedIndex);
    assert_matches!(err, Error::CorruptedIndex("structural kind registry"));
    Ok(())
}

#[test]
fn structural_kind_registration_persists_and_loads_on_reopen() -> Result<()> {
    use crate::registry::TypeByteZone;

    let dir = tempfile::tempdir()?;
    {
        let vault = Vault::open(dir.path(), test_config())?;
        vault.register_structural_kind(110, "np", TypeByteZone::CompiledProduct, "notes-pack")?;

        let key = structural_kind_registry_key(110);
        let rows = vault_meta_rows_with_prefix(&vault, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, key.to_vec());
    }

    let reopened = Vault::open(dir.path(), test_config())?;
    let registration = reopened
        .structural_kind_registration(110)
        .expect("registration must load from vault_meta on reopen");
    assert_eq!(registration.type_byte, 110);
    assert_eq!(registration.short_id_prefix, "np");
    assert_eq!(registration.zone, TypeByteZone::CompiledProduct);
    assert_eq!(registration.pack, "notes-pack");
    assert_eq!(
        reopened.structural_kind_registrations(),
        vec![registration],
        "runtime registry must mirror persisted dynamic rows only"
    );
    Ok(())
}

#[test]
fn registered_structural_kind_unblocks_writes_and_short_ids() -> Result<()> {
    use crate::registry::TypeByteZone;

    let (_dir, vault) = open_test_vault();
    let before = EntityId::now();
    let err = vault
        .put_entity(&before, 110, test_time_range(1, 1), 2, b"before-register")
        .expect_err("unregistered dynamic byte must fail closed");
    assert_eq!(err.kind(), ErrorKind::InvalidEntityType);
    assert_matches!(err, Error::InvalidEntityType(110));
    assert_no_entity_state(&vault, &before)?;

    vault.register_structural_kind(110, "np", TypeByteZone::CompiledProduct, "notes-pack")?;

    let after = EntityId::now();
    vault.put_entity(&after, 110, test_time_range(3, 3), 4, b"after-register")?;
    assert_eq!(
        vault.get(&after)?.ok_or(Error::EntityNotFound)?,
        b"after-register"
    );

    let short_id = find_short_id_any_schema(&vault, &after)?
        .expect("registered dynamic kind must mint a short id");
    assert_eq!(short_id, "np1");

    let rtxn = vault.store.env.read_txn()?;
    let counter = vault
        .store
        .vault_meta
        .get(&rtxn, &short_id_counter_key(110))?
        .expect("dynamic type short-id counter must live in vault_meta");
    assert_eq!(*counter, 1_u64.to_le_bytes());
    Ok(())
}

#[test]
fn persisted_structural_kind_registry_matches_runtime_config() -> Result<()> {
    use crate::registry::{TypeByteZone, entity_type_registry_entry, zone_of};

    let (_dir, vault) = open_test_vault();
    vault.register_structural_kind(110, "np", TypeByteZone::CompiledProduct, "notes-pack")?;
    vault.register_structural_kind(
        111,
        "pd",
        TypeByteZone::CompiledProduct,
        "productivity-pack",
    )?;
    vault.register_structural_kind(112, "cc", TypeByteZone::CompiledProduct, "crm-pack")?;

    let rows = vault.structural_kind_registrations();
    assert_eq!(rows.len(), 3);
    for registration in rows {
        assert_eq!(
            zone_of(registration.type_byte),
            registration.zone,
            "persisted registry band must match zone_of({})",
            registration.type_byte
        );
        assert!(
            entity_type_registry_entry(registration.type_byte).is_none(),
            "runtime registry must not shadow static registry byte {}",
            registration.type_byte
        );
    }
    Ok(())
}

#[test]
fn legacy_dynamic_registration_on_static_byte_is_tolerated_on_open() -> Result<()> {
    use crate::registry::{ENTITY_TYPE_BLOB_ARTIFACT, TypeByteZone, short_id_prefix};

    let (dir, vault) = open_test_vault();
    // A registration minted while BLOB_ARTIFACT's byte was still free for
    // dynamic packs, carried into a current vault: raw kind_reg record under
    // dynamic prefix "zz". Written raw because the current
    // register_structural_kind rejects the statically-claimed byte. The record
    // is at the CURRENT version — the byte-space v3 re-key rewrites every
    // surviving row before stamping, so a legacy REGISTRATION never implies a
    // legacy record FORMAT.
    let mut key = STRUCTURAL_KIND_REGISTRY_KEY_PREFIX.to_vec();
    key.push(ENTITY_TYPE_BLOB_ARTIFACT);
    let pack = b"legacy-pack";
    let mut record = vec![
        STRUCTURAL_KIND_REGISTRY_RECORD_VERSION,
        ENTITY_TYPE_BLOB_ARTIFACT,
        3,
        2,
    ];
    record.extend_from_slice(&u16::try_from(pack.len()).expect("pack len").to_le_bytes());
    record.extend_from_slice(b"zz");
    record.extend_from_slice(pack);
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, &record)?;
        Ok(())
    })?;
    drop(vault);

    // Reopen must tolerate the legacy row instead of failing as corruption.
    let vault = Vault::open(dir.path(), test_config())?;
    // The static definition wins: no runtime registration shadows byte 85.
    assert!(
        vault
            .structural_kind_registrations()
            .iter()
            .all(|row| row.type_byte != ENTITY_TYPE_BLOB_ARTIFACT)
    );
    assert_eq!(short_id_prefix(ENTITY_TYPE_BLOB_ARTIFACT)?, "ba");
    // The statically-claimed byte stays closed to new dynamic registration…
    let err = vault
        .register_structural_kind(
            ENTITY_TYPE_BLOB_ARTIFACT,
            "qq",
            TypeByteZone::CompiledProduct,
            "new-pack",
        )
        .expect_err("static byte must stay closed to dynamic registration");
    assert_eq!(err.kind(), ErrorKind::StructuralKindCollision);
    // …and the legacy prefix stays reserved for rows minted under it.
    let err = vault
        .register_structural_kind(110, "zz", TypeByteZone::CompiledProduct, "new-pack")
        .expect_err("legacy prefix must stay reserved");
    assert_eq!(err.kind(), ErrorKind::StructuralKindCollision);
    Ok(())
}

#[test]
fn productivity_entity_types_round_trip() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let task_list = EntityId::now();
    let task = EntityId::now();

    vault
        .batch()
        .put(
            &task_list,
            ENTITY_TYPE_TASK_LIST,
            test_time_range(100, 100),
            101,
            b"project",
        )
        .put(
            &task,
            ENTITY_TYPE_TASK,
            test_time_range(200, 200),
            201,
            &task_body(TaskRole::Task),
        )
        .commit()?;

    assert_eq!(vault.get(&task_list)?.unwrap(), b"project");
    assert_eq!(
        vault.get(&task)?.unwrap(),
        task_body(TaskRole::Task).as_slice()
    );
    Ok(())
}

#[test]
fn entity_id_rejects_reserved_sentinel_bytes() {
    assert!(EntityId::from_bytes([0x00; 16]).is_err());
    assert!(EntityId::from_bytes([0xFF; 16]).is_err());

    let mut claim_counter = [0xFF; 16];
    claim_counter[0] = 0;
    assert!(EntityId::from_bytes(claim_counter).is_err());

    let mut task_list_counter = [0xFF; 16];
    task_list_counter[0] = ENTITY_TYPE_TASK_LIST;
    assert!(EntityId::from_bytes(task_list_counter).is_err());

    let mut non_reserved = [0xFF; 16];
    non_reserved[0] = ENTITY_TYPE_REDACTION_AUDIT;
    assert!(EntityId::from_bytes(non_reserved).is_ok());
}

#[test]
fn entity_id_from_hex_rejects_reserved_sentinel_bytes() {
    assert!(EntityId::from_hex("00000000000000000000000000000000").is_err());
    assert!(EntityId::from_hex("ffffffffffffffffffffffffffffffff").is_err());
    assert!(EntityId::from_hex("00ffffffffffffffffffffffffffffff").is_err());
    // A short-id-bearing kind's counter sentinel, spelled from the constant so
    // the byte-space v3 re-key cannot leave a stale hex literal asserting a
    // byte that no longer carries a prefix.
    let task_list_counter = format!("{:02x}{}", ENTITY_TYPE_TASK_LIST, "ff".repeat(15));
    assert!(EntityId::from_hex(&task_list_counter).is_err());
}

#[test]
fn batch_put_invalid_entity_type_returns_early_error() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    let err = vault
        .batch()
        .put(&id, 255, test_time_range(1, 1), 2, b"bad-type")
        .commit()
        .expect_err("expected InvalidEntityType for type 255");
    assert!(
        matches!(err, Error::InvalidEntityType(255)),
        "expected InvalidEntityType(255), got {err:?}"
    );

    // Verify nothing was written
    assert!(vault.get(&id)?.is_none());
    Ok(())
}

#[test]
fn txn_batch_put_invalid_entity_type_returns_error() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put(&id, 255, test_time_range(1, 1), 2, b"bad-type")
                .apply(wtxn)
        })
        .expect_err("expected InvalidEntityType for type 255");
    assert!(
        matches!(err, Error::InvalidEntityType(255)),
        "expected InvalidEntityType(255), got {err:?}"
    );
    assert!(vault.get(&id)?.is_none());

    Ok(())
}

/// D5: public puts of a REGISTERED maintenance-band kind must fail with the
/// distinct `MaintenanceKindNotWritable` error — not the misleading
/// `InvalidEntityType` — and must write nothing. The engine-internal writers
/// are unaffected (the receipt writer, see
/// `redaction_receipt_indexes_temporal_occurred_start_as_point_event`, the
/// `ensure_model_substrate` door, and grant/policy substrate writers).
#[test]
fn public_put_of_maintenance_kind_rejected_with_distinct_typed_error() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    for (kind_byte, payload) in [
        (ENTITY_TYPE_REDACTION_AUDIT, b"forged-receipt".as_slice()),
        (ENTITY_TYPE_MODEL, b"forged-model".as_slice()),
        (
            ENTITY_TYPE_AUTHORITY_LOG,
            b"forged-authority-log".as_slice(),
        ),
        (ENTITY_TYPE_POLICY_MANIFEST, b"forged-policy".as_slice()),
        (ENTITY_TYPE_FEDERATION_GRANT, b"forged-grant".as_slice()),
        (ENTITY_TYPE_ACCESS_GRANT, b"forged-access-grant".as_slice()),
        (
            ENTITY_TYPE_COUNTERPARTY_CONTACT,
            b"forged-counterparty-contact".as_slice(),
        ),
        (
            ENTITY_TYPE_OUTBOUND_GRANT,
            b"forged-outbound-grant".as_slice(),
        ),
    ] {
        let id = EntityId::now();

        // put_entity (routes through BatchBuilder; eager gate).
        let err = vault
            .put_entity(&id, kind_byte, test_time_range(1, 1), 2, payload)
            .expect_err("public put of a maintenance kind must fail");
        assert!(
            matches!(err, Error::MaintenanceKindNotWritable(byte) if byte == kind_byte),
            "expected MaintenanceKindNotWritable({kind_byte}), got {err:?}"
        );
        assert_eq!(err.kind(), ErrorKind::MaintenanceKindNotWritable);
        assert_ne!(err.kind(), ErrorKind::InvalidEntityType);

        // TxnBatchBuilder (apply-time gate in apply_put).
        let err = vault
            .with_write_txn(|wtxn| {
                vault
                    .batch_in()
                    .put(&id, kind_byte, test_time_range(1, 1), 2, payload)
                    .apply(wtxn)
            })
            .expect_err("txn batch put of a maintenance kind must fail");
        assert!(
            matches!(err, Error::MaintenanceKindNotWritable(byte) if byte == kind_byte),
            "expected MaintenanceKindNotWritable({kind_byte}), got {err:?}"
        );

        // Nothing was written by either path.
        assert!(vault.get(&id)?.is_none());
        assert!(vault.entities_by_type(kind_byte)?.is_empty());
        let rtxn = vault.store.env.read_txn()?;
        let type_key = Store::encode_type_key(kind_byte, &id);
        assert!(vault.store.type_index.get(&rtxn, &type_key)?.is_none());
        let occurred_key = Store::encode_temporal_key(1, &id);
        assert!(
            vault
                .store
                .temporal_occurred_start
                .get(&rtxn, &occurred_key)?
                .is_none()
        );
        let learned_key = Store::encode_temporal_key(2, &id);
        assert!(
            vault
                .store
                .temporal_learned
                .get(&rtxn, &learned_key)?
                .is_none()
        );
        assert!(vault.store.short_ids.get(&rtxn, id.as_bytes())?.is_none());
        // No short-id counter sentinel was allocated for the maintenance band.
        let mut sentinel = [0xFF_u8; ENTITY_ID_LEN];
        sentinel[0] = kind_byte;
        assert!(vault.store.short_ids.get(&rtxn, &sentinel)?.is_none());
    }

    Ok(())
}

/// D5 counterpart: `InvalidEntityType` still covers genuinely UNKNOWN bytes,
/// including unregistered bytes inside the 120+ maintenance band — the
/// distinct maintenance error is reserved for registered maintenance kinds.
#[test]
fn unknown_type_bytes_still_fail_with_invalid_entity_type() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // Every byte the v3 re-key moved into the system zone left this list when
    // its kind was registered; public puts of those bytes now fail
    // MaintenanceKindNotWritable — covered by the D5 gate test. DIAGNOSTIC (69)
    // left it that way in ONE-1394. What stays InvalidEntityType is the
    // canon-reserved system bytes with no engine substrate (72 SUSPICIOUS_WAKE,
    // 74 CLAIM_CLASS_DESCRIPTOR, 75 SKILL_HUB), free bytes inside
    // otherwise-live zones, the PackByteMap half (128–247), and the 255
    // sentinel.
    for unknown in [72_u8, 74, 75, 99, 107, 125, 130, 200, 255] {
        let id = EntityId::now();
        let err = vault
            .put_entity(&id, unknown, test_time_range(1, 1), 2, b"unknown-type")
            .expect_err("unregistered type byte must fail");
        assert!(
            matches!(err, Error::InvalidEntityType(byte) if byte == unknown),
            "expected InvalidEntityType({unknown}), got {err:?}"
        );
        assert_eq!(err.kind(), ErrorKind::InvalidEntityType);
        assert!(vault.get(&id)?.is_none());
    }

    Ok(())
}

#[test]
fn reput_with_different_type_byte_is_rejected_with_no_index_residue() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault
        .batch()
        .put(&id, 1, test_time_range(100, 200), 300, b"old-data")
        .commit()?;
    let record_before = read_raw_entity(&vault, &id)?;
    let short_id_before = read_short_id_value(&vault, &id)?;

    // D2: the type byte is immutable once a record exists. The pre-D2 engine
    // silently re-homed the type_index row and kept the old short id, leaving
    // a SESSION entity addressed as "tn1".
    let err = vault
        .batch()
        .put(&id, 2, test_time_range(400, 500), 600, b"new-data")
        .commit()
        .expect_err("re-put with a different type byte must be rejected");
    assert!(
        matches!(
            err,
            Error::EntityTypeImmutable {
                id: err_id,
                existing: 1,
                attempted: 2,
            } if err_id == id
        ),
        "expected EntityTypeImmutable {{ existing: 1, attempted: 2 }}, got {err:?}"
    );

    // Stored record and short-id row are byte-for-byte unchanged.
    assert_eq!(read_raw_entity(&vault, &id)?, record_before);
    assert_eq!(read_short_id_value(&vault, &id)?, short_id_before);

    // Original index rows intact; no rows for the rejected attempt.
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .type_index
            .get(&rtxn, &Store::encode_type_key(1, &id))?
            .is_some()
    );
    assert!(
        vault
            .store
            .type_index
            .get(&rtxn, &Store::encode_type_key(2, &id))?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &Store::encode_temporal_key(100, &id))?
            .is_some()
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &Store::encode_temporal_key(200, &id))?
            .is_some()
    );
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &Store::encode_temporal_key(300, &id))?
            .is_some()
    );
    assert!(
        vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &Store::encode_temporal_key(400, &id))?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &Store::encode_temporal_key(500, &id))?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &Store::encode_temporal_key(600, &id))?
            .is_none()
    );

    Ok(())
}

#[test]
fn txn_batch_reput_with_different_type_byte_rejects_before_staging_writes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault.put_entity(&id, 1, test_time_range(100, 200), 300, b"old-data")?;
    let record_before = read_raw_entity(&vault, &id)?;
    let short_id_before = read_short_id_value(&vault, &id)?;

    // Commit the externally-owned transaction DESPITE the error: the
    // apply-time gate must reject before staging any write, so an
    // implementation that re-homes index rows before checking the type byte
    // leaves residue these assertions catch.
    let mut wtxn = vault.store.env.write_txn()?;
    let err = vault
        .batch_in()
        .put(&id, 2, test_time_range(400, 500), 600, b"new-data")
        .apply(&mut wtxn)
        .expect_err("re-put with a different type byte must be rejected");
    assert!(
        matches!(
            err,
            Error::EntityTypeImmutable {
                id: err_id,
                existing: 1,
                attempted: 2,
            } if err_id == id
        ),
        "expected EntityTypeImmutable {{ existing: 1, attempted: 2 }}, got {err:?}"
    );
    wtxn.commit()?;

    assert_eq!(read_raw_entity(&vault, &id)?, record_before);
    assert_eq!(read_short_id_value(&vault, &id)?, short_id_before);

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .type_index
            .get(&rtxn, &Store::encode_type_key(2, &id))?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &Store::encode_temporal_key(400, &id))?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &Store::encode_temporal_key(500, &id))?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &Store::encode_temporal_key(600, &id))?
            .is_none()
    );

    Ok(())
}

#[test]
fn txn_batch_reput_with_different_type_byte_preserves_long_interval_row() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    // Seed an entity whose occurred span exceeds the long-interval threshold,
    // so a temporal_long_intervals row exists (manifest DB n21: key
    // encode_temporal_key(occurred_end, id), value occurred_start BE).
    let old_start = 100_u64;
    let old_end = old_start + LONG_INTERVAL_THRESHOLD_SECS + 1;
    vault.put_entity(
        &id,
        1,
        test_time_range(old_start, old_end),
        300,
        b"old-data",
    )?;

    let long_interval_key = Store::encode_temporal_key(old_end, &id);
    {
        let rtxn = vault.store.env.read_txn()?;
        let value = vault
            .store
            .temporal_long_intervals
            .get(&rtxn, &long_interval_key)?
            .expect("seed entity must have a temporal_long_intervals row");
        assert_eq!(value, &old_start.to_be_bytes()[..]);
    }

    // D2 ordering: the immutability gate must fire BEFORE the old-row deletes
    // in apply_put — a wrong implementation that runs the old-long-interval
    // delete first would drop the row, then error. Commit the externally-owned
    // transaction DESPITE the error to expose any such pre-gate delete.
    let mut wtxn = vault.store.env.write_txn()?;
    let err = vault
        .batch_in()
        .put(&id, 2, test_time_range(400, 500), 600, b"new-data")
        .apply(&mut wtxn)
        .expect_err("re-put with a different type byte must be rejected");
    assert!(
        matches!(
            err,
            Error::EntityTypeImmutable {
                id: err_id,
                existing: 1,
                attempted: 2,
            } if err_id == id
        ),
        "expected EntityTypeImmutable {{ existing: 1, attempted: 2 }}, got {err:?}"
    );
    wtxn.commit()?;

    // The long-interval row survives the failed re-type, byte-for-byte.
    let rtxn = vault.store.env.read_txn()?;
    let value = vault
        .store
        .temporal_long_intervals
        .get(&rtxn, &long_interval_key)?
        .expect("temporal_long_intervals row must survive a rejected re-type");
    assert_eq!(value, &old_start.to_be_bytes()[..]);

    Ok(())
}

#[test]
fn batch_double_put_same_id_different_type_rejects_and_writes_nothing() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    // Same-batch TOCTOU vector: two puts for the same id with different type
    // bytes in one batch. The apply-time gate reads the stored envelope inside
    // the batch's own write transaction (read-your-own-writes), so the second
    // put must see the first put's staged record and reject.
    let err = vault
        .batch()
        .put(&id, 1, test_time_range(100, 200), 300, b"first")
        .put(&id, 2, test_time_range(400, 500), 600, b"second")
        .commit()
        .expect_err("second put with a different type byte must reject the batch");
    assert!(
        matches!(
            err,
            Error::EntityTypeImmutable {
                id: err_id,
                existing: 1,
                attempted: 2,
            } if err_id == id
        ),
        "expected EntityTypeImmutable {{ existing: 1, attempted: 2 }}, got {err:?}"
    );

    // Batch-abort atomicity: the builder owns the transaction and aborts on
    // error, so NO record survives — not even the first (valid) put.
    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.store.entities.get(&rtxn, id.as_bytes())?.is_none());
    assert!(vault.store.short_ids.get(&rtxn, id.as_bytes())?.is_none());
    assert!(
        vault
            .store
            .type_index
            .get(&rtxn, &Store::encode_type_key(1, &id))?
            .is_none()
    );
    assert!(
        vault
            .store
            .type_index
            .get(&rtxn, &Store::encode_type_key(2, &id))?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &Store::encode_temporal_key(100, &id))?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &Store::encode_temporal_key(300, &id))?
            .is_none()
    );

    Ok(())
}

#[test]
fn put_with_reversed_occurred_range_is_rejected_and_nothing_is_written() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    // D3: occurred_start > occurred_end is rejected with a typed error. The
    // pre-D3 engine silently swapped the bounds and stored (100, 300).
    // Type byte 1 (TURN) keeps the body opaque so this isolates the time-range
    // gate — type 0 is reserved for CLAIM, whose bodies are validated (D18).
    let err = vault
        .batch()
        .put(&id, 1, test_time_range(300, 100), 400, b"payload")
        .commit()
        .expect_err("occurred_start > occurred_end must be rejected");
    assert!(
        matches!(
            err,
            Error::InvalidTimeRange {
                start: 300,
                end: 100
            }
        ),
        "expected InvalidTimeRange {{ start: 300, end: 100 }}, got {err:?}"
    );

    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.entities.get(&rtxn, id.as_bytes())?.is_none());
        assert!(vault.store.short_ids.get(&rtxn, id.as_bytes())?.is_none());
        assert!(
            vault
                .store
                .type_index
                .get(&rtxn, &Store::encode_type_key(1, &id))?
                .is_none()
        );
        // The pre-D3 swap stored (start: 100, end: 300) — assert both
        // orientations are absent from every temporal index.
        for ts in [100_u64, 300] {
            let key = Store::encode_temporal_key(ts, &id);
            assert!(
                vault
                    .store
                    .temporal_occurred_start
                    .get(&rtxn, &key)?
                    .is_none()
            );
            assert!(
                vault
                    .store
                    .temporal_occurred_end
                    .get(&rtxn, &key)?
                    .is_none()
            );
        }
        assert!(
            vault
                .store
                .temporal_learned
                .get(&rtxn, &Store::encode_temporal_key(400, &id))?
                .is_none()
        );
    }

    // A reversed range whose swapped span exceeds the long-interval
    // threshold: the pre-D3 swap would also have written a
    // temporal_long_intervals row keyed on the (swapped) occurred_end.
    let long_id = EntityId::now();
    let reversed_start = 300 + LONG_INTERVAL_THRESHOLD_SECS + 1;
    let err = vault
        .batch()
        .put(
            &long_id,
            1,
            test_time_range(reversed_start, 100),
            400,
            b"payload",
        )
        .commit()
        .expect_err("reversed long interval must be rejected");
    assert!(
        matches!(err, Error::InvalidTimeRange { start, end: 100 } if start == reversed_start),
        "expected InvalidTimeRange {{ start: {reversed_start}, end: 100 }}, got {err:?}"
    );

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .entities
            .get(&rtxn, long_id.as_bytes())?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_long_intervals
            .get(&rtxn, &Store::encode_temporal_key(reversed_start, &long_id))?
            .is_none()
    );

    Ok(())
}

#[test]
fn txn_batch_put_with_reversed_occurred_range_rejected_at_apply_time() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    // TxnBatchBuilder has no eager validation — this exercises the
    // authoritative apply-time gate in apply_put. Commit the transaction
    // despite the error to prove the gate rejected before staging any write.
    let mut wtxn = vault.store.env.write_txn()?;
    let err = vault
        .batch_in()
        .put(&id, 1, test_time_range(300, 100), 400, b"payload")
        .apply(&mut wtxn)
        .expect_err("occurred_start > occurred_end must be rejected");
    assert!(
        matches!(
            err,
            Error::InvalidTimeRange {
                start: 300,
                end: 100
            }
        ),
        "expected InvalidTimeRange {{ start: 300, end: 100 }}, got {err:?}"
    );
    wtxn.commit()?;

    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.store.entities.get(&rtxn, id.as_bytes())?.is_none());
    assert!(vault.store.short_ids.get(&rtxn, id.as_bytes())?.is_none());
    for ts in [100_u64, 300] {
        let key = Store::encode_temporal_key(ts, &id);
        assert!(
            vault
                .store
                .temporal_occurred_start
                .get(&rtxn, &key)?
                .is_none()
        );
        assert!(
            vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &key)?
                .is_none()
        );
    }

    Ok(())
}

#[test]
fn point_event_start_equals_end_stays_accepted() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    // D3 boundary: start == end is a legal point event.
    vault
        .batch()
        .put(&id, 1, test_time_range(777, 777), 800, b"point")
        .commit()?;

    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .entities
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(raw[1..9], 777_u64.to_be_bytes());
    assert_eq!(raw[9..17], 777_u64.to_be_bytes());

    // Point-event index convention: occurred_start row only, no occurred_end
    // row (apply_put writes temporal_occurred_end only when start != end).
    let key = Store::encode_temporal_key(777, &id);
    assert!(
        vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &key)?
            .is_some()
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &key)?
            .is_none()
    );

    Ok(())
}
