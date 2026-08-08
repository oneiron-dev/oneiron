//! Byte-space v3 canon conformance (ONE-1754, ARCH-0058).
//!
//! Canon is AUTHORITATIVE. `oneiron-docs` `site/src/data/oneiron-contracts.ts`
//! decides every type byte; the engine follows. These tests compare the engine
//! registry against a VENDORED SNAPSHOT of the normalized canon arrays so the
//! comparison is reproducible offline and so a hand-edit of the snapshot is
//! itself a test failure.
//!
//! The snapshot is generated from canon at a recorded docs commit; regenerating
//! it is how a canon change reaches the engine, and the payload hash is what
//! stops the snapshot drifting from the canon it claims to mirror.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use oneiron::registry::{
    ENTITY_TYPE_REGISTRY, EntityClassification, TypeByteZone, entity_type_registry_entry, zone_of,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Snapshot {
    #[serde(rename = "docsCommit")]
    docs_commit: String,
    #[serde(rename = "payloadBlake3")]
    payload_blake3: String,
    payload: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct Payload {
    #[serde(rename = "storageAbiVersion")]
    storage_abi_version: u16,
    #[serde(rename = "typeByteZones")]
    type_byte_zones: Vec<CanonZone>,
    #[serde(rename = "entityKinds")]
    entity_kinds: Vec<CanonKind>,
    #[serde(rename = "systemBandAllocation")]
    system_band_allocation: Vec<CanonAllocation>,
    #[serde(rename = "byteMigrationV3")]
    byte_migration_v3: Vec<CanonMigration>,
}

#[derive(Debug, Deserialize)]
struct CanonZone {
    range: String,
    start: u16,
    end: u16,
}

#[derive(Debug, Deserialize)]
struct CanonKind {
    id: String,
    classification: String,
    #[serde(rename = "typeByte")]
    type_byte: Option<u8>,
    #[serde(rename = "shortIdPrefix")]
    short_id_prefix: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CanonAllocation {
    byte: u8,
    kind: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct CanonMigration {
    kind: String,
    #[serde(rename = "newByte")]
    new_byte: u8,
}

/// Canon rows the engine deliberately does NOT register yet.
///
/// Listing them EXPLICITLY is the point: a reserved canon row must stay visible
/// in conformance as "reserved, engine-pending" instead of quietly vanishing
/// from the census the moment nobody implements it.
const CANON_RESERVED_UNREGISTERED: &[(u8, &str)] = &[
    (69, "DIAGNOSTIC"),
    (72, "SUSPICIOUS_WAKE"),
    (74, "CLAIM_CLASS_DESCRIPTOR"),
    (75, "SKILL_HUB"),
];

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/oneiron-contracts-byte-space-v3.json")
}

fn load() -> (Snapshot, Payload) {
    let raw = std::fs::read_to_string(fixture_path()).expect("vendored canon snapshot is readable");
    let snapshot: Snapshot = serde_json::from_str(&raw).expect("snapshot parses");
    let payload: Payload =
        serde_json::from_value(snapshot.payload.clone()).expect("snapshot payload parses");
    (snapshot, payload)
}

/// The engine's registry must equal the vendored canon snapshot exactly, and
/// the snapshot must equal the canon it was generated from.
///
/// The payload hash is the second half of that sentence: without it, editing
/// the snapshot to match a drifted engine would "fix" this test while silently
/// severing it from canon. BLAKE3 over the compact, authored-key-order
/// serialization of `payload` is the canonicalization — `serde_json` is built
/// with `preserve_order`, so re-serializing the parsed payload reproduces the
/// generator's bytes.
#[test]
fn byte_space_v3_matches_vendored_canon() {
    let (snapshot, payload) = load();

    assert_eq!(
        snapshot.docs_commit.len(),
        40,
        "the snapshot must record the full docs commit it was generated from"
    );

    let canonical = serde_json::to_string(&snapshot.payload).expect("payload re-serializes");
    let recomputed = blake3::hash(canonical.as_bytes()).to_hex().to_string();
    assert_eq!(
        recomputed, snapshot.payload_blake3,
        "vendored canon payload hash mismatch — the snapshot was edited by hand \
         or regenerated without updating payloadBlake3; regenerate it from \
         oneiron-docs instead of adjusting the hash"
    );

    // ── zones: exactly the eight canon ranges, total over all 256 bytes ──
    assert_eq!(
        payload.type_byte_zones.len(),
        8,
        "canon pins exactly eight type-byte zones"
    );
    let mut cursor = 0_u16;
    for zone in &payload.type_byte_zones {
        assert_eq!(
            zone.start, cursor,
            "zone {} leaves a gap or overlap at {cursor}",
            zone.range
        );
        assert!(zone.end >= zone.start, "inverted zone {}", zone.range);
        cursor = zone.end + 1;
    }
    assert_eq!(cursor, 256, "the zone map must cover all 256 bytes");

    let expected_zones = [
        TypeByteZone::Semantic,
        TypeByteZone::Core,
        TypeByteZone::System,
        TypeByteZone::CompiledProduct,
        TypeByteZone::EngineExperimental,
        TypeByteZone::PackHandle,
        TypeByteZone::PackExperimental,
        TypeByteZone::Sentinel,
    ];
    for (zone, expected) in payload.type_byte_zones.iter().zip(expected_zones) {
        for byte in zone.start..=zone.end {
            let byte = u8::try_from(byte).expect("zone bounds stay inside u8");
            assert_eq!(
                zone_of(byte),
                expected,
                "byte {byte} must sit in canon zone {}",
                zone.range
            );
        }
    }

    // ── every canon row with a byte is either registered identically or an
    //    explicitly declared reserve ──
    let reserved: BTreeMap<u8, &str> = CANON_RESERVED_UNREGISTERED.iter().copied().collect();
    let mut canon_bytes: BTreeMap<u8, &str> = BTreeMap::new();
    for kind in &payload.entity_kinds {
        let Some(byte) = kind.type_byte else {
            // Pack kinds whose byte is assigned at registration carry no byte
            // in canon and must not be statically registered here either.
            assert!(
                !ENTITY_TYPE_REGISTRY
                    .iter()
                    .any(|entry| entry.kind == kind.id),
                "{} has no canon byte but the engine registered one",
                kind.id
            );
            continue;
        };
        assert!(
            canon_bytes.insert(byte, &kind.id).is_none(),
            "canon assigns byte {byte} twice"
        );

        if let Some(name) = reserved.get(&byte) {
            assert_eq!(
                *name, kind.id,
                "reserved byte {byte} names a different kind in canon"
            );
            assert!(
                entity_type_registry_entry(byte).is_none(),
                "{} ({byte}) is declared reserved/engine-pending but IS registered — \
                 either implement it and drop the reserve, or fix the reserve list",
                kind.id
            );
            continue;
        }

        let entry = entity_type_registry_entry(byte).unwrap_or_else(|| {
            panic!(
                "canon assigns {} to byte {byte} but the engine registers nothing there",
                kind.id
            )
        });
        assert_eq!(entry.kind, kind.id, "byte {byte} names a different kind");
        assert_eq!(
            entry.short_id_prefix,
            kind.short_id_prefix.as_deref(),
            "{} short-id prefix disagrees with canon",
            kind.id
        );
        assert!(
            classification_matches(entry.classification, &kind.classification),
            "{} classification disagrees with canon: engine {:?} vs canon {:?}",
            kind.id,
            entry.classification,
            kind.classification
        );
        assert_eq!(
            entry.zone,
            zone_of(byte),
            "{} carries a zone that is not its byte's zone",
            kind.id
        );
    }

    // Every reserve named above must actually appear in canon — a reserve that
    // canon dropped would otherwise sit here forever unnoticed.
    for (byte, name) in CANON_RESERVED_UNREGISTERED {
        assert_eq!(
            canon_bytes.get(byte).copied(),
            Some(*name),
            "reserved byte {byte} ({name}) is no longer a canon row"
        );
    }

    // ── no engine row without a canon row ──
    for entry in ENTITY_TYPE_REGISTRY {
        assert_eq!(
            canon_bytes.get(&entry.type_byte).copied(),
            Some(entry.kind),
            "engine registers {} at byte {} with no matching canon row",
            entry.kind,
            entry.type_byte
        );
    }
    let engine_bytes: BTreeSet<u8> = ENTITY_TYPE_REGISTRY
        .iter()
        .map(|entry| entry.type_byte)
        .collect();
    assert_eq!(
        engine_bytes.len(),
        ENTITY_TYPE_REGISTRY.len(),
        "the engine registry contains a duplicate type byte"
    );

    // ── the system-band allocation table agrees with the kind rows ──
    for allocation in &payload.system_band_allocation {
        assert_eq!(
            zone_of(allocation.byte),
            TypeByteZone::System,
            "{} is listed in the system band at byte {} which is not the system zone",
            allocation.kind,
            allocation.byte
        );
        assert_eq!(
            canon_bytes.get(&allocation.byte).copied(),
            Some(allocation.kind.as_str()),
            "systemBandAllocation and the entity-kind rows disagree at byte {} ({})",
            allocation.byte,
            allocation.state
        );
    }

    // ── the migration's DESTINATIONS are canon; sources are engine history ──
    let mut destinations = BTreeSet::new();
    for migration in &payload.byte_migration_v3 {
        assert!(
            destinations.insert(migration.new_byte),
            "byteMigrationV3 assigns destination {} twice",
            migration.new_byte
        );
        assert_eq!(
            canon_bytes.get(&migration.new_byte).copied(),
            Some(migration.kind.as_str()),
            "{} migrates to byte {} but canon puts a different kind there",
            migration.kind,
            migration.new_byte
        );
    }

    assert_eq!(
        payload.storage_abi_version,
        oneiron::store::STORAGE_ABI_VERSION,
        "canon and the engine disagree about STORAGE_ABI_VERSION"
    );
}

/// The pack half carries NO static ENTITY-TYPE allocations — the census is
/// empty, and `u8::MAX` in particular is not spelled as a type byte anywhere.
///
/// This is a SOURCE scan rather than a registry scan on purpose: the registry
/// only sees constants someone remembered to register, while the defect this
/// guards against is a stray type-byte constant that never reaches the registry
/// but still teaches the next reader that the pack half is allocatable.
/// `serialize.rs`'s old `OTHER_ENTITY_TYPE = u8::MAX` grouping sentinel was
/// exactly that shape, and it is what this test was written to keep out.
///
/// The census has NO exemptions, deliberately. An allow-list for zone-boundary
/// declarations would leave 128–255 (and 255 itself) spellable as a static byte
/// constant, which is precisely what the prohibition forbids — so the pack-half
/// zone edges live inline in `zone_of`'s match, the one place that IS the
/// allocation table, and are never bound to a name a later reader could reuse
/// as a type byte.
#[test]
fn byte_space_v3_has_no_static_pack_half_allocations() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    let mut files = 0_usize;

    let mut stack = vec![src.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("source tree is readable") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            files += 1;
            let text = std::fs::read_to_string(&path).expect("source file is readable");
            for (index, line) in text.lines().enumerate() {
                let Some((name, value)) = static_u8_const(line) else {
                    continue;
                };
                if value >= 128 && names_an_entity_type(&name) {
                    offenders.push(format!(
                        "{}:{}: {}",
                        path.strip_prefix(&src).unwrap_or(&path).display(),
                        index + 1,
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        files > 50,
        "the census scanned only {files} files — the scan is not reaching the source tree"
    );
    assert!(
        offenders.is_empty(),
        "static entity-type constants in the pack half (128-255) are forbidden by \
         byte-space v3; PackByteMap owns 128-247, 248-254 are experimental, and 255 \
         is the sentinel:\n{}",
        offenders.join("\n")
    );
}

/// Whether a constant name marks an ENTITY-TYPE allocation, as opposed to some
/// unrelated `u8` (a MessagePack marker, an id-range start, a test seed).
fn names_an_entity_type(name: &str) -> bool {
    name.contains("ENTITY_TYPE") || name.contains("TYPE_BYTE") || name.ends_with("_KIND")
}

/// Parses `const NAME: u8 = <literal>;` into `(name, value)`, resolving the
/// `u8::MAX` spelling the old grouping sentinel used.
fn static_u8_const(line: &str) -> Option<(String, u16)> {
    let trimmed = line.trim();
    let rest = trimmed
        .strip_prefix("pub const ")
        .or_else(|| trimmed.strip_prefix("pub(crate) const "))
        .or_else(|| trimmed.strip_prefix("pub(super) const "))
        .or_else(|| trimmed.strip_prefix("const "))?;
    let (name, tail) = rest.split_once(": u8 = ")?;
    let value = tail.strip_suffix(';')?.trim();
    let parsed = if value == "u8::MAX" {
        255
    } else {
        let value = value.strip_suffix("_u8").unwrap_or(value);
        match value.strip_prefix("0x") {
            Some(hex) => u16::from_str_radix(hex, 16).ok()?,
            None => value.parse::<u16>().ok()?,
        }
    };
    Some((name.trim().to_owned(), parsed))
}

fn classification_matches(engine: EntityClassification, canon: &str) -> bool {
    match engine {
        EntityClassification::Semantic => canon == "semantic",
        EntityClassification::Core => canon == "core",
        EntityClassification::Pack => canon == "pack",
        EntityClassification::Maintenance => canon == "maintenance" || canon == "system",
    }
}
