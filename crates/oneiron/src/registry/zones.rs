//! Type-byte zones: classification, zone map, and the `zone_of` table.

/// Registry classification mirroring the contracts.ts §1
/// `EntityClassification` enum: `"semantic" | "core" | "pack" | "maintenance"`.
///
/// CLAIM (byte 0) is the single SEMANTIC type (ARCH-0003) and deliberately
/// NOT a StructuralKind; core and pack kinds ARE StructuralKinds; the system
/// zone's engine-authored records (REDACTION_AUDIT … SKILL_CONTENT_ANCHOR) are
/// not StructuralKinds either. Classification, not zone position, is what makes
/// a kind engine-authored: COMPANION_REGISTER sits inside the same 64–99 zone
/// and stays publicly writable because it is classified `Pack`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntityClassification {
    /// `"semantic"` — CLAIM, the single subject·predicate·value type.
    Semantic,
    /// `"core"` — universal CORE StructuralKinds (TURN … NOTIFICATION).
    Core,
    /// `"pack"` — pack-registered StructuralKinds (TASK_LIST / TASK /
    /// MACHINE / CODE_ARTIFACT today; other pack kinds get bytes at pack
    /// registration).
    Pack,
    /// `"maintenance"` — system/maintenance records.
    Maintenance,
}

/// The v3 type-byte ZONE map — the sole allocation authority, mirroring
/// contracts.ts §1 `typeByteBands`. The high bit is the engine/pack boundary:
/// the engine half is 0–127, the pack half 128–255.
///
/// Storage ABI: every u8 falls in exactly one zone. Zone membership is pure
/// namespace allocation — an unregistered byte still has a zone but is
/// rejected by `validate_entity_type` on every write path.
///
/// This is NOT the sync-selector / federation-scope vocabulary. That is a
/// separate, deliberately frozen wire type
/// ([`crate::federation::SelectorRange`]); allocation decisions read this
/// enum and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeByteZone {
    /// Byte `0` — CLAIM's semantic type byte, not a StructuralKind.
    Semantic,
    /// Bytes `1–63` — universal CORE StructuralKinds. LOCKED, UNTOUCHED.
    Core,
    /// Bytes `64–99` — system kinds. Engine-authored maintenance records plus
    /// the classification-routed exceptions that stay publicly writable.
    System,
    /// Bytes `100–125` — compiled-in product packs. The ONLY zone a dynamic
    /// `register_structural_kind` may allocate within in production.
    CompiledProduct,
    /// Bytes `126–127` — engine-half experimental. Development mode only.
    EngineExperimental,
    /// Bytes `128–247` — PackByteMap per-vault local handles. NEVER statically
    /// allocated; rejected outright until the first runtime-installed-pack
    /// ticket ships the per-vault name → handle map.
    PackHandle,
    /// Bytes `248–254` — pack-half experimental. Development mode only.
    PackExperimental,
    /// Byte `255` — reserved sentinel. Always rejected, in every mode.
    Sentinel,
}

/// The single semantic type byte (CLAIM) — the entirety of the `0` zone.
pub const TYPE_BYTE_SEMANTIC: u8 = 0;

/// First byte of the CORE StructuralKinds zone (`1–63`).
pub const TYPE_BYTE_ZONE_CORE_START: u8 = 1;

/// Last byte of the CORE StructuralKinds zone (`1–63`).
pub const TYPE_BYTE_ZONE_CORE_END: u8 = 63;

/// First byte of the system-kind zone (`64–99`).
pub const TYPE_BYTE_ZONE_SYSTEM_START: u8 = 64;

/// Last byte of the system-kind zone (`64–99`).
pub const TYPE_BYTE_ZONE_SYSTEM_END: u8 = 99;

/// First byte of the compiled-in product-pack zone (`100–125`).
pub const TYPE_BYTE_ZONE_COMPILED_PRODUCT_START: u8 = 100;

/// Last byte of the compiled-in product-pack zone (`100–125`).
pub const TYPE_BYTE_ZONE_COMPILED_PRODUCT_END: u8 = 125;

/// First byte of the engine-half experimental zone (`126–127`).
pub const TYPE_BYTE_ZONE_ENGINE_EXPERIMENTAL_START: u8 = 126;

/// Last byte of the engine-half experimental zone (`126–127`).
pub const TYPE_BYTE_ZONE_ENGINE_EXPERIMENTAL_END: u8 = 127;

/// Maps a type byte to its v3 zone. Total over all 256 bytes.
///
/// The pack half's edges are spelled as literals HERE and nowhere else. Byte
/// 128 is not an allocation, but `pub const TYPE_BYTE_…: u8 = 128;` is
/// indistinguishable from one at a glance and is exactly the shape the
/// `byte_space_v3_has_no_static_pack_half_allocations` census forbids without
/// exemption — so the engine half keeps its named edges and the pack half's
/// live inside the match that IS the allocation table. Totality is still the
/// compiler's: this match has no wildcard arm.
#[must_use]
pub const fn zone_of(type_byte: u8) -> TypeByteZone {
    match type_byte {
        TYPE_BYTE_SEMANTIC => TypeByteZone::Semantic,
        TYPE_BYTE_ZONE_CORE_START..=TYPE_BYTE_ZONE_CORE_END => TypeByteZone::Core,
        TYPE_BYTE_ZONE_SYSTEM_START..=TYPE_BYTE_ZONE_SYSTEM_END => TypeByteZone::System,
        TYPE_BYTE_ZONE_COMPILED_PRODUCT_START..=TYPE_BYTE_ZONE_COMPILED_PRODUCT_END => {
            TypeByteZone::CompiledProduct
        }
        TYPE_BYTE_ZONE_ENGINE_EXPERIMENTAL_START..=TYPE_BYTE_ZONE_ENGINE_EXPERIMENTAL_END => {
            TypeByteZone::EngineExperimental
        }
        128..=247 => TypeByteZone::PackHandle,
        248..=254 => TypeByteZone::PackExperimental,
        255 => TypeByteZone::Sentinel,
    }
}
