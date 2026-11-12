//! Stable pack provenance and structural-kind short-id namespaces.

/// Stable short-id namespace for CAMPAIGN entities.
///
/// Two lowercase ASCII letters per the short-id convention; it names CAMPAIGN,
/// not the CRM pack as a whole, and is collision-vetted by the registration API
/// against both static and already-registered runtime prefixes. This is a
/// namespace token, not an entity-type byte.
pub const CAMPAIGN_SHORT_ID_PREFIX: &str = "ca";

/// Pack provenance persisted in the vault-scoped structural-kind registration.
pub const CRM_PACK_ID: &str = "oneiron-crm";

/// Stable short-id namespace for SAVED_QUERY entities. Two lowercase ASCII
/// letters per the short-id convention; a namespace token, never a type byte.
pub const SAVED_QUERY_SHORT_ID_PREFIX: &str = "sq";

/// Pack provenance persisted in PROJECT's and its revision kind's vault-scoped
/// structural-kind registrations.
pub const PROJECT_PACK: &str = "oneiron.project";

/// Stable short-id namespace for PROJECT entities.
pub const PROJECT_SHORT_ID_PREFIX: &str = "pj";

/// Stable short-id namespace for PROJECT_REVISION entities, beside PROJECT in
/// PROJECT's pack.
pub const PROJECT_REVISION_SHORT_ID_PREFIX: &str = "pv";

/// The kind name of each compiled-in product kind that is registered at run
/// time, keyed by the pack and short-id prefix of its registration. A
/// vault-scoped registration persists its byte, prefix, zone, pack and family,
/// never a kind name; reads name the kind from this table, so a project reads
/// back as `PROJECT` (ARCH-0016:18) and not as `TYPE_<byte>`.
pub const COMPILED_PRODUCT_KIND_NAMES: &[CompiledProductKindName] = &[
    CompiledProductKindName {
        pack: PROJECT_PACK,
        short_id_prefix: PROJECT_SHORT_ID_PREFIX,
        kind: "PROJECT",
    },
    CompiledProductKindName {
        pack: PROJECT_PACK,
        short_id_prefix: PROJECT_REVISION_SHORT_ID_PREFIX,
        kind: "PROJECT_REVISION",
    },
    CompiledProductKindName {
        pack: CRM_PACK_ID,
        short_id_prefix: CAMPAIGN_SHORT_ID_PREFIX,
        kind: "CAMPAIGN",
    },
    CompiledProductKindName {
        pack: CRM_PACK_ID,
        short_id_prefix: SAVED_QUERY_SHORT_ID_PREFIX,
        kind: "SAVED_QUERY",
    },
];

/// One row of [`COMPILED_PRODUCT_KIND_NAMES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompiledProductKindName {
    /// The pack the kind's run-time registration names.
    pub pack: &'static str,
    /// The short-id prefix the kind's run-time registration names.
    pub short_id_prefix: &'static str,
    /// The kind name reads spell.
    pub kind: &'static str,
}

/// The kind name of the compiled-in product kind registered under `pack` and
/// `short_id_prefix`, or `None` for a registration no compiled-in kind owns.
#[must_use]
pub fn compiled_product_kind_name(pack: &str, short_id_prefix: &str) -> Option<&'static str> {
    COMPILED_PRODUCT_KIND_NAMES
        .iter()
        .find(|row| row.pack == pack && row.short_id_prefix == short_id_prefix)
        .map(|row| row.kind)
}
