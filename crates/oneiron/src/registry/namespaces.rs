//! Presentation-id namespaces for entity kinds and vaults.

use super::registry_table::ENTITY_TYPE_REGISTRY;
use super::zones::TypeByteZone;

/// What an id-namespace prefix names.
///
/// The entity registry can only describe things that HAVE a type byte. `vt`
/// names vaults, and a vault is not an entity — it is the container entities
/// live in. Minting a VAULT type byte to make `vt` expressible would put a
/// false row in the storage ABI, so the namespace registry carries the
/// non-entity prefixes instead and the entity registry stays honest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdNamespaceTarget {
    /// A registered entity kind, named by its type byte.
    EntityType(u8),
    /// A vault, addressed by its 32-byte `authority::AuthorityVaultId`.
    Vault,
}

/// One presentation-id namespace: the prefix and what it resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdNamespaceRegistryEntry {
    pub target: IdNamespaceTarget,
    pub prefix: &'static str,
}

/// Canonical prefix for the vault id namespace.
pub const VAULT_ID_NAMESPACE_PREFIX: &str = "vt";

/// Presentation-id namespaces that are NOT backed by an entity type.
///
/// Entity-backed namespaces are not duplicated here — [`id_namespace_for_prefix`]
/// derives them from [`ENTITY_TYPE_REGISTRY`], so a prefix has exactly one
/// definition site and the two tables cannot drift apart.
pub const ID_NAMESPACE_REGISTRY: &[IdNamespaceRegistryEntry] = &[IdNamespaceRegistryEntry {
    target: IdNamespaceTarget::Vault,
    prefix: VAULT_ID_NAMESPACE_PREFIX,
}];

/// Resolves a presentation-id prefix to its namespace.
///
/// Entity kinds answer to their canonical prefix AND to any declared legacy
/// spelling; non-entity namespaces answer only to their canonical prefix
/// (nothing has retired one yet). Returns `None` for a prefix no registry
/// declares — that is the unknown-prefix RESOLUTION failure, and the layer
/// above may still admit the id through an exact alias row.
/// The returned entry always carries the CANONICAL spelling, so a caller
/// resolving a retired prefix learns the current one in the same lookup.
#[must_use]
pub fn id_namespace_for_prefix(prefix: &str) -> Option<IdNamespaceRegistryEntry> {
    if let Some(entry) = ENTITY_TYPE_REGISTRY
        .iter()
        .find(|entry| entry.answers_to_prefix(prefix))
        // A kind with no canonical prefix has no presentation namespace at all,
        // retired spellings or not — total by construction, no panic path.
        && let Some(canonical) = entry.short_id_prefix
    {
        return Some(IdNamespaceRegistryEntry {
            target: IdNamespaceTarget::EntityType(entry.type_byte),
            prefix: canonical,
        });
    }
    ID_NAMESPACE_REGISTRY
        .iter()
        .find(|entry| entry.prefix == prefix)
        .copied()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralKindRegistration {
    pub type_byte: u8,
    pub short_id_prefix: String,
    pub zone: TypeByteZone,
    pub pack: String,
}
