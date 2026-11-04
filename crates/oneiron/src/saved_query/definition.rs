use crate::Vault;
use crate::campaign::CRM_PACK_ID;
use crate::error::Result;
use crate::registry::{StructuralKindRegistration, TypeByteFamily};

pub use crate::registry::pack_namespaces::SAVED_QUERY_SHORT_ID_PREFIX;

pub use crate::memory::query_records::SAVED_QUERY_SCHEMA_VERSION;

/// Registers the SAVED_QUERY structural kind for a NEW vault.
/// The caller explicitly declares the replication family, just as for CAMPAIGN.
///
/// `assigned_type_byte` comes from the byte-space-v3 registration flow run by
/// the vault/pack initializer; this module never chooses, infers, or hard-codes
/// a byte. Mirrors [`crate::campaign::register_campaign_kind`] exactly: the CRM
/// pack has ONE identity, and both kinds enter through the same registrar.
///
/// # Errors
///
/// Propagates the existing registration errors unchanged — a byte outside the
/// `Crm` band yields `StructuralKindZoneViolation`, and a taken byte or prefix
/// yields `StructuralKindTypeByteCollision` / `StructuralKindPrefixCollision`.
/// SAVED_QUERY adds no registration failure mode of its own.
pub fn register_saved_query_kind(
    vault: &Vault,
    assigned_type_byte: u8,
    family: TypeByteFamily,
) -> Result<StructuralKindRegistration> {
    vault.register_structural_kind_in_family(
        assigned_type_byte,
        SAVED_QUERY_SHORT_ID_PREFIX,
        family,
        CRM_PACK_ID,
    )
}

pub use crate::memory::query_records::CreateSavedQueryRequest;
pub use crate::memory::query_records::EvalMode;
pub use crate::memory::query_records::EvalPolicy;
pub use crate::memory::query_records::QueryScope;
pub use crate::memory::query_records::SavedQueryDefinition;
pub use crate::memory::query_records::SavedQueryLifecycle;
pub use crate::memory::query_records::SavedQueryRecord;
pub use crate::memory::query_records::UpdateSavedQueryRequest;
