//! Exact, inert PACK.md source catalogs. A source blob is never an install grant.
mod codec;
mod doors;
mod manifest;
mod source;

pub(crate) use codec::{decode as decode_source_body, validate_pack_source_put};
pub use manifest::{PackAdapter, PackKind, PackManifest};
pub use source::PackSource;

pub(crate) fn export_source_body(
    source: &PackSource,
) -> crate::error::Result<crate::serialize::ExportBody> {
    Ok(crate::serialize::ExportBody::from_bytes(
        &codec::encode(source)?,
        crate::registry::ENTITY_TYPE_ASSET,
    ))
}

#[cfg(test)]
mod tests;

fn invalid(reason: &'static str) -> crate::error::Error {
    crate::error::Error::InvalidConfig(format!("pack source: {reason}"))
}

mod admission;
mod admission_types;
mod bundled_skills;
mod schema;
pub use admission_types::{
    PackInstallAsk, PackInstallDisposition, PackInstallReceipt, PackQualification, PackQualifier,
    PackRuntimeRecipe,
};
#[cfg(test)]
mod admission_tests;
