//! Exact stored skill package values, envelope codecs and source parsing.

pub(crate) use oneiron_store::skill_package::capability;
pub(crate) mod codec;
pub(crate) mod folder;
pub(crate) use oneiron_store::skill_package::package;
pub(crate) mod site_folder;

pub use crate::write_envelope::skill_source::{HubFile, SkillPackageFormat};
pub use codec::{decode_hub_package, encode_hub_package};
pub(crate) use folder::{package_from_files, package_from_source};
pub use package::{HubIndexEntry, HubPackage, SkillCapabilitySurface};
