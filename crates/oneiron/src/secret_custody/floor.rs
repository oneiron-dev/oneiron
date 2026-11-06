//! Stored custody floor resolution, defined in the store layer.

pub(super) use crate::secret_record::floor::{MapValue, as_u64, required_value, single_map_value};
pub(crate) use crate::secret_record::floor::{
    PolicyManifestWalkError, policy_manifest_bodies_strict, policy_manifest_body_map,
};
