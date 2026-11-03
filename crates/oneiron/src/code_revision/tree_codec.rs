//! Queue and retirement codecs are defined with the revision record.

pub(super) use crate::store::code_revision_record::tree_codec::{
    blobs_to_value, blobs_from_value, tested_to_value, tested_from_value, hash_queue_fields, retirements_to_value, retirements_from_value, hash_import_fields,
};
