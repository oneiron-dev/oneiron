//! Turn and message VAD annotation persistence.

pub(crate) use crate::store::vad_annotation::{
    VAD_ANNOTATION_CLAIM_PREDICATE, VAD_ANNOTATION_META, VadAnnotationCleanup,
    VadAnnotationMetaKey, decode_vad_annotation_claim_body_if_present,
    delete_vad_annotation_metadata_for_type_in_txn, delete_vad_annotation_metadata_in_txn,
    vad_annotation_claim_body, vad_annotation_claim_id, vad_annotation_delete_scope_exists_in_txn,
    vad_annotation_from_value, vad_annotation_meta_key,
};
