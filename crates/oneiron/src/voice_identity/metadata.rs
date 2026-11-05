//! Vector-free recognition metadata remains readable for admission and hard deletion.

use super::enrollment_law::VoicePrintLegalEvidence;
use super::types::{
    VoiceEmbeddingSpaceV1, VoicePrintCalibration, VoicePrintPurpose, VoicePrintRecordV1,
};
use crate::EntityId;

#[derive(Debug, Clone, PartialEq)]
pub(super) struct PrintMetadata {
    pub(super) subject_ref: EntityId,
    pub(super) contact_ref: Option<EntityId>,
    pub(super) relationship_ref: Option<EntityId>,
    pub(super) consent_event_ref: String,
    pub(super) world_ref: Option<EntityId>,
    pub(super) consented_purposes: Vec<VoicePrintPurpose>,
    pub(super) legal: VoicePrintLegalEvidence,
    pub(super) space: VoiceEmbeddingSpaceV1,
    pub(super) sample_ids: Vec<String>,
    pub(super) sample_languages: Vec<String>,
    pub(super) calibration: VoicePrintCalibration,
    pub(super) print_generation: EntityId,
    pub(super) created_at: u64,
    pub(super) updated_at: u64,
    pub(super) delete_after: Option<u64>,
}

impl From<&VoicePrintRecordV1> for PrintMetadata {
    fn from(record: &VoicePrintRecordV1) -> Self {
        Self {
            subject_ref: record.subject_ref.clone(),
            contact_ref: record.contact_ref.clone(),
            relationship_ref: record.relationship_ref.clone(),
            consent_event_ref: record.consent_event_ref.clone(),
            world_ref: record.world_ref.clone(),
            consented_purposes: record.consented_purposes.clone(),
            legal: record.legal.clone(),
            space: record.space.clone(),
            sample_ids: record.sample_ids.clone(),
            sample_languages: record.sample_languages.clone(),
            calibration: record.calibration.clone(),
            print_generation: record.print_generation.clone(),
            created_at: record.created_at.clone(),
            updated_at: record.updated_at.clone(),
            delete_after: record.delete_after.clone(),
        }
    }
}

impl PrintMetadata {
    pub(super) fn with_centroid(self, centroid: Vec<f32>) -> VoicePrintRecordV1 {
        VoicePrintRecordV1 {
            subject_ref: self.subject_ref,
            contact_ref: self.contact_ref,
            relationship_ref: self.relationship_ref,
            consent_event_ref: self.consent_event_ref,
            world_ref: self.world_ref,
            consented_purposes: self.consented_purposes,
            legal: self.legal,
            space: self.space,
            sample_ids: self.sample_ids,
            sample_languages: self.sample_languages,
            calibration: self.calibration,
            print_generation: self.print_generation,
            created_at: self.created_at,
            updated_at: self.updated_at,
            delete_after: self.delete_after,
            centroid,
        }
    }
}
