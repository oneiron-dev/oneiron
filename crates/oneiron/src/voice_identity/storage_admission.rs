//! Sidecar row access, the one deletion routine, enrollment laws, and match/clustering/invite-elimination admission.

use crate::ports::EntityStoreRead;
use std::collections::{BTreeMap, BTreeSet, HashSet};

use heed::{RoTxn, RwTxn};

use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_COUNTERPARTY_CONTACT, ENTITY_TYPE_RELATIONSHIP};
use crate::side_table::{self, Raw, SideKey, SideTable};
use crate::store::Store;

use super::codec_records::decode_print_record;
use super::math_keys::{
    corrupt_voice_row, cosine_similarity, digest16, invalid_voice, l2_normalize, require_non_empty,
    voice_cosine_in_space,
};
use super::types::{
    VOICE_CALIBRATION_MIN_LANGUAGES, VOICE_MAX_MATCH_SEGMENTS, VoiceConsentEventV1,
    VoiceConsentState, VoiceEnrollmentOrigin, VoiceEnrollmentRequest, VoiceEnrollmentSampleV1,
    VoiceMatchRequest, VoicePrintCalibration, VoicePrintRecordV1, VoiceSegmentEmbeddingInput,
    VoiceSessionRosterV1,
};
use crate::error::RegistryError;

/// Voice consent decision event. Key: subject id16 + digest16(event id).
pub(super) const CONSENT: SideTable<(EntityId, [u8; 16]), VoiceConsentEventV1, Raw> =
    SideTable::new(&side_table::VOICE_IDENTITY_CONSENT);

/// Active-space pointer row: subject -> active space id text.
///
/// Shares its declared prefix with [`PRINT_RECORD`]: the pointer row's key is
/// exactly the subject id (no digest suffix), the print row's key is the
/// subject id plus a 16-byte space digest, and the two shapes cannot collide.
/// They also cannot be scanned through one typed lens at once, so
/// [`delete_voice_biometrics_in_txn`] and [`active_print_subjects`] read both
/// shapes undecoded through [`print_family_rows`].
pub(super) const PRINT_POINTER: SideTable<EntityId, String, Raw> =
    SideTable::new(&side_table::VOICE_IDENTITY_PRINT);

/// Print row: one centroid for one (subject, embedding space). Key: subject
/// id16 + digest16(space id).
pub(super) const PRINT_RECORD: SideTable<(EntityId, [u8; 16]), VoicePrintRecordV1, Raw> =
    SideTable::new(&side_table::VOICE_IDENTITY_PRINT);

/// Enrollment sample row. Key: digest16(subject id16 + sample id).
pub(super) const SAMPLE: SideTable<[u8; 16], VoiceEnrollmentSampleV1, Raw> =
    SideTable::new(&side_table::VOICE_IDENTITY_SAMPLE);

/// Resolved session speaker roster. Key: digest16(voice session ref).
pub(super) const ROSTER: SideTable<[u8; 16], VoiceSessionRosterV1, Raw> =
    SideTable::new(&side_table::VOICE_IDENTITY_ROSTER);

/// The print-family rows under `key_prefix`, undecoded (pointer and print rows
/// share the declared prefix; see [`PRINT_POINTER`]). Keys are the bytes after
/// the table prefix.
pub(super) fn print_family_rows(
    store: &Store,
    rtxn: &RoTxn<'_>,
    key_prefix: &[u8],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    PRINT_RECORD
        .iter_raw_from(store, rtxn, key_prefix)?
        .collect()
}

pub(super) fn read_consent_event(
    store: &Store,
    rtxn: &RoTxn<'_>,
    subject: &EntityId,
    event_id: &str,
) -> Result<Option<VoiceConsentEventV1>> {
    let digest = digest16(b"voice_identity.consent", event_id.as_bytes());
    CONSENT.get(store, rtxn, &(*subject, digest))
}

fn read_consent_events(
    store: &Store,
    rtxn: &RoTxn<'_>,
    subject: &EntityId,
) -> Result<Vec<VoiceConsentEventV1>> {
    Ok(CONSENT
        .scan_from(store, rtxn, subject.as_bytes())?
        .into_iter()
        .map(|(_, event)| event)
        .collect())
}

/// Reads the subject's ACTIVE print row through the active-space pointer.
pub(super) fn read_active_print(
    store: &Store,
    rtxn: &RoTxn<'_>,
    subject: &EntityId,
) -> Result<Option<VoicePrintRecordV1>> {
    let Some(space_id) = PRINT_POINTER.get(store, rtxn, subject)? else {
        return Ok(None);
    };
    let digest = digest16(b"voice_identity.space", space_id.as_bytes());
    let Some(record) = PRINT_RECORD.get(store, rtxn, &(*subject, digest))? else {
        return Err(corrupt_voice_row());
    };
    Ok(Some(record))
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn read_sample(
    store: &Store,
    rtxn: &RoTxn<'_>,
    subject: &EntityId,
    sample_id: &str,
) -> Result<Option<VoiceEnrollmentSampleV1>> {
    let digest = sample_digest(subject, sample_id);
    SAMPLE.get(store, rtxn, &digest)
}

/// The digest half of a sample row's key: subject id and sample id, hashed
/// together so the key never carries the sample id's raw text.
pub(super) fn sample_digest(subject: &EntityId, sample_id: &str) -> [u8; 16] {
    let mut scoped = Vec::with_capacity(ENTITY_ID_LEN + sample_id.len());
    scoped.extend_from_slice(subject.as_bytes());
    scoped.extend_from_slice(sample_id.as_bytes());
    digest16(b"voice_identity.sample", &scoped)
}

/// Every subject that currently has an active-space pointer, in key order.
///
/// Scans the WHOLE print-family prefix, which mixes pointer rows (subject id
/// only) and print rows (subject id + space digest); a length check keeps
/// only the pointer shape, so this reads undecoded rows rather than a
/// [`PRINT_POINTER`] scan (which would fail to decode the longer print rows
/// instead of skipping them).
pub(super) fn active_print_subjects(store: &Store, rtxn: &RoTxn<'_>) -> Result<Vec<EntityId>> {
    let mut subjects = Vec::new();
    for (key, _) in print_family_rows(store, rtxn, &[])? {
        if key.len() != ENTITY_ID_LEN {
            continue;
        }
        let raw: [u8; ENTITY_ID_LEN] =
            key.as_slice().try_into().map_err(|_| corrupt_voice_row())?;
        subjects.push(EntityId::from_bytes(raw).map_err(|_| corrupt_voice_row())?);
    }
    Ok(subjects)
}

/// What one biometric deletion transaction removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct VoiceDeletionTally {
    pub(super) print_rows: usize,
    pub(super) sample_rows: usize,
    pub(super) vector_rows: usize,
    pub(super) active_pointer: bool,
    owner_ref_rows: usize,
}

impl VoiceDeletionTally {
    pub(super) const fn is_empty(self) -> bool {
        self.print_rows == 0
            && self.sample_rows == 0
            && self.owner_ref_rows == 0
            && !self.active_pointer
    }
}

/// The ONE biometric deletion routine.
///
/// Explicit withdrawal and retention pruning share it, so both paths delete
/// exactly the same rows: every print row of the subject (each holding one
/// centroid), every sample/vector row those prints reference, and the
/// active-space pointer.
///
/// The read is an undecoded scan over the shared pointer/print-record prefix
/// for the same reason [`active_print_subjects`] reads one (see
/// [`PRINT_POINTER`]'s doc comment); the print-row deletes remove the EXACT
/// keys this scan just observed rather than re-deriving them from the
/// record, so a stored key that ever drifted from its record's own space id
/// would still be removed.
pub(super) fn delete_voice_biometrics_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    subject: &EntityId,
) -> Result<VoiceDeletionTally> {
    let rows = print_family_rows(store, wtxn, subject.as_bytes())?;

    let mut sample_digests: BTreeSet<[u8; 16]> = BTreeSet::new();
    let mut print_keys: Vec<(EntityId, [u8; 16])> = Vec::new();
    let mut tally = VoiceDeletionTally {
        owner_ref_rows: super::ref_bank::delete_owner_refs(store, wtxn, subject)?,
        ..VoiceDeletionTally::default()
    };

    for (key, value) in rows {
        if key.as_slice() == subject.as_bytes().as_slice() {
            tally.active_pointer = true;
            continue;
        }
        let record = decode_print_record(&value)?;
        for sample_id in &record.sample_ids {
            sample_digests.insert(sample_digest(subject, sample_id));
        }
        // One print row holds exactly one centroid vector.
        tally.vector_rows = tally.vector_rows.saturating_add(1);
        print_keys.push(SideKey::decode_key(&key).ok_or_else(corrupt_voice_row)?);
    }

    for key in print_keys {
        if PRINT_RECORD.delete(store, wtxn, &key)? {
            tally.print_rows = tally.print_rows.saturating_add(1);
        }
    }
    for digest in sample_digests {
        if SAMPLE.delete(store, wtxn, &digest)? {
            tally.sample_rows = tally.sample_rows.saturating_add(1);
            tally.vector_rows = tally.vector_rows.saturating_add(1);
        }
    }
    if tally.active_pointer {
        PRINT_POINTER.delete(store, wtxn, subject)?;
    }
    Ok(tally)
}

fn entity_type_in_txn(store: &Store, rtxn: &RoTxn<'_>, id: &EntityId) -> Result<Option<u8>> {
    let Some(raw) = store.port_entity_record(rtxn, id)? else {
        return Ok(None);
    };

    Ok(Some(raw.entity_type))
}

/// Law 9: a retention link must name an EXISTING RELATIONSHIP entity.
pub(super) fn require_relationship_entity(
    store: &Store,
    rtxn: &RoTxn<'_>,
    relationship: &EntityId,
) -> Result<()> {
    let found = entity_type_in_txn(store, rtxn, relationship)?;
    if found == Some(ENTITY_TYPE_RELATIONSHIP) {
        Ok(())
    } else {
        Err(Error::Registry(RegistryError::InvalidRelationship {
            relationship: *relationship,
            found,
        }))
    }
}

pub(super) fn require_counterparty_contact_entity(
    store: &Store,
    rtxn: &RoTxn<'_>,
    contact: &EntityId,
) -> Result<()> {
    match entity_type_in_txn(store, rtxn, contact)? {
        Some(ENTITY_TYPE_COUNTERPARTY_CONTACT) => Ok(()),
        Some(other) => Err(Error::InvalidEntityType(other)),
        None => Err(Error::EntityNotFound),
    }
}

/// Laws 1 and 10: consent must precede enrollment, cover the purpose, and not
/// have been withdrawn since.
pub(super) fn admit_enrollment_consent(
    store: &Store,
    rtxn: &RoTxn<'_>,
    request: &VoiceEnrollmentRequest,
) -> Result<VoiceConsentEventV1> {
    let event = read_consent_event(
        store,
        rtxn,
        &request.subject_ref,
        &request.consent_event_ref,
    )?
    .ok_or_else(|| invalid_voice("voice enrollment needs a recorded consent event"))?;
    if event.state != VoiceConsentState::Granted {
        return Err(invalid_voice(
            "voice enrollment consent event is not a grant",
        ));
    }
    if !event.covers(&request.purpose) {
        return Err(invalid_voice(
            "voice enrollment consent does not cover the requested purpose",
        ));
    }
    if event.occurred_at > request.requested_at {
        return Err(invalid_voice(
            "voice enrollment consent must precede the enrollment request",
        ));
    }
    let withdrawn = read_consent_events(store, rtxn, &request.subject_ref)?
        .into_iter()
        .any(|candidate| {
            candidate.state == VoiceConsentState::Withdrawn
                && candidate.covers(&request.purpose)
                && candidate.occurred_at >= event.occurred_at
        });
    if withdrawn {
        return Err(invalid_voice(
            "voice consent for this purpose was withdrawn after the cited grant",
        ));
    }
    Ok(event)
}

/// Law 2: which provenance a sample must carry.
pub(super) fn admit_sample_origin(
    sample: &VoiceEnrollmentSampleV1,
    is_contact_enrollment: bool,
    consent: &VoiceConsentEventV1,
) -> Result<()> {
    match &sample.origin {
        VoiceEnrollmentOrigin::AuthenticatedSoloSession {
            session_ref,
            speaker_count,
        } => {
            if is_contact_enrollment {
                return Err(invalid_voice(
                    "contact voice samples require a consented diarized segment",
                ));
            }
            require_non_empty(session_ref, "voice enrollment session ref")?;
            if *speaker_count != 1 {
                return Err(invalid_voice(
                    "passive principal voice samples require a solo session (speaker_count == 1)",
                ));
            }
            Ok(())
        }
        VoiceEnrollmentOrigin::ConsentedDiarizedSegment {
            recording_ref,
            segment_id,
        } => {
            if !is_contact_enrollment {
                return Err(invalid_voice(
                    "principal voice samples require an authenticated solo session",
                ));
            }
            require_non_empty(recording_ref, "voice enrollment recording ref")?;
            require_non_empty(segment_id, "voice enrollment segment id")?;
            if sample.source_ref != *recording_ref {
                return Err(invalid_voice(
                    "voice enrollment sample source_ref must name its recording",
                ));
            }
            if consent.basis.recording_ref() != Some(recording_ref.as_str()) {
                return Err(invalid_voice(
                    "voice enrollment consent does not name this recording",
                ));
            }
            Ok(())
        }
    }
}

/// Law 3: duration-weighted mean of normalized samples, normalized again.
pub(super) fn compute_centroid(
    samples: &[&VoiceEnrollmentSampleV1],
    dimension: usize,
) -> Result<Vec<f32>> {
    let mut accumulator = vec![0.0_f64; dimension];
    let mut total_weight = 0.0_f64;
    for sample in samples {
        let normalized = l2_normalize(&sample.vector, dimension)?;
        let weight = sample.duration_ms as f64;
        for (slot, value) in accumulator.iter_mut().zip(normalized.iter()) {
            *slot += weight * f64::from(*value);
        }
        total_weight += weight;
    }
    if total_weight <= 0.0 {
        return Err(invalid_voice(
            "voice enrollment samples need a positive total duration",
        ));
    }
    let mean: Vec<f32> = accumulator
        .iter()
        .map(|value| (*value / total_weight) as f32)
        .collect();
    l2_normalize(&mean, dimension)
}

/// Law 3: mixed-language means at least two distinct tags.
pub(super) fn calibration_for(languages: &[String]) -> VoicePrintCalibration {
    let distinct: BTreeSet<&str> = languages.iter().map(String::as_str).collect();
    if distinct.len() >= VOICE_CALIBRATION_MIN_LANGUAGES {
        VoicePrintCalibration::Calibrated
    } else {
        VoicePrintCalibration::Collecting
    }
}

/// One active centroid admitted as a match candidate.
#[derive(Debug, Clone)]
pub(super) struct VoiceMatchCandidate {
    pub(super) subject_ref: EntityId,
    pub(super) contact_ref: Option<EntityId>,
    space_id: String,
    centroid: Vec<f32>,
    pub(super) calibration: VoicePrintCalibration,
}

/// Validates a match request and returns its segments in canonical order,
/// every admitted vector L2-normalized at this door.
///
/// Canonical order is (start_ms, segment_id) — the Law 6 residual-label key —
/// so a caller that hands the same segments in a different order gets a
/// byte-identical roster. Segment ids are distinct, so that pair is a total
/// order.
///
/// Law 5: the comparison door is a plain dot product over already-normalized
/// vectors, and every stored-side vector is normalized. Normalizing here is
/// what makes each enrolled-match and residual-linkage score an actual cosine
/// instead of a magnitude-scaled one, so a loud segment cannot buy acceptance
/// and a quiet one cannot be rejected for its length. [`l2_normalize`] runs
/// the dimension, finiteness, and non-zero checks, so admission validation
/// folds into it. The caller's request is untouched.
pub(super) fn admit_match_segments(
    request: &VoiceMatchRequest,
) -> Result<Vec<VoiceSegmentEmbeddingInput>> {
    require_non_empty(&request.voice_session_ref, "voice session ref")?;
    require_non_empty(&request.recording_id, "voice recording id")?;
    require_non_empty(&request.space_id, "voice embedding space id")?;
    request.policy.validate()?;
    if request.segments.len() > VOICE_MAX_MATCH_SEGMENTS {
        return Err(invalid_voice(
            "voice match request exceeds the supported segment count",
        ));
    }

    let mut seen: HashSet<&str> = HashSet::with_capacity(request.segments.len());
    let mut dimension: Option<usize> = None;
    let mut segments = Vec::with_capacity(request.segments.len());
    for segment in &request.segments {
        require_non_empty(&segment.segment_id, "voice segment id")?;
        if !seen.insert(segment.segment_id.as_str()) {
            return Err(invalid_voice("voice segment ids must be distinct"));
        }
        if segment.start_ms >= segment.end_ms {
            return Err(invalid_voice("voice segment needs start_ms < end_ms"));
        }
        // Law 4: a foreign-space segment is an error, never a low score.
        if segment.space_id != request.space_id {
            return Err(invalid_voice(
                "cross-space voice segment rejected: embedding space_id differs",
            ));
        }
        let declared = *dimension.get_or_insert(segment.vector.len());
        // Law 5: validate and normalize in one step; only unit-length vectors
        // are ever admitted, so every downstream score is a true cosine.
        let mut admitted = segment.clone();
        admitted.vector = l2_normalize(&segment.vector, declared)?;
        segments.push(admitted);
    }

    segments.sort_by(|left, right| {
        (left.start_ms, left.segment_id.as_str()).cmp(&(right.start_ms, right.segment_id.as_str()))
    });
    Ok(segments)
}

pub(super) fn load_match_candidates(
    store: &Store,
    rtxn: &RoTxn<'_>,
    space_id: &str,
) -> Result<Vec<VoiceMatchCandidate>> {
    let mut candidates = Vec::new();
    for subject in active_print_subjects(store, rtxn)? {
        let Some(record) = read_active_print(store, rtxn, &subject)? else {
            continue;
        };
        if record.space.space_id != space_id {
            // A print pinned to another space is simply not a candidate here;
            // it is never compared and never scored low.
            continue;
        }
        candidates.push(VoiceMatchCandidate {
            subject_ref: record.subject_ref,
            contact_ref: record.contact_ref,
            space_id: record.space.space_id.clone(),
            centroid: l2_normalize(&record.centroid, record.space.dimension)?,
            calibration: record.calibration,
        });
    }
    // Deterministic subject-id tie-break for equal scores.
    candidates.sort_by_key(|left| left.subject_ref);
    Ok(candidates)
}

/// Law 5: highest enrolled score, subject-id tie-break, accept at threshold.
pub(super) fn best_enrolled_match<'a>(
    segment_space_id: &str,
    segment_vector: &[f32],
    candidates: &'a [VoiceMatchCandidate],
    known_threshold: f32,
) -> Result<Option<(&'a VoiceMatchCandidate, f32)>> {
    let mut best: Option<(&VoiceMatchCandidate, f32)> = None;
    for candidate in candidates {
        let score = voice_cosine_in_space(
            segment_space_id,
            segment_vector,
            &candidate.space_id,
            &candidate.centroid,
        )?;
        let improves = best.is_none_or(|(_, best_score)| score > best_score);
        if improves {
            best = Some((candidate, score));
        }
    }
    Ok(best.filter(|(_, score)| *score >= known_threshold))
}

/// Law 6: single-linkage agglomerative cosine clustering of residuals only.
///
/// At a fixed linkage threshold single linkage is exactly the connected
/// components of the "cosine at or above threshold" graph, so the result does
/// not depend on merge order at all. Clusters come back ordered by their
/// earliest member in the caller's canonical segment order.
pub(super) fn cluster_residuals(
    vectors: &[&[f32]],
    residual_threshold: f32,
) -> Result<Vec<Vec<usize>>> {
    fn find(parent: &mut [usize], mut node: usize) -> usize {
        while parent[node] != node {
            parent[node] = parent[parent[node]];
            node = parent[node];
        }
        node
    }

    let count = vectors.len();
    let mut parent: Vec<usize> = (0..count).collect();

    for left in 0..count {
        for right in (left + 1)..count {
            if cosine_similarity(vectors[left], vectors[right])? >= residual_threshold {
                let (root_left, root_right) = (find(&mut parent, left), find(&mut parent, right));
                if root_left != root_right {
                    let (low, high) = if root_left < root_right {
                        (root_left, root_right)
                    } else {
                        (root_right, root_left)
                    };
                    parent[high] = low;
                }
            }
        }
    }

    let mut clusters: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for index in 0..count {
        let root = find(&mut parent, index);
        clusters.entry(root).or_default().push(index);
    }
    Ok(clusters.into_values().collect())
}

/// Law 7: name the unique remaining attendee, or keep everyone anonymous.
///
/// Ambiguity is not resolved by lowering a threshold or by nudging a score;
/// it simply leaves the anonymous labels in place.
pub(super) fn unambiguous_invite_remainder(
    invite_attendee_refs: &[EntityId],
    matched_refs: &BTreeSet<EntityId>,
    residual_cluster_count: usize,
) -> Option<EntityId> {
    let remaining: BTreeSet<EntityId> = invite_attendee_refs
        .iter()
        .copied()
        .filter(|attendee| !matched_refs.contains(attendee))
        .collect();
    if remaining.len() == 1 && residual_cluster_count == 1 {
        remaining.into_iter().next()
    } else {
        None
    }
}

pub(super) fn residual_cluster_ref(index: usize) -> String {
    format!("residual.{}", index.saturating_add(1))
}

pub(super) fn residual_speaker_label(index: usize) -> String {
    format!("anonymous speaker {}", index.saturating_add(1))
}
