//! Vault surface for consent, enrollment, segment matching, roster reads, withdrawal, and pruning.

use std::collections::{BTreeSet, HashSet};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::codec_core::{encode_consent_event, encode_sample};
use super::codec_records::{decode_roster, encode_print_record, encode_roster};
use super::math_keys::{
    invalid_voice, require_non_empty, require_sha256_hex, validate_voice_vector,
    voice_active_pointer_key, voice_consent_key, voice_print_key, voice_roster_key,
    voice_sample_key,
};
use super::storage_admission::{
    active_print_subjects, admit_enrollment_consent, admit_match_segments, admit_sample_origin,
    best_enrolled_match, calibration_for, cluster_residuals, compute_centroid,
    delete_voice_biometrics_in_txn, load_match_candidates, read_active_print,
    require_counterparty_contact_entity, require_relationship_entity, residual_cluster_ref,
    residual_speaker_label, unambiguous_invite_remainder,
};
use super::types::{
    VoiceAttributionEvidence, VoiceConsentEventV1, VoiceConsentState, VoiceEnrollmentRequest,
    VoiceEnrollmentSampleV1, VoiceMatchRequest, VoicePrintRecordV1, VoiceResolvedSegment,
    VoiceSessionRosterV1, VoiceWithdrawalReceipt, VoiceWithdrawalRequest,
};

impl Vault {
    /// Appends one consent or withdrawal decision to the private consent log.
    ///
    /// The record carries who, when, what purposes, how consent was captured,
    /// and its evidence refs. It grants no owner authority, no outbound
    /// permission, and no disclosure widening, and it never carries a vector.
    pub fn record_voice_consent(&self, event: &VoiceConsentEventV1) -> Result<()> {
        let data = encode_consent_event(event)?;
        let key = voice_consent_key(&event.subject_ref, &event.event_id);
        self.with_write_txn(|wtxn| {
            self.store.vault_meta.put(wtxn, &key, &data)?;
            Ok(())
        })
    }

    /// Builds (or rebuilds) one subject's active voice print.
    ///
    /// Consent is checked first, then sample provenance, then the vectors
    /// themselves. The subject's previous print rows, their sample/vector
    /// rows, and the active-space pointer are replaced inside the same write
    /// transaction, so a re-pinned model never leaves a stale centroid behind
    /// and a rejected request writes nothing at all.
    pub fn enroll_voice_print(
        &self,
        request: &VoiceEnrollmentRequest,
    ) -> Result<VoicePrintRecordV1> {
        request.space.validate()?;
        require_non_empty(&request.consent_event_ref, "voice consent event ref")?;
        if request.samples.is_empty() {
            return Err(invalid_voice("voice enrollment needs at least one sample"));
        }

        // Deterministic accumulation order: the centroid must not depend on
        // the order the caller happened to hand the samples over in.
        let mut ordered: Vec<&VoiceEnrollmentSampleV1> = request.samples.iter().collect();
        ordered.sort_by(|left, right| left.sample_id.cmp(&right.sample_id));
        let mut seen_ids: HashSet<&str> = HashSet::with_capacity(ordered.len());
        for sample in &ordered {
            require_non_empty(&sample.sample_id, "voice sample id")?;
            require_non_empty(&sample.source_ref, "voice sample source ref")?;
            require_non_empty(&sample.language, "voice sample language")?;
            require_sha256_hex(&sample.source_sha256)?;
            if sample.duration_ms == 0 {
                return Err(invalid_voice("voice sample duration must be positive"));
            }
            if !seen_ids.insert(sample.sample_id.as_str()) {
                return Err(invalid_voice("voice sample ids must be distinct"));
            }
            validate_voice_vector(&sample.vector, request.space.dimension)?;
        }

        let is_contact_enrollment = request.contact_ref.is_some();
        let centroid = compute_centroid(&ordered, request.space.dimension)?;
        let sample_ids: Vec<String> = ordered
            .iter()
            .map(|sample| sample.sample_id.clone())
            .collect();
        let sample_languages: Vec<String> = ordered
            .iter()
            .map(|sample| sample.language.clone())
            .collect();
        let calibration = calibration_for(&sample_languages);

        let store = &self.store;
        let subject = request.subject_ref;
        self.with_write_txn(|wtxn| {
            let consent = admit_enrollment_consent(store, wtxn, request)?;
            for sample in &ordered {
                admit_sample_origin(sample, is_contact_enrollment, &consent)?;
            }
            if let Some(contact_ref) = request.contact_ref.as_ref() {
                require_counterparty_contact_entity(store, wtxn, contact_ref)?;
            }
            if let Some(relationship_ref) = request.relationship_ref.as_ref() {
                require_relationship_entity(store, wtxn, relationship_ref)?;
            }

            let previous = read_active_print(store, wtxn, &subject)?;
            delete_voice_biometrics_in_txn(store, wtxn, &subject)?;

            let record = VoicePrintRecordV1 {
                subject_ref: subject,
                contact_ref: request.contact_ref,
                relationship_ref: request.relationship_ref,
                consent_event_ref: request.consent_event_ref.clone(),
                space: request.space.clone(),
                centroid: centroid.clone(),
                sample_ids: sample_ids.clone(),
                sample_languages: sample_languages.clone(),
                calibration,
                created_at: previous.map_or(request.requested_at, |prior| prior.created_at),
                updated_at: request.requested_at,
                delete_after: None,
            };
            let body = encode_print_record(&record)?;
            store.vault_meta.put(
                wtxn,
                &voice_print_key(&subject, &request.space.space_id),
                &body,
            )?;
            store.vault_meta.put(
                wtxn,
                &voice_active_pointer_key(&subject),
                request.space.space_id.as_bytes(),
            )?;
            for sample in &ordered {
                store.vault_meta.put(
                    wtxn,
                    &voice_sample_key(&subject, &sample.sample_id),
                    &encode_sample(sample)?,
                )?;
            }
            Ok(record)
        })
    }

    /// Resolves one voice session's diarized segments into a stored roster.
    ///
    /// Enrolled principals are matched first and removed; only what is left
    /// enters residual clustering; invite elimination then names at most one
    /// unambiguous remainder. The stored roster carries labels, scores, and
    /// evidence — never an embedding vector.
    pub fn resolve_voice_segments(
        &self,
        request: &VoiceMatchRequest,
    ) -> Result<VoiceSessionRosterV1> {
        let segments = admit_match_segments(request)?;
        let known_threshold = request.policy.known_threshold;

        let rtxn = self.store.env.read_txn()?;
        let candidates = load_match_candidates(&self.store, &rtxn, &request.space_id)?;
        drop(rtxn);

        let mut resolved: Vec<Option<VoiceResolvedSegment>> = vec![None; segments.len()];
        let mut matched_refs: BTreeSet<EntityId> = BTreeSet::new();
        let mut residual_indexes: Vec<usize> = Vec::new();

        for (index, segment) in segments.iter().enumerate() {
            let matched = best_enrolled_match(
                &segment.space_id,
                &segment.vector,
                &candidates,
                known_threshold,
            )?;
            match matched {
                Some((candidate, score)) => {
                    matched_refs.insert(candidate.subject_ref);
                    if let Some(contact_ref) = candidate.contact_ref {
                        matched_refs.insert(contact_ref);
                    }
                    resolved[index] = Some(VoiceResolvedSegment {
                        segment_id: segment.segment_id.clone(),
                        start_ms: segment.start_ms,
                        end_ms: segment.end_ms,
                        speaker_label: candidate.subject_ref.to_hex(),
                        subject_ref: Some(candidate.subject_ref),
                        contact_ref: candidate.contact_ref,
                        evidence: VoiceAttributionEvidence::EnrolledPrint {
                            subject_ref: candidate.subject_ref,
                            score,
                            calibration: candidate.calibration,
                        },
                    });
                }
                None => residual_indexes.push(index),
            }
        }

        // Law 6: accepted segments are gone before clustering starts, and no
        // enrolled centroid ever participates in it.
        let residual_vectors: Vec<&[f32]> = residual_indexes
            .iter()
            .map(|index| segments[*index].vector.as_slice())
            .collect();
        let clusters = cluster_residuals(&residual_vectors, request.policy.residual_threshold)?;
        let invited = unambiguous_invite_remainder(
            &request.invite_attendee_refs,
            &matched_refs,
            clusters.len(),
        );

        for (cluster_index, members) in clusters.iter().enumerate() {
            for member in members {
                let index = residual_indexes[*member];
                let segment = &segments[index];
                let (label, subject_ref, contact_ref, evidence) = match invited {
                    Some(attendee_ref) => (
                        attendee_ref.to_hex(),
                        None,
                        Some(attendee_ref),
                        VoiceAttributionEvidence::InviteElimination { attendee_ref },
                    ),
                    None => (
                        residual_speaker_label(cluster_index),
                        None,
                        None,
                        VoiceAttributionEvidence::ResidualCluster {
                            cluster_ref: residual_cluster_ref(cluster_index),
                        },
                    ),
                };
                resolved[index] = Some(VoiceResolvedSegment {
                    segment_id: segment.segment_id.clone(),
                    start_ms: segment.start_ms,
                    end_ms: segment.end_ms,
                    speaker_label: label,
                    subject_ref,
                    contact_ref,
                    evidence,
                });
            }
        }

        // Law 8: the roster is stored only once every segment resolved.
        let segments = resolved
            .into_iter()
            .map(|entry| entry.ok_or_else(|| Error::InvariantViolation("voice segment unresolved")))
            .collect::<Result<Vec<_>>>()?;

        let roster = VoiceSessionRosterV1 {
            voice_session_ref: request.voice_session_ref.clone(),
            recording_id: request.recording_id.clone(),
            embedding_space_id: request.space_id.clone(),
            known_threshold,
            segments,
            created_at: request.created_at,
        };
        let body = encode_roster(&roster)?;
        let key = voice_roster_key(&roster.voice_session_ref);
        self.with_write_txn(|wtxn| {
            self.store.vault_meta.put(wtxn, &key, &body)?;
            Ok(())
        })?;
        Ok(roster)
    }

    /// Reads a stored roster. A missing roster is `Ok(None)`; a corrupt one is
    /// an error, so the interlocutor seam can fail closed on it.
    pub fn voice_session_roster(
        &self,
        voice_session_ref: &str,
    ) -> Result<Option<VoiceSessionRosterV1>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(bytes) = self
            .store
            .vault_meta
            .get(&rtxn, &voice_roster_key(voice_session_ref))?
        else {
            return Ok(None);
        };
        decode_roster(&bytes).map(Some)
    }

    /// Ends a voice-print retention relationship and stamps `delete_after`.
    ///
    /// The relationship must resolve to an existing RELATIONSHIP entity and
    /// must be the one the print is actually linked to. The print is retained
    /// until `ended_at + retention_secs`, then removed by
    /// [`Vault::prune_expired_voice_prints`] through the same deletion
    /// transaction explicit withdrawal uses.
    pub fn end_voice_relationship(
        &self,
        subject_ref: EntityId,
        relationship_ref: EntityId,
        ended_at: u64,
        retention_secs: u64,
    ) -> Result<()> {
        let delete_after = ended_at
            .checked_add(retention_secs)
            .ok_or(Error::ArithmeticOverflow("voice print retention deadline"))?;
        let store = &self.store;
        self.with_write_txn(|wtxn| {
            require_relationship_entity(store, wtxn, &relationship_ref)?;
            let record =
                read_active_print(store, wtxn, &subject_ref)?.ok_or(Error::EntityNotFound)?;
            if record.relationship_ref != Some(relationship_ref) {
                return Err(invalid_voice(
                    "voice print is not linked to the supplied relationship",
                ));
            }
            let updated = VoicePrintRecordV1 {
                updated_at: ended_at,
                delete_after: Some(delete_after),
                ..record
            };
            let body = encode_print_record(&updated)?;
            store.vault_meta.put(
                wtxn,
                &voice_print_key(&subject_ref, &updated.space.space_id),
                &body,
            )?;
            Ok(())
        })
    }

    /// Hard-deletes every voice print whose retention deadline has passed.
    ///
    /// Uses the same deletion transaction as explicit withdrawal, so a pruned
    /// subject and a withdrawn subject are left in exactly the same state.
    /// Returns the pruned subjects in ascending id order.
    pub fn prune_expired_voice_prints(&self, now: u64) -> Result<Vec<EntityId>> {
        let store = &self.store;
        self.with_write_txn(|wtxn| {
            let mut expired: Vec<EntityId> = Vec::new();
            for subject in active_print_subjects(store, wtxn)? {
                let Some(record) = read_active_print(store, wtxn, &subject)? else {
                    continue;
                };
                if record.delete_after.is_some_and(|deadline| deadline <= now) {
                    expired.push(subject);
                }
            }
            expired.sort_unstable();
            for subject in &expired {
                delete_voice_biometrics_in_txn(store, wtxn, subject)?;
            }
            Ok(expired)
        })
    }

    /// Withdraws consent and hard-deletes the subject's biometric material.
    ///
    /// One write transaction appends the non-biometric withdrawal event and
    /// removes the print row, every stored sample/vector row, and the
    /// active-space pointer. A second call is idempotent: nothing is left to
    /// delete, and the receipt says `already_absent`.
    pub fn withdraw_voice_consent(
        &self,
        request: &VoiceWithdrawalRequest,
    ) -> Result<VoiceWithdrawalReceipt> {
        let event = VoiceConsentEventV1 {
            event_id: request.event_id.clone(),
            subject_ref: request.subject_ref,
            recorded_by_ref: request.recorded_by_ref,
            occurred_at: request.occurred_at,
            purposes: request.purposes.clone(),
            basis: request.basis.clone(),
            state: VoiceConsentState::Withdrawn,
        };
        let body = encode_consent_event(&event)?;
        let consent_key = voice_consent_key(&event.subject_ref, &event.event_id);

        let store = &self.store;
        let subject = request.subject_ref;
        let tally = self.with_write_txn(|wtxn| {
            let tally = delete_voice_biometrics_in_txn(store, wtxn, &subject)?;
            store.vault_meta.put(wtxn, &consent_key, &body)?;
            Ok(tally)
        })?;

        Ok(VoiceWithdrawalReceipt {
            consent_event_ref: request.event_id.clone(),
            subject_ref: subject,
            already_absent: tally.is_empty(),
            deleted_print: tally.print_rows > 0,
            deleted_sample_count: tally.sample_rows,
            deleted_vector_count: tally.vector_rows,
            deleted_active_pointer: tally.active_pointer,
        })
    }
}

/// Stores a roster directly, without running a match pass.
///
/// Test-only seam for the ILD-3 interlocutor gates, which need a roster of a
/// given SHAPE (owner print, contact print, invite elimination, residual) far
/// more cheaply than a full enrollment fixture would supply one.
#[cfg(test)]
pub(crate) fn put_voice_roster_for_test(
    vault: &Vault,
    roster: &VoiceSessionRosterV1,
) -> Result<()> {
    let body = encode_roster(roster)?;
    let key = voice_roster_key(&roster.voice_session_ref);
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, &body)?;
        Ok(())
    })
}

/// Stores arbitrary bytes at a roster key, for the corrupt-roster gate.
#[cfg(test)]
pub(crate) fn put_raw_voice_roster_for_test(
    vault: &Vault,
    voice_session_ref: &str,
    bytes: &[u8],
) -> Result<()> {
    let key = voice_roster_key(voice_session_ref);
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, bytes)?;
        Ok(())
    })
}
