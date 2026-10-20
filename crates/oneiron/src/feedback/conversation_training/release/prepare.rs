//! An offer's preparation: its hold in local custody, then its seal and its
//! signed manifest (OF-420 A2; TRAINING-LINK = C; TL-6).

use oneiron_vault_contract::conversation_training::{
    TRAINING_OFFER_TYPE, TRAINING_PRIVACY_EVERYWHERE, TRAINING_SCHEMA_VERSION,
    TRAINING_TEXT_ENCODING, TrainingChunkV2, TrainingFilterV2, TrainingOfferBodyV2,
    TrainingOfferV2, TrainingPayloadV2, TrainingSettingV2, offer_chunk_file_name,
    offer_manifest_file_name,
};

use crate::Vault;
use crate::error::{Error, Result};
use crate::feedback::FilteredText;

use super::super::anonymous::{self, AnonymousPiece, TrainingTransport};
use super::super::crypto::{IntakeRecipient, seal_training_text, sign_training_payload};
use super::super::custody::{
    self, SubmissionCustody, SubmissionState, put_submission_in, random_id,
};
use super::super::lifecycle::{SealedTrainingOffer, TrainingScope, TrainingSubmissionId};
use super::super::link;
use super::super::source::TrainingSelection;
use super::{Placed, Prepared, Setting};

impl Vault {
    /// Holds one submission in local custody: a new one under a new id, the
    /// next number of the private order and, in the month of `now` and the
    /// current link generation (its key made live first), the next ordinal
    /// of that pair's scope and its piece code, C (TL-6), taking `transport`;
    /// a retry of one still held under its own id, order, month, generation,
    /// ordinal, first preparation time, C, transport and anonymous standing.
    /// A held one it supersedes is withheld in the same write, an anonymous
    /// one taking its withdrawal intent. `None` while a purge stands:
    /// nothing is held.
    pub(super) fn hold_submission(
        &self,
        (reuse, superseded): (
            Option<(TrainingSubmissionId, &SubmissionCustody)>,
            Option<TrainingSubmissionId>,
        ),
        selection: &TrainingSelection,
        setting: &Setting,
        (policy, transport): ([u8; 32], TrainingTransport),
        now: u64,
    ) -> Result<Option<Placed>> {
        self.with_write_txn_grouped(|txn| {
            let state = custody::state(self, txn)?;
            if state.purge.is_some() {
                return Ok(None);
            }
            if let Some(old) = superseded
                && let Some(mut row) = custody::submission(self, txn, old)?
                && row.state == SubmissionState::Held
            {
                row.state = SubmissionState::Withheld;
                anonymous::withdraw(&mut row);
                put_submission_in(self, txn, old, &row)?;
            }
            let (local_seq, placed, piece, (transport, standing)) = match reuse {
                // A retry keeps its C as it was made, never made again, and
                // its transport.
                Some((id, held)) => (
                    held.local_seq,
                    Placed {
                        id,
                        scope: state.scope_of(&held.month, held.generation)?,
                        month: held.month.clone(),
                        generation: held.generation,
                        scope_seq: held.scope_seq,
                        prepared_at: held.prepared_at,
                    },
                    held.piece,
                    (held.transport, held.anonymous.clone()),
                ),
                None => {
                    let local_seq = custody::next_local_seq_in(self, txn)?;
                    let generation = custody::link_generation_in(self, txn)?;
                    let month = link::training_month(now);
                    let (scope, scope_seq) =
                        custody::next_scope_seq_in(self, txn, &month, generation)?;
                    let id = TrainingSubmissionId(random_id());
                    // C, made once here under K at the generation it was
                    // placed in; the zeroized K drops with this arm.
                    let piece = {
                        let key = link::training_link_key(self, txn, generation)?;
                        link::piece_code(&key, &id.0, &month)
                    };
                    let placed = Placed {
                        id,
                        month,
                        generation,
                        scope,
                        scope_seq,
                        prepared_at: now,
                    };
                    (
                        local_seq,
                        placed,
                        piece,
                        (transport, AnonymousPiece::default()),
                    )
                }
            };
            let row = SubmissionCustody {
                source: selection.source,
                persons: selection.persons.clone(),
                worlds: selection.worlds.clone(),
                messages: selection.message_ids(),
                source_revision: selection.revision,
                setting_revision: setting.revision,
                setting_act: setting.act,
                policy_revision: policy,
                local_seq,
                month: placed.month.clone(),
                generation: placed.generation,
                scope_seq: placed.scope_seq,
                prepared_at: placed.prepared_at,
                piece,
                transport,
                anonymous: standing,
                published_at: None,
                state: SubmissionState::Held,
                files: true,
                receipt: None,
                used_runs: Vec::new(),
            };
            put_submission_in(self, txn, placed.id, &row)?;
            Ok(Some(placed))
        })
    }

    /// Seals a held submission's filtered text to the intake under its
    /// scope, and signs its manifest naming that month's codes; `None` when
    /// this install has no key to sign with.
    pub(super) fn seal_offer(
        &self,
        prepared: &Prepared<'_>,
        filtered: &FilteredText,
        intake: &IntakeRecipient,
    ) -> Result<Option<SealedTrainingOffer>> {
        let placed = prepared.placed;
        // The key of the generation it was placed in, never another's.
        let key = {
            let txn = self.store.env.read_txn()?;
            link::training_link_key(self, &txn, placed.generation)?
        };
        let text = filtered.as_str().as_bytes();
        let submission = placed.id.to_hex();
        let sealed = seal_training_text(intake, &placed.scope, &placed.id.0, text)?;
        let mut ciphertext = blake3::Hasher::new();
        let mut chunks = Vec::with_capacity(sealed.len());
        let mut files = Vec::with_capacity(sealed.len());
        for (part, bytes) in sealed.into_iter().enumerate() {
            let part = u32::try_from(part)
                .map_err(|_| Error::ArithmeticOverflow("training offer chunk count"))?;
            let file = offer_chunk_file_name(&submission, part).ok_or(
                Error::InvariantViolation("a submission id names no chunk file"),
            )?;
            ciphertext.update(&bytes);
            chunks.push(TrainingChunkV2 {
                part,
                bytes: bytes.len() as u64,
                digest: blake3::hash(&bytes).to_hex().to_string(),
                file: file.clone(),
            });
            files.push((file, bytes));
        }
        let selection = prepared.selection;
        let month = placed.month.as_str();
        let body = TrainingOfferBodyV2 {
            submission_id: submission.clone(),
            scope: oneiron_vault_contract::hex(&placed.scope),
            event_seq: placed.scope_seq,
            source: link::code_hex(&key, link::SOURCE, &selection.source, month),
            persons: link::code_set(&key, link::PERSON, &selection.persons, month),
            worlds: link::code_set(&key, link::WORLD, &selection.worlds, month),
            training: TrainingSettingV2 {
                on: prepared.setting.on,
            },
            privacy: TRAINING_PRIVACY_EVERYWHERE.to_owned(),
            filter: TrainingFilterV2 {
                model: filtered.filter().model.clone(),
                stack_sha16: filtered.filter().stack_sha16.clone(),
            },
            payload: TrainingPayloadV2 {
                encoding: TRAINING_TEXT_ENCODING.to_owned(),
                key_id: oneiron_vault_contract::hex(intake.key_id()),
                text_bytes: text.len() as u64,
                ciphertext_digest: ciphertext.finalize().to_hex().to_string(),
                chunks,
            },
            prepared_at: placed.prepared_at,
        };
        let Some(signature) = sign_training_payload(self, TRAINING_OFFER_TYPE, &body)? else {
            return Ok(None);
        };
        let manifest = TrainingOfferV2 {
            schema_version: TRAINING_SCHEMA_VERSION,
            file_type: TRAINING_OFFER_TYPE.to_owned(),
            body,
            signature,
        };
        let bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|_| Error::InvariantViolation("a training offer manifest does not encode"))?;
        let name = offer_manifest_file_name(&submission).ok_or(Error::InvariantViolation(
            "a submission id names no manifest file",
        ))?;
        Ok(Some(SealedTrainingOffer {
            submission: placed.id,
            scope: TrainingScope(placed.scope),
            event_seq: placed.scope_seq,
            manifest: (name, bytes),
            chunks: files,
        }))
    }
}
