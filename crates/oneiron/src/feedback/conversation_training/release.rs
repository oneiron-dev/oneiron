//! The offer pass and its release gate (OF-420 A2, A3; D1; FIX 5502).
//!
//! Release is publication. While the vault's setting is on, each of the
//! vault's conversations is selected from the canonical rows, once; a source
//! that passes the egress check is filtered in the vault, held in local
//! custody (a submission row, then its sealed bytes staged by the
//! transport), and released: [`Vault::release_training_submission`]
//! rechecks the source, the setting, the opt-outs and the worlds immediately
//! before the transport renames the offer into `offers/`. Only a release
//! publishes; a withheld offer is purged, so a setting turned off refuses
//! every held offer. Retries of an offer still held keep its id.

use std::collections::{BTreeMap, BTreeSet};

use oneiron_vault_contract::conversation_training::{
    TRAINING_OFFER_TYPE, TRAINING_PRIVACY_EVERYWHERE, TRAINING_SCHEMA_VERSION,
    TRAINING_TEXT_ENCODING, TrainingChunkV1, TrainingFilterV1, TrainingOfferBodyV1,
    TrainingOfferV1, TrainingPayloadV1, TrainingReceiptStatusV1, TrainingSettingV1,
    offer_chunk_file_name, offer_manifest_file_name,
};

use crate::Vault;
use crate::authority::AuthorityFold;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::limit_ask::EngineLimit;

use super::super::redaction::{FilteredText, TextFilter, TextFilterError};
use super::crypto::{IntakeRecipient, seal_training_text, sign_training_payload};
use super::custody::{
    self, ControlChange, SubmissionCustody, SubmissionState, next_event_seq_in, put_submission_in,
    random_id, record_control_in,
};
use super::lifecycle::{
    PublisherTrainingLifecycle, ReleaseDecision, SealedTrainingOffer, TrainingSubmissionId,
    TrainingUnavailable, TrainingWithheld,
};
use super::source::{self, TrainingSelection};
use super::{ConversationSource, Eligibility, eligible};

/// The key context of an offer's worlds' settings digest.
const POLICY_REVISION_CONTEXT: &str = "oneiron publisher training world policy revision v1";

/// What one offer pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrainingOfferPass {
    /// The submissions released and published.
    pub published: Vec<TrainingSubmissionId>,
    /// The submissions a release held back, and why; each was purged.
    pub withheld: Vec<(TrainingSubmissionId, TrainingWithheld)>,
    /// Why the pass stopped before every source was judged, if it did.
    pub unavailable: Option<TrainingUnavailable>,
}

/// The vault's training setting an offer is prepared on.
struct Setting {
    /// Whether it was on.
    on: bool,
    /// Its revision.
    revision: [u8; 32],
    /// The authority entry of the choice in force.
    act: Option<[u8; 32]>,
    /// The admin's PERSON who set it, when its row is stored here.
    set_by: Option<EntityId>,
}

impl Setting {
    /// The setting as `fold` reads it in `txn`.
    fn of(vault: &Vault, txn: &heed::RoTxn<'_>, fold: &AuthorityFold) -> Result<Self> {
        let setting = &fold.conversation_training_vault;
        Ok(Self {
            on: setting.on(),
            revision: setting.revision().0,
            act: setting.act(),
            set_by: vault.conversation_learning_set_by_in_txn(txn, fold)?,
        })
    }
}

/// What became of one source in a pass.
enum Offered {
    Published(TrainingSubmissionId),
    Withheld(TrainingSubmissionId, TrainingWithheld),
    Skipped,
    Unavailable(TrainingUnavailable),
}

impl Vault {
    /// Whether a prepared offer may be published now (D1): release is
    /// publication, so the transport calls this immediately before it
    /// renames the offer into `offers/`, and only
    /// [`ReleaseDecision::Release`] publishes. Every file in `offers/` is
    /// therefore a released offer. Withdrawals never wait on a release: they
    /// reach the intake as controls, ordered by `event_seq` with the offers
    /// (C6).
    ///
    /// The release reads everything again, not only what was read when the
    /// offer was queued: the source is selected anew, the opt-outs as they
    /// stand now, and its revision must match (a changed source needs a new
    /// offer, D4); the vault's setting revision must be the one the offer was
    /// prepared on; the worlds' settings must be unchanged; and the source
    /// must pass the egress check now ([`eligible`]), the setting on
    /// included.
    ///
    /// # Errors
    /// Storage faults, and history this vault lacks, as the fold reads them:
    /// never a release.
    pub fn release_training_submission(
        &self,
        submission: TrainingSubmissionId,
    ) -> Result<ReleaseDecision> {
        let (row, selection, setting, policy_revision) = {
            let txn = self.store.env.read_txn()?;
            let Some(row) = custody::submission(self, &txn, submission)? else {
                return Ok(ReleaseDecision::Withheld(TrainingWithheld::NotHeld));
            };
            if row.state != SubmissionState::Held {
                return Ok(ReleaseDecision::Withheld(TrainingWithheld::NotHeld));
            }
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let Some(selection) = source::select(self, &txn, &fold, row.source)? else {
                return Ok(ReleaseDecision::Withheld(TrainingWithheld::SourceGone));
            };
            let setting = Setting::of(self, &txn, &fold)?;
            let policy = policy_digest(&fold, &selection.worlds);
            (row, selection, setting, policy)
        };
        if selection.revision != row.source_revision {
            return Ok(ReleaseDecision::Withheld(TrainingWithheld::SourceChanged));
        }
        if policy_revision != row.policy_revision {
            return Ok(ReleaseDecision::Withheld(TrainingWithheld::PolicyChanged));
        }
        if setting.revision != row.setting_revision {
            return Ok(ReleaseDecision::Withheld(TrainingWithheld::ChoiceChanged));
        }
        let source = ConversationSource {
            source: row.source,
            persons: selection.persons,
            worlds: selection.worlds,
        };
        if let Eligibility::Withheld(reason) = eligible(self, self, &source)? {
            return Ok(ReleaseDecision::Withheld(TrainingWithheld::Ineligible(
                reason,
            )));
        }
        Ok(ReleaseDecision::Release {
            source_revision: selection.revision,
            setting_revision: setting.revision,
            policy_revision,
            event_seq: row.event_seq,
        })
    }

    /// One offer pass (A2, A3): while the vault's setting is on, every
    /// conversation of the vault, selected once, judged, filtered in the
    /// vault, held, sealed to `intake`, staged on `sink` and released. A
    /// source still moving (a row newer than `quiet_secs`) waits for a later
    /// pass, whole. A source already published at its revision is not
    /// offered again; a changed one is offered anew, and once the newer
    /// offer is published, a forget control naming the older published ones
    /// of that source is recorded in the same write (a source edit
    /// invalidates the old version; the new offer stays live).
    ///
    /// The caller judged that offers may be written at all: an intake key in
    /// the outbox and, for a self-hosted vault, an account binding. A filter
    /// that cannot run stops the pass with nothing of that source sent.
    ///
    /// # Errors
    /// Storage faults, a rule read that fails, and a transport that could
    /// not stage, publish or purge: the pass stops, and what is held stays
    /// held for the next pass.
    pub fn offer_conversation_training(
        &self,
        sink: &dyn PublisherTrainingLifecycle,
        filter: &dyn TextFilter,
        intake: &IntakeRecipient,
        quiet_secs: u64,
    ) -> Result<TrainingOfferPass> {
        let now = crate::unix_seconds_now();
        let mut pass = TrainingOfferPass::default();
        let (rooms, latest) = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            // Off: nothing is selected, read or filtered.
            if !fold.conversation_training_vault.on() {
                return Ok(pass);
            }
            let rooms = source::vault_conversations(self, &txn)?;
            let mut latest: BTreeMap<EntityId, (TrainingSubmissionId, SubmissionCustody)> =
                BTreeMap::new();
            for (id, row) in custody::submissions(self, &txn)? {
                let newer = latest
                    .get(&row.source)
                    .is_none_or(|(_, held)| held.event_seq < row.event_seq);
                if newer {
                    latest.insert(row.source, (id, row));
                }
            }
            (rooms, latest)
        };
        let _ = self.measure_limit(EngineLimit::MaintenanceRowItems, rooms.len() as u64);
        for room in rooms {
            let offer = Offer {
                sink,
                filter,
                intake,
                room,
                held: latest.get(&room),
                now,
                quiet_secs,
            };
            match self.offer_one(&offer)? {
                Offered::Published(id) => pass.published.push(id),
                Offered::Withheld(id, why) => pass.withheld.push((id, why)),
                Offered::Skipped => {}
                Offered::Unavailable(why) => {
                    pass.unavailable = Some(why);
                    return Ok(pass);
                }
            }
        }
        Ok(pass)
    }

    /// One source through the pass.
    fn offer_one(&self, offer: &Offer<'_>) -> Result<Offered> {
        let (selection, setting, policy) = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let Some(selection) = source::select(self, &txn, &fold, offer.room)? else {
                return Ok(Offered::Skipped);
            };
            let setting = Setting::of(self, &txn, &fold)?;
            let policy = policy_digest(&fold, &selection.worlds);
            (selection, setting, policy)
        };
        if selection.newest.saturating_add(offer.quiet_secs) > offer.now {
            return Ok(Offered::Skipped);
        }
        let reuse = match offer.held {
            Some((id, row)) if row.source_revision == selection.revision => match row.state {
                SubmissionState::Held => Some((*id, row.event_seq)),
                SubmissionState::Published => return Ok(Offered::Skipped),
                SubmissionState::Withheld | SubmissionState::Withdrawn
                    if row.setting_revision == setting.revision
                        && row.policy_revision == policy =>
                {
                    return Ok(Offered::Skipped);
                }
                SubmissionState::Withheld | SubmissionState::Withdrawn => None,
            },
            _ => None,
        };
        let source = ConversationSource {
            source: selection.source,
            persons: selection.persons.clone(),
            worlds: selection.worlds.clone(),
        };
        if let Eligibility::Withheld(_) = eligible(self, self, &source)? {
            return Ok(Offered::Skipped);
        }
        // Whole-conversation work, measured, never capped (Rule 5).
        let text = selection.text();
        let _ = self.measure_limit(EngineLimit::MaintenanceTextBytes, text.len() as u64);
        let _ = self.measure_limit(
            EngineLimit::MaintenanceRowItems,
            selection.messages.len() as u64,
        );
        let filtered = match offer.filter.filter(&text) {
            Ok(filtered) => filtered,
            Err(TextFilterError::Unavailable(reason)) => {
                return Ok(Offered::Unavailable(
                    TrainingUnavailable::FilterUnavailable(reason),
                ));
            }
            Err(TextFilterError::Rejected(_)) => return Ok(Offered::Skipped),
        };
        // A held offer of an older revision is superseded: it is never
        // released, and its staged bytes are purged.
        let superseded = offer
            .held
            .filter(|(_, row)| reuse.is_none() && row.state == SubmissionState::Held)
            .map(|(id, _)| *id);
        let (id, event_seq) =
            self.hold_submission((reuse, superseded), &selection, &setting, policy, offer.now)?;
        let Some(sealed) = self.seal_offer(
            &Prepared {
                id,
                event_seq,
                selection: &selection,
                setting: &setting,
                policy,
                now: offer.now,
            },
            &filtered,
            offer.intake,
        )?
        else {
            return Ok(Offered::Unavailable(TrainingUnavailable::NoInstallKey));
        };
        let queued = offer.sink.accept(&sealed)?;
        match self.release_training_submission(id)? {
            ReleaseDecision::Release { .. } => {
                offer.sink.publish(&queued)?;
                self.mark_submission(id, SubmissionState::Published, offer.now)?;
                Ok(Offered::Published(id))
            }
            ReleaseDecision::Withheld(why) => {
                offer.sink.purge(id)?;
                self.mark_submission(id, SubmissionState::Withheld, offer.now)?;
                Ok(Offered::Withheld(id, why))
            }
        }
    }

    /// Holds one submission in local custody, under a new id and event
    /// number or, for a retry of one still held, under its own; a held one
    /// it supersedes is withheld in the same write.
    fn hold_submission(
        &self,
        (reuse, superseded): (
            Option<(TrainingSubmissionId, u64)>,
            Option<TrainingSubmissionId>,
        ),
        selection: &TrainingSelection,
        setting: &Setting,
        policy: [u8; 32],
        now: u64,
    ) -> Result<(TrainingSubmissionId, u64)> {
        self.with_write_txn_grouped(|txn| {
            if let Some(old) = superseded
                && let Some(mut row) = custody::submission(self, txn, old)?
                && row.state == SubmissionState::Held
            {
                row.state = SubmissionState::Withheld;
                put_submission_in(self, txn, old, &row)?;
            }
            let (id, event_seq) = match reuse {
                Some(held) => held,
                None => (
                    TrainingSubmissionId(random_id()),
                    next_event_seq_in(self, txn)?,
                ),
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
                event_seq,
                prepared_at: now,
                published_at: None,
                state: SubmissionState::Held,
                files: true,
                receipt: None,
                used_runs: Vec::new(),
            };
            put_submission_in(self, txn, id, &row)?;
            Ok((id, event_seq))
        })
    }

    /// Seals a held submission's filtered text to the intake and signs its
    /// manifest; `None` when this install has no key to sign with.
    fn seal_offer(
        &self,
        prepared: &Prepared<'_>,
        filtered: &FilteredText,
        intake: &IntakeRecipient,
    ) -> Result<Option<SealedTrainingOffer>> {
        let vault_id = *self.vault_id().as_bytes();
        let text = filtered.as_str().as_bytes();
        let submission = prepared.id.to_hex();
        let sealed = seal_training_text(intake, &vault_id, &prepared.id.0, text)?;
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
            chunks.push(TrainingChunkV1 {
                part,
                bytes: bytes.len() as u64,
                digest: blake3::hash(&bytes).to_hex().to_string(),
                file: file.clone(),
            });
            files.push((file, bytes));
        }
        let selection = prepared.selection;
        let setting = prepared.setting;
        let hex_set = |ids: &BTreeSet<EntityId>| -> Vec<String> {
            ids.iter().map(EntityId::to_hex).collect()
        };
        let body = TrainingOfferBodyV1 {
            submission_id: submission.clone(),
            event_seq: prepared.event_seq,
            engine_vault_id: oneiron_vault_contract::hex(&vault_id),
            source: selection.source.to_hex(),
            source_revision: oneiron_vault_contract::hex(&selection.revision),
            persons: hex_set(&selection.persons),
            worlds: hex_set(&selection.worlds),
            training: TrainingSettingV1 {
                on: setting.on,
                revision: oneiron_vault_contract::hex(&setting.revision),
                set_by: setting.set_by.as_ref().map(EntityId::to_hex),
                act: setting.act.map(|act| oneiron_vault_contract::hex(&act)),
            },
            world_policy_revision: oneiron_vault_contract::hex(&prepared.policy),
            privacy: TRAINING_PRIVACY_EVERYWHERE.to_owned(),
            filter: TrainingFilterV1 {
                model: filtered.filter().model.clone(),
                stack_sha16: filtered.filter().stack_sha16.clone(),
            },
            payload: TrainingPayloadV1 {
                encoding: TRAINING_TEXT_ENCODING.to_owned(),
                key_id: oneiron_vault_contract::hex(intake.key_id()),
                text_bytes: text.len() as u64,
                ciphertext_digest: ciphertext.finalize().to_hex().to_string(),
                chunks,
            },
            prepared_at: prepared.now,
        };
        let Some(signature) = sign_training_payload(self, TRAINING_OFFER_TYPE, &body)? else {
            return Ok(None);
        };
        let manifest = TrainingOfferV1 {
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
            submission: prepared.id,
            event_seq: prepared.event_seq,
            manifest: (name, bytes),
            chunks: files,
        }))
    }

    /// Settles a held submission after its release: published, and every
    /// older published submission of the same source withdrawn by an id-only
    /// forget control naming exactly those ids; or withheld, its files
    /// already purged. A row no longer held is left as it stands.
    fn mark_submission(
        &self,
        id: TrainingSubmissionId,
        state: SubmissionState,
        now: u64,
    ) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            let Some(mut row) = custody::submission(self, txn, id)? else {
                return Ok(());
            };
            if row.state != SubmissionState::Held {
                return Ok(());
            }
            row.state = state;
            if state == SubmissionState::Published {
                row.published_at = Some(now);
                forget_older_in(self, txn, id, &row, now)?;
            } else {
                row.files = false;
            }
            put_submission_in(self, txn, id, &row)
        })
    }
}

/// Withdraws every published submission of `row`'s source but `id` that
/// the intake has not already removed, and records one forget control
/// naming exactly those ids: the source changed, so its older versions are
/// invalid, while the offer just published stays live.
fn forget_older_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: TrainingSubmissionId,
    row: &SubmissionCustody,
    now: u64,
) -> Result<()> {
    let mut older = Vec::new();
    for (other, mut held) in custody::submissions(vault, txn)? {
        let removed = held
            .receipt
            .is_some_and(|mark| mark.status == TrainingReceiptStatusV1::Removed);
        if other == id
            || held.source != row.source
            || held.state != SubmissionState::Published
            || removed
        {
            continue;
        }
        held.state = SubmissionState::Withdrawn;
        put_submission_in(vault, txn, other, &held)?;
        older.push(other.0);
    }
    if older.is_empty() {
        return Ok(());
    }
    let change = ControlChange::ForgetSource {
        source: row.source,
        submissions: older,
    };
    record_control_in(vault, txn, change, now)?;
    Ok(())
}

/// One source's place in a pass.
struct Offer<'a> {
    sink: &'a dyn PublisherTrainingLifecycle,
    filter: &'a dyn TextFilter,
    intake: &'a IntakeRecipient,
    room: EntityId,
    held: Option<&'a (TrainingSubmissionId, SubmissionCustody)>,
    now: u64,
    quiet_secs: u64,
}

/// A held submission, ready to seal.
struct Prepared<'a> {
    id: TrainingSubmissionId,
    event_seq: u64,
    selection: &'a TrainingSelection,
    setting: &'a Setting,
    policy: [u8; 32],
    now: u64,
}

/// The digest of `worlds`' settings revisions on `fold`.
fn policy_digest(fold: &AuthorityFold, worlds: &BTreeSet<EntityId>) -> [u8; 32] {
    let mut digest = blake3::Hasher::new_derive_key(POLICY_REVISION_CONTEXT);
    for world in worlds {
        digest.update(world.as_bytes());
        digest.update(&fold.world_policy_revision(*world).0);
    }
    *digest.finalize().as_bytes()
}
