//! The offer pass and its release gate (OF-420 A2, A3; D1; FIX 5502;
//! TRAINING-LINK = C).
//!
//! Release is publication. While the vault's setting is on, each of the
//! vault's conversations is selected from the canonical rows, once; a source
//! that passes the egress check is filtered in the vault, held in local
//! custody (a submission row, then its sealed bytes staged by the
//! transport), and released: [`Vault::release_training_submission`]
//! rechecks the source, the setting, the opt-outs and the worlds immediately
//! before the transport renames the offer into `offers/`. Only a release
//! publishes; a withheld offer is purged, so a setting turned off refuses
//! every held offer. Retries of an offer still held keep its id, its month
//! and scope, its ordinal there and its first preparation time.
//!
//! An offer names no vault, source, person or world: the scope of the month
//! it was first prepared in, its ordinal within that scope, and that month's
//! codes for its source, persons and worlds (`link`). The release's private
//! rechecks read the raw ids and revisions local custody keeps. While a
//! purge stands (TL-5) the pass prepares and releases nothing.
//!
//! An offer is sealed only under the training link key of the generation it
//! was placed in. After a restore that brought no key, the pass first mints
//! one afresh under the next generation (FIX 5892); a held offer of an older
//! generation is never resealed with it: its release withholds it
//! ([`TrainingWithheld::LinkRotated`]), it stands withdrawn, since it never
//! left, and its source is prepared again as a new offer. A published
//! source is not offered again for the rotation alone.

use std::collections::{BTreeMap, BTreeSet};

use oneiron_vault_contract::conversation_training::{
    TRAINING_OFFER_TYPE, TRAINING_PRIVACY_EVERYWHERE, TRAINING_SCHEMA_VERSION,
    TRAINING_TEXT_ENCODING, TrainingChunkV2, TrainingFilterV2, TrainingOfferBodyV2,
    TrainingOfferV2, TrainingPayloadV2, TrainingReceiptStatusV2, TrainingSettingV2,
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
    self, ControlChange, SubmissionCustody, SubmissionState, put_submission_in, random_id,
    record_control_in,
};
use super::lifecycle::{
    PublisherTrainingLifecycle, ReleaseDecision, SealedTrainingOffer, TrainingScope,
    TrainingSubmissionId, TrainingUnavailable, TrainingWithheld,
};
use super::link;
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
}

impl Setting {
    /// The setting as `fold` reads it.
    fn of(fold: &AuthorityFold) -> Self {
        let setting = &fold.conversation_training_vault;
        Self {
            on: setting.on(),
            revision: setting.revision().0,
            act: setting.act(),
        }
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
    /// of their scope (C6).
    ///
    /// The release reads everything again, not only what was read when the
    /// offer was queued: the source is selected anew, the opt-outs as they
    /// stand now, and its revision must match (a changed source needs a new
    /// offer, D4); the vault's setting revision must be the one the offer was
    /// prepared on; the worlds' settings must be unchanged; and the source
    /// must pass the egress check now ([`eligible`]), the setting on
    /// included. While a purge stands (TL-5) nothing is released.
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
            let state = custody::state(self, &txn)?;
            if state.purge.is_some() {
                return Ok(ReleaseDecision::Withheld(TrainingWithheld::Purging));
            }
            if state.orphaned(row.generation) {
                return Ok(ReleaseDecision::Withheld(TrainingWithheld::LinkRotated));
            }
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let Some(selection) = source::select(self, &txn, &fold, row.source)? else {
                return Ok(ReleaseDecision::Withheld(TrainingWithheld::SourceGone));
            };
            let setting = Setting::of(&fold);
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
            event_seq: row.scope_seq,
        })
    }

    /// One offer pass (A2, A3): while the vault's setting is on, every
    /// conversation of the vault, selected once, judged, filtered in the
    /// vault, held, sealed to `intake`, staged on `sink` and released. A
    /// source still moving (a row newer than `quiet_secs`) waits for a later
    /// pass, whole. A source already published at its revision is not
    /// offered again; a changed one is offered anew, and once the newer
    /// offer is published, forget controls naming the older published ones
    /// of that source are recorded in the same write, one per month they
    /// were prepared in (a source edit invalidates the old version; the new
    /// offer stays live). While a purge stands (TL-5) nothing is prepared.
    /// It first mints the training link key afresh when a restore lost it,
    /// and withdraws every held offer of an older generation (FIX 5892). The
    /// pass ends by handing `sink` the vault's scopes.
    ///
    /// The caller judged that offers may be written at all: an intake key in
    /// the outbox and, for a self-hosted vault, an account binding. A filter
    /// that cannot run stops the pass with nothing of that source sent.
    ///
    /// # Errors
    /// Storage faults, a rule read that fails, a training link key that is
    /// gone, and a transport that could not stage, publish or purge: the
    /// pass stops, and what is held stays held for the next pass.
    pub fn offer_conversation_training(
        &self,
        sink: &dyn PublisherTrainingLifecycle,
        filter: &dyn TextFilter,
        intake: &IntakeRecipient,
        quiet_secs: u64,
    ) -> Result<TrainingOfferPass> {
        let now = crate::unix_seconds_now();
        let mut pass = TrainingOfferPass::default();
        {
            let txn = self.store.env.read_txn()?;
            // A purge stands: nothing new is prepared.
            if custody::state(self, &txn)?.purge.is_some() {
                return Ok(pass);
            }
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            // Off: nothing is selected, read or filtered.
            if !fold.conversation_training_vault.on() {
                return Ok(pass);
            }
        }
        self.renew_lost_training_link()?;
        self.withdraw_rotated_offers(sink, &mut pass, now)?;
        let (rooms, latest, generation) = {
            let txn = self.store.env.read_txn()?;
            let generation = custody::state(self, &txn)?.link_generation;
            let rooms = source::vault_conversations(self, &txn)?;
            let mut latest: BTreeMap<EntityId, (TrainingSubmissionId, SubmissionCustody)> =
                BTreeMap::new();
            for (id, row) in custody::submissions(self, &txn)? {
                let newer = latest
                    .get(&row.source)
                    .is_none_or(|(_, held)| held.local_seq < row.local_seq);
                if newer {
                    latest.insert(row.source, (id, row));
                }
            }
            (rooms, latest, generation)
        };
        let _ = self.measure_limit(EngineLimit::MaintenanceRowItems, rooms.len() as u64);
        for room in rooms {
            let offer = Offer {
                sink,
                filter,
                intake,
                room,
                held: latest.get(&room),
                generation,
                now,
                quiet_secs,
            };
            match self.offer_one(&offer)? {
                Offered::Published(id) => pass.published.push(id),
                Offered::Withheld(id, why) => pass.withheld.push((id, why)),
                Offered::Skipped => {}
                Offered::Unavailable(why) => {
                    pass.unavailable = Some(why);
                    break;
                }
            }
        }
        self.write_training_scopes(sink)?;
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
            let setting = Setting::of(&fold);
            let policy = policy_digest(&fold, &selection.worlds);
            (selection, setting, policy)
        };
        if selection.newest.saturating_add(offer.quiet_secs) > offer.now {
            return Ok(Offered::Skipped);
        }
        // An offer of an older generation is never reused or taken for a
        // settled one: its source is prepared again under the current key.
        let current = |row: &SubmissionCustody| row.generation == offer.generation;
        let reuse = match offer.held {
            Some((id, row)) if row.source_revision == selection.revision => match row.state {
                SubmissionState::Held if current(row) => Some((*id, row)),
                SubmissionState::Published => return Ok(Offered::Skipped),
                SubmissionState::Withheld | SubmissionState::Withdrawn
                    if current(row)
                        && row.setting_revision == setting.revision
                        && row.policy_revision == policy =>
                {
                    return Ok(Offered::Skipped);
                }
                SubmissionState::Held | SubmissionState::Withheld | SubmissionState::Withdrawn => {
                    None
                }
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
        let Some(placed) =
            self.hold_submission((reuse, superseded), &selection, &setting, policy, offer.now)?
        else {
            return Ok(Offered::Skipped);
        };
        let prepared = Prepared {
            placed: &placed,
            selection: &selection,
            setting: &setting,
        };
        let Some(sealed) = self.seal_offer(&prepared, &filtered, offer.intake)? else {
            return Ok(Offered::Unavailable(TrainingUnavailable::NoInstallKey));
        };
        let queued = offer.sink.accept(&sealed)?;
        match self.release_training_submission(placed.id)? {
            ReleaseDecision::Release { .. } => {
                offer.sink.publish(&queued)?;
                self.mark_submission(placed.id, SubmissionState::Published, offer.now)?;
                Ok(Offered::Published(placed.id))
            }
            ReleaseDecision::Withheld(why) => {
                offer.sink.purge(placed.id)?;
                self.mark_submission(placed.id, withheld_state(&why), offer.now)?;
                Ok(Offered::Withheld(placed.id, why))
            }
        }
    }

    /// Holds one submission in local custody: a new one under a new id, the
    /// next number of the private order and, in the month of `now` and the
    /// current link generation (its key made live first), the next ordinal
    /// of that pair's scope; a retry of one still held under its own id,
    /// order, month, generation, ordinal and first preparation time. A held
    /// one it supersedes is withheld in the same write. `None` while a purge
    /// stands: nothing is held.
    fn hold_submission(
        &self,
        (reuse, superseded): (
            Option<(TrainingSubmissionId, &SubmissionCustody)>,
            Option<TrainingSubmissionId>,
        ),
        selection: &TrainingSelection,
        setting: &Setting,
        policy: [u8; 32],
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
                put_submission_in(self, txn, old, &row)?;
            }
            let (local_seq, placed) = match reuse {
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
                ),
                None => {
                    let local_seq = custody::next_local_seq_in(self, txn)?;
                    let generation = custody::link_generation_in(self, txn)?;
                    let month = link::training_month(now);
                    let (scope, scope_seq) =
                        custody::next_scope_seq_in(self, txn, &month, generation)?;
                    let id = TrainingSubmissionId(random_id());
                    let placed = Placed {
                        id,
                        month,
                        generation,
                        scope,
                        scope_seq,
                        prepared_at: now,
                    };
                    (local_seq, placed)
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
    fn seal_offer(
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

    /// Withdraws every held offer of an orphaned generation (FIX 5892): it
    /// is never resealed with the current key, so its release withholds it
    /// ([`TrainingWithheld::LinkRotated`]); it never left, so it stands
    /// withdrawn, its staged bytes purged, and its source is prepared again
    /// as a new offer.
    fn withdraw_rotated_offers(
        &self,
        sink: &dyn PublisherTrainingLifecycle,
        pass: &mut TrainingOfferPass,
        now: u64,
    ) -> Result<()> {
        let rotated: Vec<TrainingSubmissionId> = {
            let txn = self.store.env.read_txn()?;
            let state = custody::state(self, &txn)?;
            custody::submissions(self, &txn)?
                .into_iter()
                .filter(|(_, row)| {
                    row.state == SubmissionState::Held && state.orphaned(row.generation)
                })
                .map(|(id, _)| id)
                .collect()
        };
        for id in rotated {
            if self.release_training_submission(id)?
                == ReleaseDecision::Withheld(TrainingWithheld::LinkRotated)
            {
                sink.purge(id)?;
                self.mark_submission(id, SubmissionState::Withdrawn, now)?;
                pass.withheld.push((id, TrainingWithheld::LinkRotated));
            }
        }
        Ok(())
    }

    /// Settles a held submission after its release: published, and every
    /// older published submission of the same source withdrawn by id-only
    /// forget controls naming exactly those ids; or withheld or withdrawn,
    /// its files already purged. A row no longer held is left as it stands.
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
/// the intake has not already removed, and records forget controls naming
/// exactly those ids: one per month and generation they were prepared in,
/// each under that pair's scope, never recoded under the new offer's (none
/// for an orphaned generation, counted unavailable). The source changed, so
/// its older versions are invalid, while the offer just published stays
/// live.
fn forget_older_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: TrainingSubmissionId,
    row: &SubmissionCustody,
    now: u64,
) -> Result<()> {
    let mut older: BTreeMap<(String, u32), Vec<[u8; 16]>> = BTreeMap::new();
    for (other, mut held) in custody::submissions(vault, txn)? {
        let removed = held
            .receipt
            .is_some_and(|mark| mark.status == TrainingReceiptStatusV2::Removed);
        if other == id
            || held.source != row.source
            || held.state != SubmissionState::Published
            || removed
        {
            continue;
        }
        held.state = SubmissionState::Withdrawn;
        put_submission_in(vault, txn, other, &held)?;
        older
            .entry((held.month, held.generation))
            .or_default()
            .push(other.0);
    }
    for ((month, generation), submissions) in older {
        let change = ControlChange::ForgetSource {
            source: row.source,
            submissions,
        };
        record_control_in(vault, txn, (&month, generation), change, now)?;
    }
    Ok(())
}

/// One source's place in a pass.
struct Offer<'a> {
    sink: &'a dyn PublisherTrainingLifecycle,
    filter: &'a dyn TextFilter,
    intake: &'a IntakeRecipient,
    room: EntityId,
    held: Option<&'a (TrainingSubmissionId, SubmissionCustody)>,
    /// The current training link generation.
    generation: u32,
    now: u64,
    quiet_secs: u64,
}

/// Where a held submission sits: its id, the month of its first
/// preparation and the link generation it was placed in, that pair's scope,
/// its ordinal there, and when it was first prepared. A retry keeps every
/// one of them.
struct Placed {
    id: TrainingSubmissionId,
    month: String,
    generation: u32,
    scope: [u8; 32],
    scope_seq: u64,
    prepared_at: u64,
}

/// A held submission, ready to seal.
struct Prepared<'a> {
    placed: &'a Placed,
    selection: &'a TrainingSelection,
    setting: &'a Setting,
}

/// Where a submission a release held back for `why` stands: withdrawn when
/// its generation's key is gone, since it never left (FIX 5892), withheld
/// otherwise.
fn withheld_state(why: &TrainingWithheld) -> SubmissionState {
    if *why == TrainingWithheld::LinkRotated {
        SubmissionState::Withdrawn
    } else {
        SubmissionState::Withheld
    }
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
