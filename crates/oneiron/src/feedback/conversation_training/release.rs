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
//!
//! Each offer takes the transport the pass is given (TL-6): a self-hosted
//! vault's leave through the anonymous training window under their C, a
//! managed vault's through the outbox's V2 files. A held offer is reused
//! only on the same transport. An anonymous piece the intake asked afresh
//! for (`recipient_refresh_required`) is never sealed again under its C:
//! its source alone skips "same revision, withheld: skip", and is offered
//! again as a new submission under a new C.

mod prepare;

use std::collections::{BTreeMap, BTreeSet};

use oneiron_vault_contract::conversation_training::TrainingReceiptStatusV2;

use crate::Vault;
use crate::authority::AuthorityFold;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::limit_ask::EngineLimit;

use super::super::redaction::{TextFilter, TextFilterError};
use super::anonymous::{self, TrainingTransport};
use super::crypto::IntakeRecipient;
use super::custody::{
    self, ControlChange, SubmissionCustody, SubmissionState, put_submission_in, record_control_in,
};
use super::lifecycle::{
    PublisherTrainingLifecycle, ReleaseDecision, TrainingSubmissionId, TrainingUnavailable,
    TrainingWithheld,
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
    /// vault, held, sealed to `intake`, staged on `sink` and released, each
    /// new offer taking `transport` (TL-6: the server's placement, anonymous
    /// for a self-hosted vault, hosted for a managed one). A
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
    /// the outbox and, for a self-hosted vault, its self-host shipper on, the
    /// anonymous training window its offers leave through (TL-6), which
    /// installs that key from the intake's public descriptor. A filter that
    /// cannot run stops the pass with nothing of that source sent.
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
        transport: TrainingTransport,
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
                transport,
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
        // settled one: its source is prepared again under the current key. A
        // held one is reused only on the same transport. An anonymous piece
        // the intake asked afresh for is offered again, under a new C.
        let current = |row: &SubmissionCustody| row.generation == offer.generation;
        let reuse = match offer.held {
            Some((id, row)) if row.source_revision == selection.revision => match row.state {
                SubmissionState::Held if current(row) && row.transport == offer.transport => {
                    Some((*id, row))
                }
                SubmissionState::Published => return Ok(Offered::Skipped),
                SubmissionState::Withheld | SubmissionState::Withdrawn
                    if current(row)
                        && row.setting_revision == setting.revision
                        && row.policy_revision == policy
                        && !anonymous::refresh_requested(row) =>
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
        let Some(placed) = self.hold_submission(
            (reuse, superseded),
            &selection,
            &setting,
            (policy, offer.transport),
            offer.now,
        )?
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
/// for an orphaned generation, counted unavailable); every anonymous one
/// takes its withdrawal intent in the same write instead, and joins no
/// control. The source changed, so
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
        anonymous::withdraw(&mut held);
        put_submission_in(vault, txn, other, &held)?;
        if held.transport == TrainingTransport::Hosted {
            older
                .entry((held.month, held.generation))
                .or_default()
                .push(other.0);
        }
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
    /// The transport a new offer takes (TL-6).
    transport: TrainingTransport,
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
