//! Explicit promotion from an off-record session into the durable vault.
//!
//! This module also HOLDS [`FloorWrites`] — the sole overlay -> base durable
//! writer surface (ARCH-0052 D6). Every durable crossing an off-record session
//! is allowed to make goes through one of its operations; a source audit that
//! finds an overlay -> base write anywhere else is a defect.

use heed::RwTxn;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::genui::ConsentActorIdentity;
use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;
use crate::store::{GateDecisionRecord, Store};

use super::lifecycle::{
    OFF_RECORD_CLOSED_FENCE_VALUE, live_session_entry, off_record_fence_key, session_entry_state,
    vet_off_record_session_ref,
};

mod floor_writes_seal {
    pub(super) struct Seal;
}

/// The ONLY overlay -> base durable writer surface (ARCH-0052 D6).
///
/// Construction is `pub(crate) fn new` and nothing else: the module-private
/// `_seal` field forbids a struct literal outside this module, there is no
/// `pub` constructor, and the borrowed `store` never escapes — so no caller
/// can reach raw base access through this type. `gate.rs` and `deletion.rs`
/// hold the crate-visible call sites, which reach it through the stable
/// `crate::off_record::FloorWrites` re-export.
pub(crate) struct FloorWrites<'store> {
    store: &'store Store,
    _seal: floor_writes_seal::Seal,
}

impl<'store> FloorWrites<'store> {
    /// Sole constructor.
    pub(crate) fn new(store: &'store Store) -> Self {
        Self {
            store,
            _seal: floor_writes_seal::Seal,
        }
    }

    /// Floor operation 1/3 (K1): append one evaluated EGRESS gate decision.
    ///
    /// Egress decisions are floor survivors and never conflate with the
    /// write-path decisions for session content, which stay overlay-local and
    /// evaporate with the transcript they describe.
    pub(crate) fn append_egress_gate_decision(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &GateDecisionRecord,
    ) -> Result<()> {
        self.store.append_gate_decision_in_txn(wtxn, record)
    }

    /// Floor operation 2/3 (K1): append one REDACTION_AUDIT entity and its
    /// exact ordinary entity-index footprint.
    pub(crate) fn append_redaction_audit(
        &self,
        wtxn: &mut RwTxn<'_>,
        receipt_id: &EntityId,
        learned_at: u64,
        body: &[u8],
    ) -> Result<()> {
        let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
        payload.extend_from_slice(&crate::deletion::receipt_envelope_header(learned_at));
        payload.extend_from_slice(body);
        self.store
            .entities
            .put(wtxn, receipt_id.as_bytes(), &payload)?;

        let type_key = Store::encode_type_key(ENTITY_TYPE_REDACTION_AUDIT, receipt_id);
        self.store.type_index.put(wtxn, &type_key, &[])?;
        let temporal_key = Store::encode_temporal_key(learned_at, receipt_id);
        self.store
            .temporal_occurred_start
            .put(wtxn, &temporal_key, &[])?;
        self.store.temporal_learned.put(wtxn, &temporal_key, &[])?;
        Ok(())
    }
}

const OFF_RECORD_PROMOTE_KEY_PREFIX: &[u8] = b"offrecord_promote:v0:";
const OFF_RECORD_PROMOTE_RECEIPT_VERSION: u8 = 0;

/// Durable, user-initiated receipt minted by promote. It carries opaque ids
/// only and survives the in-process session record.
///
/// The initiator fields record WHO consented, bound at mint time by
/// `ConsentActorIdentity::authenticates_principal` (ONE-1645) — never a
/// literal. A receipt therefore only ever names an actor that authenticated
/// the owner principal for this promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffRecordPromoteReceipt {
    pub version: u8,
    pub session_ref: String,
    pub turn: [u8; 16],
    pub promoted_at: u64,
    /// The authenticated actor's opaque reference.
    pub initiator_ref: String,
    /// The `ConsentActorIdentity` variant that authenticated:
    /// `"surface_actor"` or `"voice_path"` (the pinned serde tags).
    pub initiator_kind: String,
}

/// The `ConsentActorIdentity` serde tag recorded on a promote receipt.
const fn consent_actor_kind(actor: &ConsentActorIdentity) -> &'static str {
    match actor {
        ConsentActorIdentity::SurfaceActor { .. } => "surface_actor",
        ConsentActorIdentity::VoicePath { .. } => "voice_path",
    }
}

pub(super) fn off_record_promote_key(id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(OFF_RECORD_PROMOTE_KEY_PREFIX.len() + 16);
    key.extend_from_slice(OFF_RECORD_PROMOTE_KEY_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key
}

fn encode_off_record_promote(receipt: &OffRecordPromoteReceipt) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(receipt)
        .map_err(|_| Error::InvariantViolation("off-record promote receipt encode failed"))
}

fn decode_off_record_promote(bytes: &[u8]) -> Result<OffRecordPromoteReceipt> {
    rmp_serde::from_slice(bytes).map_err(|_| Error::CorruptedIndex("off-record promote receipt"))
}

impl FloorWrites<'_> {
    /// Floor operation 3/3: commit one explicit promotion receipt while
    /// lifting the legacy fence for the promoted entity.
    ///
    /// This is the FENCE-ERA promote crossing, kept functional through P4a so
    /// [`Vault::promote_off_record_turn`] keeps working against pre-existing
    /// fenced turns. **ONE-1730 REPLACES it with `promote`** (typed-journal
    /// replay in one transaction) rather than adding a fourth operation; its
    /// durable writes must stay here, never inlined into the `Vault` method.
    pub(crate) fn commit_promote(
        &self,
        wtxn: &mut RwTxn<'_>,
        turn_id: &EntityId,
        receipt: &OffRecordPromoteReceipt,
    ) -> Result<()> {
        // CONSENT GATE: only LIFT the fence for a turn whose entity body
        // actually exists at promote time. Tag-before-write means a fenced turn
        // can sit in `fenced_turns` with no entity row yet; deleting its fence
        // would let a LATER ordinary `put_entity` for the same id sail past
        // `guard_off_record_entity_put` (which keys on the fence row) and enter
        // the durable vault UNFENCED — admitting an off-record body that was
        // never present at the time of user consent. For a body-less turn,
        // retain the sessionless closed-fence marker (empty value) instead of
        // deleting the row, so the entity write door stays shut for that id.
        if self.store.entities.get(wtxn, turn_id.as_bytes())?.is_some() {
            self.store
                .vault_meta
                .delete(wtxn, &off_record_fence_key(turn_id))?;
        } else {
            self.store.vault_meta.put(
                wtxn,
                &off_record_fence_key(turn_id),
                OFF_RECORD_CLOSED_FENCE_VALUE,
            )?;
        }
        self.store.vault_meta.put(
            wtxn,
            &off_record_promote_key(turn_id),
            &encode_off_record_promote(receipt)?,
        )?;
        Ok(())
    }
}

impl Vault {
    /// Promotes exactly one legacy-fenced turn under the session's
    /// per-session lock, so close and promote cannot race.
    ///
    /// Promotion is a widening op (P2): it moves a fenced turn into the
    /// durable vault, so consent is authenticated once, AT the op, by the same
    /// actor-identity vocabulary every other consent surface uses. `actor`
    /// must authenticate `owner_principal_ref` or the call fails closed with
    /// [`Error::OffRecordPromoteUnauthenticated`] before any state is read;
    /// the receipt then records that authenticated actor rather than a
    /// literal.
    ///
    /// Seam (ONE-1647): the engine does not verify voice-print anchoring here.
    /// `ConsentActorIdentity` is consumed as-is, so when the voice-print bool
    /// becomes engine-anchored this path inherits the hardening unchanged.
    /// Promote must not grow its own voice logic.
    pub fn promote_off_record_turn(
        &self,
        session_ref: &str,
        turn_id: &EntityId,
        actor: &ConsentActorIdentity,
        owner_principal_ref: &str,
    ) -> Result<OffRecordPromoteReceipt> {
        // Authenticate BEFORE any state read: an unauthenticated promote must
        // not even learn whether the turn is fenced. Blank refs on either side
        // are rejected by `authenticates_principal` itself.
        if !actor.authenticates_principal(owner_principal_ref) {
            return Err(Error::OffRecordPromoteUnauthenticated {
                session_ref: session_ref.to_owned(),
                actor_ref: actor.actor_ref().to_owned(),
            });
        }
        vet_off_record_session_ref(session_ref)?;
        let entry = live_session_entry(&self.store, session_ref)?;
        // Hold the per-session state lock across the closing/gone check, the
        // durable promote commit, AND the in-process record update. This
        // serializes promote against close: close stamps `closing` under the
        // same lock, so it cannot freeze a stale `fenced_turns` snapshot in the
        // middle of a promote and then PolicyDelete a turn whose durable promote
        // receipt was just written (which would both lose user-consented data
        // and orphan a receipt for a deleted turn). Either promote fully commits
        // before close stamps closing (close then sees the turn already promoted
        // and keeps it), or promote observes closing first and bails BEFORE
        // committing. Deadlock-safe: nothing inside the write txn locks
        // `entry.state`.
        let receipt = {
            let mut state = session_entry_state(&entry)?;
            if state.record.closing || state.gone {
                return Err(Error::OffRecordSessionClosing {
                    session_ref: session_ref.to_owned(),
                });
            }
            let position = state
                .record
                .fenced_turns
                .iter()
                .position(|bytes| bytes == turn_id.as_bytes())
                .ok_or_else(|| Error::OffRecordTurnNotFenced {
                    session_ref: session_ref.to_owned(),
                    turn_ref: turn_id.to_hex(),
                })?;
            let receipt = OffRecordPromoteReceipt {
                version: OFF_RECORD_PROMOTE_RECEIPT_VERSION,
                session_ref: session_ref.to_owned(),
                turn: *turn_id.as_bytes(),
                promoted_at: crate::unix_seconds_now(),
                initiator_ref: actor.actor_ref().to_owned(),
                initiator_kind: consent_actor_kind(actor).to_owned(),
            };
            self.with_write_txn(|wtxn| {
                FloorWrites::new(&self.store).commit_promote(wtxn, turn_id, &receipt)
            })?;
            state.record.fenced_turns.remove(position);
            state.record.promoted_turns.push(*turn_id.as_bytes());
            entry.publish_state(&state);
            receipt
        };

        // The promotion is durably committed here (fence lifted, receipt
        // written) and close KEEPS promoted turns, so a concurrent close or
        // record mutation after this point must never be reported as a promote
        // failure. The live-window refresh below is best-effort — its error is
        // logged, not surfaced — and we deliberately do NOT re-read the session
        // record afterward: turning post-commit drift into an error would make
        // the caller see a failed promote that actually succeeded and is kept.
        #[cfg(feature = "sync")]
        if let Err(error) = self.refresh_promoted_turn_in_live_window(turn_id) {
            tracing::warn!(
                turn = %turn_id.to_hex(),
                error = %error,
                "off-record promotion committed but live-window sync refresh deferred to recovery"
            );
        }

        Ok(receipt)
    }

    #[cfg(feature = "sync")]
    fn refresh_promoted_turn_in_live_window(&self, turn_id: &EntityId) -> Result<()> {
        use crate::sync::window::{replay_pending_mirrors, reverse_rematerialize};

        for window in self.live_windows() {
            let replayed = replay_pending_mirrors(self, &window.doc, &window.key)?;
            let mirrored = reverse_rematerialize(self, &window.doc, &window.key)?;
            tracing::debug!(
                turn = %turn_id.to_hex(),
                window = %window.key,
                replayed,
                mirrored,
                "off-record promotion refreshed live sync window"
            );
        }
        Ok(())
    }

    pub fn off_record_promote_receipt(
        &self,
        turn_id: &EntityId,
    ) -> Result<Option<OffRecordPromoteReceipt>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(bytes) = self
            .store
            .vault_meta
            .get(&rtxn, &off_record_promote_key(turn_id))?
        else {
            return Ok(None);
        };
        Ok(Some(decode_off_record_promote(&bytes)?))
    }
}
