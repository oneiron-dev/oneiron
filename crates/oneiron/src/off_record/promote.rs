//! Explicit promotion from an off-record session into the durable vault.
//!
//! This module also HOLDS [`FloorWrites`] — the sole overlay -> base durable
//! writer surface (ARCH-0052 D6). Every durable crossing an off-record session
//! is allowed to make goes through one of its operations; a source audit that
//! finds an overlay -> base write anywhere else is a defect.

use std::collections::BTreeSet;

use heed::RwTxn;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, TxnBatchBuilder, parse_short_id_value};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;
use crate::session_overlay::PromotePlan;
use crate::store::{GateDecisionRecord, Store};

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

/// `EntityId` carries no serde impls, so the receipt's closure travels as the
/// raw 16-byte ids the entity tables already key on.
mod entity_ids_as_bytes {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::entity_id::EntityId;

    pub(super) fn serialize<S: Serializer>(
        ids: &[EntityId],
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        ids.iter()
            .map(EntityId::as_bytes)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Vec<EntityId>, D::Error> {
        Vec::<[u8; 16]>::deserialize(deserializer)?
            .into_iter()
            .map(|bytes| EntityId::from_bytes(bytes).map_err(D::Error::custom))
            .collect()
    }
}

/// What ONE promotion did (ARCH-0052 D4, ONE-1730).
///
/// `replayed` is the exact closure that entered base — for a witnessed turn
/// with no artifacts, the TURN, its MESSAGE, its SUMMARY, and the room's fresh
/// CONVERSATION shell. `short_id_mapping` pairs each in-room alias with the
/// canonical short id the ordinary apply allocated for the same entity, so a
/// caller holding a temporary handle can re-address the promoted row.
///
/// `PartialEq` is load-bearing: the retry contract is that a second promote of
/// the same turn returns THIS value, unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromoteOutcome {
    #[serde(with = "entity_ids_as_bytes")]
    pub replayed: Vec<EntityId>,
    pub short_id_mapping: Vec<(String, String)>,
}

/// Durable, user-initiated receipt minted by promote. It carries opaque ids
/// only and survives the in-process session record.
///
/// The receipt is also the RETRY ANSWER: it stores the first call's complete
/// [`PromoteOutcome`], so a second promote of the same turn reads it back and
/// returns it unchanged rather than allocating a second short id, restamping
/// time, duplicating an edge, or emitting a second decision receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffRecordPromoteReceipt {
    pub version: u8,
    pub session_ref: String,
    pub turn: [u8; 16],
    pub promoted_at: u64,
    pub outcome: PromoteOutcome,
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

/// The promote transaction's session-membership exemption (ARCH-0052 D2, K4).
///
/// Minted ONLY here, inside the promote transaction, out of the closure that
/// transaction is replaying. It therefore cannot answer `true` for an id the
/// granting session did not stage: another live session's overlay members are
/// still rejected by the taint guard and the entity write door, exactly as for
/// any ordinary base write.
pub(crate) struct PromoteReplayGrant {
    members: BTreeSet<EntityId>,
}

impl PromoteReplayGrant {
    fn mint(plan: &PromotePlan) -> Self {
        Self {
            members: plan.replayed.iter().copied().collect(),
        }
    }

    fn exempts(&self, id: &EntityId) -> bool {
        self.members.contains(id)
    }
}

impl FloorWrites<'_> {
    /// Floor operation 3/3 (ARCH-0052 D4, ONE-1730): replay ONE typed-journal
    /// closure into base and record that it happened — as ONE transaction.
    ///
    /// Everything durable this promotion does lands in the caller's `wtxn`:
    /// the ordinary subgraph replay (through the standard write door, with the
    /// standard gates, validators, index maintenance, counters, and decision
    /// receipts), the [`OffRecordPromoteReceipt`], and the deduplicated `pm:`
    /// pickup markers. There is no migration transaction, no index-copy
    /// transaction, and no receipt-after-commit transaction — a crash either
    /// leaves the whole promotion or none of it.
    ///
    /// # Retry
    ///
    /// The durable receipt is consulted FIRST. A turn that already has one is
    /// answered from it verbatim, even after its closure has been retired from
    /// the overlay — so retry never advances a base counter or writes a row.
    ///
    /// # Short ids
    ///
    /// Canonical short ids are NOT copied from the overlay. The ordinary
    /// `apply_put` path allocates them from the base `sid_counter:<type_byte>`
    /// rows during the replay above; this reads those rows back inside the
    /// same transaction to pair each in-room alias with its canonical id.
    pub(crate) fn promote(
        &self,
        vault: &Vault,
        wtxn: &mut RwTxn<'_>,
        session_ref: &str,
        plan: &PromotePlan,
        promoted_at: u64,
    ) -> Result<PromoteOutcome> {
        let turn = plan.turn();
        let receipt_key = off_record_promote_key(&turn);
        if let Some(stored) = self.store.vault_meta.get(wtxn, &receipt_key)? {
            let receipt = decode_off_record_promote(&stored)?;
            tracing::debug!(
                turn = %turn.to_hex(),
                replayed = receipt.outcome.replayed.len(),
                "off-record promote retry answered from the durable receipt"
            );
            return Ok(receipt.outcome);
        }

        // The ordinary write door. `apply_recording_gate_decisions` is the same
        // terminus every gated batch uses; the only thing promotion adds is the
        // origin that lets THIS session's overlay ids through the K4 guard.
        let grant = PromoteReplayGrant::mint(plan);
        let member_of = |id: &EntityId| grant.exempts(id);
        TxnBatchBuilder::promotion_replay(vault, plan.ops.clone(), &member_of)
            .apply_recording_gate_decisions(wtxn)?;

        let mut short_id_mapping = Vec::with_capacity(plan.temporary_short_ids.len());
        for (id, temporary) in &plan.temporary_short_ids {
            let canonical = self
                .store
                .short_ids_reverse
                .get(wtxn, id.as_bytes())?
                .ok_or(Error::InvariantViolation(
                    "promotion replay left a promoted entity without a canonical short id",
                ))?;
            let (canonical, _content_hash) = parse_short_id_value(&canonical)?;
            short_id_mapping.push((temporary.clone(), canonical.to_owned()));
        }

        let outcome = PromoteOutcome {
            replayed: plan.replayed.clone(),
            short_id_mapping,
        };
        let receipt = OffRecordPromoteReceipt {
            version: OFF_RECORD_PROMOTE_RECEIPT_VERSION,
            session_ref: session_ref.to_owned(),
            turn: *turn.as_bytes(),
            promoted_at,
            outcome: outcome.clone(),
        };
        self.store
            .vault_meta
            .put(wtxn, &receipt_key, &encode_off_record_promote(&receipt)?)?;

        // Call-site gated, matching `refresh_promoted_turn_in_live_window`:
        // the markers exist only on a sync build, so the non-sync build has
        // no no-op stub to keep honest.
        #[cfg(feature = "sync")]
        self.write_promote_pickup_markers(wtxn, plan, &turn)?;
        Ok(outcome)
    }

    /// One `pm:{window}:{turn}` pickup marker per DISTINCT source window the
    /// promoted closure spans, derived from the journaled `learned_at` values
    /// and committed in the promote transaction.
    ///
    /// Recovery stays the ordinary path: `sync::window::replay_pending_mirrors`
    /// and reverse rematerialization pick the marker up once the turn is no
    /// longer a live overlay member. Promotion adds no CRDT materialization of
    /// its own.
    #[cfg(feature = "sync")]
    fn write_promote_pickup_markers(
        &self,
        wtxn: &mut RwTxn<'_>,
        plan: &PromotePlan,
        turn: &EntityId,
    ) -> Result<()> {
        // Deduplicated on the marker key itself, which carries the window
        // label: two journal stamps in the same month produce one marker.
        let marker_keys: BTreeSet<String> = plan
            .source_learned_at
            .iter()
            .map(|learned_at| {
                let window = crate::sync::WindowKey::from_timestamp(*learned_at);
                format!("pm:{window}:{}", turn.to_hex())
            })
            .collect();
        for marker_key in &marker_keys {
            self.store.sync_state.put(wtxn, marker_key, &[1_u8])?;
        }
        tracing::debug!(
            turn = %turn.to_hex(),
            markers = marker_keys.len(),
            "off-record promote staged pickup markers for its source windows"
        );
        Ok(())
    }
}

impl Vault {
    /// Refreshes the live sync windows after a committed promotion.
    ///
    /// BEST EFFORT BY CONTRACT: the promote transaction has already committed
    /// and the promoted subgraph is durable, so a refresh failure must never
    /// be reported as a failed promote. The caller logs and returns the
    /// committed outcome.
    #[cfg(feature = "sync")]
    pub(super) fn refresh_promoted_turn_in_live_window(&self, turn_id: &EntityId) -> Result<()> {
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
