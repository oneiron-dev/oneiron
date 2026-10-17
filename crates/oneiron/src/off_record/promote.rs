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
use crate::batch::{BatchBuilder, BatchOp};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, OffRecordError, Result};

use crate::session_overlay::PromotePlan;
use crate::side_table::{self, Named, SideTable};
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
        crate::ports::EntityStoreMaintenance::port_redaction_audit_append(
            self.store, self, wtxn, receipt_id, learned_at, body,
        )
    }
}

const OFF_RECORD_PROMOTE_RECEIPT_VERSION: u8 = 0;

/// The durable retry receipt for one promoted turn: keyed by turn id.
const PROMOTE_RECEIPTS: SideTable<EntityId, OffRecordPromoteReceipt, Named> =
    SideTable::new(&side_table::OFF_RECORD_PROMOTE_RECEIPT);

const OFF_RECORD_COPY_RECEIPT_VERSION: u8 = 0;

/// One message a later save copied into a turn its stretch had saved before:
/// keyed by message id.
const COPY_RECEIPTS: SideTable<EntityId, OffRecordCopyReceipt, Named> =
    SideTable::new(&side_table::OFF_RECORD_COPY_RECEIPT);

/// One `pm:{window}:{turn}` pickup marker: a one-byte presence flag, keyed
/// by `{window}:{turn_hex}` after the declared `pm:` prefix.
#[cfg(feature = "sync")]
const PROMOTE_PICKUP_MARKERS: SideTable<String, [u8; 1], side_table::Raw> =
    SideTable::new(&side_table::OFF_RECORD_PROMOTE_PICKUP_MARKER);

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
/// The initiator fields record WHO consented, from the proof the saving
/// transaction rechecked, never a literal a caller passes in.
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
    /// The consenting actor's entity id, as lower-case hex.
    pub initiator_ref: String,
    /// How they proved it: [`PROMOTE_INITIATOR_OWNER`],
    /// [`PROMOTE_INITIATOR_ROOM_OWNER`] or [`PROMOTE_INITIATOR_ROOM_HOLDER`].
    pub initiator_kind: String,
    pub outcome: PromoteOutcome,
}

/// `initiator_kind` of a promotion on an [`AuthenticatedOwner`] proof.
///
/// [`AuthenticatedOwner`]: crate::consent::AuthenticatedOwner
pub const PROMOTE_INITIATOR_OWNER: &str = "owner";

/// `initiator_kind` of a room's talk saved by a person in the room who owns
/// this vault, named by the transport with the credential it checked
/// ([`OffRecordSession::save_talk_by`](crate::off_record::OffRecordSession::save_talk_by)).
pub const PROMOTE_INITIATOR_ROOM_OWNER: &str = "room_owner";

/// `initiator_kind` of a room's talk saved by someone in the room who holds
/// this vault's write grant without owning it: a member whose shared-vault
/// grant writes, or one of this vault's own agents (ARCH-0052
/// #d5-save-grant), on the slip the transport checked.
pub const PROMOTE_INITIATOR_ROOM_HOLDER: &str = "room_holder";

/// Who consented to a promotion, as its receipt names them. Built only from
/// the proof the saving door checks.
pub(crate) struct PromoteInitiator {
    actor: EntityId,
    kind: &'static str,
}

impl PromoteInitiator {
    /// The owner whose proof `vault` revalidates; the landing checks the
    /// proof again in the transaction that writes.
    pub(crate) fn owner(
        vault: &crate::Vault,
        owner: &crate::consent::AuthenticatedOwner,
    ) -> crate::error::Result<Self> {
        Ok(Self {
            actor: owner.revalidate(vault)?,
            kind: PROMOTE_INITIATOR_OWNER,
        })
    }

    pub(crate) const fn room_owner(person: EntityId) -> Self {
        Self {
            actor: person,
            kind: PROMOTE_INITIATOR_ROOM_OWNER,
        }
    }

    pub(crate) const fn room_holder(holder: EntityId) -> Self {
        Self {
            actor: holder,
            kind: PROMOTE_INITIATOR_ROOM_HOLDER,
        }
    }

    pub(crate) const fn actor(&self) -> EntityId {
        self.actor
    }
}

/// Durable receipt that ONE message of a stretch was copied into base, into a
/// turn the stretch had already saved, by a later save of its talk. The
/// turn's [`OffRecordPromoteReceipt`] stays the answer to a retry of its
/// promotion; this one answers a save that runs again, so the message is
/// never copied twice. It carries opaque ids only, and names who consented
/// to the save that copied it, as [`OffRecordPromoteReceipt`] does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OffRecordCopyReceipt {
    pub(crate) version: u8,
    pub(crate) session_ref: String,
    pub(crate) turn: [u8; 16],
    pub(crate) copied_at: u64,
    pub(crate) initiator_ref: String,
    pub(crate) initiator_kind: String,
}

/// What one copy into a saved turn did: the outcome of the messages it
/// copied now, and every message of the plan base holds by this stretch's
/// saves, now or earlier.
pub(crate) struct Appended {
    pub(crate) outcome: PromoteOutcome,
    pub(crate) held: BTreeSet<EntityId>,
}

/// The refusal of a copy whose message `order` is taken in `turn`.
fn copy_conflict(turn: EntityId, order: u32) -> Error {
    Error::OffRecord(OffRecordError::OffRecordCopyConflict {
        turn_ref: turn.to_hex(),
        order,
    })
}

impl Appended {
    /// A copy that wrote nothing; `held` is what base already holds.
    fn nothing(held: BTreeSet<EntityId>) -> Self {
        Self {
            outcome: PromoteOutcome {
                replayed: Vec::new(),
                short_id_mapping: Vec::new(),
            },
            held,
        }
    }
}

/// The promote transaction's session-membership exemption (ARCH-0052 D2, K4).
///
/// This is a CAPABILITY, not a hint: the `members` field and `mint` are
/// private to this module, so a grant can only come into existence inside the
/// promote transaction below, out of the closure that transaction is
/// replaying. `batch::BaseWriteOrigin::PromoteReplay` borrows one — there is
/// no other way to build that arm, and no predicate riding beside it that
/// crate code could hand-roll. A grant therefore cannot answer `true` for an
/// id the granting session did not stage: another live session's overlay
/// members are still rejected by the taint guard and the entity write door,
/// exactly as for any ordinary base write.
pub(crate) struct PromoteReplayGrant {
    members: BTreeSet<EntityId>,
}

impl PromoteReplayGrant {
    fn mint(plan: &PromotePlan) -> Self {
        Self {
            members: plan.replayed.iter().copied().collect(),
        }
    }

    fn mint_for(members: BTreeSet<EntityId>) -> Self {
        Self { members }
    }

    /// Readable crate-wide so both membership doors can ASK a grant they were
    /// handed; minting stays private, which is where the capability lives.
    pub(crate) fn exempts(&self, id: &EntityId) -> bool {
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
    /// receipts), the turn's tagging marker on an armed vault, the
    /// [`OffRecordPromoteReceipt`], and the deduplicated `pm:` pickup
    /// markers. There is no migration transaction, no index-copy
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
        initiator: &PromoteInitiator,
        promoted_at: u64,
    ) -> Result<PromoteOutcome> {
        // Defense at the only overlay-to-base replay door, before even a
        // durable retry receipt can answer on behalf of an anonymous room.
        if let Some(record) = self.store.off_record_sessions.record(session_ref) {
            record.mode.write_target().require_recording(session_ref)?;
        }
        let turn = plan.turn();
        if let Some(receipt) = PROMOTE_RECEIPTS.get(self.store, wtxn, &turn)? {
            tracing::debug!(
                turn = %turn.to_hex(),
                replayed = receipt.outcome.replayed.len(),
                "off-record promote retry answered from the durable receipt"
            );
            return Ok(receipt.outcome);
        }

        // ARCH-0052 #d4: the closure carries each message's AuthoredBy edge.
        // Its actor is a base identity outside the closure, so an actor base
        // does not hold would leave a dangling edge: refuse the promote.
        for op in &plan.ops {
            if let BatchOp::PublicEdgeWithCreatedAt {
                kind: EdgeKind::AuthoredBy,
                tgt,
                ..
            } = op
                && !crate::ports::EntityStoreRead::port_entity_present(self.store, wtxn, tgt)?
            {
                return Err(Error::OffRecord(
                    OffRecordError::OffRecordPromoteAuthorMissing {
                        turn_ref: turn.to_hex(),
                        actor_ref: tgt.to_hex(),
                    },
                ));
            }
        }

        // The ordinary write door. `apply_recording_gate_decisions` is the same
        // terminus every gated batch uses; the only thing promotion adds is the
        // origin that lets THIS session's overlay ids through the K4 guard.
        let grant = PromoteReplayGrant::mint(plan);
        let replay_ops = plan.ops.clone();
        BatchBuilder::promotion_replay(vault, replay_ops, &grant)
            .apply_recording_gate_decisions(wtxn)?;
        // The outbox rule (write-path hub; ARCH-0036): the promoted turn is
        // base text now, so it owes the vault's tagger a pass and its embedder
        // a vector (ARCH-0004), committed with the promotion. The receipt
        // above answers a retry first, so a retry owes nothing more.
        crate::tagging::mark_turn_in_txn(vault, wtxn, turn)?;
        crate::embed::mark_turn_in_txn(vault, wtxn, turn)?;

        let mut short_id_mapping = Vec::with_capacity(plan.temporary_short_ids.len());
        for (id, temporary) in &plan.temporary_short_ids {
            let (canonical, _content_hash) =
                crate::ports::ShortIdStoreRead::port_short_id_reference(self.store, wtxn, id)?
                    .ok_or(Error::InvariantViolation(
                        "promotion replay left a promoted entity without a canonical short id",
                    ))?;
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
            initiator_ref: initiator.actor.to_hex(),
            initiator_kind: initiator.kind.to_owned(),
            outcome: outcome.clone(),
        };
        PROMOTE_RECEIPTS.put(self.store, wtxn, &turn, &receipt)?;

        // Call-site gated, matching `refresh_promoted_turn_in_live_window`:
        // the markers exist only on a sync build, so the non-sync build has
        // no no-op stub to keep honest.
        #[cfg(feature = "sync")]
        self.write_promote_pickup_markers(wtxn, &plan.source_learned_at, &turn)?;
        Ok(outcome)
    }

    /// Floor operation 3/3, its second form (ARCH-0052 D4, D5): the promote
    /// commit's copy into a turn this stretch already saved, of the messages
    /// said into it since (an agent's run keeps speaking into one turn). A
    /// later save of the whole talk keeps them; it lands in the caller's
    /// `wtxn` with the rest of that save.
    ///
    /// The turn's promote receipt is not touched: it answers a retry of the
    /// promotion, and a retry saves nothing new. Each message copied here
    /// gets an [`OffRecordCopyReceipt`] in the same transaction instead, and
    /// a message base holds by an earlier save, under either receipt, is
    /// skipped rather than written again. The replay is the ordinary one
    /// promote runs: author check, the narrow replay grant, the ordinary
    /// batch, the turn's tagging and embedding markers, and the `pm:`
    /// markers of the messages' own windows.
    ///
    /// The writer's checks of a witness that appends to a turn run here too,
    /// against base in this transaction (Astra on #1411). Nothing is copied
    /// into a turn base no longer holds as this stretch saved it (deleted,
    /// promoted by another stretch, its conversation deleted, or its speaker
    /// no longer the messages' own), nor a message hard-deleted since, nor
    /// what a person since erased from that conversation said: its messages
    /// stay in the room, unsaved. A message whose order base now holds in the turn
    /// refuses the copy with [`OffRecordError::OffRecordCopyConflict`], and a
    /// message id base already holds without a receipt is refused; neither
    /// is ever written over or renumbered.
    pub(crate) fn copy_append(
        &self,
        vault: &Vault,
        wtxn: &mut RwTxn<'_>,
        session_ref: &str,
        plan: &PromotePlan,
        initiator: &PromoteInitiator,
        copied_at: u64,
    ) -> Result<Appended> {
        if let Some(record) = self.store.off_record_sessions.record(session_ref) {
            record.mode.write_target().require_recording(session_ref)?;
        }
        let turn = plan.turn();
        let mut held = BTreeSet::new();
        let saved = PROMOTE_RECEIPTS
            .get(self.store, wtxn, &turn)?
            .filter(|receipt| receipt.session_ref == session_ref);
        let conversation = plan.conversation();
        // A deleted turn or conversation keeps its header and edges as a
        // shell: only live rows are what this stretch saved (Sol on
        // engine-prs-30), and each also needs a body, as the witness writer
        // asks.
        let txn: &heed::RoTxn<'_> = wtxn;
        let live_body = |id: &EntityId, kind: u8| -> Result<Option<Vec<u8>>> {
            let row = crate::vault::live_entity_row_in_txn(self.store, txn, id)?;
            Ok(match row {
                crate::vault::LiveEntityRow::Live { entity_type, body }
                    if entity_type == kind && !body.is_empty() =>
                {
                    Some(body)
                }
                _ => None,
            })
        };
        let turn_body = live_body(&turn, crate::registry::ENTITY_TYPE_TURN)?;
        let live = turn_body.is_some()
            && live_body(&conversation, crate::registry::ENTITY_TYPE_CONVERSATION)?.is_some()
            && crate::ports::EdgeStoreRead::port_edge_get(
                self.store,
                txn,
                &turn,
                EdgeKind::ChildOf,
                &conversation,
            )?
            .is_some();
        let (Some(saved), Some(turn_body)) = (saved.filter(|_| live), turn_body) else {
            tracing::debug!(
                turn = %turn.to_hex(),
                "off-record copy skipped a turn base does not hold as this stretch saved it"
            );
            return Ok(Appended::nothing(held));
        };

        let mut fresh = BTreeSet::new();
        for id in &plan.replayed {
            if saved.outcome.replayed.contains(id)
                || COPY_RECEIPTS
                    .get(self.store, wtxn, id)?
                    .is_some_and(|receipt| receipt.session_ref == session_ref)
            {
                held.insert(*id);
            } else if crate::ports::EntityStoreRead::port_entity_present(self.store, wtxn, id)? {
                return Err(Error::InvariantViolation(
                    "an off-record message to copy already names a row base holds",
                ));
            } else if vault.local_hard_delete_marker_exists_in_txn(wtxn, id)? {
                // Deleted for good since it was said (a peer's tombstone can
                // name an id base never held): never written back.
                tracing::debug!(
                    turn = %turn.to_hex(),
                    "off-record copy skipped a turn holding a message since hard-deleted"
                );
                return Ok(Appended::nothing(BTreeSet::new()));
            } else {
                fresh.insert(*id);
            }
        }
        if fresh.is_empty() {
            return Ok(Appended::nothing(held));
        }
        // Every check reads the plan's own ops, which wipe with it; the copy
        // the replay takes is cloned last, straight into the builder that
        // wipes it (Sol on engine-prs-30).
        let fresh_ops = || {
            plan.ops.iter().filter(|op| {
                crate::session_overlay::replayed_subject(op).is_some_and(|id| fresh.contains(&id))
            })
        };
        let mut orders = BTreeSet::new();
        let mut bodies: Vec<&[u8]> = Vec::new();
        for op in fresh_ops() {
            match op {
                BatchOp::PublicEdgeWithCreatedAt {
                    kind: EdgeKind::AuthoredBy,
                    tgt,
                    ..
                } => {
                    let Some(author) =
                        crate::ports::EntityStoreRead::port_entity_record(self.store, wtxn, tgt)?
                    else {
                        return Err(Error::OffRecord(
                            OffRecordError::OffRecordPromoteAuthorMissing {
                                turn_ref: turn.to_hex(),
                                actor_ref: tgt.to_hex(),
                            },
                        ));
                    };
                    if author.entity_type == crate::registry::ENTITY_TYPE_PERSON
                        && !crate::conversation::room_person_write_allowed(
                            self.store,
                            wtxn,
                            conversation,
                            *tgt,
                        )?
                    {
                        tracing::debug!(
                            turn = %turn.to_hex(),
                            "off-record copy skipped a turn holding words of a person since erased from it"
                        );
                        return Ok(Appended::nothing(BTreeSet::new()));
                    }
                }
                BatchOp::Put {
                    entity_type, data, ..
                } if *entity_type == crate::registry::ENTITY_TYPE_MESSAGE => {
                    let order = crate::memory::witness_message_order(data)?;
                    if !orders.insert(order) {
                        return Err(copy_conflict(turn, order));
                    }
                    bodies.push(data.as_slice());
                }
                _ => {}
            }
        }
        // The turn's speaker is what an append to it is checked against, and
        // a native put may have changed it since the save.
        if !crate::memory::turn_admits_message_bodies(&turn_body, &bodies)? {
            tracing::debug!(
                turn = %turn.to_hex(),
                "off-record copy skipped a turn that no longer speaks as its messages"
            );
            return Ok(Appended::nothing(BTreeSet::new()));
        }
        // One message per order in a turn: an ordinary witness may have put
        // one at a copied message's order since the last save, seeing only
        // base. No base sibling shares a fresh id, so none is exempt.
        if let Some(order) = crate::memory::taken_witness_message_order(
            self.store,
            wtxn,
            &turn,
            &orders,
            &std::collections::HashSet::new(),
        )? {
            return Err(copy_conflict(turn, order));
        }
        // The copied messages' own windows, never the save's clock.
        #[cfg(feature = "sync")]
        let source_learned_at: Vec<u64> = fresh_ops()
            .filter_map(|op| match op {
                BatchOp::Put { learned_at, .. } => Some(*learned_at),
                _ => None,
            })
            .collect();
        let grant = PromoteReplayGrant::mint_for(fresh.clone());
        BatchBuilder::promotion_replay(vault, fresh_ops().cloned().collect(), &grant)
            .apply_recording_gate_decisions(wtxn)?;
        crate::tagging::mark_turn_in_txn(vault, wtxn, turn)?;
        crate::embed::mark_turn_in_txn(vault, wtxn, turn)?;

        let replayed: Vec<EntityId> = plan
            .replayed
            .iter()
            .filter(|id| fresh.contains(id))
            .copied()
            .collect();
        let mut short_id_mapping = Vec::new();
        for (id, temporary) in &plan.temporary_short_ids {
            if !fresh.contains(id) {
                continue;
            }
            let (canonical, _content_hash) =
                crate::ports::ShortIdStoreRead::port_short_id_reference(self.store, wtxn, id)?
                    .ok_or(Error::InvariantViolation(
                        "an off-record copy left a message without a canonical short id",
                    ))?;
            short_id_mapping.push((temporary.clone(), canonical.to_owned()));
        }
        for id in &replayed {
            COPY_RECEIPTS.put(
                self.store,
                wtxn,
                id,
                &OffRecordCopyReceipt {
                    version: OFF_RECORD_COPY_RECEIPT_VERSION,
                    session_ref: session_ref.to_owned(),
                    turn: *turn.as_bytes(),
                    copied_at,
                    initiator_ref: initiator.actor.to_hex(),
                    initiator_kind: initiator.kind.to_owned(),
                },
            )?;
            held.insert(*id);
        }
        #[cfg(feature = "sync")]
        self.write_promote_pickup_markers(wtxn, &source_learned_at, &turn)?;
        Ok(Appended {
            outcome: PromoteOutcome {
                replayed,
                short_id_mapping,
            },
            held,
        })
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
        source_learned_at: &[u64],
        turn: &EntityId,
    ) -> Result<()> {
        // Deduplicated on the marker key itself, which carries the window
        // label: two journal stamps in the same month produce one marker.
        let marker_keys: BTreeSet<String> = source_learned_at
            .iter()
            .map(|learned_at| {
                let window = crate::sync::WindowKey::from_timestamp(*learned_at);
                format!("{window}:{}", turn.to_hex())
            })
            .collect();
        for marker_key in &marker_keys {
            PROMOTE_PICKUP_MARKERS.put(self.store, wtxn, marker_key, &[1_u8])?;
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
        PROMOTE_RECEIPTS.get(&self.store, &rtxn, turn_id)
    }

    /// The receipt of `message`, copied into a saved turn by a later save.
    #[cfg(test)]
    pub(crate) fn off_record_copy_receipt(
        &self,
        message: &EntityId,
    ) -> Result<Option<OffRecordCopyReceipt>> {
        let rtxn = self.store.env.read_txn()?;
        COPY_RECEIPTS.get(&self.store, &rtxn, message)
    }

    /// How many sync pickup markers name `turn_id`. The marker table is
    /// crate-private, so a transport's test that pins "a refused promotion
    /// stages nothing for sync" needs a door.
    #[doc(hidden)]
    #[cfg(all(feature = "sync", feature = "test-support"))]
    pub fn off_record_promote_pickup_markers_for_test(&self, turn_id: &EntityId) -> Result<usize> {
        let rtxn = self.store.env.read_txn()?;
        let suffix = format!(":{}", turn_id.to_hex());
        Ok(PROMOTE_PICKUP_MARKERS
            .scan_keys(&self.store, &rtxn, &[])?
            .iter()
            .filter(|key| key.ends_with(&suffix))
            .count())
    }
}
