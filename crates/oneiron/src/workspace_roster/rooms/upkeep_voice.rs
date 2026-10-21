//! The room host's upkeep voice (ARCH-0067 §8, OF-417): "The engine
//! performs every room's mechanical upkeep, and a host does the speaking
//! part." The Coach files a Proposed `coach.room_upkeep.nudge` finding for
//! a room's host when a thread with open TASKs goes quiet; it never speaks.
//! Two explicit doors let the host act on it:
//!
//! - `vault.rooms.upkeep.pending` lists the nudges addressed to the caller,
//!   for rooms it hosts now, that its own lane reads and that no voice has
//!   used yet. A listed nudge does not promise the voice is allowed.
//! - `vault.rooms.upkeep.voice` posts the host's own words for one nudge as
//!   an ordinary host turn in the nudge's thread, answering the thread's
//!   newest turn, through the same witness writer `vault.rooms.speak` lands
//!   through. Its checks run again in that write ([`super::upkeep_voice_guard`]).
//!
//! Nothing here wakes a host, schedules a post or approves a finding. The
//! voice's TURN and MESSAGE ids come from the finding, so a nudge is voiced
//! once: a retry returns the turn already recorded.
use super::upkeep::{room_upkeep_fold_in_txn, room_upkeep_host_in_txn};
use super::upkeep_voice_guard::{VoiceLanes, VoicePlan, VoiceRefusal};
use super::*;
use crate::claim::ClaimReadStatus;
use crate::dreamer_runner::maintenance::coach::room_upkeep_nudge_in_txn;
use crate::memory::{WitnessAuthor, WitnessMessage};
use std::collections::BTreeMap;

const VOICE_TURN_DOMAIN: &[u8] = b"oneiron:rooms-upkeep-voice:turn:v1";
const VOICE_MESSAGE_DOMAIN: &[u8] = b"oneiron:rooms-upkeep-voice:message:v1";

/// `vault.rooms.upkeep.pending`: the caller's unvoiced room nudges, only
/// `room`'s when it names one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomUpkeepPendingRequest {
    #[serde(default)]
    pub room: Option<EntityId>,
}

/// One room upkeep nudge addressed to its host: refs and times only, as the
/// Coach filed them, never a turn's words.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RoomUpkeepNudge {
    /// The Coach's finding.
    pub finding: EntityId,
    pub room: EntityId,
    /// The quiet thread's root turn.
    pub thread: EntityId,
    /// The host it is addressed to.
    pub host: EntityId,
    /// When the thread last moved, as the Coach read it (Unix seconds).
    pub last_activity: u64,
    /// The thread's open TASKs, as the Coach read them.
    pub open_tasks: Vec<EntityId>,
    /// The finding's approval now: Proposed or Approved.
    pub approval: crate::ClaimApprovalStatus,
}

/// `vault.rooms.upkeep.voice`: the host's own words for one nudge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomUpkeepVoiceRequest {
    pub finding: EntityId,
    pub content: String,
}

/// What a voice landed, or had landed before.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RoomUpkeepVoiceReceipt {
    pub finding: EntityId,
    /// The voice's TURN, when the caller reads it; `None` with `message`
    /// for a voice whose rows were since erased.
    pub turn: Option<crate::lens::RecordRef>,
    /// The voice's MESSAGE, when the caller reads it.
    pub message: Option<crate::lens::RecordRef>,
    /// The witness write marker (`witness:<turn-hex>`).
    pub receipt_ref: String,
    /// True when the nudge was voiced already and nothing was written now.
    pub replayed: bool,
}

/// The TURN and MESSAGE ids `finding`'s voice lands under: one voice per
/// finding, whoever retries it.
pub(super) fn voice_ids(finding: EntityId) -> Result<(EntityId, EntityId)> {
    Ok((
        crate::codebase::entity_id_from_hash_material(VOICE_TURN_DOMAIN, &[finding.as_bytes()])?,
        crate::codebase::entity_id_from_hash_material(VOICE_MESSAGE_DOMAIN, &[finding.as_bytes()])?,
    ))
}

/// Whether either voice id is taken in `txn`: a room turn row, any entity
/// or an erase's marker. A taken id is never voiced again.
pub(super) fn voiced_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    (turn, message): (EntityId, EntityId),
) -> Result<bool> {
    if TURNS.get(&vault.store, txn, &turn)?.is_some() {
        return Ok(true);
    }
    for id in [turn, message] {
        if vault.get_entity_type_in_txn(txn, &id)?.is_some()
            || vault.local_hard_delete_marker_exists_in_txn(txn, &id)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

impl Memory<'_> {
    /// The room nudges addressed to the caller, for rooms it hosts now as
    /// the engine selects the host, that its lane reads and no voice has
    /// used: Proposed or Approved, never Rejected or stale. Inside a room
    /// turn, that room's only. Every nudge is read, however many (rule 5).
    pub fn rooms_upkeep_pending(
        &self,
        request: &RoomUpkeepPendingRequest,
    ) -> MemoryResult<Vec<RoomUpkeepNudge>> {
        let vault = self.vault();
        let caller = self.actor();
        let only = match (self.room_turn().map(|turn| turn.room), request.room) {
            (Some(bound), Some(room)) if bound != room => return Ok(Vec::new()),
            (bound, room) => room.or(bound),
        };
        // Lane, grant clock and TASK index before the snapshot, never in it.
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        vault.store.authorization_now()?;
        vault.backfill_tasks_by_owner()?;
        let now = crate::unix_seconds_now();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let mut hosted: BTreeMap<EntityId, bool> = BTreeMap::new();
        let mut pending = Vec::new();
        for edge in crate::ports::EdgeStoreRead::port_edges(
            &vault.store,
            &txn,
            &caller,
            crate::ports::EdgeDirection::In,
            Some(crate::EdgeKind::ClaimOf),
            None,
        )? {
            let finding = edge?.target;
            let Some(nudge) = room_upkeep_nudge_in_txn(&lane, &txn, finding)? else {
                continue;
            };
            if nudge.host != caller || only.is_some_and(|room| room != nudge.room) {
                continue;
            }
            let hosts = match hosted.get(&nudge.room) {
                Some(hosts) => *hosts,
                None => {
                    let hosts = match room_upkeep_fold_in_txn(&lane, &txn, nudge.room, now) {
                        Ok(fold) => {
                            let (input, _) = fold.finish(vault);
                            let last = input.source_refs.last().copied();
                            room_upkeep_host_in_txn(vault, &txn, nudge.room, last)? == Some(caller)
                        }
                        // A room the caller does not read.
                        Err(Error::EntityNotFound) => false,
                        Err(error) => return Err(error.into()),
                    };
                    hosted.insert(nudge.room, hosts);
                    hosts
                }
            };
            if hosts && !voiced_in(vault, &txn, voice_ids(finding)?)? {
                pending.push(nudge);
            }
        }
        Ok(pending)
    }

    /// The room's current host voices `request.finding`, a nudge addressed
    /// to it, as its own turn in the nudge's thread: `content`, answering
    /// the thread's newest turn the host reads. The engine picks that turn
    /// and records the host's claim on it when none is held; the room's
    /// witness writer, the one `vault.rooms.speak` lands through, decides
    /// the turn after every check here runs again in its write. A nudge
    /// voiced already returns its recorded turn, written once. It changes
    /// no approval.
    pub fn rooms_upkeep_voice(
        &self,
        request: &RoomUpkeepVoiceRequest,
    ) -> MemoryResult<RoomUpkeepVoiceReceipt> {
        let vault = self.vault();
        let caller = self.actor();
        let ids = voice_ids(request.finding)?;
        // Lanes, grant clock and TASK index before any snapshot.
        let lanes = VoiceLanes {
            recorded: self.read_lane(ClaimReadStatus::Recorded)?,
            surfaceable: self.read_lane(ClaimReadStatus::Surfaceable)?,
        };
        vault.store.authorization_now()?;
        vault.backfill_tasks_by_owner()?;
        let plan = {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            let now = crate::unix_seconds_now();
            if let Some(receipt) =
                self.voice_replay_in_txn(&txn, &lanes.recorded, request.finding, ids, now)?
            {
                return Ok(receipt);
            }
            let nudge = room_upkeep_nudge_in_txn(&lanes.recorded, &txn, request.finding)?
                .ok_or_else(|| VoiceRefusal::Finding.error())?;
            if nudge.host != caller {
                return Err(VoiceRefusal::Host.error());
            }
            if self.room_turn().is_some_and(|turn| turn.room != nudge.room) {
                return Err(VoiceRefusal::Scope.error());
            }
            let newest = match room_upkeep_fold_in_txn(&lanes.recorded, &txn, nudge.room, now) {
                Ok(fold) => fold.finish(vault).1,
                Err(Error::EntityNotFound) => return Err(VoiceRefusal::Scope.error()),
                Err(error) => return Err(error.into()),
            };
            let parent = *newest
                .get(&nudge.thread)
                .ok_or_else(|| VoiceRefusal::Thread.error())?;
            VoicePlan {
                nudge,
                parent,
                turn: ids.0,
                message: ids.1,
            }
        };
        let speech = WitnessTurn {
            conversation_ref: plan.nudge.room.to_hex(),
            turn_ref: Some(plan.turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(plan.message.to_hex()),
                author: WitnessAuthor::Companion,
                message_type: "text".to_owned(),
                content: request.content.clone(),
                metadata: Some(serde_json::json!({ "room_reply_to": plan.parent.to_hex() })),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.store.clock.now_recorded_at(),
            assertions: Default::default(),
        };
        // A concurrent voice of the same nudge that landed first is this
        // call's replay: the write takes it back out and lands nothing.
        let mut replay = None;
        let landed = self.witness_with_room_birth(&speech, |txn| {
            self.voice_prepare_in_txn(txn, &lanes, &plan, &mut replay)
        });
        let receipt = match landed {
            Ok(receipt) => RoomUpkeepVoiceReceipt {
                finding: request.finding,
                turn: receipt.turn,
                message: receipt.messages.into_iter().next(),
                receipt_ref: receipt.receipt_ref,
                replayed: false,
            },
            Err(error) => return replay.ok_or(error),
        };
        // The host's claim on the answered turn reaches the live windows
        // that carry it, as a claim's does.
        #[cfg(feature = "sync")]
        vault.refresh_room_turn_facts_in_live_windows(plan.parent);
        Ok(receipt)
    }
}
