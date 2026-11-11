//! The read authority and author stamp used by retained transcript imports.
//! Stored facts stay in engine-owned work; every read keeps native live guards.

use super::*;
use crate::authority::{PeerMachine, StoredHostAction, StoredReadProof};
use crate::claim::{RoomTerms, TurnTerms};
use crate::settings::{CallerLocality, ReadDestination};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TranscriptRetainedCaller {
    read_proof: Option<StoredReadProof>,
    host_action: Option<StoredHostAction>,
    room: Option<StoredRoom>,
    locality: CallerLocality,
    off_device: bool,
    peers: Vec<StoredPeer>,
    run_origin: Option<StoredRunOrigin>,
    transport: bool,
    credential: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRoom {
    room: EntityId,
    branch: Option<EntityId>,
    personal: bool,
    worlds: oneiron_authority::federation::Scope,
    facets: oneiron_authority::federation::ScopeAxis<oneiron_authority::federation::ScopeId>,
    clearance: Option<oneiron_authority::federation::Scope>,
    p7: bool,
}

#[derive(Clone, Serialize, Deserialize)]
enum StoredPeer {
    Proven { machine: EntityId, key: [u8; 32] },
    Unknown,
}

// Transcript authors consume the origin's effective run-attempt actor, not
// request-only observers or its claim-stamping session tag.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRunOrigin {
    attempt: [u8; 16],
    source: crate::claim::ClaimSource,
    approval: crate::claim::ClaimApprovalStatus,
    provenance: Vec<u8>,
}

impl Memory<'_> {
    pub(crate) fn retain_transcript_caller(&self) -> MemoryResult<TranscriptRetainedCaller> {
        let room = self.room_turn.as_ref().map(|turn| {
            let terms = turn.terms.get();
            StoredRoom {
                room: turn.room,
                branch: turn.branch,
                personal: turn.personal,
                worlds: terms.worlds,
                facets: terms.facets,
                clearance: terms.clearance,
                p7: terms.p7,
            }
        });
        let peers = self
            .destination
            .all_peers()
            .iter()
            .map(|peer| match *peer {
                PeerMachine::Proven { machine, key } => StoredPeer::Proven { machine, key },
                PeerMachine::Unknown => StoredPeer::Unknown,
            })
            .collect();
        let run_origin = self
            .write_actor()
            .run_attempt()
            .map(|attempt| {
                let origin = self
                    .host_origin
                    .as_ref()
                    .ok_or(crate::Error::InvariantViolation(
                        "transcript run attempt has no host origin",
                    ))?;
                let mut provenance = Vec::new();
                rmpv::encode::write_value(&mut provenance, origin.envelope.provenance().value())
                    .map_err(|_| {
                        crate::Error::InvariantViolation("transcript provenance did not encode")
                    })?;
                Ok::<_, MemoryError>(StoredRunOrigin {
                    attempt,
                    source: origin.envelope.source(),
                    approval: origin.envelope.approval(),
                    provenance,
                })
            })
            .transpose()?;
        Ok(TranscriptRetainedCaller {
            read_proof: self.read_proof.as_ref().map(StoredReadProof::of),
            host_action: self.host_action.as_ref().map(StoredHostAction::of),
            room,
            locality: self.locality,
            off_device: self.destination.is_off_device(),
            peers,
            run_origin,
            transport: self.transport_invocation,
            credential: self.credential,
        })
    }
}

impl TranscriptRetainedCaller {
    pub(crate) fn memory<'v>(
        &self,
        vault: &'v crate::Vault,
        actor: EntityId,
        class: crate::edge::EdgeActorClass,
    ) -> MemoryResult<Memory<'v>> {
        let mut memory = vault.memory(actor, class);
        memory.read_proof = self.read_proof.as_ref().map(StoredReadProof::restore);
        if let Some(action) = &self.host_action {
            memory = memory.with_host_action_authority(&action.restore())?;
        }
        memory.locality = self.locality;
        memory.destination = ReadDestination::from(if self.off_device {
            CallerLocality::OffDevice
        } else {
            CallerLocality::OnDevice
        });
        for peer in &self.peers {
            let destination = match *peer {
                StoredPeer::Proven { machine, key } => {
                    ReadDestination::proved(PeerMachine::Proven { machine, key })
                }
                StoredPeer::Unknown => ReadDestination::toward(PeerMachine::Unknown),
            };
            memory.destination.meet(&destination);
        }
        memory.transport_invocation = self.transport;
        memory.credential = self.credential;
        if let Some(room) = &self.room {
            let mut ceiling = match room.branch {
                Some(thread) => memory.thread_ceiling(room.room, thread)?,
                None => memory.room_ceiling(room.room)?,
            };
            let terms = TurnTerms::new(RoomTerms {
                worlds: room.worlds.clone(),
                facets: room.facets.clone(),
                clearance: room.clearance.clone(),
                p7: room.p7,
            });
            terms.meet(&ceiling.terms.get());
            ceiling.terms = terms;
            ceiling.personal = room.personal;
            memory.room_turn = Some(ceiling);
        }
        if let Some(origin) = &self.run_origin {
            let value = rmpv::decode::read_value(&mut std::io::Cursor::new(&origin.provenance))
                .map_err(|_| MemoryError::bad_request("transcript provenance did not decode"))?;
            let envelope = crate::WriteEnvelope::new(
                crate::WriteActor::new(actor, class).with_run_attempt(origin.attempt),
                origin.source,
                crate::WriteProvenance::new(value)?,
                origin.approval,
            );
            memory.host_origin = Some(HostWriteOrigin::new(envelope));
        }
        Ok(memory)
    }
}

impl TranscriptRetainedCaller {
    /// Keep the narrowing made by work on this restored reader, including
    /// checks that returned a pending hook or a storage error.
    pub(crate) fn keep_narrowed_room(&mut self, memory: &Memory<'_>) {
        if let (Some(saved), Some(turn)) = (&mut self.room, &memory.room_turn) {
            let terms = turn.terms.get();
            saved.worlds = terms.worlds;
            saved.facets = terms.facets;
            saved.clearance = terms.clearance;
            saved.p7 = terms.p7;
        }
    }
}
