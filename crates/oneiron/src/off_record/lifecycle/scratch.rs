//! Explicit selected scratch saves. Authority, selection and landing share one writer.
use std::collections::{BTreeMap, BTreeSet, HashSet};

use zeroize::Zeroizing;

use super::room::{Hearing, post_notice};
use super::save_grant::{SaveGrant, not_a_holder};
use super::session::OffRecordSession;
use super::types::OffRecordNoticeAct;
use crate::authority::VerifiedSlip;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimReadStatus, ClaimSubject, ScopedReadActorKey};
use crate::off_record::promote::{
    FloorWrites, PromoteInitiator, PromoteOutcome, PromoteReplayGrant,
};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead, ShortIdStoreRead};
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_NOTE,
    ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};
use crate::session_overlay::{
    JournalRole, OverlayKeyspace, OverlaySnapshot, PromotePlan, replayed_subject,
};
use crate::store::SessionStoreView;
use crate::store::birth_record::SavedRoomBirth;
use crate::{EdgeActorClass, EntityId, Error, Result, TimeRange, Vault, WriteActor};

pub(in crate::off_record) struct PreparedScratchSave {
    saver: WriteActor,
    artifacts: Vec<PreparedArtifact>,
    turns: Vec<PromotePlan>,
    members: BTreeSet<EntityId>,
    documents: BTreeSet<EntityId>,
    snapshot: OverlaySnapshot,
    initiator: PromoteInitiator,
    temporary_short_ids: Vec<(EntityId, String)>,
}

enum PreparedArtifact {
    Note {
        id: EntityId,
        note: crate::note::PreparedSavedNote,
        edges: Vec<BatchOp>,
        birth: SavedRoomBirth,
    },
    Claim {
        id: EntityId,
        body: ClaimBody,
        occurred: TimeRange,
        learned_at: u64,
        edges: Vec<BatchOp>,
        birth: SavedRoomBirth,
    },
    Shell {
        id: EntityId,
        header: EntityMetadataHeader,
        body: Vec<u8>,
        edges: Vec<BatchOp>,
        birth: SavedRoomBirth,
    },
}

pub(in crate::off_record) struct SavedScratch {
    pub(super) outcome: PromoteOutcome,
    pub(super) members: BTreeSet<EntityId>,
    pub(super) documents: BTreeSet<EntityId>,
    pub(super) snapshot: OverlaySnapshot,
    pub(super) turns: Vec<PromotePlan>,
    kept_messages: Vec<(EntityId, super::registry::KeptMessage)>,
}

impl PreparedScratchSave {
    pub(in crate::off_record) fn saver(&self) -> WriteActor {
        self.saver
    }
    pub(in crate::off_record) fn members(&self) -> &BTreeSet<EntityId> {
        &self.members
    }

    pub(in crate::off_record) fn land(
        self,
        floor: &FloorWrites<'_>,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        session_ref: &str,
        grant: &PromoteReplayGrant,
    ) -> Result<SavedScratch> {
        let mut mapping = Vec::new();
        let mut members = BTreeSet::new();
        let mut kept_messages = Vec::new();
        for plan in &self.turns {
            let mut held: BTreeSet<EntityId> = if plan.appends() {
                floor
                    .copy_append(
                        vault,
                        txn,
                        session_ref,
                        plan,
                        &self.initiator,
                        vault.now_recorded_at(),
                    )?
                    .held
            } else {
                floor
                    .promote(
                        vault,
                        txn,
                        session_ref,
                        plan,
                        &self.initiator,
                        vault.now_recorded_at(),
                    )?
                    .replayed
                    .into_iter()
                    .collect()
            };
            held.retain(|id| plan.replayed.contains(id));
            for id in &held {
                let raw = Zeroizing::new(vault.store.port_entity_raw(txn, id)?.ok_or(
                    Error::InvariantViolation("selected turn save left no durable row"),
                )?);
                let header = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("saved transcript entity header"))?;
                if header.entity_type == ENTITY_TYPE_MESSAGE {
                    kept_messages.push((
                        *id,
                        super::registry::KeptMessage {
                            turn: plan.turn(),
                            at: header.occurred_start,
                            digest: *blake3::hash(&raw[ENTITY_METADATA_HEADER_LEN..]).as_bytes(),
                        },
                    ));
                }
            }
            members.extend(held);
        }
        for artifact in self.artifacts {
            match artifact {
                PreparedArtifact::Note {
                    id,
                    note,
                    edges,
                    birth,
                } => {
                    note.land_in_txn(vault, txn, self.saver, grant, edges)?;
                    birth.land(vault, txn, grant)?;
                    members.insert(id);
                    #[cfg(feature = "sync")]
                    vault.queue_note_document_update_in_txn(txn, id);
                    #[cfg(not(feature = "sync"))]
                    let _ = id;
                }
                PreparedArtifact::Claim {
                    id,
                    body,
                    occurred,
                    learned_at,
                    edges,
                    birth,
                } => {
                    vault.put_saved_claim_in_txn(
                        txn, &id, &body, occurred, learned_at, self.saver, grant, edges,
                    )?;
                    birth.land(vault, txn, grant)?;
                    members.insert(id);
                }
                PreparedArtifact::Shell {
                    id,
                    header,
                    body,
                    edges,
                    birth,
                } => {
                    let mut ops = vec![BatchOp::Put {
                        id,
                        entity_type: ENTITY_TYPE_CONVERSATION,
                        occurred: TimeRange {
                            start: header.occurred_start,
                            end: header.occurred_end,
                        },
                        learned_at: header.learned_at,
                        row_version: Some(header.row_version),
                        data: body,
                        allow_maintenance: false,
                        allow_reserved_predicate: false,
                        hub_sync_imported: false,
                    }];
                    ops.extend(edges);
                    crate::batch::BatchBuilder::promotion_replay(vault, ops, grant)
                        .apply_actor(txn, &self.saver)?;
                    birth.land(vault, txn, grant)?;
                    members.insert(id);
                }
            }
        }
        for id in &members {
            let (canonical, _) =
                vault
                    .store
                    .port_short_id_reference(txn, id)?
                    .ok_or(Error::InvariantViolation(
                        "selected save left no canonical short id",
                    ))?;
            if let Some((_, temporary)) = self
                .temporary_short_ids
                .iter()
                .find(|(source, _)| source == id)
            {
                mapping.push((temporary.clone(), canonical));
            }
        }
        Ok(SavedScratch {
            outcome: PromoteOutcome {
                replayed: members.iter().copied().collect(),
                short_id_mapping: mapping,
            },
            members,
            documents: self.documents,
            snapshot: self.snapshot,
            turns: self.turns,
            kept_messages,
        })
    }
}

struct Selection<'a, 'v> {
    session: &'a OffRecordSession<'v>,
    view: &'a SessionStoreView<'a>,
    snapshot: OverlaySnapshot,
    key: ScopedReadActorKey,
    room: Option<EntityId>,
    selected: HashSet<EntityId>,
    members: BTreeSet<EntityId>,
    documents: BTreeSet<EntityId>,
    artifacts: Vec<PreparedArtifact>,
    turns: BTreeMap<EntityId, BTreeSet<EntityId>>,
}

impl Selection<'_, '_> {
    fn select(&mut self, txn: &heed::RoTxn<'_>, id: EntityId, root: bool) -> Result<()> {
        if !self.selected.insert(id) {
            return Ok(());
        }
        let vault = self.session.vault;
        let Some(staged) = self
            .snapshot
            .staged_value(OverlayKeyspace::Entities, id.as_bytes())
        else {
            if root {
                return Err(Error::EntityNotFound);
            }
            return Ok(());
        };
        let raw = staged.to_vec();
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("selected scratch entity header"))?;
        let body = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
        let read = vault
            .scoped_read_in_session(self.key.clone(), self.view)
            .with_claim_status(ClaimReadStatus::Recorded);
        let admitted = read
            .get_entities_parts_in_txn(txn, &[id])?
            .pop()
            .flatten()
            .ok_or(Error::EntityNotFound)?;
        if admitted.0 != header.entity_type
            || admitted.2 != body
            || vault.local_hard_delete_marker_exists_in_txn(txn, &id)?
        {
            return Err(Error::EntityNotFound);
        }
        if header.entity_type != ENTITY_TYPE_CLAIM
            && let Some(base) = vault.store.port_entity_raw(txn, &id)?
            && base != raw
        {
            return Err(Error::InvariantViolation(
                "selected scratch id already has another durable row",
            ));
        }
        let mut edges = Vec::new();
        let mut dependencies = Vec::new();
        for edge in self
            .view
            .port_edges(txn, &id, EdgeDirection::Out, None, None)?
        {
            let edge = edge?;
            dependencies.push(edge.target);
            let vad = edge.vad.unwrap_or(oneiron_contracts::affect::Vad::NEUTRAL);
            edges.push(match edge.provenance {
                Some(provenance) => BatchOp::EdgeWithCreatedAt {
                    src: id,
                    kind: edge.kind,
                    tgt: edge.target,
                    weight: edge.weight,
                    created_at: edge.created_at,
                    vad,
                    provenance: Some(provenance),
                },
                None => BatchOp::PublicEdgeWithCreatedAt {
                    src: id,
                    kind: edge.kind,
                    tgt: edge.target,
                    weight: edge.weight,
                    created_at: edge.created_at,
                    vad,
                },
            });
        }
        let artifact = match header.entity_type {
            ENTITY_TYPE_NOTE => {
                let note = crate::note::PreparedSavedNote::from_room_in_txn(
                    vault,
                    self.view,
                    &self.snapshot,
                    txn,
                    id,
                    self.session.pending_scan_checks(),
                )?;
                dependencies.extend(note.dependencies()?);
                self.documents.insert(note.document_slot());
                PreparedArtifact::Note {
                    id,
                    note,
                    edges,
                    birth: SavedRoomBirth::prepare(self.view, txn, id)?,
                }
            }
            ENTITY_TYPE_CLAIM => {
                if !self.snapshot.journal_entries().iter().any(|entry| matches!(&entry.op,
                    BatchOp::Put { id: source, entity_type: ENTITY_TYPE_CLAIM, data, .. } if *source == id && *data == body
                )) { return Err(Error::EntityNotFound); }
                let body = crate::claim::validate_claim_body_and_decode_in_txn(
                    &vault.store,
                    txn,
                    &body,
                    false,
                )?;
                if let ClaimSubject::Entity(subject) = body.subject {
                    dependencies.push(subject);
                }
                PreparedArtifact::Claim {
                    id,
                    body,
                    occurred: TimeRange {
                        start: header.occurred_start,
                        end: header.occurred_end,
                    },
                    learned_at: header.learned_at,
                    edges,
                    birth: SavedRoomBirth::prepare(self.view, txn, id)?,
                }
            }
            ENTITY_TYPE_TURN if !root => {
                self.turns.entry(id).or_default();
                if let Some(room) = self.room {
                    super::room::require_sight_in_txn(
                        vault,
                        txn,
                        self.session.session_ref(),
                        room,
                        EntityId::from_hex(self.key.actor_ref())?,
                        &[header.occurred_start],
                    )?;
                }
                return Ok(());
            }
            ENTITY_TYPE_MESSAGE | ENTITY_TYPE_SUMMARY if !root => {
                let source = self.snapshot.journal_entries().iter().find(|entry| {
                    matches!(&entry.op,
                        BatchOp::Put { id: source, entity_type, data, .. }
                            if *source == id && *entity_type == header.entity_type && *data == body
                    ) && matches!((header.entity_type, entry.role),
                        (ENTITY_TYPE_MESSAGE, JournalRole::MessagePartOf)
                            | (ENTITY_TYPE_SUMMARY, JournalRole::SummaryDerivedFrom))
                }).ok_or(Error::EntityNotFound)?;
                let turn = source.scope.turn();
                if let Some(room) = self.room {
                    super::room::require_sight_in_txn(
                        vault,
                        txn,
                        self.session.session_ref(),
                        room,
                        EntityId::from_hex(self.key.actor_ref())?,
                        &[header.occurred_start],
                    )?;
                }
                self.turns.entry(turn).or_default().insert(id);
                for dependency in dependencies {
                    self.select(txn, dependency, false)?;
                }
                self.members.insert(id);
                return Ok(());
            }
            ENTITY_TYPE_CONVERSATION if !root => {
                if !self.snapshot.journal_entries().iter().any(|entry| entry.role == JournalRole::ConversationShell
                    && matches!(&entry.op, BatchOp::Put { id: source, entity_type: ENTITY_TYPE_CONVERSATION, data, .. } if *source == id && *data == body)) {
                    return Err(Error::EntityNotFound);
                }
                PreparedArtifact::Shell {
                    id,
                    header,
                    body,
                    edges,
                    birth: SavedRoomBirth::prepare(self.view, txn, id)?,
                }
            }
            other => return Err(Error::InvalidEntityType(other)),
        };
        for dependency in dependencies {
            self.select(txn, dependency, false)?;
        }
        self.members.insert(id);
        self.artifacts.push(artifact);
        Ok(())
    }

    fn turn_plans(&mut self, promoted: &[[u8; 16]]) -> Result<Vec<PromotePlan>> {
        let mut plans = Vec::new();
        for (turn, selected) in &self.turns {
            let keep = |entry: &crate::session_overlay::JournalEntry| {
                matches!(
                    entry.role,
                    JournalRole::ConversationShell | JournalRole::TurnPut
                ) || matches!(&entry.op,
                    BatchOp::Edge { src, .. } | BatchOp::PublicEdgeWithCreatedAt { src, .. }
                        | BatchOp::EdgeWithCreatedAt { src, .. } if *src == *turn
                ) || replayed_subject(&entry.op).is_some_and(|id| selected.contains(&id))
            };
            let plan = if promoted.contains(turn.as_bytes()) {
                self.snapshot.plan_append_where(*turn, keep)?
            } else {
                self.snapshot.plan_promotion_where(*turn, keep)?
            };
            self.members.extend(plan.replayed.iter().copied());
            plans.push(plan);
        }
        Ok(plans)
    }
}

impl OffRecordSession<'_> {
    /// Preserve one scratch NOTE/CLAIM and its document, on this vault's real
    /// write grant. Source authorship is data; `holder` is the saving actor.
    pub fn save_artifact_by(
        &self,
        holder: EntityId,
        credential: &VerifiedSlip,
        reference: &str,
    ) -> Result<PromoteOutcome> {
        let grant = SaveGrant::claimed(holder, credential)
            .ok_or_else(|| not_a_holder(self.session_ref(), holder))?;
        let class = match credential.claims().actor_class.as_deref() {
            Some("human") => EdgeActorClass::Human,
            Some("agent") => EdgeActorClass::Agent,
            _ => return Err(not_a_holder(self.session_ref(), holder)),
        };
        self.save_artifact(reference, WriteActor::new(holder, class), false, |txn| {
            grant.require_in_txn(self.vault, txn, self.session_ref())?;
            let key = self
                .vault
                .credential_target_key_in_txn(txn, credential)?
                .ok_or_else(|| not_a_holder(self.session_ref(), holder))?;
            Ok((key, grant.initiator_in_txn(self.vault, txn)?))
        })
    }

    /// The vault owner's selected save, with the same proof rechecked in the
    /// writer that keeps it; the room's current roster still applies.
    pub fn save_artifact_as(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        reference: &str,
    ) -> Result<PromoteOutcome> {
        let key = self.vault.owner_proof_read_key(owner)?;
        let actor = owner
            .revalidate_as_vault_owner_in_txn(self.vault, &self.vault.store.env.read_txn()?)?;
        self.save_artifact(
            reference,
            WriteActor::new(actor, EdgeActorClass::Human),
            true,
            |txn| {
                owner.revalidate_as_vault_owner_in_txn(self.vault, txn)?;
                Ok((key.clone(), PromoteInitiator::room_owner(actor)))
            },
        )
    }

    fn save_artifact(
        &self,
        reference: &str,
        saver: WriteActor,
        owner: bool,
        mut authority: impl FnMut(&heed::RoTxn<'_>) -> Result<(ScopedReadActorKey, PromoteInitiator)>,
    ) -> Result<PromoteOutcome> {
        let mut state = self.recording_state()?;
        let room = state.record.room.map(EntityId::from_bytes).transpose()?;
        let prepare = |txn: &heed::RoTxn<'_>, key, initiator| -> Result<PreparedScratchSave> {
            if let Some(room) = room {
                if !self.is_member_in_txn(txn, room, saver.entity_ref())? {
                    return Err(super::room::not_in_room(
                        self.session_ref(),
                        saver.entity_ref(),
                    ));
                }
            } else if !owner && self.entry.creator.map(|who| who.actor) != Some(saver.entity_ref())
            {
                return Err(not_a_holder(self.session_ref(), saver.entity_ref()));
            }
            self.participant_in_txn(txn)?;
            let view = self.read_view()?;
            let snapshot = self.entry.overlay.snapshot()?;
            // Alias lookup in this same composed snapshot, not a new read txn.
            let id = match crate::memory::room_short_ref(reference.trim()) {
                Some((alias, hash)) => {
                    let mut key = alias.as_bytes().to_vec();
                    key.push(hash);
                    let raw = view
                        .short_ids
                        .get(txn, &key)?
                        .ok_or(Error::EntityNotFound)?;
                    EntityId::from_bytes(
                        (&raw[..])
                            .try_into()
                            .map_err(|_| Error::CorruptedIndex("room short id"))?,
                    )?
                }
                None => EntityId::from_hex(reference.trim())?,
            };
            let mut selection = Selection {
                session: self,
                view: &view,
                snapshot,
                key,
                room,
                selected: HashSet::new(),
                members: BTreeSet::new(),
                documents: BTreeSet::new(),
                artifacts: Vec::new(),
                turns: BTreeMap::new(),
            };
            selection.select(txn, id, true)?;
            let turns = selection.turn_plans(&state.record.promoted_turns)?;
            let temporary_short_ids = selection
                .members
                .iter()
                .map(|id| {
                    Ok(view
                        .port_short_id_reference(txn, id)?
                        .map(|(short, _)| (*id, short)))
                })
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect();
            Ok(PreparedScratchSave {
                saver,
                artifacts: selection.artifacts,
                turns,
                members: selection.members,
                documents: selection.documents,
                snapshot: selection.snapshot,
                initiator,
                temporary_short_ids,
            })
        };
        let floor = FloorWrites::new(&self.vault.store).saving(self.entry.overlay.clone());
        // The preview only brings selected result files into the vault. It
        // never mints a replay grant; the committing writer prepares afresh.
        #[cfg(unix)]
        let preview_turns = {
            let txn = self.vault.store.env.read_txn()?;
            let (key, initiator) = authority(&txn)?;
            prepare(&txn, key, initiator)?.turns
        };
        #[cfg(unix)]
        let bodies = floor.import_result_bodies(self.vault, self.session_ref(), &preview_turns)?;
        let saved = self.vault.with_write_txn_grouped(|txn| {
            let (key, initiator) = authority(txn)?;
            let prepared = prepare(txn, key, initiator)?;
            #[cfg(unix)]
            floor.require_preimported_selected_results(&preview_turns, &prepared.turns)?;
            let landed =
                floor.save_scratch_in_txn(self.vault, txn, self.session_ref(), prepared)?;
            Ok((landed, Hearing::in_txn(self.vault, txn, room)))
        });
        #[cfg(unix)]
        self.vault.discard_unnamed_promoted_bodies(bodies);
        let (saved, hearing) = saved?;
        // No retirement or room-visible success before the durable commit.
        for plan in &saved.turns {
            if !state.record.promoted_turns.contains(plan.turn().as_bytes()) {
                state.record.promoted_turns.push(*plan.turn().as_bytes());
            }
        }
        if state.record.room.is_some() {
            for (id, kept) in saved.kept_messages {
                state.kept_messages.entry(id).or_insert(kept);
            }
        }
        post_notice(
            &mut state,
            OffRecordNoticeAct::SavedArtifact,
            saver.entity_ref(),
            hearing,
        );
        self.entry.publish_state(&state);
        if let Err(error) = self.entry.overlay.retire_saved_artifacts(
            &saved.snapshot,
            &saved.members,
            &saved.documents,
        ) {
            tracing::warn!(%error, "selected scratch save committed; retirement deferred to close");
        }
        Ok(saved.outcome)
    }
}
