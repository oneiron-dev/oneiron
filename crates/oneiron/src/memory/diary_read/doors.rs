//! Diary read, review, grant, and reader-list doors.

use std::collections::BTreeMap;

use super::{
    DIARY_READ_LOG, DIARY_READ_REQUEST, DIARY_READ_REVIEW, DIARY_READ_VERB, DiaryEntry,
    DiaryEntryAdmission, DiaryReadGate, DiaryReadHold, DiaryReadOutcome, DiaryReadRecord,
    DiaryReadRequest, DiaryReadReview, DiaryReader, DiaryReaderList, DiaryReviewAnswer,
    DiaryReviewState, REVIEW_INBOX_IMPACT, SealedPadReader, agent_reviews_diary_reads_in_txn,
    coach_reads_pads_in_txn, diary_entries_in_txn, live_note_in_txn, standing_request_in_txn,
    work_vault_admin_in_txn,
};
use crate::batch::secret_scan::LiftedKeys;
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, ConsentReceipt, GrantBound,
};
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::memory::authorship::*;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::note::NoteKind;
use crate::{EntityId, Vault, WriteActor};
use crate::{
    agent_inbox_lens::AgentInboxLensItem,
    inbox::view_values::{AgentInboxDiaryReview, AgentInboxItemKind},
    inbox::view_values::{AgentInboxParticipant, InboxImpact},
};

impl Vault {
    /// Sets whether `agent` reviews each read of its diary first. The host
    /// that provisions Eiri turns it on for her agent id; absent means off.
    pub fn set_agent_diary_read_review(&self, agent: EntityId, on: bool) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            DIARY_READ_REVIEW.put(&self.store, txn, &agent, &DiaryReadReview(on))
        })
    }

    /// Whether `agent` reviews each read of its diary first.
    pub fn agent_diary_read_review(&self, agent: EntityId) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        agent_reviews_diary_reads_in_txn(self, &txn, &agent)
    }

    /// Each pending review as a row of its agent's INBOX: one unthreaded
    /// update per request, named by its `diary-read:` handle, until the agent
    /// answers it. The row carries the reader and their reason, and
    /// `self.memory.diary.review` answers it.
    pub(crate) fn diary_read_inbox_items(&self) -> Result<Vec<AgentInboxLensItem>> {
        let txn = self.store.env.read_txn()?;
        let mut items = Vec::new();
        for ((agent, request), row) in DIARY_READ_REQUEST.scan(&self.store, &txn)? {
            if row.state != DiaryReviewState::Pending {
                continue;
            }
            let handle = format!("diary-read:{}:{}", agent.to_hex(), request.to_hex());
            items.push(AgentInboxLensItem {
                item_id: handle.clone(),
                kind: AgentInboxItemKind::CoordinationUpdate,
                thread_ref: None,
                identity_ref: Some(agent),
                actor_ref: agent,
                facet_ref: None,
                participants: vec![AgentInboxParticipant {
                    identity_ref: Some(agent),
                    actor_ref: agent,
                }],
                impact: InboxImpact(REVIEW_INBOX_IMPACT),
                occurred_at: row.asked_at,
                receipt_ref: None,
                payload_ref: Some(handle),
                concern: None,
                diary_review: Some(AgentInboxDiaryReview {
                    request,
                    reader: row.reader,
                    reader_class: row.reader_class,
                    reason: row.reason,
                }),
                sender: None,
                widening: None,
            });
        }
        Ok(items)
    }
}

impl Memory<'_> {
    /// Reads `agent`'s diary as this caller, stating `reason`, in ONE
    /// transaction: the caller's `diary.read` Grants decide which entries it
    /// gets, the read lands in the agent's log, and an agent that reviews
    /// gets the reason to answer first. A person authenticates.
    pub fn read_agent_diary(
        &self,
        reader: Option<&AuthenticatedOwner>,
        agent: EntityId,
        reason: &str,
    ) -> MemoryResult<DiaryReadOutcome> {
        self.with_verified_actor_write_txn(|txn| {
            let actor = self.diary_reader_in_txn(txn, reader)?;
            let mut gate = DiaryReadGate::new(actor, reason)?;
            gate.touch(self.vault, txn, agent)?;
            let mut entries = Vec::new();
            for (id, note, learned_at) in diary_entries_in_txn(self.vault, txn, agent)? {
                // Each entry the gate judges, read or counted as held.
                self.produced_from([id]);
                if gate.admit(self.vault, txn, agent, id)? == DiaryEntryAdmission::Read {
                    entries.push(DiaryEntry {
                        id,
                        learned_at,
                        markdown: note.markdown,
                    });
                }
            }
            self.mask_diary_entries_in_txn(txn, &mut entries)?;
            let receipt = gate.finish_in_txn(self.vault, txn)?;
            let Some(read) = receipt.agents.into_iter().next() else {
                return Ok(DiaryReadOutcome::Granted {
                    read: None,
                    entries,
                });
            };
            let held = |hold| read.held.iter().any(|(held, _)| *held == hold);
            Ok(match read.request {
                _ if read.read.is_some() || (read.whole_diary && read.held.is_empty()) => {
                    DiaryReadOutcome::Granted {
                        read: read.read,
                        entries,
                    }
                }
                Some(request) if held(DiaryReadHold::PendingReview) => {
                    DiaryReadOutcome::PendingReview { request }
                }
                Some(request) if held(DiaryReadHold::Declined) => {
                    DiaryReadOutcome::Declined { request }
                }
                _ => DiaryReadOutcome::NotCovered,
            })
        })
    }

    fn mask_diary_entries_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        entries: &mut [DiaryEntry],
    ) -> MemoryResult<()> {
        if !entries.is_empty() && self.reads_lifted_keys_masked_in_txn(txn)? {
            for entry in entries {
                let keys = LiftedKeys::of_in_txn(&self.vault.store, txn, [&entry.markdown])?;
                if let Some(markdown) = keys.masked(&entry.markdown) {
                    entry.markdown = markdown;
                }
            }
        }
        Ok(())
    }

    /// `self.memory.diary.review`: this agent's Y/N to a reader's reason.
    /// Only the diary's own agent answers; a spent yes stays spent.
    pub fn answer_diary_read(&self, input: &DiaryReviewAnswer) -> MemoryResult<DiaryReadRequest> {
        let request = EntityId::from_hex(&input.request)
            .map_err(|_| MemoryError::bad_request("request is not an entity id"))?;
        self.with_verified_actor_write_txn(|txn| {
            let key = (self.actor, request);
            let mut row = DIARY_READ_REQUEST
                .get(&self.vault.store, txn, &key)?
                .ok_or_else(|| MemoryError::not_found("no review request of this diary"))?;
            if row.state == DiaryReviewState::Used {
                return Err(MemoryError::bad_request(
                    "this yes already admitted its read",
                ));
            }
            row.state = if input.approve {
                DiaryReviewState::Approved
            } else {
                DiaryReviewState::Declined
            };
            row.answered_at = Some(self.vault.store.clock.now_recorded_at());
            DIARY_READ_REQUEST.put(&self.vault.store, txn, &key, &row)?;
            Ok(row)
        })
    }

    /// The owner sets whether `agent` reviews each read of its diary first.
    pub fn set_diary_read_review(
        &self,
        owner: &AuthenticatedOwner,
        agent: EntityId,
        on: bool,
    ) -> MemoryResult<()> {
        self.with_verified_actor_write_txn(|txn| {
            self.require_bound_owner_in_txn(txn, owner)?;
            DIARY_READ_REVIEW.put(&self.vault.store, txn, &agent, &DiaryReadReview(on))?;
            Ok(())
        })
    }

    /// The owner mints a `diary.read` Grant: `reader` reads `agent`'s whole
    /// diary, or only `entries` when any are named (each must be one of the
    /// agent's live diary entries).
    pub fn grant_diary_read(
        &self,
        owner: &AuthenticatedOwner,
        reader: WriteActor,
        agent: EntityId,
        entries: &[EntityId],
    ) -> MemoryResult<ConsentReceipt> {
        self.with_verified_actor_write_txn(|txn| {
            self.require_bound_owner_in_txn(txn, owner)?;
            verify_live_actor(self.vault, txn, reader)?;
            let bound = if entries.is_empty() {
                action_bound(self.vault, txn, reader, DIARY_READ_VERB, agent)?
            } else {
                for entry in entries {
                    let ours =
                        live_note_in_txn(self.vault, txn, entry)?.is_some_and(|(note, _)| {
                            note.kind == NoteKind::Diary && note.author_ref.is(agent)
                        });
                    if !ours {
                        return Err(MemoryError::bad_request(format!(
                            "{} is not a live diary entry of this agent",
                            entry.to_hex()
                        )));
                    }
                }
                GrantBound::action(
                    ActorBound::new(reader.entity_ref().to_hex())?
                        .with_actor_class(reader.actor_class().gate_actor_class())?,
                    ActionClass::new(DIARY_READ_VERB)?,
                    ActionEnvelope::new(entries.iter().map(EntityId::to_hex))?
                        .with_target(root_id(self.vault, txn)?)?,
                )?
            };
            Ok(self.vault.create_standing_grant_in_txn(txn, owner, bound)?)
        })
    }

    fn require_bound_owner_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &AuthenticatedOwner,
    ) -> Result<()> {
        if self.actor != verify_owner(self.vault, txn, owner)?
            || self.actor_class != EdgeActorClass::Human
        {
            return Err(authority_denied("owner proof must name the bound caller"));
        }
        Ok(())
    }

    /// The reader this caller is: a person with their authentication, or a
    /// live agent or system actor.
    fn diary_reader_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        proof: Option<&AuthenticatedOwner>,
    ) -> Result<WriteActor> {
        let actor = self.write_actor();
        match proof {
            Some(proof) => {
                if self.actor != proof.revalidate_person_in_txn(self.vault, txn)?
                    || self.actor_class != EdgeActorClass::Human
                {
                    return Err(authority_denied(
                        "diary-read authentication must name the bound human",
                    ));
                }
            }
            None if self.actor_class == EdgeActorClass::Human => {
                return Err(authority_denied(
                    "a person reads a diary with their authentication",
                ));
            }
            None => {}
        }
        verify_live_actor(self.vault, txn, actor)?;
        Ok(actor)
    }
}

impl Memory<'_> {
    /// Reads `agent`'s sealed scratchpads as this caller, stating `reason`, in
    /// ONE transaction (AGM-1+8, agent-mind §2.6). The ruled readers need no
    /// Grant: a live vault owner reads their agents' sealed pads, an Admin of
    /// a work vault reads its agents' through this same logged step (OF-490
    /// = B), and the Coach reads a work agent's, never a companion's. The
    /// read lands in the agent's read log beside its diary reads, recorded
    /// as the ruled reader it was admitted as, so the agent sees who read,
    /// as what and why, and the companion's owner sees an Admin's reads
    /// ([`Memory::admin_pad_reads`]). An agent that reviews reads answers the
    /// reason first. Any other reader is not covered: a health flag never
    /// grants access, and a personal vault has no Admin reader.
    pub fn read_agent_sealed_pads(
        &self,
        reader: Option<&AuthenticatedOwner>,
        agent: EntityId,
        reason: &str,
    ) -> MemoryResult<DiaryReadOutcome> {
        self.with_verified_actor_write_txn(|txn| {
            let actor = self.diary_reader_in_txn(txn, reader)?;
            let reason = DiaryReadGate::new(actor, reason)?.reason;
            let reader = actor.entity_ref();
            let human = actor.actor_class() == EdgeActorClass::Human;
            // The agent itself reads as no ruled reader and is not logged.
            let ruled = if reader == agent {
                None
            } else if human
                && crate::policy_model::is_live_vault_owner_in_txn(self.vault, txn, &reader)?
            {
                Some(SealedPadReader::Owner)
            } else if human && work_vault_admin_in_txn(self.vault, txn, reader)? {
                Some(SealedPadReader::Admin)
            } else if reader == crate::dreamer_runner::authority::coach_actor_id()?
                && coach_reads_pads_in_txn(self.vault, txn, &agent)?
            {
                Some(SealedPadReader::Coach)
            } else {
                return Ok(DiaryReadOutcome::NotCovered);
            };
            let review =
                reader != agent && agent_reviews_diary_reads_in_txn(self.vault, txn, &agent)?;
            let mut request = if review {
                standing_request_in_txn(self.vault, txn, agent, reader, &reason)?
            } else {
                None
            };
            let at = self.vault.store.clock.now_recorded_at();
            let reader_class = actor.actor_class().gate_actor_class();
            match request
                .as_ref()
                .map(|request| (request.state, request.request))
            {
                _ if !review => {}
                Some((DiaryReviewState::Approved, _)) => {}
                Some((DiaryReviewState::Declined, request)) => {
                    return Ok(DiaryReadOutcome::Declined { request });
                }
                Some((DiaryReviewState::Pending, request)) => {
                    return Ok(DiaryReadOutcome::PendingReview { request });
                }
                // A standing request is never a spent one.
                Some((DiaryReviewState::Used, _)) | None => {
                    let row = DiaryReadRequest {
                        request: self.vault.store.clock.entity_id()?,
                        reader,
                        reader_class: reader_class.to_owned(),
                        reason: reason.clone(),
                        asked_at: at,
                        state: DiaryReviewState::Pending,
                        answered_at: None,
                        read: None,
                        ruled_reader: ruled,
                    };
                    DIARY_READ_REQUEST.put(&self.vault.store, txn, &(agent, row.request), &row)?;
                    return Ok(DiaryReadOutcome::PendingReview {
                        request: row.request,
                    });
                }
            }
            let kind = NoteKind::Registered("scratchpad".to_owned());
            let mut entries = Vec::new();
            for pad in self.vault.sealed_scratchpads_in_txn(txn, agent)? {
                if let Some((note, learned_at)) = live_note_in_txn(self.vault, txn, &pad)?
                    && note.kind == kind
                    && note.author_ref.is(agent)
                {
                    entries.push(DiaryEntry {
                        id: pad,
                        learned_at,
                        markdown: note.markdown,
                    });
                }
            }
            self.mask_diary_entries_in_txn(txn, &mut entries)?;
            if reader == agent {
                return Ok(DiaryReadOutcome::Granted {
                    read: None,
                    entries,
                });
            }
            // Every read states its reason and is logged, an empty one too.
            let read = self.vault.store.clock.entity_id()?;
            let mut spent = None;
            if let Some(yes) = request.as_mut() {
                yes.state = DiaryReviewState::Used;
                yes.read = Some(read);
                DIARY_READ_REQUEST.put(&self.vault.store, txn, &(agent, yes.request), yes)?;
                spent = Some(yes.request);
            }
            DIARY_READ_LOG.put(
                &self.vault.store,
                txn,
                &(agent, read),
                &DiaryReadRecord {
                    read,
                    reader,
                    reader_class: reader_class.to_owned(),
                    reason,
                    at,
                    entries: entries.iter().map(|entry| entry.id).collect(),
                    grants: Vec::new(),
                    request: spent,
                    source: "pad".to_owned(),
                    ruled_reader: ruled,
                },
            )?;
            Ok(DiaryReadOutcome::Granted {
                read: Some(read),
                entries,
            })
        })
    }
}

impl Memory<'_> {
    /// The ruled readers of this agent's sealed scratchpads, as
    /// `read_agent_sealed_pads` admits them: a live vault owner, a work
    /// vault's Admins, and the Coach unless the agent is a companion.
    pub fn sealed_pad_readers(&self) -> MemoryResult<Vec<SealedPadReader>> {
        crate::memory::verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let admin = self.vault.vault_kind_in_txn(&txn)? == crate::agent_def::VaultKind::Work;
        let coach = coach_reads_pads_in_txn(self.vault, &txn, &self.actor)?;
        Ok(std::iter::once(SealedPadReader::Owner)
            .chain(admin.then_some(SealedPadReader::Admin))
            .chain(coach.then_some(SealedPadReader::Coach))
            .collect())
    }

    /// This agent's reader list. Its diary's readers are the actors that an
    /// active, owner-minted `diary.read` Grant admits, to the whole diary or
    /// to some of its entries, as [`DiaryReadGate`] admits them. Its sealed
    /// pads' readers are the ruled ones, as `read_agent_sealed_pads` admits
    /// them. An unrooted vault delegates no Grant, so its diary has none.
    pub fn diary_reader_list(&self) -> MemoryResult<DiaryReaderList> {
        let sealed_pads = self.sealed_pad_readers()?;
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let agent = self.actor;
        let Ok(root) = root_id(self.vault, &txn) else {
            return Ok(DiaryReaderList {
                diary: Vec::new(),
                sealed_pads,
            });
        };
        let entries = diary_entries_in_txn(self.vault, &txn, agent)?;
        let mut diary: BTreeMap<(String, Option<String>), DiaryReader> = BTreeMap::new();
        for grant in self.vault.active_standing_consent_grants_in_txn(&txn)? {
            let bound = grant.bound();
            let Some(actor) = bound.actor() else {
                continue;
            };
            let covers = |target: EntityId| -> Result<bool> {
                let mut subject = ActorBound::new(actor.actor_ref())?;
                if let Some(class) = actor.actor_class() {
                    subject = subject.with_actor_class(class)?;
                }
                let required = GrantBound::action(
                    subject,
                    ActionClass::new(DIARY_READ_VERB)?,
                    ActionEnvelope::new([target.to_hex()])?.with_target(root.clone())?,
                )?;
                Ok(bound.contains(&required))
            };
            let whole = covers(agent)?;
            let mut covered = 0;
            if !whole {
                for (entry, _, _) in &entries {
                    covered += usize::from(covers(*entry)?);
                }
                if covered == 0 {
                    continue;
                }
            }
            // As `delegated_grant` admits: only an active Grant the root
            // owner minted delegates.
            let Some(row) = self
                .vault
                .consent_grant_in_txn(&txn, &bound.digest().to_hex())?
            else {
                continue;
            };
            // A minter that no longer reads as a live owner delegates nothing:
            // the gate's own check refuses it too.
            if !row.is_active()
                || !is_root_owner(self.vault, &txn, row.owner_stamp.actor).unwrap_or(false)
            {
                continue;
            }
            let key = (
                actor.actor_ref().to_owned(),
                actor.actor_class().map(str::to_owned),
            );
            let reader = diary.entry(key).or_insert_with(|| DiaryReader {
                actor_ref: actor.actor_ref().to_owned(),
                actor_class: actor.actor_class().map(str::to_owned),
                whole: false,
                entries: 0,
            });
            reader.whole |= whole;
            reader.entries = reader.entries.max(covered);
        }
        Ok(DiaryReaderList {
            diary: diary.into_values().collect(),
            sealed_pads,
        })
    }
}
