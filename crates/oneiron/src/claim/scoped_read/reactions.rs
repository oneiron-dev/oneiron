//! Reactions riding along with the conversation records a scoped read admits.
use super::*;
use crate::context_pack::{ComposedFieldProducers, ContextPack};
use crate::disclosure::DisclosureContext;
use crate::reaction::{REACTIONS_FIELD, ReactionPill, ReactionSignal};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use std::collections::{BTreeMap, HashMap};

impl ScopedRead<'_> {
    /// The current reactions on one conversation record this read may see,
    /// one grouped line per glyph (`👍×8 (Anna, Ben, +6)`), first put first,
    /// with the receipt of the read that admitted them (FIX 8669).
    pub fn reaction_lines(&self, record: &EntityId) -> Result<ScopedReadResult<Vec<String>>> {
        self.reaction_lines_counting(record, &mut Vec::new())
    }

    /// [`Self::reaction_lines`], adding to `counted` each reaction claim its
    /// lines count.
    pub(crate) fn reaction_lines_counting(
        &self,
        record: &EntityId,
        counted: &mut Vec<EntityId>,
    ) -> Result<ScopedReadResult<Vec<String>>> {
        let rtxn = self.grant_read_txn()?;
        let (policy, receipt) = self.reaction_walk_in(&rtxn)?;
        let value =
            self.reaction_lines_in(&rtxn, &policy, None, record, counted, &mut Vec::new())?;
        Ok(ScopedReadResult { value, receipt })
    }

    /// The policy a reaction walk judges its rows under in `rtxn`, and the
    /// receipt of that walk (FIX 8669). The walk asks for no narrowing and
    /// judges each row under the key's own ceiling, the scope the receipt
    /// names as applied, so every row it withholds is the key's own denial
    /// and stays opaque (FIX 8670): the receipt counts none. A disclosure
    /// clamp narrows the audience, not the read, so a row it keeps out adds
    /// no count either. A key whose credential is no longer live refuses
    /// here, as every receipted read does, rather than answer under a scope
    /// it cannot read.
    fn reaction_walk_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
    ) -> Result<(PolicyManifestResolution, ScopedReadReceipt)> {
        let (applied, policy) = self.resolve_retrieval_filter_in(rtxn, None)?;
        let receipt = self.receipt_for(None, &policy, &applied, 0);
        Ok((policy, receipt))
    }

    fn reaction_lines_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        disclosure: Option<&DisclosureContext>,
        record: &EntityId,
        counted: &mut Vec<EntityId>,
        named: &mut Vec<EntityId>,
    ) -> Result<Vec<String>> {
        crate::reaction::grouped_lines_in(self.vault, rtxn, *record, named, |row| {
            let admitted = self.is_entity_readable_with_policy_in(rtxn, policy, &row.id)?
                && self.disclosed_in(rtxn, disclosure, &row.id)?;
            if admitted {
                counted.push(row.id);
            }
            Ok(admitted)
        })
    }

    /// Whether `disclosure`, when the read runs under one, admits the stored
    /// row `id`. A row that is gone, or a claim that does not decode, is not.
    fn disclosed_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        disclosure: Option<&DisclosureContext>,
        id: &EntityId,
    ) -> Result<bool> {
        let Some(disclosure) = disclosure else {
            return Ok(true);
        };
        let Some(row) = self.entity_record_in(rtxn, id)? else {
            return Ok(false);
        };
        let claim = if row.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
            match crate::claim::decode_claim_body(&row.body, true) {
                Ok(claim) => Some(claim),
                Err(_) => return Ok(false),
            }
        } else {
            None
        };
        disclosure.admits(&self.vault.store, rtxn, id, row.entity_type, claim.as_ref())
    }

    /// Attaches each hydrated MESSAGE or TURN result's grouped reaction lines
    /// under [`REACTIONS_FIELD`]. Run after the pack's own scope filter, and
    /// fold the returned receipt of the read that admitted the lines into
    /// the pack's own (FIX 8669).
    pub fn attach_reactions(&self, pack: &mut ContextPack) -> Result<ScopedReadReceipt> {
        self.attach_reactions_under(pack, None)
    }

    /// [`Self::attach_reactions`] for a pack assembled under `disclosure`:
    /// a line counts only the reactions the clamp admits as well.
    pub fn attach_reactions_under(
        &self,
        pack: &mut ContextPack,
        disclosure: Option<&DisclosureContext>,
    ) -> Result<ScopedReadReceipt> {
        self.attach_reactions_quoting(pack, &HashMap::new(), disclosure, &mut Vec::new())
    }

    /// [`Self::attach_reactions_under`], which also records in `producers`
    /// the rows each record's attached lines are read from (FIX 1435): the
    /// reaction claims the lines count and the reactors they name. They come
    /// from the same walk that writes the lines. A record that gets no lines
    /// records none. The receipt is the same.
    pub fn attach_reactions_listing_producers(
        &self,
        pack: &mut ContextPack,
        disclosure: Option<&DisclosureContext>,
        producers: &mut ComposedFieldProducers,
    ) -> Result<ScopedReadReceipt> {
        self.attach_reactions_walk(
            pack,
            &HashMap::new(),
            disclosure,
            |record, counted, named, attached| {
                if attached {
                    producers.record_reaction_lines(record, counted.into_iter().chain(named));
                }
            },
        )
    }

    /// [`Self::attach_reactions_under`] for a pack whose TURNs took the place
    /// of matched messages (`quoted`, per TURN): a TURN's lines are followed
    /// by those of each message it quotes that this read may see. Each
    /// reaction claim a line counts is added to `counted`. Every line of the
    /// pack is read in one snapshot, under the one receipt returned.
    pub(crate) fn attach_reactions_quoting(
        &self,
        pack: &mut ContextPack,
        quoted: &HashMap<EntityId, Vec<EntityId>>,
        disclosure: Option<&DisclosureContext>,
        counted: &mut Vec<EntityId>,
    ) -> Result<ScopedReadReceipt> {
        self.attach_reactions_walk(pack, quoted, disclosure, |_, claims, _, _| {
            counted.extend(claims);
        })
    }

    /// The one walk behind [`Self::attach_reactions_quoting`] and
    /// [`Self::attach_reactions_listing_producers`]. For each MESSAGE or TURN
    /// result, `walked` gets the record, the reaction claims its lines count,
    /// the reactors they name, and whether the lines were attached.
    fn attach_reactions_walk(
        &self,
        pack: &mut ContextPack,
        quoted: &HashMap<EntityId, Vec<EntityId>>,
        disclosure: Option<&DisclosureContext>,
        mut walked: impl FnMut(EntityId, Vec<EntityId>, Vec<EntityId>, bool),
    ) -> Result<ScopedReadReceipt> {
        let rtxn = self.grant_read_txn()?;
        let (policy, receipt) = self.reaction_walk_in(&rtxn)?;
        for entity in &mut pack.results {
            if !matches!(entity.entity_type, ENTITY_TYPE_MESSAGE | ENTITY_TYPE_TURN) {
                continue;
            }
            let (mut counted, mut named) = (Vec::new(), Vec::new());
            let mut lines = self.reaction_lines_in(
                &rtxn,
                &policy,
                disclosure,
                &entity.id,
                &mut counted,
                &mut named,
            )?;
            for message in quoted.get(&entity.id).into_iter().flatten() {
                if self.is_entity_readable_with_policy_in(&rtxn, &policy, message)?
                    && self.disclosed_in(&rtxn, disclosure, message)?
                {
                    lines.extend(self.reaction_lines_in(
                        &rtxn,
                        &policy,
                        disclosure,
                        message,
                        &mut counted,
                        &mut named,
                    )?);
                }
            }
            let attached = match (entity.fields.as_mut(), lines.is_empty()) {
                (Some(fields), false) => {
                    fields.insert(REACTIONS_FIELD.to_owned(), serde_json::json!(lines));
                    true
                }
                _ => false,
            };
            walked(entity.id, counted, named, attached);
        }
        Ok(receipt)
    }

    /// [`crate::Vault::reaction_pills`] under this read, in one snapshot: only
    /// messages this read reads get pills, and a pill counts only the
    /// reactions it reads, each under its whole admission. The pills come
    /// with the receipt of that read (FIX 8669). Like every read on this
    /// lane, an owner lane refuses once its binding is gone.
    pub fn reaction_pills(
        &self,
        messages: &[EntityId],
        viewer: EntityId,
    ) -> Result<ScopedReadResult<BTreeMap<EntityId, Vec<ReactionPill>>>> {
        let rtxn = self.grant_read_txn()?;
        let (policy, receipt) = self.reaction_walk_in(&rtxn)?;
        let mut readable = Vec::with_capacity(messages.len());
        for message in messages {
            if self.is_entity_readable_with_policy_in(&rtxn, &policy, message)? {
                readable.push(*message);
            }
        }
        let value = self
            .vault
            .reaction_pills_in(&rtxn, &readable, viewer, |row| {
                self.is_entity_readable_with_policy_in(&rtxn, &policy, &row.id)
            })?;
        Ok(ScopedReadResult { value, receipt })
    }

    /// Whether this read may see a reaction signal: the reacted record and
    /// the reaction CLAIM are both readable here, each under the read's whole
    /// admission (its credential's records and Scope, relationship grants,
    /// audience). The reaction is judged at every claim status, so a removal
    /// reaches a reader who may read the put it removed.
    pub fn is_reaction_signal_readable(&self, signal: &ReactionSignal) -> Result<bool> {
        self.is_reaction_signal_readable_under(signal, None)
    }

    /// [`Self::is_reaction_signal_readable`] for a read under `disclosure`:
    /// the clamp must admit the reacted record and the reaction as well.
    pub fn is_reaction_signal_readable_under(
        &self,
        signal: &ReactionSignal,
        disclosure: Option<&DisclosureContext>,
    ) -> Result<bool> {
        let rtxn = self.grant_read_txn()?;
        let policy = self.live_policy_manifest_in(&rtxn)?;
        Ok(
            self.is_entity_readable_with_policy_in(&rtxn, &policy, &signal.message)?
                && self
                    .at_every_claim_status()?
                    .is_entity_readable_with_policy_in(&rtxn, &policy, &signal.reaction)?
                && self.disclosed_in(&rtxn, disclosure, &signal.message)?
                && self.disclosed_in(&rtxn, disclosure, &signal.reaction)?,
        )
    }
}

impl<'a> ScopedRead<'a> {
    /// This read admitting claims of every status, and otherwise the same:
    /// its key, audience, peers, room ceiling and session view.
    fn at_every_claim_status(&self) -> Result<ScopedRead<'a>> {
        let room_ceiling = self
            .room_ceiling
            .lock()
            .map_err(|_| Error::InvariantViolation("room ceiling lock"))?
            .clone();
        Ok(ScopedRead {
            vault: self.vault,
            actor_key: self.actor_key.clone(),
            audience: self.audience.clone(),
            peer_reads: self.peer_reads.clone(),
            audience_cache: Mutex::new(Default::default()),
            room_ceiling: Mutex::new(room_ceiling),
            room_ceilings_built: AtomicUsize::new(0),
            session_view: self.session_view,
            claim_status: ClaimReadStatus::Recorded,
            recall_authority: Mutex::new(None),
            room_peer: self.room_peer,
            own_owner_authority: self.own_owner_authority,
            records_cover: self.records_cover.clone(),
            judged_at: self.judged_at,
        })
    }
}
