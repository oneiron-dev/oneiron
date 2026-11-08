//! Reactions riding along with the conversation records a scoped read admits.
use super::access_gate::HeldAuthority;
use super::*;
use crate::context_pack::ContextPack;
use crate::disclosure::DisclosureContext;
use crate::reaction::{REACTIONS_FIELD, ReactionPill, ReactionSignal};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use std::collections::{BTreeMap, HashMap};

/// What one read admits a conversation record's reactions under, in one
/// snapshot: the lane's own resolved request (its bound caller filter met
/// with the floor), the held authority its rows share, and the disclosure
/// clamp the read runs under, if any (FIX 3977), and the receipt of the
/// walk (FIX 8669).
struct ReactionAdmission<'d> {
    policy: PolicyManifestResolution,
    filter: ResolvedRetrievalFilter,
    authority: HeldAuthority,
    disclosure: Option<&'d DisclosureContext>,
    receipt: ScopedReadReceipt,
}

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
        let admission = self.reaction_admission_in(&rtxn, None)?;
        let value = self.reaction_lines_in(&rtxn, &admission, record, counted)?;
        Ok(ScopedReadResult {
            value,
            receipt: admission.receipt,
        })
    }

    /// The admission this lane's reactions take in `rtxn`: the lane's own
    /// request, resolved as a door that names none resolves it (its bound
    /// caller filter met with the floor), so a reaction CLAIM meets the check
    /// a claim this lane reads directly meets (FIX 3977), and the receipt of
    /// that walk (FIX 8669). The walk asks for no narrowing of its own and
    /// judges each row under the scope the receipt names as applied, so every
    /// row it withholds is the key's own denial or the caller's own filter
    /// and stays opaque (FIX 8670): the receipt counts none. A disclosure
    /// clamp narrows the audience, not the read, so a row it keeps out adds
    /// no count either. A key whose credential is no longer live refuses
    /// here, as every receipted read does, rather than answer under a scope
    /// it cannot read.
    fn reaction_admission_in<'d>(
        &self,
        rtxn: &heed::RoTxn<'_>,
        disclosure: Option<&'d DisclosureContext>,
    ) -> Result<ReactionAdmission<'d>> {
        let (filter, policy) = self.resolve_retrieval_filter_in(rtxn, None)?;
        let receipt = self.receipt_for(None, &policy, &filter, 0);
        Ok(ReactionAdmission {
            policy,
            filter,
            authority: self.held_for(None),
            disclosure,
            receipt,
        })
    }

    /// Whether this lane reads the row `id` under `admission`: the row
    /// admission under the lane's resolved request, then the clamp.
    fn row_admitted_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        admission: &ReactionAdmission<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        Ok(self.is_entity_readable_held_in(
            rtxn,
            &admission.policy,
            id,
            &admission.filter,
            &admission.authority,
        )? && self.disclosed_in(rtxn, admission.disclosure, id)?)
    }

    fn reaction_lines_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        admission: &ReactionAdmission<'_>,
        record: &EntityId,
        counted: &mut Vec<EntityId>,
    ) -> Result<Vec<String>> {
        crate::reaction::grouped_lines_in(self.vault, rtxn, *record, |row| {
            let admitted = self.row_admitted_in(rtxn, admission, &row.id)?;
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
        let rtxn = self.grant_read_txn()?;
        // One snapshot, one resolved request and one held authority for
        // every record's reactions (FIX 3977), under one receipt (FIX 8669).
        let admission = self.reaction_admission_in(&rtxn, disclosure)?;
        for entity in &mut pack.results {
            if !matches!(entity.entity_type, ENTITY_TYPE_MESSAGE | ENTITY_TYPE_TURN) {
                continue;
            }
            let mut lines = self.reaction_lines_in(&rtxn, &admission, &entity.id, counted)?;
            for message in quoted.get(&entity.id).into_iter().flatten() {
                if self.row_admitted_in(&rtxn, &admission, message)? {
                    lines.extend(self.reaction_lines_in(&rtxn, &admission, message, counted)?);
                }
            }
            if let (Some(fields), false) = (entity.fields.as_mut(), lines.is_empty()) {
                fields.insert(REACTIONS_FIELD.to_owned(), serde_json::json!(lines));
            }
        }
        Ok(admission.receipt)
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
        // The lane's own resolved request, as its recall reactions take it
        // (FIX 3977).
        let admission = self.reaction_admission_in(&rtxn, None)?;
        let mut readable = Vec::with_capacity(messages.len());
        for message in messages {
            if self.row_admitted_in(&rtxn, &admission, message)? {
                readable.push(*message);
            }
        }
        let value = self
            .vault
            .reaction_pills_in(&rtxn, &readable, viewer, |row| {
                self.row_admitted_in(&rtxn, &admission, &row.id)
            })?;
        Ok(ScopedReadResult {
            value,
            receipt: admission.receipt,
        })
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
        // Each side under its lane's own resolved request (FIX 3977): the
        // record on this lane, the reaction on its every-status twin, which
        // keeps the same bound caller filter.
        let every_status = self.at_every_claim_status()?;
        let record = self.reaction_admission_in(&rtxn, disclosure)?;
        let reaction = every_status.reaction_admission_in(&rtxn, disclosure)?;
        Ok(self.row_admitted_in(&rtxn, &record, &signal.message)?
            && every_status.row_admitted_in(&rtxn, &reaction, &signal.reaction)?)
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
            read_filter: self.read_filter.clone(),
        })
    }
}
