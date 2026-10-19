//! The reads a code run bound to an off-record session serves through the
//! room's own view (WILL L11-01, S01-1): `vault.get`, `vault.hydrate`,
//! `vault.refs.resolve`, `vault.search.bm25` and the run's own
//! `vault.search`.
//!
//! Each call reads ONE view of the room ([`SessionReadContext`]), under the
//! narrow key the run's host admitted for its caller, never a wider one:
//! content is the room's overlay ∪ base, while grants, policy and the
//! caller's standing stay base. A row the room staged reads at the position
//! its write staged beside it; one whose position the room cannot prove has
//! no name for a key that reads only some worlds. Nothing here asks where a
//! caller or the vault runs: the key carries whatever the host's own judges
//! made of its caller, and the read applies it as every other read does.
//!
//! Neighbors, claim lists and history, hybrid search and recall are later
//! opt-ins: their enumeration still reads base. A hydrate that would serve an
//! image in a resolved form needs a served-form receipt the room does not
//! keep yet (S01-2), so it answers [`SessionAnswer::ServedFormUnrecorded`].

use std::cell::Cell;
use std::time::Instant;

use super::read_lane::ReadTargetSlot;
use super::structural::kind_string_for_type;
use super::support::short_ref_in_txn;
use super::{
    EntityView, LexicalHit, MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult, caps,
    resolve_entity_ref,
};

use crate::claim::{ClaimReadStatus, PointRead, ScopedRead, ScopedReadActorKey, ScopedReadResult};
use crate::entity_id::EntityId;
use crate::lens::{RecordRefPreview, ResolveRecordRefRequest};
use crate::off_record::{OffRecordSession, SessionWriteRoute};
use crate::pipeline::ScoredEntity;
use crate::store::SessionStoreView;
use crate::task_verb::sdk::{EntityRequest, HydrateRequest, QueryBm25Request};
use crate::vault::{ReadMode, RevisionRef};
use crate::{Vault, WriteActor};

/// One read a run bound to a room serves through the room's view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionRead {
    /// `vault.get`.
    Get,
    /// `vault.hydrate`.
    Hydrate,
    /// `vault.refs.resolve`.
    RefsResolve,
    /// `vault.search.bm25`.
    SearchBm25,
}

/// What one read in the room answers.
pub(crate) enum SessionAnswer {
    /// The read's answer, encoded as its verb's row encodes it, and the rows
    /// it served, for the run's release rule.
    Answered {
        output: serde_json::Value,
        rows: Vec<EntityId>,
    },
    /// A hydrate that would serve an image in a resolved form. That form's
    /// served-form receipt has no home in the room yet, so the read gives no
    /// answer rather than one without its receipt.
    ServedFormUnrecorded,
}

/// One call's read of a room: the room, the run's captured route, the
/// narrow key the run's host admitted for its caller, and ONE view of the
/// room that every step of the call reads, so a call never sees a torn
/// overlay-base union.
pub(crate) struct SessionReadContext<'s> {
    vault: &'s Vault,
    session: &'s OffRecordSession<'s>,
    route: &'s SessionWriteRoute,
    key: ScopedReadActorKey,
    view: SessionStoreView<'s>,
}

impl<'s> SessionReadContext<'s> {
    /// The read of `session` in `vault` under `key`, through `route`, over a
    /// view of the room taken now.
    ///
    /// # Errors
    ///
    /// The view's own refusal.
    pub(crate) fn new(
        vault: &'s Vault,
        session: &'s OffRecordSession<'s>,
        route: &'s SessionWriteRoute,
        key: ScopedReadActorKey,
    ) -> crate::Result<Self> {
        Ok(Self {
            vault,
            session,
            route,
            key,
            view: session.read_view()?,
        })
    }

    /// `read` of `input`, the verb's own typed input, for `actor`, the run's
    /// actor, whose handle projects each admitted row as the verb's other
    /// doors project it. Each read keeps its verb's contract: the same caps,
    /// the same claim statuses, the same answer and the same refusals.
    ///
    /// # Errors
    ///
    /// The verb's own refusals: a bad input, a ref that resolves to nothing
    /// this key reads, a room that flipped or closed.
    pub(crate) fn answer(
        &self,
        read: SessionRead,
        actor: WriteActor,
        input: &serde_json::Value,
    ) -> MemoryResult<SessionAnswer> {
        let memory = self.vault.memory(actor.entity_ref(), actor.actor_class());
        let (output, rows) = match read {
            SessionRead::Get => {
                let input: EntityRequest = decode(input)?;
                let (read, _) = self.get(&memory, &input.entity_ref)?;
                let rows = read.value.iter().filter_map(view_id).collect();
                (encode(&read)?, rows)
            }
            SessionRead::Hydrate => {
                let input: HydrateRequest = decode(input)?;
                caps::check_batch_len("refs", input.refs.len())?;
                let Some(read) = self.hydrate(&memory, &input.refs)? else {
                    return Ok(SessionAnswer::ServedFormUnrecorded);
                };
                let rows = read.value.iter().filter_map(view_id).collect();
                (encode(&read)?, rows)
            }
            SessionRead::RefsResolve => {
                let input: ResolveRecordRefRequest = decode(input)?;
                let read = self.resolve_record_ref(&memory, &input)?;
                let rows = EntityId::from_hex(&read.value.record.id)
                    .ok()
                    .into_iter()
                    .collect();
                (encode(&read)?, rows)
            }
            SessionRead::SearchBm25 => {
                let input: QueryBm25Request = decode(input)?;
                caps::check_query(&input.query)?;
                caps::check_limit_nonzero(input.limit)?;
                let read = self.query_bm25(&memory, &input.query, input.limit)?;
                let rows = read
                    .value
                    .iter()
                    .filter_map(|hit| hit.record.as_ref())
                    .filter_map(|record| EntityId::from_hex(&record.id).ok())
                    .collect();
                (encode(&read)?, rows)
            }
        };
        Ok(SessionAnswer::Answered { output, rows })
    }

    /// The run's own `vault.search` in the room, on the key's surfaceable
    /// lane: each posting admitted inside the scan, and every hit admitted
    /// again before it is released, as a canonical run's narrowed search is.
    ///
    /// # Errors
    ///
    /// The route's refusal once the room flipped or closed; storage errors.
    pub(crate) fn search_text(
        &self,
        query: &str,
        limit: usize,
    ) -> crate::Result<Vec<ScoredEntity>> {
        let lane = self.lane(ClaimReadStatus::Surfaceable);
        let hits = self
            .session
            .search_text_scoped_routed(self.route, &self.view, &lane, query, limit)?;
        Ok(lane.filter_scored_entities(hits)?.value)
    }

    /// The key's lane over this call's view, serving `claims`.
    fn lane(&self, claims: ClaimReadStatus) -> ScopedRead<'_> {
        self.vault
            .scoped_read_in_session(self.key.clone(), &self.view)
            .with_claim_status(claims)
    }

    /// `vault.get` in the room, on the Recorded lane (every claim status, as
    /// `Memory::get_entity` reads), with the view's live revision read in
    /// the same snapshot, for `vault.refs.resolve` to name.
    fn get(
        &self,
        memory: &Memory<'_>,
        reference: &str,
    ) -> MemoryResult<(ScopedReadResult<Option<EntityView>>, Option<String>)> {
        let lane = self.lane(ClaimReadStatus::Recorded);
        let target = self.target(reference)?;
        let reads: Vec<_> = target
            .iter()
            .map(|(id, mode)| PointRead::id(*id).at(*mode))
            .collect();
        let read = lane.read_projected(&reads, None, |txn, rows| {
            let (Some((id, mode)), Some(row)) = (target, rows.into_iter().next().flatten()) else {
                return Ok::<_, MemoryError>((None, None));
            };
            let view = memory.entity_view_of_in_txn(&lane, txn, row, mode)?;
            let live = crate::vault::entity_revision::revision_for_mode_in_txn(
                &lane.store_read(),
                txn,
                &id,
                ReadMode::Live,
            )?;
            Ok((view, live.map(RevisionRef::to_hex)))
        })?;
        let (view, live) = read.value;
        Ok((
            ScopedReadResult {
                value: view,
                receipt: read.receipt,
            },
            live,
        ))
    }

    /// `vault.hydrate` in the room: every ref resolved and read in one
    /// snapshot, a ref that reads nothing `NOT_FOUND` under the read's
    /// receipt, as `Memory::hydrate` answers. `None` when a view is an image
    /// ASSET the hydrate would serve in a resolved form.
    fn hydrate(
        &self,
        memory: &Memory<'_>,
        refs: &[String],
    ) -> MemoryResult<Option<ScopedReadResult<Vec<EntityView>>>> {
        let lane = self.lane(ClaimReadStatus::Recorded);
        let targets = refs
            .iter()
            .map(|reference| self.target(reference))
            .collect::<MemoryResult<Vec<_>>>()?;
        let ScopedReadResult { value, receipt } = memory.read_views(&lane, &targets)?;
        let mut views = Vec::with_capacity(value.len());
        for (reference, view) in refs.iter().zip(value) {
            let Some(view) = view else {
                return Err(MemoryError::not_found(format!(
                    "entity {reference:?} does not resolve"
                ))
                .with_read_receipt(receipt));
            };
            views.push(view);
        }
        let asset = kind_string_for_type(crate::registry::ENTITY_TYPE_ASSET);
        for (target, view) in targets.iter().zip(&views) {
            if let Some((id, ReadMode::Live)) = target
                && view.kind == asset
                && super::asset_image_in_lane(&lane, *id)?.is_some()
            {
                return Ok(None);
            }
        }
        Ok(Some(ScopedReadResult {
            value: views,
            receipt,
        }))
    }

    /// `vault.refs.resolve` in the room: the same bounded preview and the
    /// same one refusal, the view and its live revision read together.
    fn resolve_record_ref(
        &self,
        memory: &Memory<'_>,
        input: &ResolveRecordRefRequest,
    ) -> MemoryResult<ScopedReadResult<RecordRefPreview>> {
        let live = Cell::new(None);
        memory.record_ref_preview(
            input,
            |reference| {
                let (read, revision) = self.get(memory, reference)?;
                live.set(revision);
                Ok(read)
            },
            |_| Ok(live.take()),
        )
    }

    /// `vault.search.bm25` in the room, on the key's surfaceable lane: the
    /// room's scoped search, then the hits read, ranked and named as
    /// `Memory::query_bm25` answers, each by the room's short ref for it.
    fn query_bm25(
        &self,
        memory: &Memory<'_>,
        query: &str,
        limit: usize,
    ) -> MemoryResult<ScopedReadResult<Vec<LexicalHit>>> {
        let lane = self.lane(ClaimReadStatus::Surfaceable);
        let hits = self
            .session
            .search_text_scoped_routed(self.route, &self.view, &lane, query, limit)?;
        let hits = lane.filter_scored_entities(hits)?;
        memory.lexical_hits(&lane, hits, |id| self.short_ref(id))
    }

    /// The short ref this call's view names `id` by: the room's alias for a
    /// row it staged, else the vault's.
    fn short_ref(&self, id: &EntityId) -> MemoryResult<Option<String>> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(|error| MemoryError::from(crate::Error::from(error)))?;
        short_ref_in_txn(&self.view.read(), &txn, id)
    }

    /// The entity `reference` names in the room, at the frontier it names:
    /// a 32-hex id, the room's own short ref (`s<n>:<hash>`) or the vault's,
    /// each optionally pinned as `<ref>@<revision>`. `None` is a ref that
    /// names nothing here, never a withheld row: admission is the lane's.
    fn target(&self, reference: &str) -> MemoryResult<ReadTargetSlot> {
        let (reference, mode) = match reference.rsplit_once('@') {
            Some((reference, revision)) => (
                reference.trim(),
                ReadMode::Pinned(RevisionRef::from_hex(revision)?),
            ),
            None => (reference.trim(), ReadMode::Live),
        };
        if let Some((alias, hash)) = room_short_ref(reference) {
            // A room's alias names its row's live body: a pin of one names
            // no revision the room can check.
            if mode != ReadMode::Live {
                return Ok(None);
            }
            return Ok(self.room_alias(alias, hash)?.map(|id| (id, mode)));
        }
        let id = match mode {
            // A pinned vault ref resolves against its pin, as on base; a
            // pinned id is checked by the lane's read of that revision.
            ReadMode::Pinned(revision) if !is_hex_id(reference) => self
                .vault
                .resolve_pinned_entity_reference(reference, revision)?,
            _ => match resolve_entity_ref(self.vault, reference) {
                Ok(id) => Some(id),
                Err(error) if error.code == MEMORY_CODE_NOT_FOUND => None,
                Err(error) => return Err(error),
            },
        };
        Ok(id.map(|id| (id, mode)))
    }

    /// The row a room write names as its subject (WILL L11-01, S01-2a): the
    /// room's own alias for a row it staged, in this call's view of the
    /// room, else what the ref names as the vault resolves it, with the
    /// vault's refusals. Nothing is read on the key's lane here: whether the
    /// row stands is the write's own check, in the transaction that stages
    /// it.
    pub(crate) fn write_subject(&self, reference: &str) -> MemoryResult<EntityId> {
        if let Some((alias, hash)) = room_short_ref(reference.trim())
            && let Some(id) = self.room_alias(alias, hash)?
        {
            return Ok(id);
        }
        resolve_entity_ref(self.vault, reference)
    }

    /// The row the room's alias `alias` names at content hash `hash`, in this
    /// call's view of the room.
    fn room_alias(&self, alias: &str, hash: u8) -> MemoryResult<Option<EntityId>> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(|error| MemoryError::from(crate::Error::from(error)))?;
        let mut key = alias.as_bytes().to_vec();
        key.push(hash);
        let Some(raw) = self.view.short_ids.get(&txn, &key)? else {
            return Ok(None);
        };
        Ok(<[u8; 16]>::try_from(&raw[..])
            .ok()
            .and_then(|bytes| EntityId::from_bytes(bytes).ok()))
    }
}

/// One BM25 search of `view`, a room's view, on `lane`, a narrow key's lane
/// over it (WILL L11-01): every posting is admitted on the lane inside the
/// scan, through the index's own filtered port, so a row the key cannot read
/// takes no place in the ranking; `admit` refuses the scan's snapshot once
/// the run's participant is gone. Answers the scores and when the search
/// started, for its run's telemetry row.
///
/// # Errors
///
/// `admit`'s refusal; the lane's authority errors; storage errors.
pub(crate) fn scoped_session_text(
    vault: &Vault,
    view: &SessionStoreView<'_>,
    lane: &ScopedRead<'_>,
    query: &str,
    limit: usize,
    admit: impl FnOnce(&heed::RoTxn<'_>) -> crate::Result<()>,
) -> crate::Result<(Vec<ScoredEntity>, (u64, Instant))> {
    let config = crate::config::Bm25RankProfile::default().to_bm25_config()?;
    let (filter, policy) = lane.recall_plan()?;
    let started = (vault.store.clock.now_recorded_at(), Instant::now());
    if filter.deny_all {
        lane.end_recall_plan()?;
        return Ok((Vec::new(), started));
    }
    lane.persist_grant_clock()?;
    let scores = {
        let txn = vault.store.env.read_txn()?;
        admit(&txn)?;
        let mut admits = |id: &EntityId| lane.recall_candidate_in(&txn, &policy, &filter, id);
        vault.text_scoped_in_txn(
            view,
            &txn,
            crate::ports::TextQuery {
                query,
                limit,
                rank: &config,
                filter_all: true,
                matches_scope: &mut admits,
                private_note_ids: None,
            },
        )
    };
    lane.end_recall_plan()?;
    Ok((scores?, started))
}

/// A room's own short ref, `s<n>:<hash>`: the alias a room mints for each
/// row it stages (`SessionOverlay::alloc_session_short_id`), outside the
/// vault's grammar, so neither names the other's row.
fn room_short_ref(reference: &str) -> Option<(&str, u8)> {
    let (alias, hash) = reference.split_once(':')?;
    let ordinal = alias.strip_prefix('s')?;
    if ordinal.is_empty()
        || !ordinal.bytes().all(|byte| byte.is_ascii_digit())
        || hash.len() != 2
        || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    u8::from_str_radix(hash, 16).ok().map(|hash| (alias, hash))
}

fn is_hex_id(reference: &str) -> bool {
    reference.len() == 32 && reference.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn view_id(view: &EntityView) -> Option<EntityId> {
    EntityId::from_hex(&view.id_hex).ok()
}

fn decode<T: serde::de::DeserializeOwned>(value: &serde_json::Value) -> MemoryResult<T> {
    serde_path_to_error::deserialize(value.clone())
        .map_err(|error| MemoryError::bad_request(format!("invalid SDK request: {error}")))
}

fn encode(value: &impl serde::Serialize) -> MemoryResult<serde_json::Value> {
    serde_json::to_value(value).map_err(|_| MemoryError::bad_request("SDK result encoding failed"))
}
