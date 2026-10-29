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
//! opt-ins: their enumeration still reads base. A hydrate that serves an image
//! in a resolved form keeps each form's served-form receipt in the room before
//! it answers, as a canonical hydrate keeps it in the vault (S01-2b).

use std::cell::Cell;
use std::time::Instant;

use super::asset_resolve::serve_hydrated_views;
use super::read_lane::ReadTargetSlot;
use super::support::short_ref_in_txn;
use super::{
    EntityView, LexicalHit, MEMORY_CODE_INTERNAL, MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND,
    Memory, MemoryError, MemoryResult, caps, resolve_entity_ref,
};

use crate::claim::{ClaimReadStatus, PointRead, ScopedRead, ScopedReadActorKey, ScopedReadResult};
use crate::entity_id::EntityId;
use crate::lens::{RecordRefPreview, ResolveRecordRefRequest};
use crate::off_record::{OffRecordSession, SessionWriteRoute};
use crate::pipeline::ScoredEntity;
use crate::receipt::ServedForm;
use crate::session_overlay::RouteTarget;
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
                let read = self.hydrate(&memory, &input.refs)?;
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

    /// The run's own `vault.search` in the room, on the key's lane serving
    /// `claims`: each posting admitted inside the scan, and every hit
    /// admitted again before it is released, as a canonical run's narrowed
    /// search is.
    ///
    /// # Errors
    ///
    /// The route's refusal once the room flipped or closed; storage errors.
    pub(crate) fn search_text(
        &self,
        query: &str,
        limit: usize,
        claims: ClaimReadStatus,
    ) -> crate::Result<Vec<ScoredEntity>> {
        let lane = self.lane(claims);
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
    /// receipt, as `Memory::hydrate` answers. A live image ASSET is served in
    /// its resolved form, as a canonical hydrate serves it (OF-329), each
    /// form served first kept in the room ([`Self::keep_served_forms`]).
    fn hydrate(
        &self,
        memory: &Memory<'_>,
        refs: &[String],
    ) -> MemoryResult<ScopedReadResult<Vec<EntityView>>> {
        let lane = self.lane(ClaimReadStatus::Recorded);
        let targets = refs
            .iter()
            .map(|reference| self.target(reference))
            .collect::<MemoryResult<Vec<_>>>()?;
        let ScopedReadResult { value, mut receipt } = memory.read_views(&lane, &targets)?;
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
        let forms = serve_hydrated_views(&lane, &targets, &mut views, &mut receipt)?;
        self.keep_served_forms(&lane, &forms)?;
        Ok(ScopedReadResult {
            value: views,
            receipt,
        })
    }

    /// Keeps `forms`, the forms this call's hydrate served on `lane`, in the
    /// room before the hydrate answers (WILL L11-01 S01-2b): each one a
    /// served-form receipt staged on the run's captured route
    /// ([`ScopedRead::commit_served_forms_in_room`]). A hydrate that served no
    /// form keeps, allocates and checks nothing, and answers as it did. A
    /// room back on record lands its route in base, where nothing proves
    /// the forms' evidence, so that hydrate refuses ([`served_forms_on_base`])
    /// rather than answer without its receipts.
    ///
    /// # Errors
    ///
    /// The route's own refusal once the room flipped, closed or keeps no
    /// record; [`served_forms_on_base`]; the holder's refusal; the room's
    /// budget refusal; storage errors.
    fn keep_served_forms(&self, lane: &ScopedRead<'_>, forms: &[ServedForm]) -> MemoryResult<()> {
        if forms.is_empty() {
            return Ok(());
        }
        self.route.revalidate()?;
        if self.route.target() == RouteTarget::Base {
            return Err(served_forms_on_base());
        }
        lane.commit_served_forms_in_room(self.session, self.route, forms)?;
        Ok(())
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
        let revisions = self.indexed_revisions(&hits.value)?;
        memory.lexical_hits(&lane, hits, &revisions, |id| self.short_ref(id))
    }

    /// The revision the room's text index holds for each hit, read through
    /// the room's view, which pins its staged rows as base pins its own: the
    /// revision whose text the room's search matched (FIX 9956). A hit with
    /// no indexed revision is read live.
    fn indexed_revisions(
        &self,
        hits: &[crate::pipeline::ScoredEntity],
    ) -> MemoryResult<std::collections::HashMap<EntityId, crate::vault::RevisionRef>> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(|error| MemoryError::from(crate::Error::from(error)))?;
        let view = self.view.read();
        let mut revisions = std::collections::HashMap::with_capacity(hits.len());
        for hit in hits {
            if let Some(revision) = self
                .vault
                .indexed_revision_from_in_txn(&view, &txn, &hit.id)?
            {
                revisions.insert(hit.id, revision);
            }
        }
        Ok(revisions)
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

    /// The evidence refs a room write's caller supplied (FIX 4281; Engine
    /// 10-22), each read in this call's view of the room on its key, in one
    /// snapshot: a ref naming a TURN the key reads is that TURN, with its
    /// body as read. Every other ref (one naming nothing, a malformed one, a
    /// row the key does not read, a row that is no TURN) is kept as supplied
    /// and never refuses the write. Nothing is capped.
    ///
    /// # Errors
    ///
    /// Storage and corruption errors resolving a ref, and the lane's own
    /// refusals, as any read meets them.
    pub(crate) fn supplied_evidence(
        &self,
        refs: &[String],
    ) -> MemoryResult<Vec<crate::provenance::birth::room::SuppliedEvidence>> {
        let mut targets = Vec::with_capacity(refs.len());
        for reference in refs {
            targets.push(match self.target(reference) {
                Ok(target) => target,
                Err(error) if error.code != MEMORY_CODE_INTERNAL => None,
                Err(error) => return Err(error),
            });
        }
        let reads: Vec<_> = targets
            .iter()
            .flatten()
            .map(|(id, mode)| PointRead::id(*id).at(*mode))
            .collect();
        let mut rows = self
            .lane(ClaimReadStatus::Recorded)
            .read(&reads, None)?
            .value
            .into_iter();
        Ok(refs
            .iter()
            .zip(targets)
            .map(|(reference, target)| {
                let row = target.and_then(|_| rows.next().flatten());
                crate::provenance::birth::room::SuppliedEvidence {
                    supplied: reference.clone(),
                    turn: row
                        .filter(|row| row.entity_type == crate::registry::ENTITY_TYPE_TURN)
                        .and_then(|row| Some((row.id, row.body?))),
                }
            })
            .collect())
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
        let admit = lane.recall_candidates_in(&txn, &policy, &filter);
        let mut admits = |id: &EntityId| admit(id);
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

/// The refusal of a room's hydrate that served an image in a resolved form
/// on a route that lands in base (WILL L11-01 S01-2b): nothing proves in base
/// the evidence its served-form receipts would name, so the read gives no
/// answer rather than one without them. A hydrate that served no form, and
/// every other read, still answers there.
fn served_forms_on_base() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        "a hydrate in a room on record keeps no served-form receipt for its image forms",
        &["Hydrate the image from a run outside the room, or with no image ASSET among its refs."],
    )
}

/// A room's own short ref, `s<n>:<hash>`: the alias a room mints for each
/// row it stages (`SessionOverlay::alloc_session_short_id`), outside the
/// vault's grammar, so neither names the other's row. A room NOTE's reads
/// resolve it too (FIX 4280, `OffRecordSession::room_row`).
pub(crate) fn room_short_ref(reference: &str) -> Option<(&str, u8)> {
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
