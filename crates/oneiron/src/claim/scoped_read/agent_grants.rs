//! FIX 7462: an agent's ordinary read also admits what one of its own live
//! owner-minted Grants covers (owner principle 2: an agent within its Grant
//! is the owner's delegated will wherever it runs).
//!
//! A row's own admission is today's (B) first, unchanged; only once B
//! refuses does A try each live Grant the reader's own standing for "read"
//! rests on, each alone: never two Grants' axes together, never another
//! reader's, the principal's or the owner's Grant, and never for a key that
//! supplies a proof, carries a Scope or is the owner's. Under one Grant the
//! row is judged as a key holding a proof of that Grant would be: the Grant
//! first admits the row's record position, the floor is the one such a proof
//! gives the key, and the Grant stands in for the relationship checks and
//! the positive CLAIM or record check. Every other check binds as in B, the
//! device-local worlds under the key's own locality among them. A only ever
//! adds a row: a Grant row that does not decode, and any store, fold or
//! clock failure, admits nothing and leaves B's answer, counted in a warning
//! that names no content.

use crate::claim::ClaimRecordScope;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use super::access_gate::HeldAuthority;
use super::*;
use crate::edge::EdgeActorClass;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_MACHINE, ENTITY_TYPE_SECRET_CUSTODY};
use oneiron_authority::federation::Scope;

/// One reader's live Grants, each id with its Scope.
type ReaderGrants = Rc<[(EntityId, Scope)]>;

/// What each agent Grant that names one credential's holder and stands for
/// `read` lets a read reach; `None` when no Grant has ever named the holder
/// (`Vault::agent_grant_read_bounds_in_txn`).
pub(super) type HolderGrantBounds = Rc<Option<Vec<Scope>>>;

/// What one read asked of its rows beyond its key's own floor, so A resolves
/// its filter under a Grant as the read resolved its own.
#[derive(Clone, Default)]
pub(super) enum AskedFilter {
    /// The rows' filter came from a caller this read does not see: A meets
    /// that filter with the Grant's floor, so it never reads wider than asked.
    #[default]
    Unknown,
    /// The request the read narrowed its key's floor by; `None` is the floor
    /// alone.
    Known(Option<RetrievalFilter>),
}

/// The Grants one serving txn's row checks hold: each reader's own, loaded at
/// the first row that reader's B refuses, and each credential holder's
/// standing read bounds, loaded at the first row its key judges
/// ([`ScopedReadActorKey::agent_grant_holder`]); both dropped with the txn's
/// [`HeldAuthority`]. A peer's and a named read's row checks share them, each
/// reading its own actor's entry, never another's.
#[derive(Clone, Default)]
pub(super) struct HeldGrants {
    by_reader: Rc<RefCell<BTreeMap<EntityId, ReaderGrants>>>,
    by_holder: Rc<RefCell<BTreeMap<EntityId, HolderGrantBounds>>>,
    asked: AskedFilter,
}

impl HeldGrants {
    /// None held yet, for row checks that asked `asked`.
    pub(super) fn fresh(asked: AskedFilter) -> Self {
        Self {
            by_reader: Rc::default(),
            by_holder: Rc::default(),
            asked,
        }
    }

    /// The same Grants, for row checks that asked `asked`.
    pub(super) fn shared_asking(&self, asked: AskedFilter) -> Self {
        Self {
            by_reader: Rc::clone(&self.by_reader),
            by_holder: Rc::clone(&self.by_holder),
            asked,
        }
    }

    /// What the read these row checks serve asked.
    pub(super) fn asked(&self) -> &AskedFilter {
        &self.asked
    }

    /// `reader`'s Grants in this txn: `load`ed at the first ask, then held.
    fn of(&self, reader: EntityId, load: impl FnOnce() -> Vec<(EntityId, Scope)>) -> ReaderGrants {
        if let Some(grants) = self.by_reader.borrow().get(&reader) {
            return Rc::clone(grants);
        }
        let grants: ReaderGrants = load().into();
        self.by_reader
            .borrow_mut()
            .insert(reader, Rc::clone(&grants));
        grants
    }

    /// `holder`'s standing read bounds in this txn: `load`ed at the first
    /// ask, then held. A failed load holds nothing, so the next row asks
    /// again.
    ///
    /// # Errors
    /// `load`'s.
    pub(super) fn bounds_of(
        &self,
        holder: EntityId,
        load: impl FnOnce() -> Result<Option<Vec<Scope>>>,
    ) -> Result<HolderGrantBounds> {
        if let Some(bounds) = self.by_holder.borrow().get(&holder) {
            return Ok(Rc::clone(bounds));
        }
        let bounds: HolderGrantBounds = Rc::new(load()?);
        self.by_holder
            .borrow_mut()
            .insert(holder, Rc::clone(&bounds));
        Ok(bounds)
    }
}

/// What a receipt reports over a key's own floor and its live Grants
/// ([`ScopedRead::live_grant_receipt_scope_in`]).
pub(super) struct LiveGrantReceiptScope {
    /// The key's own floor and each live Grant's floor, as one envelope.
    pub(super) ceiling: crate::gate::RetrievalPolicyFloor,
    /// The read's applied filter joined with each live Grant's filter under
    /// the read's request.
    pub(super) applied: ResolvedRetrievalFilter,
    /// Whether the key's own floor and every live Grant have a static
    /// boundary (the `grant_scope` hint).
    pub(super) statically_bounded: bool,
}

impl ScopedRead<'_> {
    /// A for the row `raw` of `id`, tried only once B refused it: whether one
    /// of the reader's own live Grants admits it alone. `filter` is the one B
    /// judged it under, `asked` what the read asked beyond its key's floor.
    #[expect(
        clippy::too_many_arguments,
        reason = "A judges the row B judged, under B's filter, held authority and request"
    )]
    pub(super) fn own_row_readable_by_grant_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        raw: &[u8],
        filter: &ResolvedRetrievalFilter,
        authority: &HeldAuthority,
        asked: &AskedFilter,
    ) -> bool {
        let Some(reader) = self.grant_reader() else {
            return false;
        };
        let request = match asked {
            AskedFilter::Known(request) => request.clone(),
            // B's own filter, met with the Grant's floor: never wider than
            // the caller asked. One that reads nothing leaves A nothing.
            AskedFilter::Unknown if filter.deny_all => return false,
            AskedFilter::Unknown => Some(as_request(filter)),
        };
        let grants = authority.grants().of(reader, || {
            reader_grants_or_empty_in(self.vault, rtxn, reader)
        });
        for (grant, scope) in &*grants {
            match self.own_row_under_grant_in(
                rtxn,
                policy,
                id,
                raw,
                request.as_ref(),
                authority,
                scope,
            ) {
                Ok(true) => return true,
                Ok(false) => {}
                Err(error) => warn_grant_errors(1, &[*grant], Some(error.kind())),
            }
        }
        false
    }

    /// Whether a read that asked nothing of its own ([`Self::held_for`]
    /// `(None)`) reads no row at all in `rtxn`: `filter` (B) denies all and,
    /// for a reader A may stand for, none of the live Grants `held` holds in
    /// `rtxn` reads a row alone either. A door that answers nothing to a
    /// reader who reads nothing asks this, not B alone, once its rows take
    /// the held row gate, since an identity agent's own floor reads nothing
    /// (FIX-LIST SCOPED-READ-UNKNOWN-AUTHORITY-CALLERS). It only skips:
    /// every row the door serves still takes the row gate.
    pub(super) fn reads_nothing_held_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        held: &HeldAuthority,
    ) -> bool {
        if !filter.deny_all {
            return false;
        }
        let Some(reader) = self.grant_reader() else {
            return true;
        };
        if matches!(held.grants().asked(), AskedFilter::Unknown) {
            return true;
        }
        let grants = held.grants().of(reader, || {
            reader_grants_or_empty_in(self.vault, rtxn, reader)
        });
        self.candidates_under_grants(policy, filter, None, &grants)
            .deny_all
    }

    /// The candidates a search under `filter` may rank (FIX 7528): the rows
    /// `filter` (B, resolved from `requested`) reads and, for a reader A may
    /// stand for, the rows each of its own live Grants reads alone under
    /// `requested`, as one envelope (`union_envelope`). It is only the
    /// search's prefilter: every candidate still takes the row gate, B first
    /// and then A under each Grant alone, so it admits no row by itself. A
    /// Grant floor that cannot be judged adds nothing and is counted, as A
    /// counts it; the envelope is then B's alone.
    pub(super) fn candidate_filter_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        requested: Option<&RetrievalFilter>,
    ) -> ResolvedRetrievalFilter {
        match self.live_read_grants_in(rtxn) {
            Some(grants) => self.candidates_under_grants(policy, filter, requested, &grants),
            None => filter.clone(),
        }
    }

    /// The applied scope a search receipt under `filter` starts from (FIX
    /// 7528). With `report_live_grants` it is `filter` alone:
    /// [`Self::live_grant_receipt_scope_in`] joins the Grants the rows' gate
    /// held, so the ceiling and the applied scope name the same Grants even
    /// when one lapsed between two loads (review round 1 of #9794).
    /// Otherwise the candidates, joined with the Grants live in `rtxn`.
    pub(super) fn receipt_candidates_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        requested: Option<&RetrievalFilter>,
        report_live_grants: bool,
    ) -> ResolvedRetrievalFilter {
        if report_live_grants {
            return filter.clone();
        }
        self.candidate_filter_in(rtxn, policy, filter, requested)
    }

    /// The live Grants A may stand on for this key, each with its read
    /// Scope, when A may stand for it ([`Self::grant_reader`]); `None` when
    /// A never stands for it. A lookup that fails adds no Grant and is
    /// counted, as A counts it.
    fn live_read_grants_in(&self, rtxn: &heed::RoTxn<'_>) -> Option<Vec<(EntityId, Scope)>> {
        let reader = self.grant_reader()?;
        Some(reader_grants_or_empty_in(self.vault, rtxn, reader))
    }

    /// `filter` joined with the rows each of `grants` reads alone under
    /// `requested`, as one envelope ([`Self::candidate_filter_in`]).
    fn candidates_under_grants(
        &self,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        requested: Option<&RetrievalFilter>,
        grants: &[(EntityId, Scope)],
    ) -> ResolvedRetrievalFilter {
        // Each Grant reads under what the read asked, its bound caller
        // filter among it (FIX 3977).
        let requested = self.asked_request(requested);
        let requested = requested.as_deref();
        let mut candidates = filter.clone();
        for (grant, scope) in grants {
            let floor =
                policy.retrieval_floor_for_actor_with_scope(Some(&self.actor_key), Some(scope));
            match crate::gate::narrow_retrieval_filter(&floor, requested) {
                Ok(under) => {
                    candidates =
                        candidates.union_envelope(&under.under_credential_of(&self.actor_key));
                }
                Err(error) => warn_grant_errors(1, &[*grant], Some(error.kind())),
            }
        }
        candidates
    }

    /// The scope a receipt that reports its live Grants states, in the
    /// serving snapshot `rtxn` (FIX GRANT-READ-NARROWING-SAYS-DENY-ALL): the
    /// key's own floor and each of its own live Grants' floors as its
    /// ceiling, and `applied` joined with what each live Grant reads alone
    /// under `requested`, as the search candidates join them (FIX 7528).
    /// `report_live_grants` is whether this receipt reports them: a lane's
    /// own setting ([`ScopedRead::with_live_grant_receipts`]), or the
    /// retrieval loop's, which always does. `None` when it does not, and for
    /// a key A never stands for. It only reports: every row took the row
    /// gate, B first, then each Grant alone.
    ///
    /// With `held`, the Grants are the ones the row gate held in this
    /// snapshot (loaded here, and held, when no row asked yet), so the
    /// receipt names the Grants that judged its rows even when one lapsed
    /// on the running clock since (review round 1 of #9775).
    pub(super) fn live_grant_receipt_scope_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        applied: &ResolvedRetrievalFilter,
        requested: Option<&RetrievalFilter>,
        held: Option<&HeldAuthority>,
        report_live_grants: bool,
    ) -> Option<LiveGrantReceiptScope> {
        if !report_live_grants {
            return None;
        }
        let reader = self.grant_reader()?;
        let load = || reader_grants_or_empty_in(self.vault, rtxn, reader);
        let grants: ReaderGrants = match held {
            Some(held) => held.grants().of(reader, load),
            None => load().into(),
        };
        let mut ceiling = policy.retrieval_floor_for_actor(Some(&self.actor_key));
        // A static boundary holds when the key's own floor has one and so
        // does each live Grant, each judged whole: by its own Scope, or by
        // the policy rows that still cap a read carrying it (gate/grants.rs
        // applies a matching non-house row to an explicit Scope too).
        let mut statically_bounded = ceiling
            .has_grant_scope_bound(self.actor_key.authority_scope())
            || policy.scoped_read_grants_all_bounded(&self.actor_key);
        for (_, scope) in grants.iter() {
            let floor =
                policy.retrieval_floor_for_actor_with_scope(Some(&self.actor_key), Some(scope));
            statically_bounded &= floor.has_grant_scope_bound(Some(scope))
                || policy.scoped_read_grants_all_bounded_with_scope(&self.actor_key, Some(scope));
            ceiling = ceiling.alternative_envelope(&floor);
        }
        Some(LiveGrantReceiptScope {
            ceiling,
            applied: self.candidates_under_grants(policy, applied, requested, &grants),
            statically_bounded,
        })
    }

    /// The reader A may stand for ([`ScopedReadActorKey::grant_reader`]).
    fn grant_reader(&self) -> Option<EntityId> {
        self.actor_key.grant_reader()
    }

    /// The row under `grant` alone: the Grant first admits the row's record
    /// position and holds it inside the Grant's facets, then the row's own
    /// admission runs under the floor a proof of the Grant gives this key,
    /// `request` met on top as the read met it. The position names no facet
    /// (`Scope::admits`) and an identity key carries no facet limit of its
    /// own, so the facets are judged here: a Grant limited to some facets
    /// reads only their records (owner ruling FACET-READ = A; Astra delta
    /// review of #8340, D1).
    #[expect(
        clippy::too_many_arguments,
        reason = "one Grant's row admission takes the row, its request and the held authority"
    )]
    fn own_row_under_grant_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        raw: &[u8],
        request: Option<&RetrievalFilter>,
        authority: &HeldAuthority,
        grant: &Scope,
    ) -> Result<bool> {
        if !self.grant_admits_position_in(rtxn, id, raw, grant)?
            || !self.row_inside_facets_in(rtxn, id, raw, &grant.facets)?
        {
            return Ok(false);
        }
        let floor = policy.retrieval_floor_for_actor_with_scope(Some(&self.actor_key), Some(grant));
        let filter = self.under_caller_filter(
            crate::gate::narrow_retrieval_filter(&floor, request)?
                .under_credential_of(&self.actor_key),
        );
        self.own_row_readable_in(rtxn, policy, id, raw, &filter, authority, Some(grant))
    }

    /// Whether `grant` admits the record position of the row `raw` of `id`,
    /// as the explicit-Scope gates judge one: a CLAIM's own record Scope, any
    /// other row's where `scope_for_blob` places it on this read's store. A
    /// row with no position admits nothing, and sealed custody is never one.
    pub(crate) fn grant_admits_position_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
        grant: &Scope,
    ) -> Result<bool> {
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type == ENTITY_TYPE_SECRET_CUSTODY {
            return Ok(false);
        }
        let record = if header.entity_type == ENTITY_TYPE_CLAIM {
            let Ok(body) = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true) else {
                return Ok(false);
            };
            Some(body.record_scope("read"))
        } else {
            match self.session_view {
                Some(view) => {
                    crate::federation::record_scope::scope_for_blob(view, rtxn, *id, raw)?
                }
                None => crate::federation::record_scope::scope_for_blob(
                    &self.vault.store,
                    rtxn,
                    *id,
                    raw,
                )?,
            }
        };
        // A NOTE in several worlds is judged at one world the read's own
        // ceiling and the Grant both hold, base reality first (FIX-LIST 9433).
        let ceiling = self.actor_key.world_ceiling();
        Ok(record.is_some_and(|record| {
            let record = crate::federation::record_scope::note_world::held_at(
                &self.store_read(),
                rtxn,
                *id,
                header.entity_type,
                &record,
                &[&ceiling.worlds, &grant.worlds],
            );
            grant.admits("read", &record, &Scope::top())
        }))
    }
}

impl ScopedReadActorKey {
    /// The reader A may stand for: this key's own actor, while the key
    /// supplies no proof, carries no Scope and is not the owner's. A narrowed
    /// key (`read_nothing` among them) stays exactly as it is.
    fn grant_reader(&self) -> Option<EntityId> {
        if self.proof.is_some()
            || self.authority_scope().is_some()
            || self.vault_owner_ref().is_some()
        {
            return None;
        }
        EntityId::from_hex(self.actor_ref()).ok()
    }

    /// Whether a CLAIM placed at `facet` sits inside the facets a read under
    /// this key admits: the key's own facet limits and, for a key whose
    /// actor reads through its own live Grants (A), one of its Grants over
    /// CLAIMs that holds `facet`, as A judges each Grant alone. An actor with
    /// no Grant over CLAIMs is judged by the key's limits alone. A standing
    /// answer lands where its asker reads it back (review round 1 on #9604).
    ///
    /// # Errors
    /// A store failure reading the key's limits or the actor's Grants.
    pub(crate) fn reads_claims_at_facet_in(
        &self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        facet: EntityId,
    ) -> Result<bool> {
        if !self.facets_allow_placed_in(vault, txn, &[facet], None)? {
            return Ok(false);
        }
        let Some(reader) = self.grant_reader() else {
            return Ok(true);
        };
        let grants = reader_grants_in(vault, txn, reader)?;
        let mut over_claims = grants
            .iter()
            .filter(|(_, scope)| scope.bands.contains(&ENTITY_TYPE_CLAIM))
            .peekable();
        if over_claims.peek().is_none() {
            return Ok(true);
        }
        Ok(over_claims.any(|(_, scope)| {
            crate::federation::facet_read::placed_facets_admit(&scope.facets, &[facet])
        }))
    }
}

/// Every live Grant `reader` reads under, each with its Scope: none unless it
/// is a live agent definition or a base agent's MACHINE (its class taken from
/// its own row) whose standing for "read" holds now
/// (`authority::principal_standing_in_txn`), and then each Grant that alone
/// stands for it by that same rule (`AgentGrantStanding::stands_for`). A
/// Grant row that does not decode stands for no one, and is counted.
fn reader_grants_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    reader: EntityId,
) -> Result<Vec<(EntityId, Scope)>> {
    let class = match crate::vault::live_entity_row_in_txn(&vault.store, txn, &reader)?.live_type()
    {
        Some(ENTITY_TYPE_AGENT_DEF) => EdgeActorClass::Agent,
        Some(ENTITY_TYPE_MACHINE) => EdgeActorClass::System,
        _ => return Ok(Vec::new()),
    };
    if crate::authority::principal_standing_in_txn(vault, txn, reader, class, "read")?.is_none() {
        return Ok(Vec::new());
    }
    let now = vault.grant_judgement_secs_in_txn(txn)?;
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    let (grants, undecoded) = vault.agent_grants_reporting_in_txn(txn)?;
    if !undecoded.is_empty() {
        warn_grant_errors(undecoded.len(), &undecoded, None);
    }
    let classes = crate::federation::AgentVerbClasses::for_grants_in_txn(
        &vault.store,
        txn,
        grants
            .iter()
            .filter(|standing| standing.grant.member_ref == reader)
            .map(|standing| &standing.grant),
    )?;
    // A Grant whose `read` a class it names admits reads under its Scope
    // with `read` listed (FIX 8735); an unclassed Grant's Scope is its own.
    Ok(grants
        .iter()
        .filter(|standing| {
            standing.stands_in_txn(vault, txn, reader, "read", now, &owners, &classes)
        })
        .map(|standing| {
            (
                standing.id,
                standing.grant.scope_for_verb("read", &classes).into_owned(),
            )
        })
        .collect())
}

/// [`reader_grants_in`], with a lookup that fails read as no Grant (an empty
/// list) and counted, as A counts it.
fn reader_grants_or_empty_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    reader: EntityId,
) -> Vec<(EntityId, Scope)> {
    reader_grants_in(vault, txn, reader).unwrap_or_else(|error| {
        warn_grant_errors(1, &[], Some(error.kind()));
        Vec::new()
    })
}

/// `filter` as a request: met with a floor, it narrows that floor to what
/// `filter` reads, never past it.
pub(super) fn as_request(filter: &ResolvedRetrievalFilter) -> RetrievalFilter {
    RetrievalFilter {
        entity_types: filter.entity_types.clone(),
        max_sensitivity_band: Some(filter.max_sensitivity_band),
        include_stale: Some(filter.include_stale),
        min_confidence: Some(filter.min_confidence),
        min_salience: Some(filter.min_salience),
    }
}

/// A step of A that admitted nothing because it could not judge: `count`
/// Grant rows that did not decode, or a store, fold or clock failure of its
/// `kind`. The read keeps B's answer. Grant ids and the error's kind only,
/// never content.
fn warn_grant_errors(count: usize, grants: &[EntityId], kind: Option<crate::ErrorKind>) {
    let grants: Vec<String> = grants.iter().map(EntityId::to_hex).collect();
    tracing::warn!(
        count,
        ?grants,
        error_kind = ?kind,
        "an agent's own Grant admitted nothing it could not judge; the read keeps its own answer \
         (FIX 7462)"
    );
}
