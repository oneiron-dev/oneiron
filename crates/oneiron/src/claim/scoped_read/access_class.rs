//! FIX 11915 stage B: a CLAIM row's admission judged once per access class.
//!
//! Most of a CLAIM's admission reads only the row's access tuple: its world,
//! facet and project stamps, sensitivity band, relationship set and privacy,
//! principal, opaque scope, status, scalars, predicate class and `FacetOf`
//! targets. That part, [`class_judge_in`], sees the row's [`ClassView`] and
//! the reader ([`ClassReader`]) and never the row's id or bytes, so its
//! verdict holds for every row of the class: one serving txn's
//! [`HeldAuthority`] holds it per reader, and each class is judged once. The
//! rest, [`ScopedRead::per_item_judge_in`], reads the row itself and runs for
//! every row.
//!
//! A reader whose credential or saved lane carries a record list, a row with
//! no body, a history control, and a row whose view does not build take the
//! row admission unchanged (`ScopedRead::own_row_readable_in`), and so does
//! every other kind.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use super::access_gate::HeldAuthority;
use super::*;
use crate::federation::Scope;
use crate::gate::{ClaimReadPolicy, ClaimReadView};

/// Readers one serving txn holds class verdicts for. A further reader's
/// classes are judged, never held.
const READERS_HELD: usize = 64;

/// Classes one reader's verdicts hold in one serving txn. A further class is
/// judged, never held.
const CLASSES_HELD: usize = 8192;

/// What a CLAIM's class verdict reads of its row, and nothing else. Built
/// only by [`ClassView::of`]; [`ClassView::key`] encodes every field, so two
/// rows with one key are one class.
struct ClassView<'b> {
    /// The claim's world, base reality as its id.
    world: EntityId,
    scope_facet: EntityId,
    scope_project: EntityId,
    /// `None`: a sensitivity that does not read.
    sensitivity_band: Option<u8>,
    rel: RelationshipScope,
    private: bool,
    principal: Option<EntityId>,
    scope: Option<&'b rmpv::Value>,
    /// `scope` as MessagePack, as the key carries it.
    scope_bytes: Option<Vec<u8>>,
    generic_readable: bool,
    mined_preference: bool,
    approval: ClaimApprovalStatus,
    lifecycle: ClaimLifecycleStatus,
    stale: bool,
    confidence: f32,
    salience: Option<f32>,
    /// The claim's `FacetOf` targets, sorted and distinct.
    facets: Vec<EntityId>,
}

impl<'b> ClassView<'b> {
    /// The class of the claim `body`, whose principal audience is
    /// `principal` (`claim_principal_id` of it) and whose `FacetOf` targets
    /// are `facets`; `None` where its scope does not encode, which the row
    /// admission meets in its own order.
    fn of(
        body: &'b ClaimBody,
        principal: Option<EntityId>,
        mut facets: Vec<EntityId>,
    ) -> Option<Self> {
        facets.sort_unstable();
        facets.dedup();
        let (rel, private) = claim_access_axes(body);
        let scope_bytes = body
            .scope
            .as_ref()
            .map(|scope| {
                let mut bytes = Vec::new();
                rmpv::encode::write_value(&mut bytes, scope).map(|()| bytes)
            })
            .transpose()
            .ok()?;
        Some(Self {
            world: body.world.unwrap_or_else(crate::claim::base_world_id),
            scope_facet: body.scope_facet,
            scope_project: body.scope_project,
            sensitivity_band: crate::claim::claim_sensitivity_band(body),
            rel,
            private,
            principal,
            scope: body.scope.as_ref(),
            scope_bytes,
            generic_readable: crate::claim::claim_generic_readable(body),
            mined_preference: crate::edit_distance::miner::is_mined_preference(&body.predicate),
            approval: body.approval,
            lifecycle: body.lifecycle,
            stale: body.stale,
            confidence: body.confidence,
            salience: body.salience,
            facets,
        })
    }

    /// The class's canonical bytes: every field in declaration order, each
    /// set sorted, each part of variable length prefixed by its length, so
    /// two views share a key only when every field is equal.
    fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(192);
        key.extend_from_slice(self.world.as_bytes());
        key.extend_from_slice(self.scope_facet.as_bytes());
        key.extend_from_slice(self.scope_project.as_bytes());
        match self.sensitivity_band {
            Some(band) => key.extend_from_slice(&[1, band]),
            None => key.push(0),
        }
        match &self.rel {
            Some(ids) => {
                key.push(1);
                put_ids(&mut key, ids.iter().copied());
            }
            None => key.push(0),
        }
        key.push(u8::from(self.private));
        put_id_option(&mut key, self.principal);
        match &self.scope_bytes {
            Some(bytes) => {
                key.push(1);
                put_bytes(&mut key, bytes);
            }
            None => key.push(0),
        }
        key.push(u8::from(self.generic_readable));
        key.push(u8::from(self.mined_preference));
        put_bytes(&mut key, self.approval.as_str().as_bytes());
        put_bytes(&mut key, self.lifecycle.as_str().as_bytes());
        key.push(u8::from(self.stale));
        key.extend_from_slice(&self.confidence.to_bits().to_be_bytes());
        match self.salience {
            Some(salience) => {
                key.push(1);
                key.extend_from_slice(&salience.to_bits().to_be_bytes());
            }
            None => key.push(0),
        }
        put_ids(&mut key, self.facets.iter().copied());
        key
    }

    /// The claim's record position, as `ClaimBody::record_scope` stamps it.
    fn record(&self) -> Scope {
        crate::claim::record_scope_at(
            self.world,
            self.scope_facet,
            self.scope_project,
            self.sensitivity_band,
            "read",
        )
    }

    /// What the claim read selectors judge of the class at `record`.
    fn read_view(&self, record: Scope) -> ClaimReadView<'_> {
        ClaimReadView {
            record,
            scope: self.scope,
            stale: self.stale,
            confidence: self.confidence,
            salience: self.salience,
            facets: &self.facets,
        }
    }
}

/// `bytes`, prefixed by its length.
fn put_bytes(key: &mut Vec<u8>, bytes: &[u8]) {
    key.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    key.extend_from_slice(bytes);
}

/// `ids` in their order, prefixed by their count.
fn put_ids(key: &mut Vec<u8>, ids: impl ExactSizeIterator<Item = EntityId>) {
    key.extend_from_slice(&(ids.len() as u64).to_be_bytes());
    for id in ids {
        key.extend_from_slice(id.as_bytes());
    }
}

/// `id`, or its absence.
fn put_id_option(key: &mut Vec<u8>, id: Option<EntityId>) {
    match id {
        Some(id) => {
            key.push(1);
            key.extend_from_slice(id.as_bytes());
        }
        None => key.push(0),
    }
}

/// The reader a class verdict is judged for, as [`class_judge_in`] reads it:
/// its key, its room turn's terms as the turn holds them now, its lane's
/// claim status mode, the filter and the Grant the row is judged under, and
/// what the claim read selectors read of the policy. These are every reader
/// input that can differ inside one serving txn; what the judge reads of the
/// txn (the key's relationship grants and memberships, owner exemption, room
/// facets and guest grant) is that txn's for that key.
struct ClassReader<'r> {
    key: &'r ScopedReadActorKey,
    /// A room turn's terms are shared by every lane built from the turn and
    /// only narrow, and the key names them by identity alone; a verdict
    /// holds only under the terms it was read under. Judging may narrow them
    /// by this snapshot's room facets, and a turn never widens, so terms the
    /// turn has left are never read again.
    turn_terms: Option<RoomTerms>,
    status: ClaimReadStatus,
    filter: &'r ResolvedRetrievalFilter,
    grant: Option<&'r Scope>,
    policy: ClaimReadPolicy<'r>,
}

/// One reader's class verdicts in one serving txn: the reader, owned, and
/// each class's verdict by the class's key.
struct ReaderVerdicts {
    key: ScopedReadActorKey,
    turn_terms: Option<RoomTerms>,
    status: ClaimReadStatus,
    filter: ResolvedRetrievalFilter,
    grant: Option<Scope>,
    policy: ClaimReadPolicy<'static>,
    verdicts: HashMap<Vec<u8>, bool>,
}

impl ReaderVerdicts {
    fn of(reader: &ClassReader<'_>) -> Self {
        Self {
            key: reader.key.clone(),
            turn_terms: reader.turn_terms.clone(),
            status: reader.status,
            filter: reader.filter.clone(),
            grant: reader.grant.cloned(),
            policy: reader.policy.clone().into_owned(),
            verdicts: HashMap::new(),
        }
    }

    /// Whether these are `reader`'s verdicts: every input of the reader the
    /// same.
    fn reads_as(&self, reader: &ClassReader<'_>) -> bool {
        self.status == reader.status
            && self.grant.as_ref() == reader.grant
            && self.filter == *reader.filter
            && self.policy.reads_as(&reader.policy)
            && self.turn_terms == reader.turn_terms
            && self.key == *reader.key
    }
}

/// The CLAIM access class verdicts one serving txn's row checks hold, by
/// reader (FIX 11915): only a verdict, never an error, which propagates as
/// before. A peer's and a named read's row checks share them, each reader
/// holding its own.
#[derive(Clone, Default)]
pub(super) struct ClassVerdicts(Rc<RefCell<Vec<ReaderVerdicts>>>);

impl ClassVerdicts {
    /// `reader`'s verdict on `class`, once held.
    fn held(&self, reader: &ClassReader<'_>, class: &[u8]) -> Option<bool> {
        self.0
            .borrow()
            .iter()
            .find(|held| held.reads_as(reader))
            .and_then(|held| held.verdicts.get(class).copied())
    }

    /// Holds `verdict` as `reader`'s on `class`, while the bounds leave room.
    fn hold(&self, reader: &ClassReader<'_>, class: Vec<u8>, verdict: bool) {
        let mut readers = self.0.borrow_mut();
        let index = match readers.iter().position(|held| held.reads_as(reader)) {
            Some(index) => index,
            None if readers.len() < READERS_HELD => {
                readers.push(ReaderVerdicts::of(reader));
                readers.len() - 1
            }
            None => return,
        };
        if let Some(held) = readers.get_mut(index)
            && held.verdicts.len() < CLASSES_HELD
        {
            held.verdicts.insert(class, verdict);
        }
    }
}

/// Every tuple conjunct of a CLAIM's admission for `reader`, over the class
/// `view` (L02 04:5x condition 1): no row id and no row bytes, and of `txn`
/// only what the reader's key names. In the row admission's order: the
/// relationship gate (a Grant stands in for it, FIX 7462), the guest bound,
/// the facet limits, the principal audience, a mined preference's principal,
/// the claim status and the scalar ceiling, then the claim read selectors.
fn class_judge_in<'v>(
    vault: &'v crate::Vault,
    txn: &heed::RoTxn<'_>,
    reader: &ClassReader<'_>,
    view: &ClassView<'_>,
    authority: &HeldAuthority<'v>,
) -> Result<bool> {
    let key = reader.key;
    let record = view.record();
    if reader.grant.is_none() && key.relationship_gated_in(vault, txn)? {
        let read = RelationshipRead::Gated {
            kind: ENTITY_TYPE_CLAIM,
            space: view.rel.clone(),
            private: view.private,
            record: record.clone(),
        };
        if !authority.relationship_allows_in(vault, txn, key.principal_ref, |context| {
            read.allowed_by(context)
        })? {
            return Ok(false);
        }
    }
    if !key.guest_bound_admits_at(vault, txn, || Ok(Some(record.clone())))
        || !key.facets_allow_placed_in(vault, txn, &view.facets)?
        || !key.admits_principal(view.principal)
        || (view.mined_preference && view.principal.is_none())
        || !reader.status.admits_status(
            reader.filter,
            view.generic_readable,
            view.approval,
            view.lifecycle,
            view.stale,
        )
        || !crate::pipeline::claim_scalars_ceiling_allowed(
            reader.filter,
            view.sensitivity_band,
            view.confidence,
            view.salience,
        )
    {
        return Ok(false);
    }
    Ok(crate::gate::claim_read_policy_allows(
        &reader.policy,
        key,
        &view.read_view(record),
        reader.grant.or(key.authority_scope()),
    ))
}

impl<'v> ScopedRead<'v> {
    /// The CLAIM row `raw` of `id`'s admission judged by its access class
    /// (FIX 11915), or `None` where the row takes the row admission: a
    /// reader with a record list, a row with no body, a history control, or
    /// a row whose class view does not build. `header` is the row's, a
    /// CLAIM's, whose type, band and filter the row admission met before
    /// this; `grant` and `filter` are as `Self::own_row_readable_in` takes
    /// them.
    #[expect(
        clippy::too_many_arguments,
        reason = "a claim row's admission under its filter, held authority and an optional Grant"
    )]
    pub(super) fn claim_by_class_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        raw: &[u8],
        header: &EntityMetadataHeader,
        filter: &ResolvedRetrievalFilter,
        authority: &HeldAuthority<'v>,
        grant: Option<&Scope>,
    ) -> Result<Option<bool>> {
        if !self.reads_by_class() || raw.len() <= ENTITY_METADATA_HEADER_LEN {
            return Ok(None);
        }
        if !self.row_stands_in(rtxn, id, raw, header, authority.asks_use_of(id))? {
            return Ok(Some(false));
        }
        let Ok(body) = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true) else {
            return Ok(None);
        };
        if crate::claim::history_store::machine_history_kind(&body.predicate).is_some() {
            return Ok(None);
        }
        let Ok(principal) = claim_principal_id(&body) else {
            return Ok(None);
        };
        // The split's failure order (L02 04:5x condition 4): every per-item
        // conjunct that can fail runs first, in the row admission's order,
        // so its error is the read's whatever the class; only then is the
        // class verdict read, or judged and held. A class conjunct's error is
        // never held and propagates as the row admission's does. A view that
        // does not build past them takes the row admission, which judges the
        // row whole again.
        if !self.per_item_judge_in(rtxn, id, raw, &body, principal, authority)? {
            return Ok(Some(false));
        }
        let Ok(facets) = self.claim_facet_refs_in(rtxn, id) else {
            return Ok(None);
        };
        let Some(view) = ClassView::of(&body, principal, facets) else {
            return Ok(None);
        };
        self.class_verdict_in(rtxn, policy, filter, grant, &view, authority)
            .map(Some)
    }

    /// Whether this lane's CLAIM rows may be judged by class: neither its
    /// credential's records caveat nor its saved lane's names rows (L02 04:5x
    /// condition 2a). A record list names rows by id, which no class
    /// carries, so such a reader takes the row admission, with its support
    /// slip and its artifact records cover.
    fn reads_by_class(&self) -> bool {
        self.actor_key.record_bound.is_none()
            && self
                .actor_key
                .proof
                .as_ref()
                .is_none_or(|proof| proof.claims().records.is_empty())
    }

    /// Every per-item or time conjunct of the CLAIM row `raw` of `id`, with
    /// `body` and principal audience `principal`, past its standing (L02
    /// 04:5x condition 2), in the row admission's order: its audience
    /// (device, private threads, own entry, asked worlds, room turn and
    /// peers), the credential's records and channel caveats, the proof's
    /// liveness now, the claim's live support, a mined preference's decay at
    /// the judged time, and its causal standing under its writers'
    /// revocations.
    fn per_item_judge_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
        body: &ClaimBody,
        principal: Option<EntityId>,
        authority: &HeldAuthority<'v>,
    ) -> Result<bool> {
        if !self.audience_readable_raw_in(rtxn, id, raw, authority)?
            || !self.credential_allows_row_in(rtxn, id)
            || !self.proof_live_in(rtxn)?
            || !crate::claim::has_live_support_in_txn(&self.store_read(), rtxn, body)?
        {
            return Ok(false);
        }
        // A mined preference with no principal is the class's to refuse.
        if principal.is_some()
            && crate::edit_distance::miner::is_mined_preference(&body.predicate)
            && !self.preference_in_force_in(rtxn, id, body)?
        {
            return Ok(false);
        }
        self.claim_causally_admitted_in(rtxn, id, body)
    }

    /// This reader's verdict on the class `view` under `filter`, `policy`
    /// and `grant`: the one `authority` holds, else judged now and held.
    fn class_verdict_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        grant: Option<&Scope>,
        view: &ClassView<'_>,
        authority: &HeldAuthority<'v>,
    ) -> Result<bool> {
        let reader = ClassReader {
            key: &self.actor_key,
            turn_terms: self
                .actor_key
                .room_turn
                .as_ref()
                .map(|turn| turn.terms.get()),
            status: self.claim_status,
            filter,
            grant,
            policy: ClaimReadPolicy::of(policy),
        };
        let class = view.key();
        let verdicts = authority.class_verdicts();
        if let Some(verdict) = verdicts.held(&reader, &class) {
            return Ok(verdict);
        }
        let verdict = class_judge_in(self.vault, rtxn, &reader, view, authority)?;
        verdicts.hold(&reader, class, verdict);
        Ok(verdict)
    }
}
