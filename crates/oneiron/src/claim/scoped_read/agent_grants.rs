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

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use super::access_gate::HeldAuthority;
use super::*;
use crate::edge::EdgeActorClass;
use crate::federation::Scope;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_MACHINE, ENTITY_TYPE_SECRET_CUSTODY};

/// One reader's live Grants, each id with its Scope.
type ReaderGrants = Rc<[(EntityId, Scope)]>;

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
/// the first row that reader's B refuses and dropped with the txn's
/// [`HeldAuthority`]. A peer's and a named read's row checks share them, each
/// reading its own actor's entry, never another's.
#[derive(Clone, Default)]
pub(super) struct HeldGrants {
    by_reader: Rc<RefCell<BTreeMap<EntityId, ReaderGrants>>>,
    asked: AskedFilter,
}

impl HeldGrants {
    /// None held yet, for row checks that asked `asked`.
    pub(super) fn fresh(asked: AskedFilter) -> Self {
        Self {
            by_reader: Rc::default(),
            asked,
        }
    }

    /// The same Grants, for row checks that asked `asked`.
    pub(super) fn shared_asking(&self, asked: AskedFilter) -> Self {
        Self {
            by_reader: Rc::clone(&self.by_reader),
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
}

impl<'v> ScopedRead<'v> {
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
        authority: &HeldAuthority<'v>,
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
            reader_grants_in(self.vault, rtxn, reader).unwrap_or_else(|error| {
                warn_grant_errors(1, &[], Some(error.kind()));
                Vec::new()
            })
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

    /// The reader A may stand for: this key's own actor, while the key
    /// supplies no proof, carries no Scope and is not the owner's. A narrowed
    /// key (`read_nothing` among them) stays exactly as it is.
    fn grant_reader(&self) -> Option<EntityId> {
        let key = &self.actor_key;
        if key.proof.is_some() || key.authority_scope().is_some() || key.vault_owner_ref().is_some()
        {
            return None;
        }
        EntityId::from_hex(key.actor_ref()).ok()
    }

    /// The row under `grant` alone: the Grant first admits the row's record
    /// position, then the row's own admission runs under the floor a proof
    /// of the Grant gives this key, `request` met on top as the read met it.
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
        authority: &HeldAuthority<'v>,
        grant: &Scope,
    ) -> Result<bool> {
        if !self.grant_admits_position_in(rtxn, id, raw, grant)? {
            return Ok(false);
        }
        let floor = policy.retrieval_floor_for_actor_with_scope(Some(&self.actor_key), Some(grant));
        let filter = crate::gate::narrow_retrieval_filter(&floor, request)?
            .under_credential_of(&self.actor_key);
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
    let now = vault.instant_in_txn(txn)?.secs();
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    let (grants, undecoded) = vault.agent_grants_reporting_in_txn(txn)?;
    if !undecoded.is_empty() {
        warn_grant_errors(undecoded.len(), &undecoded, None);
    }
    Ok(grants
        .into_iter()
        .filter(|standing| standing.stands_in_txn(vault, txn, reader, "read", now, &owners))
        .map(|standing| (standing.id, standing.grant.authority_scope))
        .collect())
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
