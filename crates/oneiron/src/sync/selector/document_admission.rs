//! Transaction-bound peer document admission from stored ledger truth.
//!
//! Neither a remembered subscription nor a peer-controlled window map is
//! authority to append text. Grant, pact and graph selection share the writer.

use super::authorize::{ceiling_for_grant, resolve_selector_position};
use super::codec::{SyncSelector, selector_err};
use super::scope::{CoreferenceExportContext, entity_selector_decision, facet_filter};
use crate::authority::{AuthorityFold, FederationGrantActivation, federation_grant_activation};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::error::{Error, Result, SyncSelectorValidation as SelectorError};
use crate::federation::decode_federation_grant_body;
use crate::federation::{FederationGrant, FederationGrantRole, FederationGrantScope, Position};
use crate::{EntityId, Vault};
use std::collections::BTreeSet;

pub(super) struct DocumentGrant {
    pub(super) grant: FederationGrant,
    pub(super) fold: AuthorityFold,
    pub(super) position: Position,
    /// NOTE reads and peer writes use different verb classes on the same row.
    verb: &'static str,
}

pub(super) fn authorize_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    writer: Option<EntityId>,
) -> Result<DocumentGrant> {
    let raw = vault
        .get_raw_in(txn, &selector.grant_id)?
        .ok_or_else(|| selector_err(SelectorError::GrantNotFound))?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or_else(|| selector_err(SelectorError::GrantHeader))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_FEDERATION_GRANT {
        return Err(selector_err(SelectorError::GrantWrongType));
    }
    // A deleted grant confers nothing, even while an unapplied delete leaves
    // its body stored.
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &selector.grant_id)?.is_live() {
        return Err(selector_err(SelectorError::GrantNotFound));
    }
    let grant = decode_federation_grant_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])?;
    if grant.role.is_guest() || !matches!(grant.scope, FederationGrantScope::Vault { .. }) {
        return Err(selector_err(SelectorError::GrantScopeMismatch));
    }
    if grant.scope != scope {
        return Err(selector_err(SelectorError::GrantScopeMismatch));
    }
    if grant.member_ref != selector.member_ref
        || writer.is_some_and(|actor| actor != grant.member_ref)
    {
        return Err(selector_err(SelectorError::MemberNotGranted));
    }
    if writer.is_some()
        && !matches!(
            grant.role,
            FederationGrantRole::Owner
                | FederationGrantRole::Admin
                | FederationGrantRole::Member
                | FederationGrantRole::Delegate
        )
    {
        return Err(denied());
    }
    if !grant.confers_at(crate::unix_seconds_now()) {
        return Err(selector_err(SelectorError::GrantExpired));
    }
    // A readonly fold uses exactly this writer snapshot and cannot open a nested writer.
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    match federation_grant_activation(&fold, &selector.grant_id) {
        FederationGrantActivation::Unpacted | FederationGrantActivation::Active => {}
        FederationGrantActivation::Inactive(_) => {
            return Err(selector_err(SelectorError::GrantInactive));
        }
    }
    let position =
        resolve_selector_position(selector, &ceiling_for_grant(&fold, &selector.grant_id))?;
    Ok(DocumentGrant {
        grant,
        fold,
        position,
        verb: if writer.is_some() { "write" } else { "read" },
    })
}

/// Authorize an exact existing item edit under a promoted canonical window.
/// Read selection (facet closure) and write authority are independent checks.
pub(in crate::sync) fn admit_promoted_entity_write_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    new_blob: &[u8],
    scope: FederationGrantScope,
    selector: &SyncSelector,
    proof: &crate::authority::VerifiedSlip,
) -> Result<()> {
    let old = vault.get_raw_in(txn, &id)?.ok_or_else(denied)?;
    let old_header = EntityMetadataHeader::parse(&old).ok_or_else(denied)?;
    let new_header = EntityMetadataHeader::parse(new_blob).ok_or_else(denied)?;
    if old_header.entity_type != new_header.entity_type
        || old_header.learned_at != new_header.learned_at
        || proof.claims().holder_ref != selector.member_ref.to_hex()
        || !proof.allows_verb("write")
    {
        return Err(denied());
    }
    let admission = authorize_in_txn(vault, txn, scope, selector, Some(selector.member_ref))?;
    admit_selected_in_txn(vault, txn, id, selector, &admission)?;
    let mut record = crate::federation::record_scope::scope_for_blob(&vault.store, txn, id, &old)?
        .ok_or_else(denied)?;
    record.verbs =
        crate::federation::ScopeAxis::Some(std::collections::BTreeSet::from(["write".to_string()]));
    if !admission
        .grant
        .authority_scope
        .admits("write", &record, &crate::federation::Scope::top())
        || !proof
            .scope()
            .admits("write", &record, &crate::federation::Scope::top())
    {
        return Err(denied());
    }
    crate::federation::record_scope::validate_edit_birth_scope(
        &vault.store,
        txn,
        id,
        new_header.entity_type,
        &new_blob[ENTITY_METADATA_HEADER_LEN..],
    )
}

pub(in crate::sync) fn admit_document_write_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    scope: FederationGrantScope,
    selector: &SyncSelector,
) -> Result<()> {
    let admission = authorize_in_txn(vault, txn, scope, selector, Some(selector.member_ref))?;
    admit_selected_in_txn(vault, txn, id, selector, &admission)
}

/// Admits `id` only when it sits in the closed subgraph `admission`
/// resolved, read from stored rows in this writer.
pub(super) fn admit_selected_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    selector: &SyncSelector,
    admission: &DocumentGrant,
) -> Result<()> {
    if selected_in_txn(vault, txn, id, selector, admission, None)? {
        Ok(())
    } else {
        Err(denied())
    }
}

/// Whether sync egress under `admission` would carry `id`: it sits in the
/// closed subgraph, and neither it nor the seed that selects it is a row
/// the export withholds before selection. `device_only` is the export's
/// own read of the flagged worlds.
pub(super) fn egress_selected_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    selector: &SyncSelector,
    (admission, device_only): (&DocumentGrant, &BTreeSet<EntityId>),
) -> Result<bool> {
    selected_in_txn(vault, txn, id, selector, admission, Some(device_only))
}

/// Whether `id` sits in the closed subgraph `admission` resolved, read from
/// stored rows in this writer.
fn selected_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    selector: &SyncSelector,
    admission: &DocumentGrant,
    egress: Option<&BTreeSet<EntityId>>,
) -> Result<bool> {
    let selection = StoredSelection {
        vault,
        txn,
        selector,
        admission,
        egress,
    };
    let mut budget = crate::vault::MAX_EDGE_QUERY_RESULTS;
    let Some((visible, seed)) = selection.candidate(id, &mut budget)? else {
        return Ok(false);
    };
    if facet_filter(admission.position.as_scope()).is_none() || visible || seed {
        return Ok(true);
    }
    // The export's facet closure is ONE hop from a selected seed, never a
    // transitive walk. Re-read both endpoint rows and every live facet stamp
    // from this writer; a stale window cannot preserve a removed seed.
    for row in crate::ports::EdgeStoreRead::port_edges(
        &vault.store,
        txn,
        &id,
        crate::ports::EdgeDirection::Both,
        None,
        None,
    )? {
        spend(&mut budget)?;
        let edge = row?;
        if edge.kind == EdgeKind::SameAs
            && !super::scope::document_coreference_context_in_txn(
                vault,
                txn,
                &admission.fold,
                selector,
                id,
                edge.target,
            )?
            .allows(id, edge.target)
        {
            continue;
        }
        if selection
            .candidate(edge.target, &mut budget)?
            .is_some_and(|(_, seed)| seed)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

struct StoredSelection<'a, 'env> {
    vault: &'a Vault,
    txn: &'a heed::RoTxn<'env>,
    selector: &'a SyncSelector,
    admission: &'a DocumentGrant,
    /// Sync egress, with the worlds flagged device-only: a row also passes
    /// the exporter's own withholdings, so a row the export withholds never
    /// justifies another's selection.
    egress: Option<&'a BTreeSet<EntityId>>,
}

impl StoredSelection<'_, '_> {
    fn candidate(&self, id: EntityId, budget: &mut usize) -> Result<Option<(bool, bool)>> {
        let Some(raw) = self.vault.get_raw_in(self.txn, &id)? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if self
            .vault
            .local_hard_delete_marker_exists_in_txn(self.txn, &id)?
            || self.vault.store.off_record_sessions.contains_entity(&id)?
        {
            return Ok(None);
        }
        // A selector can only narrow a stored grant. Derive the current
        // digest-bound record position in this transaction, just as export
        // does; missing or stale stamps cannot acquire authority from a
        // matching legacy selector (including via the facet closure below).
        let Some(mut record) =
            crate::federation::record_scope::scope_for_blob(&self.vault.store, self.txn, id, &raw)?
        else {
            return Ok(None);
        };
        let withheld = match self.egress {
            Some(device_only) => !self.egress_carries(id, &raw, device_only)?,
            None => false,
        };
        if withheld
            || !super::scope::settled_world_selected(
                &raw,
                &record,
                self.admission.position.as_scope(),
            )
        {
            return Ok(None);
        }
        // Role verbs gate peer writes on top of the stored authority scope.
        if self.admission.verb == "write"
            && !crate::federation::grant_allows_content_write(&self.admission.grant, &record)
        {
            return Ok(None);
        }
        record.verbs = crate::federation::ScopeAxis::Some(std::collections::BTreeSet::from([self
            .admission
            .verb
            .to_owned()]));
        if !self.admission.grant.authority_scope.admits(
            self.admission.verb,
            &record,
            &crate::federation::Scope::top(),
        ) {
            return Ok(None);
        }
        let coreference = if header.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
            let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            if let crate::claim::ClaimSubject::Edge {
                source,
                kind: EdgeKind::SameAs,
                target,
            } = body.subject
            {
                super::scope::document_coreference_context_in_txn(
                    self.vault,
                    self.txn,
                    &self.admission.fold,
                    self.selector,
                    source,
                    target,
                )?
            } else {
                CoreferenceExportContext::default()
            }
        } else {
            CoreferenceExportContext::default()
        };
        let Some(decision) = entity_selector_decision(
            self.vault,
            (&id, &raw),
            self.selector,
            &Default::default(),
            self.admission.position.as_scope(),
            &coreference,
        ) else {
            return Ok(None);
        };
        let mut seed = false;
        if let Some(facets) = facet_filter(self.admission.position.as_scope()) {
            for row in crate::ports::EdgeStoreRead::port_edges(
                &self.vault.store,
                self.txn,
                &id,
                crate::ports::EdgeDirection::Out,
                Some(EdgeKind::FacetOf),
                None,
            )? {
                spend(budget)?;
                let edge = row?;
                let target_type = self.vault.get_entity_type_in_txn(self.txn, &edge.target)?;
                // The same stored endpoint type table used by the export
                // mirror: off-table rows neither seed nor suppress selection.
                if !target_type.is_some_and(|target| {
                    crate::batch::facet_of_endpoint_types_on_table(header.entity_type, target)
                }) {
                    continue;
                }
                if !facets.contains(&crate::federation::ScopeId(edge.target)) {
                    return Ok(None);
                }
                seed = true;
            }
        }
        Ok(Some((decision.facet_visible, seed)))
    }
}

impl StoredSelection<'_, '_> {
    /// The exporter's and the window packer's withholdings: an erased row, a
    /// claim no sync door ships, custody that may not sync, a row of a
    /// device-only world, an LFS chunk, a row its causal history does not
    /// admit. A stale row still ships and still selects; an epoch refuses a
    /// stale source before asking.
    fn egress_carries(
        &self,
        id: EntityId,
        raw: &[u8],
        device_only: &BTreeSet<EntityId>,
    ) -> Result<bool> {
        let state = crate::ports::TombstoneStoreRead::port_deletion_state(
            &self.vault.store,
            self.txn,
            &id,
        )?;
        if state.deleted
            || !crate::sync::local_claims::claim_sync_allowed(raw)
            || (raw.first().copied() == Some(crate::registry::ENTITY_TYPE_SECRET_CUSTODY)
                && !crate::secret_custody::custody_sync_allowed(&raw[ENTITY_METADATA_HEADER_LEN..]))
            || crate::settings::device_only_withholds(
                &self.vault.store,
                self.txn,
                device_only,
                &id,
            )?
            || crate::origin::lfs::is_lfs_chunk_asset_in_txn(&self.vault.store, self.txn, &id)?
        {
            return Ok(false);
        }
        match crate::authority::row_causal_admitted(self.vault, self.txn, &id, raw) {
            Err(Error::InvalidClaimBody(_)) => Ok(false),
            admitted => admitted,
        }
    }
}

fn spend(budget: &mut usize) -> Result<()> {
    *budget = budget
        .checked_sub(1)
        .ok_or(Error::IndexOverflow("document selector"))?;
    Ok(())
}

fn denied() -> Error {
    Error::sync_protocol(crate::error::SyncProtocolValidation::DocumentAdmissionDenied)
}
