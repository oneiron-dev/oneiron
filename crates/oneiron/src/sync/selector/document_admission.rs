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

/// Whether `id` sits in the closed subgraph `admission` resolved, read from
/// stored rows in this writer.
pub(super) fn admit_selected_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    selector: &SyncSelector,
    admission: &DocumentGrant,
) -> Result<()> {
    let selection = StoredSelection {
        vault,
        txn,
        selector,
        admission,
    };
    let mut budget = crate::vault::MAX_EDGE_QUERY_RESULTS;
    let Some((visible, seed)) = selection.candidate(id, &mut budget)? else {
        return Err(denied());
    };
    if facet_filter(admission.position.as_scope()).is_none() || visible || seed {
        return Ok(());
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
            return Ok(());
        }
    }
    Err(denied())
}

struct StoredSelection<'a, 'env> {
    vault: &'a Vault,
    txn: &'a heed::RoTxn<'env>,
    selector: &'a SyncSelector,
    admission: &'a DocumentGrant,
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
                if !facets.contains(&edge.target) {
                    return Ok(None);
                }
                seed = true;
            }
        }
        Ok(Some((decision.facet_visible, seed)))
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
