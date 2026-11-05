//! Original inputs of the shared write gate's successful grant branch.
//!
//! This borrowed view is provenance data, not historical authorization or a
//! recipient-admission capability. The observer cannot change the gate result.

use super::*;
use crate::authority::AuthorityFold;

/// Inputs observed at the actual successful branch, before its locals leave
/// scope. No raw source body is serialized or retained by this view.
pub(crate) struct SharedVaultWriteInputs<'a> {
    vault_id: u64,
    writer: WriteActor,
    principal: WriteActor,
    fold: &'a AuthorityFold,
    grant_id: EntityId,
    grant_raw: &'a [u8],
    requested: &'a SharedVaultWrite,
    expiry_checked_at: Option<u64>,
}

/// Owned original inputs retained only by the actual batch frame. This is
/// ephemeral provenance data; it cannot be serialized as admission evidence.
pub(crate) struct OwnedSharedVaultWriteInputs {
    vault_id: u64,
    writer: WriteActor,
    principal: WriteActor,
    fold: AuthorityFold,
    grant_id: EntityId,
    grant_raw: Vec<u8>,
    requested: SharedVaultWrite,
    expiry_checked_at: Option<u64>,
}

impl OwnedSharedVaultWriteInputs {
    pub(crate) fn as_borrowed(&self) -> SharedVaultWriteInputs<'_> {
        SharedVaultWriteInputs {
            vault_id: self.vault_id,
            writer: self.writer,
            principal: self.principal,
            fold: &self.fold,
            grant_id: self.grant_id,
            grant_raw: &self.grant_raw,
            requested: &self.requested,
            expiry_checked_at: self.expiry_checked_at,
        }
    }
}

impl SharedVaultWriteInputs<'_> {
    /// Copies only the inputs supplied by this original success callback.
    pub(crate) fn into_owned(self) -> OwnedSharedVaultWriteInputs {
        OwnedSharedVaultWriteInputs {
            vault_id: self.vault_id,
            writer: self.writer,
            principal: self.principal,
            fold: self.fold.clone(),
            grant_id: self.grant_id,
            grant_raw: self.grant_raw.to_vec(),
            requested: self.requested.clone(),
            expiry_checked_at: self.expiry_checked_at,
        }
    }

    pub(crate) fn vault_id(&self) -> u64 {
        self.vault_id
    }

    pub(crate) fn writer(&self) -> WriteActor {
        self.writer
    }

    /// The actual folder-import substitution, when the original gate made one.
    pub(crate) fn principal(&self) -> WriteActor {
        self.principal
    }

    pub(crate) fn fold(&self) -> &AuthorityFold {
        self.fold
    }

    pub(crate) fn grant(&self) -> (EntityId, &[u8]) {
        (self.grant_id, self.grant_raw)
    }

    pub(crate) fn requested(&self) -> &SharedVaultWrite {
        self.requested
    }

    /// The clock value used by this grant's expiry predicate, not a later
    /// capture time. None means that predicate read no expiry clock.
    pub(crate) fn expiry_checked_at(&self) -> Option<u64> {
        self.expiry_checked_at
    }
}

impl Vault {
    /// Runs the original live write gate, observing only its successful grant
    /// branch. No observation means no captured input, not personal standing,
    /// a missing grant or permission to skip recipient source admission.
    pub(crate) fn authorize_shared_vault_write_observing_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
        writer: &WriteActor,
        requested: &SharedVaultWrite,
        mut on_success: Option<&mut dyn FnMut(SharedVaultWriteInputs<'_>)>,
    ) -> Result<()> {
        // A folder's note-import MACHINE writes as the member its own stored
        // record names as both its importer and its maker: that member's
        // binding and live grant decide, as for the member's own write, and
        // a refusal there is final. The stored actor stays the MACHINE. Every
        // other writer, and a MACHINE that names no such member, writes on
        // its own standing.
        let principal = match crate::note::folder_import_creator_in_txn(
            &self.store,
            txn,
            &writer.entity_ref(),
        )? {
            Some(importer) => {
                let member = WriteActor::new(importer, EdgeActorClass::Human);
                match writer.authority_frontier() {
                    Some(frontier) => member.with_authority_frontier(frontier),
                    None => member,
                }
            }
            None => *writer,
        };
        let fold = self.verify_write_actor_in_txn(txn, &principal)?;
        // A deleted shared vault takes no further write of any kind.
        if vault_id == 0
            || matches!(requested, SharedVaultWrite::PersonalVault)
            || self.shared_vault_deletion_in_txn(txn)?.is_some()
        {
            return Err(denied());
        }
        let member = principal.entity_ref();
        for entry in self
            .store
            .port_entity_ids_by_type(txn, ENTITY_TYPE_FEDERATION_GRANT, None)?
        {
            let id = entry?;
            let raw = self
                .store
                .port_entity_record(txn, &id)?
                .ok_or_else(denied)?
                .encode();
            if EntityMetadataHeader::parse(&raw)
                .is_none_or(|header| header.entity_type != ENTITY_TYPE_FEDERATION_GRANT)
            {
                return Err(denied());
            }
            // A deleted grant is no membership: its shell is skipped here, and a
            // stored body counts only while its row is live, checked last.
            if raw.len() == ENTITY_METADATA_HEADER_LEN
                && !crate::vault::live_entity_row_in_txn(&self.store, txn, &id)?.is_live()
            {
                continue;
            }
            let grant = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            let mut expiry_checked_at = None;
            if grant.scope != FederationGrantScope::vault(vault_id)
                || grant.member_ref != member
                || grant.expires_at.is_some_and(|expires| {
                    let at = self.store.clock.now_recorded_at();
                    expiry_checked_at = Some(at);
                    at >= expires
                })
                || matches!(
                    federation_grant_activation(&fold, &id),
                    FederationGrantActivation::Inactive(_)
                )
                || !crate::vault::live_entity_row_in_txn(&self.store, txn, &id)?.is_live()
            {
                continue;
            }
            if let SharedVaultWrite::Content(scope) = requested {
                if grant_allows_content_write(&grant, scope) {
                    if let Some(observe) = on_success.as_deref_mut() {
                        observe(SharedVaultWriteInputs {
                            vault_id,
                            writer: *writer,
                            principal,
                            fold: &fold,
                            grant_id: id,
                            grant_raw: &raw,
                            requested,
                            expiry_checked_at,
                        });
                    }
                    return Ok(());
                }
                continue;
            }
            let role_permits = match requested {
                SharedVaultWrite::Admin(_)
                | SharedVaultWrite::RuleConflict
                | SharedVaultWrite::WorkspaceSettings => grant.role.is_admin(),
                SharedVaultWrite::OrgRoot | SharedVaultWrite::Veto => {
                    grant.role == FederationGrantRole::Owner
                }
                SharedVaultWrite::PersonalVault | SharedVaultWrite::Content(_) => false,
            };
            if !role_permits {
                continue;
            }
            let (verb, mut record) = match requested {
                SharedVaultWrite::Admin(power) => (power.as_str(), Scope::top()),
                SharedVaultWrite::RuleConflict => ("admin", Scope::top()),
                SharedVaultWrite::WorkspaceSettings => ("write", Scope::top()),
                SharedVaultWrite::OrgRoot => ("org:root", Scope::top()),
                SharedVaultWrite::Veto => ("owner:veto", Scope::top()),
                SharedVaultWrite::PersonalVault | SharedVaultWrite::Content(_) => unreachable!(),
            };
            record.verbs = ScopeAxis::Some(BTreeSet::from([verb.to_owned()]));
            if grant.authority_scope.admits(verb, &record, &Scope::top()) {
                if let Some(observe) = on_success.as_deref_mut() {
                    observe(SharedVaultWriteInputs {
                        vault_id,
                        writer: *writer,
                        principal,
                        fold: &fold,
                        grant_id: id,
                        grant_raw: &raw,
                        requested,
                        expiry_checked_at,
                    });
                }
                return Ok(());
            }
        }
        Err(denied())
    }
}
