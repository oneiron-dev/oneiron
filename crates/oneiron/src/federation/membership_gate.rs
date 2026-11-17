//! Transaction-bound shared-vault membership write authorization.

use super::{
    FederationGrant, FederationGrantRole, FederationGrantScope, Scope, ScopeAxis,
    decode_federation_grant_body,
};
use crate::Vault;
use crate::authority::{FederationGrantActivation, federation_grant_activation};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeActorClass;
use crate::error::{ClaimError, Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::write_envelope::WriteActor;
use std::collections::BTreeSet;

pub use crate::batch::shared_vault_write::SharedVaultWrite;

fn denied() -> Error {
    Error::Claim(ClaimError::ActorLacksClaimAuthority {
        reason: "shared-vault role or named power does not authorize this write",
    })
}

impl Vault {
    /// Checks the current stored roster, role, named verb, and scope in one snapshot.
    /// A grant over another vault or an inactive pact never contributes a power.
    pub fn authorize_shared_vault_write(
        &self,
        vault_id: u64,
        writer: &WriteActor,
        requested: &SharedVaultWrite,
    ) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        self.authorize_shared_vault_write_in_txn(&txn, vault_id, writer, requested)
    }

    /// The writer a shared-vault write is judged as, in `txn`. A folder's
    /// note-import MACHINE writes as the member its own stored record names
    /// as both its importer and its maker, as for the member's own write.
    /// Every other writer, and a MACHINE that names no such member, writes on
    /// its own standing. A writer that gives a Grant names this principal as
    /// its giver (pass 28 R2), the one whose power the gate judged.
    pub(crate) fn shared_write_principal_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        writer: &WriteActor,
    ) -> Result<WriteActor> {
        let importer =
            crate::note::folder_import_creator_in_txn(&self.store, txn, &writer.entity_ref())?;
        Ok(match importer {
            Some(importer) => {
                let member = WriteActor::new(importer, EdgeActorClass::Human);
                match writer.authority_frontier() {
                    Some(frontier) => member.with_authority_frontier(frontier),
                    None => member,
                }
            }
            None => *writer,
        })
    }

    pub(crate) fn authorize_shared_vault_write_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
        writer: &WriteActor,
        requested: &SharedVaultWrite,
    ) -> Result<()> {
        // The principal's binding and live grant decide, and a refusal there
        // is final. The stored actor stays the writer.
        let principal = self.shared_write_principal_in_txn(txn, writer)?;
        let fold = self.verify_write_actor_in_txn(txn, &principal)?;
        // A deleted shared vault takes no further write of any kind.
        if vault_id == 0
            || matches!(requested, SharedVaultWrite::PersonalVault)
            || self.shared_vault_deletion_in_txn(txn)?.is_some()
        {
            return Err(denied());
        }
        let member = principal.entity_ref();
        // Only a Grant the fold stands behind confers here (pass 28 R3): a row no
        // counted act gives, or one put back after its end, is no membership. Its
        // scope, liveness and expiry are read there.
        for row in self.shared_vault_grants_in_txn(txn, vault_id)? {
            let (id, grant) = (row.id(), row.grant());
            if grant.member_ref != member
                || matches!(
                    federation_grant_activation(&fold, &id),
                    FederationGrantActivation::Inactive(_)
                )
            {
                continue;
            }
            if let SharedVaultWrite::Content(scope) = requested {
                if grant_allows_content_write(&grant, scope) {
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
                return Ok(());
            }
        }
        Err(denied())
    }
}

/// Shared role and resolved record-scope check used by local and sync write doors.
/// A Steward is not a content writer: it derives, archives and deletes in
/// scope through their own doors, and its preset names no `write`.
pub(crate) fn grant_allows_content_write(grant: &FederationGrant, scope: &Scope) -> bool {
    if !matches!(
        grant.role,
        FederationGrantRole::Owner
            | FederationGrantRole::Deputy
            | FederationGrantRole::Admin
            | FederationGrantRole::Member
            | FederationGrantRole::Delegate
    ) {
        return false;
    }
    // A NOTE in several worlds is held at one this Grant holds (FIX-LIST 9433).
    let mut record =
        super::record_scope::note_world::any_world_at(scope, &grant.authority_scope.worlds);
    record.verbs = ScopeAxis::Some(BTreeSet::from(["write".to_owned()]));
    grant
        .authority_scope
        .admits("write", &record, &Scope::top())
}

impl Vault {
    /// Check a staged content row in the same writer that commits its mutation.
    /// Personal vaults have no shared-creation row and keep their own authority.
    pub(crate) fn authorize_shared_content_write_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: crate::EntityId,
        writer: &WriteActor,
    ) -> Result<()> {
        let Some(creation) = self.shared_vault_creation_in_txn(txn)? else {
            return Ok(());
        };
        let scope = self.content_scope_in_txn(txn, id)?;
        self.authorize_shared_vault_write_in_txn(
            txn,
            creation.vault_id,
            writer,
            &SharedVaultWrite::Content(scope),
        )
    }

    /// Resolve the current content position, never a caller's asserted one.
    pub(crate) fn content_scope_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: crate::EntityId,
    ) -> Result<Scope> {
        let raw = self.get_raw_in(txn, &id)?.ok_or_else(denied)?;
        let header = EntityMetadataHeader::parse(&raw).ok_or_else(denied)?;
        let scope = match super::record_scope::scope_for_blob(&self.store, txn, id, &raw)? {
            Some(scope) => scope,
            None if header.entity_type == crate::registry::ENTITY_TYPE_NOTE => {
                // A NOTE born without a FacetOf edge has the ordinary base/default
                // position. Never use this fallback for another record kind.
                super::record_scope::default_stamp(
                    header.entity_type,
                    crate::claim::substrate_facet_id(id)?,
                )
            }
            None => return Err(denied()),
        };
        // A NOTE carries every world its live InWorld edges place it in; each
        // Grant holds it at one of them (FIX-LIST 9433).
        Ok(super::record_scope::note_world::every_world_position(
            &self.store,
            txn,
            id,
            header.entity_type,
            scope,
        ))
    }

    /// NOTE-specific spelling for the actor-bound editor doors.
    pub(crate) fn authorize_shared_note_write_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        note: crate::EntityId,
        writer: &WriteActor,
    ) -> Result<()> {
        self.authorize_shared_content_write_in_txn(txn, note, writer)
    }
}

/// One person's live standing in a shared vault (OF-531), read over the same
/// grant, activation, expiry and liveness checks the write door applies. A
/// standing grants nothing and authorizes no write; a room join reads it and
/// never changes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipStanding {
    /// A live Owner, Deputy, Admin, Member, Viewer or Delegate grant over this vault:
    /// roster standing (ARCH-0043). A Delegate's `role` stays `Delegate`: it
    /// is never administrative, and its grant keeps its own scope, expiry
    /// and one-hop limits.
    Member {
        grant: crate::EntityId,
        role: FederationGrantRole,
    },
    /// A live ask-scoped guest grant naming the person. It is not roster
    /// standing and never becomes one. For first-party admission
    /// (`Vault::authenticated_grant_membership_in_txn`) a live vault grant
    /// whose role is outside `FIRST_PARTY_MEMBER_ROLES` reads as this too:
    /// it keeps guest grading.
    ScopedGuest { grant: crate::EntityId },
}

/// The roles whose live grant over this shared vault makes its holder a
/// member for first-party admission (FIX 360): ARCH-0043's member
/// federation names Member, Viewer or Delegate on the roster, with Owner,
/// Deputy, Admin and Steward above them. Guest keeps guest grading.
pub(crate) const FIRST_PARTY_MEMBER_ROLES: [FederationGrantRole; 7] = [
    FederationGrantRole::Owner,
    FederationGrantRole::Deputy,
    FederationGrantRole::Admin,
    FederationGrantRole::Steward,
    FederationGrantRole::Member,
    FederationGrantRole::Viewer,
    FederationGrantRole::Delegate,
];

impl Vault {
    /// Whether `person` currently holds roster membership here. This reports
    /// standing only: it grants no read, write or owner authority.
    pub fn is_live_member_person(&self, person: &crate::EntityId) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        if !crate::consent::person_is_live_in_txn(self, &txn, person)? {
            return Ok(false);
        }
        let Some(creation) = self.shared_vault_creation_in_txn(&txn)? else {
            return self.recorded_owner_is_live_in_txn(&txn, *person);
        };
        Ok(matches!(
            self.membership_standing_in_txn(&txn, creation.vault_id, person)?,
            Some(MembershipStanding::Member { .. })
        ))
    }

    /// `person`'s standing in shared vault `vault_id` in the caller's
    /// snapshot; a deleted vault holds no standing. A live Delegate grant over
    /// this vault is roster standing (FIX 8738), read only when the person
    /// holds no other roster grant, so it never hides an Owner or Admin
    /// grant; a GitPush grant is purpose-specific and an owner-agent grant is
    /// the owner's verb grant to his agent, so neither gives standing. A
    /// guest grant is ask-scoped and names no vault, so it is evidence only
    /// for the shared vault whose store holds it: asked about another
    /// `vault_id`, it gives no standing (FIX 1014). `None`: no live grant.
    pub(crate) fn membership_standing_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
        person: &crate::EntityId,
    ) -> Result<Option<MembershipStanding>> {
        if vault_id == 0 || self.shared_vault_deletion_in_txn(txn)?.is_some() {
            return Ok(None);
        }
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        if fold.vault_root_is_conflicted() {
            return Err(denied());
        }
        let guest_vault = self
            .shared_vault_creation_in_txn(txn)?
            .map(|creation| creation.vault_id);
        // A member's and a delegate's standing: only a Grant the fold stands behind
        // (pass 28 R3), never a row alone.
        let mut delegate = None;
        for row in self.shared_vault_grants_in_txn(txn, vault_id)? {
            let (id, grant) = (row.id(), row.grant());
            if grant.member_ref != *person || !super::pact_admits_grant(&fold, &id, grant) {
                continue;
            }
            match grant.role {
                FederationGrantRole::Owner
                | FederationGrantRole::Deputy
                | FederationGrantRole::Admin
                | FederationGrantRole::Steward
                | FederationGrantRole::Member
                | FederationGrantRole::Viewer => {
                    return Ok(Some(MembershipStanding::Member {
                        grant: id,
                        role: grant.role,
                    }));
                }
                // An owner-agent grant is the owner's verb grant to his
                // agent, never roster standing.
                FederationGrantRole::Delegate if !grant.is_git_push() && !grant.owner_agent => {
                    delegate.get_or_insert(MembershipStanding::Member {
                        grant: id,
                        role: grant.role,
                    });
                }
                _ => {}
            }
        }
        if delegate.is_some() || guest_vault != Some(vault_id) {
            return Ok(delegate);
        }
        // A guest's Grant stands on its counted giving, never on its row (pass 28 R3c): a
        // row no counted act gives, one put back after its revoke and one widened in place
        // make no scoped guest, and one that does not decode is skipped, never a fault.
        let now = self.store.clock.now_recorded_at();
        for entry in self
            .store
            .port_entity_ids_by_type(txn, ENTITY_TYPE_FEDERATION_GRANT, None)?
        {
            let id = entry?;
            let crate::vault::LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_FEDERATION_GRANT,
                body,
            } = crate::vault::live_entity_row_in_txn(&self.store, txn, &id)?
            else {
                continue;
            };
            if super::guest_grant_in_fold(&fold, id, &body, now)
                .is_some_and(|standing| standing.grant().member_ref == *person)
            {
                return Ok(Some(MembershipStanding::ScopedGuest { grant: id }));
            }
        }
        Ok(None)
    }

    /// The standing ONE authenticated grant gives `principal` here, for
    /// first-party admission (FIX 360). Only `grant_id` is read, never
    /// another grant the person holds: it must be live, name `principal`,
    /// carry `scope`, be unexpired and not inactive under its pact. A vault
    /// scope must be this shared vault's own id. A role in
    /// [`FIRST_PARTY_MEMBER_ROLES`] is a `Member`; any other live grant is a
    /// `ScopedGuest`. A Connect guest grant stands on a personal vault too,
    /// and only while one Active pact with its peer binds it (FIX 3016).
    /// `None` (no such live grant, a deleted vault, a personal vault for any
    /// other purpose) is a refusal, never a member. Proving the transport
    /// stays the caller's.
    pub(crate) fn authenticated_grant_membership_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: FederationGrantScope,
        principal: crate::EntityId,
        grant_id: crate::EntityId,
    ) -> Result<Option<MembershipStanding>> {
        authenticated_grant_membership_for_store_in_txn(
            &self.store,
            self.privacy_posture(),
            txn,
            scope,
            principal,
            grant_id,
        )
    }
}

/// [`Vault::authenticated_grant_membership_in_txn`] for a reader that holds a
/// `Store` and the posture its vault opened with, and no `Vault` (FIX 7461):
/// the same standing of the one grant `grant_id`, each row read through its
/// store form.
pub(crate) fn authenticated_grant_membership_for_store_in_txn(
    store: &crate::store::Store,
    posture: crate::HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
    scope: FederationGrantScope,
    principal: crate::EntityId,
    grant_id: crate::EntityId,
) -> Result<Option<MembershipStanding>> {
    if super::shared_act::shared_vault_deletion_for_store_in_txn(store, txn)?.is_some() {
        return Ok(None);
    }
    let creation = super::shared_creation::shared_vault_creation_for_store_in_txn(store, txn)?;
    let stands = match scope {
        FederationGrantScope::Connect { .. } => true,
        FederationGrantScope::Vault { vault_id } => {
            creation.is_some_and(|creation| vault_id != 0 && vault_id == creation.vault_id)
        }
        FederationGrantScope::Ask { .. } => creation.is_some(),
    };
    if !stands {
        return Ok(None);
    }
    let fold = crate::authority::authority_fold_readonly_for_store_in_txn(store, posture, txn)?;
    if fold.vault_root_is_conflicted() {
        return Err(denied());
    }
    let Some(record) = store.port_entity_record(txn, &grant_id)? else {
        return Ok(None);
    };
    let raw = record.encode();
    if EntityMetadataHeader::parse(&raw)
        .is_none_or(|header| header.entity_type != ENTITY_TYPE_FEDERATION_GRANT)
        || raw.len() == ENTITY_METADATA_HEADER_LEN
        || !crate::vault::live_entity_row_in_txn(store, txn, &grant_id)?.is_live()
    {
        return Ok(None);
    }
    let grant = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    if grant.member_ref != principal
        || grant.is_git_push()
        || grant.scope != scope
        || grant
            .expires_at
            .is_some_and(|expires| store.clock.now_recorded_at() >= expires)
        || !super::pact_admits_grant(&fold, &grant_id, &grant)
    {
        return Ok(None);
    }
    // A Grant confers only while the fold stands behind it (pass 28 R3), never as a row
    // alone: one over the shared vault on its counted giving, a guest's on its own (R3c; a
    // Connect guest's on its Active pact too).
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    let now = store.clock.now_recorded_at();
    let stands = if matches!(grant.scope, FederationGrantScope::Vault { .. }) {
        super::shared_grant_row_in_fold(&fold, grant_id, body, now).is_some()
    } else {
        super::guest_grant_in_fold(&fold, grant_id, body, now).is_some()
    };
    if !stands {
        return Ok(None);
    }
    Ok(Some(
        if matches!(grant.scope, FederationGrantScope::Vault { .. })
            && FIRST_PARTY_MEMBER_ROLES.contains(&grant.role)
        {
            MembershipStanding::Member {
                grant: grant_id,
                role: grant.role,
            }
        } else {
            MembershipStanding::ScopedGuest { grant: grant_id }
        },
    ))
}
