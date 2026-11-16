//! Who may delete one record (ARCH-0043 DEL-2, owner 9 Oct; ARCH-0073 §7,
//! OF-449 L4), judged from the vault's own rows in the caller's snapshot.
//! Every non-owner delete reads it: the cleanup archive's door and a
//! record's own (`Memory::safe_delete` once the owner predicate refuses).
//!
//! The live Owner deletes anything its bound credential reaches. An Admin
//! or a Deputy deletes what the resource axes of its live membership grant
//! hold; a Steward deletes in scope, what its live grant holds under the
//! `delete` class it names (ARCH-0043, owner 9 Nov); an Admin, a Steward or a Member
//! deletes an item it provably owns (a TASK by its Owner fact, a NOTE by
//! its author); the records the vault mints itself are no one's own. For a
//! person delete is a role default, never a Grant it must hold; a Viewer, a
//! Delegate or a guest has none. An agent deletes only
//! under ONE live Grant that names the `delete` class and holds the record,
//! given by a live Owner or by an Admin still holding it. No second
//! permission ledger is kept, and nothing a request carries asserts a role,
//! an owner or a Grant: the answer is a sealed [`DeleteAuthority`],
//! read again in each write that deletes.

use std::cell::RefCell;
use std::collections::BTreeSet;

use super::record_scope::note_world::any_world_at;
use super::{
    FederationGrant, FederationGrantRole, FederationGrantScope, MembershipStanding, Scope,
    ScopeAxis, decode_federation_grant_body,
};
use crate::Vault;
use crate::authority::VerifiedSlip;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind, Result};
use crate::ports::{DeletionMarker, EntityStoreRead, TombstoneStoreRead};
use crate::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_NOTE, ENTITY_TYPE_TASK};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::write_envelope::WriteActor;

/// The scope class a Grant names to delete, never an SDK method name.
const DELETE_VERB: &str = "delete";

pub(crate) use crate::deletion::archive_role::ArchiveDeleteRole;

/// One record's admitted delete: the role, and the grant that
/// admitted it when one did. Only [`require_delete_authority_in_txn`] builds
/// one, so no caller can assert it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DeleteAuthority {
    role: ArchiveDeleteRole,
    grant: Option<EntityId>,
}

impl DeleteAuthority {
    /// The role this delete was admitted under.
    pub(crate) const fn role(&self) -> ArchiveDeleteRole {
        self.role
    }

    /// The membership grant or agent Grant that admitted it; `None` for
    /// an Owner.
    pub(crate) const fn grant(&self) -> Option<EntityId> {
        self.grant
    }
}

/// Who asks: the actor and class a host bound, and the credential it
/// verified for that actor, if any. Identity, never authority.
#[derive(Clone, Copy)]
pub(crate) struct DeleteCaller<'a> {
    pub(crate) actor: EntityId,
    pub(crate) class: EdgeActorClass,
    pub(crate) credential: Option<&'a VerifiedSlip>,
}

/// The record one delete judges. Its row is read afresh in each check while
/// it stands. Once the delete's own scrub has applied (the row's deletion
/// fence), the scrub has retired its scope stamp, body and owner facts, so
/// the transaction that publishes the tombstone judges the record as the
/// last live read held it. The caller's binding, roles, Grants and
/// credential are read again every time.
pub(crate) struct DeleteTarget {
    id: EntityId,
    live: RefCell<Option<TargetRecord>>,
}

impl DeleteTarget {
    /// The record `id`, not yet read.
    #[must_use]
    pub(crate) const fn new(id: EntityId) -> Self {
        Self {
            id,
            live: RefCell::new(None),
        }
    }

    /// The record as `txn` holds it, or as its last live read held it once
    /// its deletion has applied; `None` where no live row was ever read.
    fn record_in(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Option<TargetRecord>> {
        if vault
            .store
            .port_deletion_marked(txn, DeletionMarker::RowFence, &self.id)?
        {
            return Ok(self.live.borrow().clone());
        }
        let record = TargetRecord::read_in(vault, txn, self.id)?;
        *self.live.borrow_mut() = record.clone();
        Ok(record)
    }

    /// The record's id.
    pub(crate) const fn id(&self) -> EntityId {
        self.id
    }

    /// Whether `person` provably owns the record, as [`Self::record_in`]
    /// reads it: a TASK by its Owner fact, a NOTE by the author its put was
    /// checked against. A person's own item never waits on a check-in
    /// (ROLES-CHECKIN 2k5; Engine ruling STEWARD-DELETE-WAIT = B).
    ///
    /// # Errors
    /// A store failure, or a NOTE body that does not decode.
    pub(crate) fn owned_by_in(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        person: EntityId,
    ) -> Result<bool> {
        match self.record_in(vault, txn)? {
            Some(record) => owned_by(vault, txn, person, &record),
            None => Ok(false),
        }
    }
}

/// Why one record may not be deleted by this caller. Each refuses that
/// record alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeleteRefusal {
    /// The person holds no live write binding and presents no live
    /// credential of its own; a root bound to no PERSON is no one here.
    Unbound,
    /// The person holds no membership role in this vault that deletes (a
    /// personal vault has none), or no such record is stored.
    NoStanding,
    /// A Member, Steward or Admin role deletes only an item it owns, and
    /// this caller does not own this one.
    NotOwnerOfItem,
    /// An Admin role holds no live grant whose resource axes hold this
    /// record, and the caller does not own it.
    OutOfAdminScope,
    /// The agent holds no one live Grant that names `delete`, holds this
    /// record and was given by a live Owner or an Admin still holding it.
    NoDeleteGrant,
    /// The bound credential does not reach this record.
    CredentialBounds,
    /// A row this check reads could not be read.
    Unreadable(ErrorKind),
}

impl DeleteRefusal {
    /// The refusal's code, the reason a typed refusal names.
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Unbound => "unbound",
            Self::NoStanding => "no_standing",
            Self::NotOwnerOfItem => "not_owner_of_item",
            Self::OutOfAdminScope => "out_of_admin_scope",
            Self::NoDeleteGrant => "no_delete_grant",
            Self::CredentialBounds => "credential_bounds",
            Self::Unreadable(_) => "unreadable",
        }
    }

    /// The refusal's text; its code leads it.
    pub(crate) fn message(self) -> String {
        let text = match self {
            Self::Unbound => "the caller holds no live authority binding".to_owned(),
            Self::NoStanding => {
                "the caller holds no role in this vault that deletes this record".to_owned()
            }
            Self::NotOwnerOfItem => {
                "a Member deletes only a NOTE or TASK it owns, and this caller does not own \
                 this record"
                    .to_owned()
            }
            Self::OutOfAdminScope => {
                "no Admin grant the caller holds holds this record, and the caller does not \
                 own it"
                    .to_owned()
            }
            Self::NoDeleteGrant => "the agent holds no live Grant that names delete and holds \
                                    this record"
                .to_owned(),
            Self::CredentialBounds => "the bound credential does not reach this record".to_owned(),
            Self::Unreadable(kind) => {
                format!("the authority for this record could not be read ({kind:?})")
            }
        };
        format!("{}: {text}", self.code())
    }
}

/// The authority `caller` holds in `txn` to delete `target`.
///
/// The Owner arm runs first and counts every live owner of the vault,
/// co-owners included (`policy_model::owners_in_txn`), with no clearance
/// term: an Owner deletes any record its bound credential reaches. A person
/// must first be someone here: a live PERSON with a live write binding, or,
/// where the rooted log binds it no key, one that presents a live `human`
/// credential this host verified for it ([`credential_names_person`]). A
/// human binding is the owner's (H149), so every other person on a rooted
/// vault acts by its credential. A root bound to no PERSON gets no role. A
/// failure to read the credential check or any other arm refuses this
/// record alone ([`DeleteRefusal::Unreadable`]).
///
/// # Errors
/// A store or fold failure of the binding or owners read, as the owner's
/// own delete path meets. A missing person, an unbound one with no
/// credential of its own, a quarantined binding or a fold with two roots is
/// [`DeleteRefusal::Unbound`].
pub(crate) fn require_delete_authority_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: DeleteCaller<'_>,
    target: &DeleteTarget,
) -> Result<std::result::Result<DeleteAuthority, DeleteRefusal>> {
    if caller.class == EdgeActorClass::Human {
        let bound = match vault
            .write_actor_bound_in_txn(txn, &WriteActor::new(caller.actor, caller.class))
        {
            Ok(bound) => bound,
            Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => {
                return Ok(Err(DeleteRefusal::Unbound));
            }
            Err(error) => return Err(error),
        };
        if !bound {
            match credential_names_person(vault, txn, caller) {
                Ok(true) => {}
                Ok(false) => return Ok(Err(DeleteRefusal::Unbound)),
                Err(error) => return Ok(Err(DeleteRefusal::Unreadable(error.kind()))),
            }
        }
        if crate::policy_model::owners_in_txn(vault, txn)?.contains(&caller.actor) {
            let owner = DeleteAuthority {
                role: ArchiveDeleteRole::Owner,
                grant: None,
            };
            let reaches = match caller.credential {
                None => Ok(true),
                Some(_) => target.record_in(vault, txn).and_then(|record| {
                    credential_reaches(vault, txn, caller, record.as_ref(), true)
                }),
            };
            return Ok(match reaches {
                Ok(true) => Ok(owner),
                Ok(false) => Err(DeleteRefusal::CredentialBounds),
                Err(error) => Err(DeleteRefusal::Unreadable(error.kind())),
            });
        }
    }
    Ok(other_arms(vault, txn, caller, target)
        .unwrap_or_else(|error| Err(DeleteRefusal::Unreadable(error.kind()))))
}

/// The Admin, Member and agent arms, then the bound credential.
fn other_arms(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: DeleteCaller<'_>,
    target: &DeleteTarget,
) -> Result<std::result::Result<DeleteAuthority, DeleteRefusal>> {
    let Some(record) = target.record_in(vault, txn)? else {
        return Ok(Err(match caller.class {
            EdgeActorClass::Human => DeleteRefusal::NoStanding,
            EdgeActorClass::Agent | EdgeActorClass::System => DeleteRefusal::NoDeleteGrant,
        }));
    };
    let admitted = match caller.class {
        EdgeActorClass::Human => person_arms(vault, txn, caller.actor, &record)?,
        EdgeActorClass::Agent | EdgeActorClass::System => {
            agent_arm(vault, txn, caller, &record)?.ok_or(DeleteRefusal::NoDeleteGrant)
        }
    };
    let admitted = match admitted {
        Ok(admitted) => admitted,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if !credential_reaches(vault, txn, caller, Some(&record), false)? {
        return Ok(Err(DeleteRefusal::CredentialBounds));
    }
    Ok(Ok(admitted))
}

/// The record as `txn` holds it: its kind, body, a TASK's Owner fact and
/// the position the scoped doors select it at. `None` where no row is
/// stored.
#[derive(Clone)]
struct TargetRecord {
    id: EntityId,
    kind: u8,
    body: Vec<u8>,
    /// A TASK's Owner fact; `None` for any other kind, or a TASK with none.
    task_owner: Option<EntityId>,
    /// `None` where the record proves no position: no grant axis holds it.
    position: Option<Scope>,
}

impl TargetRecord {
    fn read_in(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<Option<Self>> {
        let Some(raw) = vault.get_raw_in(txn, &id)? else {
            return Ok(None);
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("deleted record header"))?;
        let body = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("deleted record header"))?
            .to_vec();
        let position = super::record_scope::disclosure_scope_for_stored_row(
            &vault.store,
            txn,
            id,
            header.entity_type,
            &body,
        )?
        // A NOTE carries every world it is in; each grant or credential
        // holds it at one of them (FIX-LIST 9433).
        .map(|position| {
            super::record_scope::note_world::every_world_position(
                &vault.store,
                txn,
                id,
                header.entity_type,
                position,
            )
        });
        let task_owner = if header.entity_type == ENTITY_TYPE_TASK {
            vault
                .task_standing_in(txn, id)?
                .map(|standing| standing.owner)
        } else {
            None
        };
        Ok(Some(Self {
            id,
            kind: header.entity_type,
            body,
            task_owner,
            position,
        }))
    }
}

/// An Admin's in-scope delete, a Steward's in-scope delete under the
/// `delete` class its grant names, else an Admin's, a Steward's or a
/// Member's own item, each under one live membership grant over this shared
/// vault. A personal vault has no membership roles. The refusal names the
/// role the person holds: none, an Admin role out of scope, or a role that
/// deletes only its own items.
fn person_arms(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
    record: &TargetRecord,
) -> Result<std::result::Result<DeleteAuthority, DeleteRefusal>> {
    let Some(shared) = vault.shared_vault_creation_in_txn(txn)? else {
        return Ok(Err(DeleteRefusal::NoStanding));
    };
    let scope = FederationGrantScope::vault(shared.vault_id);
    let mut owns = None;
    let mut own_grant = None;
    let mut holds_role = false;
    let mut holds_admin = false;
    for (id, grant) in live_grants_in(vault, txn)? {
        if grant.member_ref != person || grant.scope != scope {
            continue;
        }
        let Some(MembershipStanding::Member { role, .. }) =
            vault.authenticated_grant_membership_in_txn(txn, scope, person, id)?
        else {
            continue;
        };
        if !matches!(
            role,
            FederationGrantRole::Owner
                | FederationGrantRole::Deputy
                | FederationGrantRole::Admin
                | FederationGrantRole::Steward
                | FederationGrantRole::Member
        ) {
            continue;
        }
        holds_role = true;
        holds_admin |= role.is_admin();
        if role == FederationGrantRole::Steward
            && names_delete(&grant.authority_scope)
            && record.position.as_ref().is_some_and(|position| {
                grant.authority_scope.admits(
                    DELETE_VERB,
                    &delete_record(&any_world_at(position, &grant.authority_scope.worlds)),
                    &Scope::top(),
                )
            })
        {
            return Ok(Ok(DeleteAuthority {
                role: ArchiveDeleteRole::Steward,
                grant: Some(id),
            }));
        }
        if role.is_admin()
            && record
                .position
                .as_ref()
                .is_some_and(|position| role_axes_admit(&grant.authority_scope, position))
        {
            return Ok(Ok(DeleteAuthority {
                role: ArchiveDeleteRole::Admin,
                grant: Some(id),
            }));
        }
        if own_grant.is_none() {
            let owned = match owns {
                Some(owned) => owned,
                None => *owns.insert(owned_by(vault, txn, person, record)?),
            };
            if owned {
                own_grant = Some(id);
            }
        }
    }
    Ok(match own_grant {
        Some(grant) => Ok(DeleteAuthority {
            role: ArchiveDeleteRole::Member,
            grant: Some(grant),
        }),
        None if !holds_role => Err(DeleteRefusal::NoStanding),
        None if holds_admin => Err(DeleteRefusal::OutOfAdminScope),
        None => Err(DeleteRefusal::NotOwnerOfItem),
    })
}

/// Whether `person` provably owns `record`: a TASK by its Owner fact, a NOTE
/// by the author its put was checked against. No other kind is anyone's.
fn owned_by(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
    record: &TargetRecord,
) -> Result<bool> {
    match record.kind {
        ENTITY_TYPE_TASK => Ok(record.task_owner == Some(person)),
        ENTITY_TYPE_NOTE => {
            Ok(
                crate::note::decode_note_core_in_txn(&vault.store, txn, &record.body)?
                    .author_ref
                    .is(person),
            )
        }
        _ => Ok(false),
    }
}

/// The first live Grant that alone names this agent, confers now, lists the
/// `delete` class in its explicit verb set, holds the record, was given by
/// a live owner (an owner's agent Grant) or by a person still holding an
/// Admin grant that holds the record (a Delegate), and on a shared vault
/// keeps its pact membership. Grants are never unioned. On an owner's agent
/// Grant, a verb class it names that admits `delete` lists it (FIX 8735).
fn agent_arm(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: DeleteCaller<'_>,
    record: &TargetRecord,
) -> Result<Option<DeleteAuthority>> {
    if !crate::authority::live_agent_principal_in(&vault.store, txn, caller.actor, caller.class)? {
        return Ok(None);
    }
    let Some(position) = record.position.as_ref() else {
        return Ok(None);
    };
    let now = vault.instant_in_txn(txn)?.secs();
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    let shared = vault.shared_vault_creation_in_txn(txn)?.is_some();
    let grants = live_grants_in(vault, txn)?;
    let classes = crate::federation::AgentVerbClasses::for_grants_in_txn(
        &vault.store,
        txn,
        grants
            .iter()
            .filter(|(_, grant)| grant.member_ref == caller.actor)
            .map(|(_, grant)| grant),
    )?;
    for (id, grant) in grants {
        let scope = grant.scope_for_verb(DELETE_VERB, &classes);
        if grant.member_ref != caller.actor
            || grant.role != FederationGrantRole::Delegate
            || !grant.confers_with_classes_at(now, &classes)
            || !names_delete(&scope)
            || !scope.admits(
                DELETE_VERB,
                &delete_record(&any_world_at(position, &scope.worlds)),
                &Scope::top(),
            )
        {
            continue;
        }
        let issuer_stands = match grant.delegated_by {
            Some(owner) if grant.owner_agent => owners.contains(&owner),
            Some(issuer) => issuer_holds(vault, txn, issuer, &owners, position)?,
            None => false,
        };
        if !issuer_stands || (shared && pact_lapsed(vault, txn, id, &grant)?) {
            continue;
        }
        return Ok(Some(DeleteAuthority {
            role: ArchiveDeleteRole::Agent,
            grant: Some(id),
        }));
    }
    Ok(None)
}

/// Whether the person who gave a Delegate still deletes `position`: a live
/// owner, or a live person with a live Admin grant over this shared vault
/// whose resource axes hold it.
fn issuer_holds(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    issuer: EntityId,
    owners: &[EntityId],
    position: &Scope,
) -> Result<bool> {
    if owners.contains(&issuer) {
        return Ok(true);
    }
    let Some(shared) = vault.shared_vault_creation_in_txn(txn)? else {
        return Ok(false);
    };
    if !crate::consent::person_is_live_in_txn(vault, txn, &issuer)? {
        return Ok(false);
    }
    let scope = FederationGrantScope::vault(shared.vault_id);
    for (id, grant) in live_grants_in(vault, txn)? {
        if grant.member_ref == issuer
            && grant.scope == scope
            && grant.role.is_admin()
            && role_axes_admit(&grant.authority_scope, position)
            && matches!(
                vault.authenticated_grant_membership_in_txn(txn, scope, issuer, id)?,
                Some(MembershipStanding::Member { .. })
            )
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// On a shared vault, whether the agent Grant `id` lost its pact
/// membership: the membership gate no longer admits it, or refuses it. Any
/// other failure of that check is an error, never a lapse or a standing.
fn pact_lapsed(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    grant: &FederationGrant,
) -> Result<bool> {
    match vault.authenticated_grant_membership_in_txn(txn, grant.scope, grant.member_ref, id) {
        Ok(Some(_)) => Ok(false),
        Ok(None) | Err(Error::Claim(_)) => Ok(true),
        Err(error) => Err(error),
    }
}

/// Whether `caller` presents a live credential this host verified for it as
/// a person: held by it, of the `human` class and bound to no invitation. It
/// stands in for the write binding a person on a rooted vault does not hold;
/// it confers no role, and [`credential_reaches`] still bounds every arm.
fn credential_names_person(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: DeleteCaller<'_>,
) -> Result<bool> {
    let Some(proof) = caller.credential else {
        return Ok(false);
    };
    let claims = proof.claims();
    Ok(claims.holder_ref == caller.actor.to_hex()
        && claims.actor_class.as_deref() == Some(crate::authority::ACTOR_CLASS_HUMAN)
        && claims.invitation_ref.is_none()
        && vault.capability_slip_is_live_in_txn(txn, proof)?)
}

/// Whether the credential bound to `caller`, if any, reaches `record`: live,
/// held by the caller, listing this record when record-bound, carrying no
/// channel or invitation bound, and its resource axes holding the record's
/// position. Facets bind every caller but an Owner (FACET-READ). The transport
/// judged its verbs.
fn credential_reaches(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: DeleteCaller<'_>,
    record: Option<&TargetRecord>,
    owner: bool,
) -> Result<bool> {
    let Some(proof) = caller.credential else {
        return Ok(true);
    };
    let claims = proof.claims();
    let Some(record) = record else {
        return Ok(false);
    };
    let Some(position) = record.position.as_ref() else {
        return Ok(false);
    };
    if claims.holder_ref != caller.actor.to_hex()
        || claims.invitation_ref.is_some()
        || (!claims.records.is_empty() && !claims.records.contains(&record.id.to_hex()))
        || !claims.channels.is_empty()
    {
        return Ok(false);
    }
    let credential = proof.scope();
    let facets = owner
        || matches!(credential.facets, ScopeAxis::All)
        || !position.facets.meet(&credential.facets).is_bottom();
    Ok(facets
        && role_axes_admit(credential, position)
        && vault.capability_slip_is_live_in_txn(txn, proof)?)
}

/// Whether `ceiling`'s resource axes (worlds, bands, audience, sensitivity)
/// hold `position`, its verb list not read: a person's delete is the role's
/// default.
fn role_axes_admit(ceiling: &Scope, position: &Scope) -> bool {
    let mut role = ceiling.clone();
    role.verbs = ScopeAxis::All;
    let position = any_world_at(position, &ceiling.worlds);
    role.admits(DELETE_VERB, &delete_record(&position), &Scope::top())
}

/// Whether `scope` lists the `delete` class in an explicit verb set: a
/// wildcard never stands for naming it.
fn names_delete(scope: &Scope) -> bool {
    matches!(&scope.verbs, ScopeAxis::Some(verbs) if verbs.contains(DELETE_VERB))
}

/// `position` as the record a delete names.
fn delete_record(position: &Scope) -> Scope {
    let mut record = position.clone();
    record.verbs = ScopeAxis::Some(BTreeSet::from([DELETE_VERB.to_owned()]));
    record
}

/// Every live FEDERATION_GRANT row, decoded. A row that does not decode is
/// an error.
fn live_grants_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(EntityId, FederationGrant)>> {
    let mut grants = Vec::new();
    for id in vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_FEDERATION_GRANT, None)?
    {
        let id = id?;
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            body,
        } = live_entity_row_in_txn(&vault.store, txn, &id)?
        else {
            continue;
        };
        grants.push((id, decode_federation_grant_body(&body)?));
    }
    Ok(grants)
}
