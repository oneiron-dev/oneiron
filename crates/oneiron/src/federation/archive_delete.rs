//! Who may delete one record the cleanup archived (ARCH-0073 §7, OF-449 L4),
//! judged from the vault's own rows in the caller's snapshot.
//!
//! The live Owner deletes anything its bound credential reaches. An Admin
//! deletes what the resource axes of its live membership grant hold; an
//! Admin or a Member deletes an item it provably owns (a TASK by its Owner
//! fact, a NOTE by its author); the records the vault mints itself are no
//! one's own. For a person delete is a role default, never a Grant it must
//! hold; a Viewer, a Delegate or a guest has none. An agent deletes only
//! under ONE live Grant that names the `delete` class and holds the record,
//! given by a live Owner or by an Admin still holding it. No second
//! permission ledger is kept, and nothing a request carries asserts a role,
//! an owner or a Grant: the answer is a sealed [`ArchiveDeleteAuthority`],
//! read again in each write that deletes.

use std::collections::BTreeSet;

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
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_NOTE, ENTITY_TYPE_TASK};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::write_envelope::WriteActor;

/// The scope class a Grant names to delete, never an SDK method name.
const DELETE_VERB: &str = "delete";

/// The role an archive delete was admitted under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArchiveDeleteRole {
    /// A live owner of the vault, co-owners included.
    Owner,
    /// A live Admin whose grant's resource axes hold the record.
    Admin,
    /// A live Admin or Member who provably owns the record.
    Member,
    /// An agent under one Grant that names `delete`.
    Agent,
}

impl ArchiveDeleteRole {
    /// The role's pinned name in receipts and gate reason codes.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
            Self::Agent => "agent",
        }
    }
}

/// One record's admitted archive delete: the role, and the grant that
/// admitted it when one did. Only [`require_archive_delete_in_txn`] builds
/// one, so no caller can assert it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ArchiveDeleteAuthority {
    role: ArchiveDeleteRole,
    grant: Option<EntityId>,
}

impl ArchiveDeleteAuthority {
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
pub(crate) struct ArchiveDeleteCaller<'a> {
    pub(crate) actor: EntityId,
    pub(crate) class: EdgeActorClass,
    pub(crate) credential: Option<&'a VerifiedSlip>,
}

/// Why one archived record may not be deleted by this caller. Each refuses
/// that record alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArchiveDeleteRefusal {
    /// The person holds no live write binding; a root bound to no PERSON
    /// is no one here.
    Unbound,
    /// No role or Grant this caller holds deletes this record.
    NoStanding,
    /// The bound credential does not reach this record.
    CredentialBounds,
    /// A row this check reads could not be read.
    Unreadable(ErrorKind),
}

impl ArchiveDeleteRefusal {
    /// The refusal's text; its code leads it.
    pub(crate) fn message(self) -> String {
        match self {
            Self::Unbound => {
                "archive_delete_unbound: the caller holds no live authority binding".to_owned()
            }
            Self::NoStanding => "archive_delete_no_standing: no role or Grant the caller holds \
                                 deletes this archived record"
                .to_owned(),
            Self::CredentialBounds => {
                "archive_delete_credential_bounds: the bound credential does not reach this \
                 archived record"
                    .to_owned()
            }
            Self::Unreadable(kind) => format!(
                "archive_delete_unreadable: the authority for this archived record could not be \
                 read ({kind:?})"
            ),
        }
    }
}

/// The authority `caller` holds in `txn` to delete the archived `target`.
///
/// The Owner arm runs first and counts every live owner of the vault,
/// co-owners included (`policy_model::owners_in_txn`), with no clearance
/// term: an Owner deletes any record its bound credential reaches. A person
/// must first hold a live write binding, so a root bound to no PERSON gets
/// no role. A failure to read the credential check or any other arm refuses
/// this record alone ([`ArchiveDeleteRefusal::Unreadable`]).
///
/// # Errors
/// A store or fold failure of the binding or owners read, as the owner's
/// own delete path meets. A missing or unbound person, or a fold with two
/// roots, is [`ArchiveDeleteRefusal::Unbound`].
pub(crate) fn require_archive_delete_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: ArchiveDeleteCaller<'_>,
    target: EntityId,
) -> Result<std::result::Result<ArchiveDeleteAuthority, ArchiveDeleteRefusal>> {
    if caller.class == EdgeActorClass::Human {
        match vault.verify_write_actor_in_txn(txn, &WriteActor::new(caller.actor, caller.class)) {
            Ok(_) => {}
            Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => {
                return Ok(Err(ArchiveDeleteRefusal::Unbound));
            }
            Err(error) => return Err(error),
        }
        if crate::policy_model::owners_in_txn(vault, txn)?.contains(&caller.actor) {
            let owner = ArchiveDeleteAuthority {
                role: ArchiveDeleteRole::Owner,
                grant: None,
            };
            let reaches = match caller.credential {
                None => Ok(true),
                Some(_) => TargetRecord::read_in(vault, txn, target).and_then(|record| {
                    credential_reaches(vault, txn, caller, record.as_ref(), true)
                }),
            };
            return Ok(match reaches {
                Ok(true) => Ok(owner),
                Ok(false) => Err(ArchiveDeleteRefusal::CredentialBounds),
                Err(error) => Err(ArchiveDeleteRefusal::Unreadable(error.kind())),
            });
        }
    }
    Ok(other_arms(vault, txn, caller, target)
        .unwrap_or_else(|error| Err(ArchiveDeleteRefusal::Unreadable(error.kind()))))
}

/// The Admin, Member and agent arms, then the bound credential.
fn other_arms(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: ArchiveDeleteCaller<'_>,
    target: EntityId,
) -> Result<std::result::Result<ArchiveDeleteAuthority, ArchiveDeleteRefusal>> {
    let Some(record) = TargetRecord::read_in(vault, txn, target)? else {
        return Ok(Err(ArchiveDeleteRefusal::NoStanding));
    };
    let admitted = match caller.class {
        EdgeActorClass::Human => person_arms(vault, txn, caller.actor, &record)?,
        EdgeActorClass::Agent | EdgeActorClass::System => agent_arm(vault, txn, caller, &record)?,
    };
    let Some(admitted) = admitted else {
        return Ok(Err(ArchiveDeleteRefusal::NoStanding));
    };
    if !credential_reaches(vault, txn, caller, Some(&record), false)? {
        return Ok(Err(ArchiveDeleteRefusal::CredentialBounds));
    }
    Ok(Ok(admitted))
}

/// The archived record as `txn` holds it: its kind, body and the position
/// the scoped doors select it at. `None` where no row is stored.
struct TargetRecord {
    id: EntityId,
    kind: u8,
    body: Vec<u8>,
    /// `None` where the record proves no position: no grant axis holds it.
    position: Option<Scope>,
}

impl TargetRecord {
    fn read_in(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<Option<Self>> {
        let Some(raw) = vault.get_raw_in(txn, &id)? else {
            return Ok(None);
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("archived record header"))?;
        let body = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("archived record header"))?
            .to_vec();
        let position = super::record_scope::disclosure_scope_for_stored_row(
            &vault.store,
            txn,
            id,
            header.entity_type,
            &body,
        )?;
        Ok(Some(Self {
            id,
            kind: header.entity_type,
            body,
            position,
        }))
    }
}

/// An Admin's in-scope delete, else an Admin's or a Member's own item, each
/// under one live membership grant over this shared vault. A personal vault
/// has no membership roles.
fn person_arms(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
    record: &TargetRecord,
) -> Result<Option<ArchiveDeleteAuthority>> {
    let Some(shared) = vault.shared_vault_creation_in_txn(txn)? else {
        return Ok(None);
    };
    let scope = FederationGrantScope::vault(shared.vault_id);
    let mut owns = None;
    let mut own_grant = None;
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
            FederationGrantRole::Owner | FederationGrantRole::Admin | FederationGrantRole::Member
        ) {
            continue;
        }
        if role.is_admin()
            && record
                .position
                .as_ref()
                .is_some_and(|position| role_axes_admit(&grant.authority_scope, position))
        {
            return Ok(Some(ArchiveDeleteAuthority {
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
    Ok(own_grant.map(|grant| ArchiveDeleteAuthority {
        role: ArchiveDeleteRole::Member,
        grant: Some(grant),
    }))
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
        ENTITY_TYPE_TASK => Ok(vault
            .task_standing_in(txn, record.id)?
            .is_some_and(|standing| standing.owner == person)),
        ENTITY_TYPE_NOTE => {
            #[cfg(feature = "sync")]
            let resolved = crate::entity_doc::resolve_record_body(
                &vault.store,
                txn,
                &record.id,
                &record.body,
            )?;
            #[cfg(feature = "sync")]
            let bytes = resolved.as_slice();
            #[cfg(not(feature = "sync"))]
            let bytes = record.body.as_slice();
            Ok(
                crate::note::decode_note_body_in_txn(&vault.store, txn, bytes)?
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
/// keeps its pact membership. Grants are never unioned.
fn agent_arm(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: ArchiveDeleteCaller<'_>,
    record: &TargetRecord,
) -> Result<Option<ArchiveDeleteAuthority>> {
    if !crate::authority::live_agent_principal_in(&vault.store, txn, caller.actor, caller.class)? {
        return Ok(None);
    }
    let Some(position) = record.position.as_ref() else {
        return Ok(None);
    };
    let now = vault.instant_in_txn(txn)?.secs();
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    let shared = vault.shared_vault_creation_in_txn(txn)?.is_some();
    for (id, grant) in live_grants_in(vault, txn)? {
        if grant.member_ref != caller.actor
            || grant.role != FederationGrantRole::Delegate
            || !grant.confers_at(now)
            || !names_delete(&grant.authority_scope)
            || !grant
                .authority_scope
                .admits(DELETE_VERB, &delete_record(position), &Scope::top())
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
        return Ok(Some(ArchiveDeleteAuthority {
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

/// Whether the credential bound to `caller`, if any, reaches `record`: live,
/// held by the caller, carrying no named record, channel or invitation
/// bound, and its resource axes holding the record's position. Facets bind
/// every caller but an Owner (FACET-READ). The transport judged its verbs.
fn credential_reaches(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: ArchiveDeleteCaller<'_>,
    record: Option<&TargetRecord>,
    owner: bool,
) -> Result<bool> {
    let Some(proof) = caller.credential else {
        return Ok(true);
    };
    let claims = proof.claims();
    let Some(position) = record.and_then(|record| record.position.as_ref()) else {
        return Ok(false);
    };
    if claims.holder_ref != caller.actor.to_hex()
        || claims.invitation_ref.is_some()
        || !claims.records.is_empty()
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
    role.admits(DELETE_VERB, &delete_record(position), &Scope::top())
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
