//! Company-homed work talk under one-vault mode (federation.md #one-vault-mode).
//!
//! When the vault's `one_vault` policy row reads `on`, a member who brought
//! her own companion opens Direct conversations with that companion here, in
//! the company vault, through [`Vault::open_work_talk`]. Each such
//! conversation carries an immutable [`WorkTalkBinding`] on its body,
//! registered in `vault_meta` exactly as a leader chat registers its own
//! binding, and admits exactly the two bound actors as writers
//! ([`admit_work_talk_witness`]). The companion passes on the binding
//! instead of a vault-wide Content grant, so she gains no write anywhere
//! else in the company vault; no federation grant is minted.
//!
//! A member whose companion was born here (a work companion) has no brought
//! companion: her talk is company-homed already, and the open refuses with
//! [`RecordError::NoBroughtCompanion`]. Which stored companion is which is
//! the roster row's own `companion_brought` origin, written once by the
//! Complete step from the onboarding intent: never a body heuristic, so a
//! companion born in one workspace and brought into another still reads as
//! brought here.
//!
//! Members who joined before the mode was turned on acknowledge the notice
//! once, in person, through [`Vault::acknowledge_one_vault`]; the open
//! refuses until they do ([`RecordError::OneVaultNotTold`]).

use super::*;
use crate::conversation::{ConversationBody, ConversationKind};
use crate::edge::EdgeActorClass;
use crate::error::{GateError, RecordError};
use crate::memory::{Memory, MemoryResult};
use crate::registry::ENTITY_TYPE_CONVERSATION;
use serde::{Deserialize, Serialize};

/// The `body.extra` field naming a work-talk conversation's binding.
pub(crate) const WORK_TALK_FIELD: &str = "work_talk.v1";

/// The `vault_meta` prefix registering a work-talk binding:
/// `work_talk.v1/<conversation id>`.
const WORK_TALK_PREFIX: &[u8] = b"work_talk.v1/";

/// Who a work-talk conversation binds: the member and her brought companion,
/// as the member's roster row names them when the conversation opens. The
/// binding is immutable: a put that changes it is refused, and a local put
/// that names it without its `vault_meta` registration is refused (the
/// leader-chat rule).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkTalkBinding {
    /// The workspace whose one-vault mode homed this conversation here.
    pub workspace_ref: String,
    /// The member's PERSON: a conversation member, never a writer by itself.
    pub member_person: EntityId,
    /// The member's roster actor: one of the two admitted writers.
    pub member_actor: EntityId,
    /// The brought companion's PERSON: a conversation member.
    pub companion_person: EntityId,
    /// The brought companion's actor: the other admitted writer.
    pub companion_actor: EntityId,
}

impl WorkTalkBinding {
    /// Whether `actor` is one of the two writers this binding admits.
    #[must_use]
    pub fn admits(&self, actor: EntityId) -> bool {
        actor == self.member_actor || actor == self.companion_actor
    }
}

fn denied() -> Error {
    RecordError::ConversationDenied.into()
}

fn work_talk_key(id: EntityId) -> Vec<u8> {
    [WORK_TALK_PREFIX, id.as_bytes()].concat()
}

/// The binding the work-talk conversation `room` carries, `None` for any
/// other room: an absent id, a non-conversation, or a conversation without
/// the field. A field fails closed (`ConversationDenied`) when it does not
/// decode, or when this vault's open door did not register it under
/// `work_talk.v1/<room>` with the same bytes: a replicated body carries the
/// field without its local registration, so a forged binding, one copied
/// under another id, or one added to an unbound conversation admits no
/// writer and opens no read.
pub(crate) fn work_talk_binding_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> Result<Option<WorkTalkBinding>> {
    if vault.get_entity_type_in_txn(txn, &room)? != Some(ENTITY_TYPE_CONVERSATION) {
        return Ok(None);
    }
    let body = crate::conversation::body_in(vault, txn, room)?;
    let Some(value) = body.extra.get(WORK_TALK_FIELD) else {
        return Ok(None);
    };
    let encoded = rmp_serde::to_vec_named(value).map_err(|_| denied())?;
    if vault
        .store
        .vault_meta
        .get(txn, &work_talk_key(room))?
        .as_deref()
        != Some(encoded.as_slice())
    {
        return Err(denied());
    }
    let binding: WorkTalkBinding = rmp_serde::from_slice(&encoded).map_err(|_| denied())?;
    Ok(Some(binding))
}

/// Admits a witness into `room` as `actor` when the room carries a work-talk
/// binding: `None` for any other room, the binding for one of its two bound
/// actors, and a refusal for a third writer. Call it unconditionally beside
/// `admit_leader_chat_witness` on every witness path: it no-ops on unbound
/// rooms and refuses even a Content-granted writer the binding does not name.
pub(crate) fn admit_work_talk_witness(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    actor: EntityId,
) -> Result<Option<WorkTalkBinding>> {
    let Some(binding) = work_talk_binding_in_txn(vault, txn, room)? else {
        return Ok(None);
    };
    if !binding.admits(actor) {
        return Err(denied());
    }
    Ok(Some(binding))
}

/// The roster actor still speaks for its PERSON now: a live `AGENT_DEF`
/// anchored to it. The binding names actors, so the open refuses a row whose
/// actors no longer answer for their persons (the brought-companion anchor
/// check, re-read at open).
fn require_bound_actor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    person: EntityId,
    reason: &'static str,
) -> Result<()> {
    if vault.get_entity_type_in_txn(txn, &actor)? != Some(ENTITY_TYPE_AGENT_DEF) {
        return Err(invalid(reason));
    }
    let now = vault.store.clock.now_recorded_at();
    let anchor = crate::subject_model::actor_subject_anchor_in_txn(vault, txn, &actor, now)?;
    if anchor.is_none_or(|anchor| {
        anchor.subject_ref != person
            || anchor.subject_kind != crate::write_envelope::subject_record::SubjectKind::Person
    }) {
        return Err(invalid(reason));
    }
    Ok(())
}

/// The vault's one-vault mode now, `None` for no row. An unreadable row fails
/// closed: the caller refuses rather than guessing a mode.
fn one_vault_mode_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Option<OneVaultMode>> {
    match crate::gate::resolve_policy_manifest(&vault.store, txn)?.one_vault_policy() {
        OneVaultRead::Unreadable => Err(RecordError::OneVaultSettingUnreadable.into()),
        OneVaultRead::NoRow => Ok(None),
        OneVaultRead::Row(policy) => Ok(Some(policy.mode())),
    }
}

impl Vault {
    /// Opens a company-homed work-talk conversation for the member `member`
    /// authenticates, and answers its id.
    ///
    /// The member, in person, opens a Direct conversation in this vault
    /// between her own PERSON and her brought companion's PERSON. Both
    /// persons and both writers come from her roster row, never from the
    /// caller; her person is the proof's live revalidation in this
    /// transaction, as a brought companion's consent is revalidated. The two
    /// bound writers are the roster actors: the member witnesses as her
    /// member actor, the companion as her own actor.
    ///
    /// Refusals, checked in this order: an unreadable setting refuses with
    /// the onboarding's `OneVaultSettingUnreadable`; a mode of `off`, or no
    /// row, with `WorkTalkStaysWithMember`; a member who was never told with
    /// `OneVaultNotTold`; a member with no brought companion, born or
    /// otherwise, with `NoBroughtCompanion`. A person with no roster row in
    /// this workspace is not a member here (`EntityNotFound`).
    pub fn open_work_talk(
        &self,
        workspace_ref: &str,
        member: &AuthenticatedOwner,
    ) -> Result<EntityId> {
        validate_name(
            workspace_ref,
            "workspace_ref must be 1..=256 bytes and contain no NUL",
        )?;
        self.with_write_txn_grouped(|txn| {
            let person = member.revalidate_person_in_txn(self, txn)?;
            if one_vault_mode_in_txn(self, txn)? != Some(OneVaultMode::On) {
                return Err(RecordError::WorkTalkStaysWithMember.into());
            }
            let key = RosterMemberKey {
                workspace_ref: workspace_ref.to_owned(),
                person_ref: person,
            };
            let row = MEMBER
                .get(&self.store, txn, &key)?
                .ok_or(Error::EntityNotFound)?;
            if row.one_vault_told.is_none() {
                return Err(RecordError::OneVaultNotTold.into());
            }
            let (Some(companion_person), Some(companion_actor)) =
                (row.companion_person_ref, row.companion_actor_ref)
            else {
                return Err(RecordError::NoBroughtCompanion.into());
            };
            if !row.companion_brought {
                return Err(RecordError::NoBroughtCompanion.into());
            }
            require_bound_actor_in_txn(
                self,
                txn,
                row.actor_ref,
                person,
                "member roster actor must be a live AGENT_DEF anchored to the member PERSON",
            )?;
            require_bound_actor_in_txn(
                self,
                txn,
                companion_actor,
                companion_person,
                "companion roster actor must be a live AGENT_DEF anchored to the companion PERSON",
            )?;
            let binding = WorkTalkBinding {
                workspace_ref: workspace_ref.to_owned(),
                member_person: person,
                member_actor: row.actor_ref,
                companion_person,
                companion_actor,
            };
            let encoded =
                rmp_serde::to_vec_named(&binding).map_err(|_| invalid("work talk binding"))?;
            let mut body = ConversationBody {
                kind: ConversationKind::Direct,
                member_ids: vec![person, companion_person],
                ..Default::default()
            };
            body.extra.insert(
                WORK_TALK_FIELD.to_owned(),
                rmp_serde::from_slice(&encoded).map_err(|_| denied())?,
            );
            let id = EntityId::now();
            let at = self.store.clock.now_recorded_at();
            self.store
                .vault_meta
                .put(txn, &work_talk_key(id), &encoded)?;
            crate::conversation::create_in_txn(
                self,
                txn,
                id,
                &body,
                WriteActor::new(row.actor_ref, EdgeActorClass::Agent),
                TimeRange { start: at, end: at },
                at,
                &[],
            )?;
            // The talk adopts the DAG at birth, so no ChildOf edge reaches it
            // except through an admitted append (the witness producer's or
            // the DAG door's permit, each behind `admit_work_talk_witness`):
            // a raw TURN + ChildOf pair from a structural put is refused
            // before the first turn as after it.
            crate::conversation_dag::migrate_in_txn(self, txn, &id)?;
            Ok(id)
        })
    }

    /// Records that the member `member` authenticates was told one-vault mode
    /// is on, on her own roster row, and answers the told time. The mode must
    /// read `on`: while it is `off`, or no row names it, the acknowledge is
    /// refused with `WorkTalkStaysWithMember`, and an unreadable row fails
    /// closed as the open does. An identical retry keeps the first time.
    pub fn acknowledge_one_vault(
        &self,
        workspace_ref: &str,
        member: &AuthenticatedOwner,
    ) -> Result<u64> {
        validate_name(
            workspace_ref,
            "workspace_ref must be 1..=256 bytes and contain no NUL",
        )?;
        self.with_write_txn_grouped(|txn| {
            let person = member.revalidate_person_in_txn(self, txn)?;
            if one_vault_mode_in_txn(self, txn)? != Some(OneVaultMode::On) {
                return Err(RecordError::WorkTalkStaysWithMember.into());
            }
            let key = RosterMemberKey {
                workspace_ref: workspace_ref.to_owned(),
                person_ref: person,
            };
            let mut row = MEMBER
                .get(&self.store, txn, &key)?
                .ok_or(Error::EntityNotFound)?;
            if let Some(told) = row.one_vault_told {
                return Ok(told);
            }
            let told = self.store.clock.now_recorded_at();
            row.one_vault_told = Some(told);
            MEMBER.put(&self.store, txn, &key, &row)?;
            Ok(told)
        })
    }
}

/// The proof the host bound for this surface's own actor, for a door the
/// member takes in person: never an agent's surface and never a room turn's
/// (the `work_companion.set` shape).
fn member_in_person(memory: &Memory<'_>, reason: &'static str) -> MemoryResult<AuthenticatedOwner> {
    let refused = || Error::Gate(GateError::ConsentOwnerNotAuthenticated(reason));
    if memory.room_turn().is_some() || memory.actor_class() != EdgeActorClass::Human {
        return Err(refused().into());
    }
    let owner = memory.owner_authorship().ok_or_else(refused)?;
    if owner.actor_for_read(memory.vault())? != memory.actor() {
        return Err(refused().into());
    }
    Ok(owner.clone())
}

impl Memory<'_> {
    /// Opens a company-homed work-talk conversation for the member who made
    /// this request in person, and answers its id. Only the owner proof a
    /// host bound for this surface's own actor carries it; an agent's or a
    /// room turn's surface opens nothing.
    pub fn workspace_work_talk_open(&self, workspace: &str) -> MemoryResult<EntityId> {
        let owner = member_in_person(
            self,
            "work talk opens only on the member's own authenticated request",
        )?;
        Ok(self.vault().open_work_talk(workspace, &owner)?)
    }

    /// Acknowledges the one-vault notice for the member who made this request
    /// in person, on her own roster row, and answers the told time. Only the
    /// owner proof a host bound for this surface's own actor carries it; an
    /// agent's or a room turn's surface acknowledges nothing.
    pub fn workspace_one_vault_acknowledge(&self, workspace: &str) -> MemoryResult<u64> {
        let owner = member_in_person(
            self,
            "one-vault notices are acknowledged only on the member's own authenticated request",
        )?;
        Ok(self.vault().acknowledge_one_vault(workspace, &owner)?)
    }
}
