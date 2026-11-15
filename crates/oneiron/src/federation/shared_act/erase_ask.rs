//! Erase asks (ARCH-0043 "Who may archive, delete and erase", 2026-10-09;
//! ARCH-0082 #role-defaults: "Any actor, in any role, may open an erase
//! proposal"; Engine ruling P24-SHAPE Q8 = A): in a shared vault every
//! person whose role reads the record may ask. A Member, a Viewer, a
//! Delegate or a Guest requests an erase, and an Admin, a Deputy (which
//! holds Admin's powers, ARCH-0082 #roles) or a Steward proposes one, while
//! only an Owner erases, by hand, through the erase doors and their veto
//! window. An ask erases nothing, starts no window and lifts no hold. It is
//! one durable record, an inbox ask to every live Owner, and the asker's own
//! view of it; an Owner closes it once they have erased the record or decided
//! not to.
//!
//! An agent asks too (UNBUILT-05; the lead's AGENT-ERASE-ASK-SCOPE = B,
//! 15 Nov 20:1x), on its own live owner Grant whose read reaches the record
//! ([`Vault::propose_erase_as_agent`]). In a shared vault its ask is the same
//! record, the agent its asker, with the same inbox ask to every live Owner;
//! in a personal vault it is one inbox ask to each live owner. By the act
//! rule (Fable pass 26, section 1.3) an agent's erase counts for nothing,
//! since erase is the Owner's own act (ARCH-0038 #ladder-actors), so it is a
//! question for those who may: this door writes only the question.
use super::{Role, check_vault, decode, encode, invalid, key};
use crate::check_in::RolePreset;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::ports::ClaimReadStatus;
use crate::{EntityId, Vault};

const ASK_PREFIX: &[u8] = b"shared-act:erase-ask:v1:";
/// The inbox producer of an erase ask; its event is `<ask id>:<owner id>`.
pub const NOTIFICATION_PRODUCER_ERASE_ASK: &str = "shared_vault.erase_ask";
/// The inbox producer of an agent's erase ask in a personal vault; its event
/// is `<agent id>:<record id>:<owner id>`, so asking again finds the ask
/// already put.
pub const NOTIFICATION_PRODUCER_ERASE_PROPOSAL: &str = "vault.erase_proposal";
/// The refusal for an agent with no live owner Grant whose read reaches the
/// record, and for a record that is not live: one answer for both.
const NO_READ: &str = "no live owner Grant of the caller reads the record";
const NO_STANDING: &str = "the caller is no live agent standing on a read Grant";
/// The act name an Owner's erase runs under, which a closing answer names.
const ERASE_ACT: &str = "erase";

/// Who asked: a role that works inside its scopes requests; a role that
/// runs or organises the vault proposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EraseAskKind {
    Request,
    Proposal,
}

impl EraseAskKind {
    /// What an erase ask from a live holder of `role` is, once its grant
    /// carries `read` (P24-SHAPE Q8 = A): a Member's, a Viewer's, a
    /// Delegate's or a Guest's request, or an Admin's, a Deputy's or a
    /// Steward's proposal. `None` for an Owner, who erases instead of
    /// asking; the erase itself stays the Owner's. An agent's ask is
    /// [`Self::for_agent_role`].
    pub(crate) const fn for_asker_role(role: Role) -> Option<Self> {
        match role {
            Role::Member | Role::Viewer | Role::Delegate | Role::Guest => Some(Self::Request),
            Role::Admin | Role::Deputy | Role::Steward => Some(Self::Proposal),
            Role::Owner => None,
        }
    }

    /// What an agent's erase ask is at the role its Grant reads in check-in
    /// (P24-SHAPE Q1 = A): a proposal at a role that runs or organises the
    /// vault, a request at one that works inside its scopes. An agent at
    /// the Owner role proposes, since it does not erase on its own proof
    /// before agent Owner keys.
    pub(crate) const fn for_agent_role(role: RolePreset) -> Self {
        match role {
            RolePreset::Owner | RolePreset::Deputy | RolePreset::Admin | RolePreset::Steward => {
                Self::Proposal
            }
            RolePreset::Member | RolePreset::Delegate | RolePreset::Guest => Self::Request,
        }
    }
}

/// Where an ask stands. Only an Owner closes one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EraseAskStatus {
    Open,
    /// The Owner `by` erased the record; `act` names the `erase` act it
    /// started where the veto window applied.
    Erased {
        by: String,
        act: Option<String>,
    },
    Declined {
        by: String,
    },
}

/// One person's or agent's request or proposal to erase a record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedEraseAsk {
    pub id: String,
    #[serde(with = "crate::federation::vault_id_decimal")]
    pub vault_id: u64,
    pub kind: EraseAskKind,
    /// The asker's PERSON id, or an agent asker's agent definition id, hex.
    pub asker: String,
    /// The record the asker wants erased, entity id hex.
    pub record: String,
    pub asked_at: u64,
    pub status: EraseAskStatus,
    pub closed_at: Option<u64>,
}

/// An agent's ask that the Owners erase a record
/// ([`Vault::propose_erase_as_agent`]). It erases nothing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EraseProposal {
    /// The record, entity id hex.
    pub record: String,
    /// A request or a proposal, by the role the agent's Grant reads.
    pub kind: EraseAskKind,
    /// In a shared vault, the erase ask it opened or found open, which
    /// `vault.shared.erase_asks` lists and an Owner closes. `None` in a
    /// personal vault, whose owners hold the ask in their inbox.
    pub shared_ask: Option<SharedEraseAsk>,
}

impl Vault {
    fn erase_asks_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
    ) -> Result<Vec<SharedEraseAsk>> {
        let mut asks = Vec::new();
        for row in self.store.vault_meta.prefix_iter(txn, ASK_PREFIX)? {
            let (_, raw) = row?;
            let ask: SharedEraseAsk = decode(&raw)?;
            if ask.vault_id == vault_id {
                asks.push(ask);
            }
        }
        Ok(asks)
    }

    /// Ask the Owners to erase `record`, a live record of this vault: every
    /// live holder whose grant carries `read` asks, a request or a proposal
    /// by their role ([`EraseAskKind::for_asker_role`]). Every live Owner gets an inbox ask
    /// naming the record. Asking again while the asker's ask for the record is
    /// open answers that ask, and writes nothing.
    pub fn ask_shared_erase(
        &self,
        asker: &AuthenticatedOwner,
        vault_id: u64,
        record: EntityId,
    ) -> Result<SharedEraseAsk> {
        let mut txn = self.store.env.write_txn()?;
        // Person tier; the role is read from the live roster below.
        let actor = asker.revalidate_person_in_txn(self, &txn)?;
        check_vault(self, &txn, vault_id)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let holders = self.live_act_holders(&txn, vault_id, now)?;
        let kind = holders
            .iter()
            .find(|holder| holder.member == actor)
            .and_then(|holder| {
                EraseAskKind::for_asker_role(holder.role)
                    .filter(|_| holder.can(&[holder.role], "read"))
            })
            .ok_or_else(invalid)?;
        if !crate::vault::live_entity_row_in_txn(&self.store, &txn, &record)?.is_live() {
            return Err(invalid());
        }
        let (ask, opened) = self.open_erase_ask_in_txn(
            &mut txn, vault_id, &holders, now, actor, kind, record, false,
        )?;
        // An ask already open answers with nothing written: the writer's
        // clock floors are dropped with it, as before the agent door
        // (Astra review of #8340).
        if opened {
            txn.commit()?;
        }
        Ok(ask)
    }

    /// The erase ask by `asker` for `record` in shared vault `vault_id`, a
    /// live record, and whether this call opened it: the one already open
    /// (with `declined_answers`, also one an Owner declined), else a new one,
    /// with an inbox ask to every live Owner of `holders` naming the record.
    /// The caller has judged `asker` and its `kind`.
    #[allow(clippy::too_many_arguments)]
    fn open_erase_ask_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        vault_id: u64,
        holders: &[super::LiveActHolder],
        now: u64,
        asker: EntityId,
        kind: EraseAskKind,
        record: EntityId,
        declined_answers: bool,
    ) -> Result<(SharedEraseAsk, bool)> {
        let (asker_hex, record_hex) = (asker.to_hex(), record.to_hex());
        if let Some(standing) = self
            .erase_asks_in_txn(txn, vault_id)?
            .into_iter()
            .find(|ask| {
                (ask.status == EraseAskStatus::Open
                    || (declined_answers && matches!(ask.status, EraseAskStatus::Declined { .. })))
                    && ask.asker == asker_hex
                    && ask.record == record_hex
            })
        {
            return Ok((standing, false));
        }
        let ask = SharedEraseAsk {
            id: self.store.clock.entity_id()?.to_hex(),
            vault_id,
            kind,
            asker: asker_hex,
            record: record_hex,
            asked_at: now,
            status: EraseAskStatus::Open,
            closed_at: None,
        };
        self.store
            .vault_meta
            .put(txn, &key(ASK_PREFIX, &ask.id), &encode(&ask)?)?;
        for owner in super::live_owners(holders, None) {
            self.record_notification_in_txn(
                txn,
                &NotificationEvent {
                    kind: NotificationKind::Ask,
                    source: NotificationSource {
                        producer: NOTIFICATION_PRODUCER_ERASE_ASK.to_owned(),
                        event: format!("{}:{}", ask.id, owner.to_hex()),
                        result: Some(ask.id.clone()),
                        ..NotificationSource::default()
                    },
                    subject_refs: vec![record],
                    recipient: Some(owner),
                    created_at: now,
                    origin_conversation: None,
                },
            )?;
        }
        Ok((ask, true))
    }

    /// `memory`'s agent asks the Owners to erase `record`, a live record its
    /// own live owner Grant reads (UNBUILT-05; AGENT-ERASE-ASK-SCOPE = B;
    /// ARCH-0082 #role-defaults: "Any actor, in any role, may open an erase
    /// proposal"). The ask is a request or a proposal by the role its Grants
    /// read ([`EraseAskKind::for_agent_role`]; a proposal when any reads a
    /// proposing role). In a shared vault it is the erase ask
    /// [`Self::ask_shared_erase`] writes, the agent its asker; in a personal
    /// vault, one inbox ask to each live owner naming the record. Asking
    /// again answers the same ask, and in a shared vault an ask the Owners
    /// declined answers too: an agent does not ask again what an Owner
    /// declined (Astra review of #8340). It erases nothing; the erase stays
    /// the Owner's own act.
    ///
    /// # Errors
    ///
    /// FORBIDDEN for a caller that is no agent, that is switched off, retired
    /// or archived, or that no live owner Grant listing `read` names; one
    /// FORBIDDEN for a record the agent does not read and for one
    /// that is not live; storage errors.
    pub fn propose_erase_as_agent(
        &self,
        memory: &Memory<'_>,
        record: EntityId,
    ) -> MemoryResult<EraseProposal> {
        let agent = memory.actor();
        if memory.actor_class() != EdgeActorClass::Agent {
            return Err(refused("the caller is no agent"));
        }
        // A caller with no live standing is refused before its lane persists
        // any clock (Astra review of #8340, F3); the writer's snapshot below
        // judges it again, and that judgement is the one that counts.
        {
            let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
            crate::memory::verify_actor_binding_in_txn(self, &txn, agent, EdgeActorClass::Agent)?;
            if crate::authority::principal_standing_in_txn(
                self,
                &txn,
                agent,
                EdgeActorClass::Agent,
                "read",
            )?
            .is_none()
            {
                return Err(refused(NO_STANDING));
            }
        }
        // The agent's own read lane, held to its own live owner Grants
        // whatever else admits a row (Astra review of #8340, F2), opened
        // before the writer (its verification snapshot closes first: LMDB
        // allows one per thread), then judged in the writer's snapshot,
        // which the ask is written in.
        let lane = memory.read_lane_within_own_agent_grants(ClaimReadStatus::Recorded)?;
        lane.persist_grant_clock()?;
        let mut txn = self.store.env.write_txn().map_err(crate::Error::from)?;
        crate::memory::verify_actor_binding_in_txn(self, &txn, agent, EdgeActorClass::Agent)?;
        // The one standing rule, in this snapshot: an enabled, active agent
        // definition the archive has not taken, on a live owner Grant that
        // lists `read` and keeps its pact membership (review of #8340).
        if crate::authority::principal_standing_in_txn(
            self,
            &txn,
            agent,
            EdgeActorClass::Agent,
            "read",
        )?
        .is_none()
        {
            return Err(refused(NO_STANDING));
        }
        let policy = lane.live_policy_manifest_in(&txn)?;
        if !lane.is_ref_readable_with_policy_in(&txn, &policy, &record)?
            || !crate::vault::live_entity_row_in_txn(&self.store, &txn, &record)?.is_live()
        {
            return Err(refused(NO_READ));
        }
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let kind = self
            .agent_erase_ask_kind_in_txn(&txn, agent, now)?
            .ok_or_else(|| refused("no live owner Grant names the caller"))?;
        let shared_ask = match self.shared_vault_creation_in_txn(&txn)? {
            Some(creation) => {
                check_vault(self, &txn, creation.vault_id)?;
                let holders = self.live_act_holders(&txn, creation.vault_id, now)?;
                Some(
                    self.open_erase_ask_in_txn(
                        &mut txn,
                        creation.vault_id,
                        &holders,
                        now,
                        agent,
                        kind,
                        record,
                        true,
                    )?
                    .0,
                )
            }
            None => {
                self.propose_owner_erase_in_txn(&mut txn, now, agent, record)?;
                None
            }
        };
        txn.commit().map_err(crate::Error::from)?;
        Ok(EraseProposal {
            record: record.to_hex(),
            kind,
            shared_ask,
        })
    }

    /// What `agent`'s erase ask is, by the roles its live owner Grants read
    /// in check-in: each names it, stands at `now` and was given by a live
    /// owner. `None` when no such Grant exists.
    fn agent_erase_ask_kind_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        agent: EntityId,
        now: u64,
    ) -> Result<Option<EraseAskKind>> {
        let owners = crate::policy_model::owners_in_txn(self, txn)?;
        let mut kind = None;
        for standing in crate::federation::agent_grants_for_store_in_txn(&self.store, txn)? {
            if standing.grant.member_ref != agent
                || !standing.stands_at(now)
                || !owners.contains(&standing.delegated_by)
            {
                continue;
            }
            let role = crate::check_in::agent_grant_role_in_txn(self, txn, agent, &standing.grant)?;
            let asks = EraseAskKind::for_agent_role(role);
            if kind != Some(EraseAskKind::Proposal) {
                kind = Some(asks);
            }
        }
        Ok(kind)
    }

    /// A personal vault's erase ask by `agent` for `record`: one inbox ask
    /// to each live owner, naming the record. Asking again finds the ask
    /// already put, so an owner who set it aside is not asked again.
    fn propose_owner_erase_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        now: u64,
        agent: EntityId,
        record: EntityId,
    ) -> Result<()> {
        let (agent_hex, record_hex) = (agent.to_hex(), record.to_hex());
        for owner in crate::policy_model::owners_in_txn(self, txn)? {
            self.record_notification_in_txn(
                txn,
                &NotificationEvent {
                    kind: NotificationKind::Ask,
                    source: NotificationSource {
                        producer: NOTIFICATION_PRODUCER_ERASE_PROPOSAL.to_owned(),
                        event: format!("{agent_hex}:{record_hex}:{}", owner.to_hex()),
                        result: Some(record_hex.clone()),
                        ..NotificationSource::default()
                    },
                    subject_refs: vec![record],
                    recipient: Some(owner),
                    created_at: now,
                    origin_conversation: None,
                },
            )?;
        }
        Ok(())
    }

    /// The erase asks `reader` may see in `vault_id`: every ask for a live
    /// Owner, the reader's own asks for anyone else.
    pub fn shared_erase_asks(
        &self,
        reader: &AuthenticatedOwner,
        vault_id: u64,
    ) -> Result<Vec<SharedEraseAsk>> {
        let txn = self.store.env.read_txn()?;
        // Person tier: an Owner reads every ask, an asker their own.
        let reader = reader.revalidate_person_in_txn(self, &txn)?;
        check_vault(self, &txn, vault_id)?;
        let holders = self.live_act_holders(&txn, vault_id, self.store.clock.now_recorded_at())?;
        let owner = super::live_owners(&holders, None).contains(&reader);
        let reader = reader.to_hex();
        Ok(self
            .erase_asks_in_txn(&txn, vault_id)?
            .into_iter()
            .filter(|ask| owner || ask.asker == reader)
            .collect())
    }

    /// A live Owner closes open ask `ask_id`: `erased` when they erased its
    /// record, naming with `act` the `erase` act they started where the veto
    /// window applied, else declined. Closing erases nothing.
    pub fn close_shared_erase_ask(
        &self,
        owner: &AuthenticatedOwner,
        ask_id: &str,
        erased: bool,
        act: Option<&str>,
    ) -> Result<SharedEraseAsk> {
        let ask_key = key(ASK_PREFIX, &EntityId::from_hex(ask_id)?.to_hex());
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_person_in_txn(self, &txn)?;
        let raw = self
            .store
            .vault_meta
            .get(&txn, &ask_key)?
            .ok_or_else(invalid)?;
        let mut ask: SharedEraseAsk = decode(&raw)?;
        check_vault(self, &txn, ask.vault_id)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let holders = self.live_act_holders(&txn, ask.vault_id, now)?;
        if ask.status != EraseAskStatus::Open
            || !super::live_owners(&holders, None).contains(&actor)
            || (!erased && act.is_some())
        {
            return Err(invalid());
        }
        let act = match act {
            Some(id) => {
                let started = self
                    .pending_authority_act_in_txn(&txn, id)?
                    .ok_or_else(invalid)?;
                if started.act != ERASE_ACT || started.vault_id != ask.vault_id {
                    return Err(invalid());
                }
                Some(started.id)
            }
            None => None,
        };
        let by = actor.to_hex();
        ask.status = if erased {
            EraseAskStatus::Erased { by, act }
        } else {
            EraseAskStatus::Declined { by }
        };
        ask.closed_at = Some(now);
        self.store
            .vault_meta
            .put(&mut txn, &ask_key, &encode(&ask)?)?;
        txn.commit()?;
        Ok(ask)
    }
}

fn refused(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("vault.records.erase_propose: {why}"),
        &["Ask about a live record your own live owner Grant reads."],
    )
}
