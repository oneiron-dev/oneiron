//! The Connect carrier of a world-settings ask (FIX 4702). An agent's ask on
//! a world shared from a connected vault goes to the owning vault's holders,
//! and their answer comes back. Each leg is signed by its host's root key and
//! carried by an owner, as a Connect window is
//! (`SyncClient::export_connect_window_as`), and the receiving vault checks
//! the live pact, its epoch and the peer owner key it pinned at Connect
//! before it reads a field. An ask lands at the owning vault's world-privacy
//! door as any agent's request does: its holders there decide under their
//! own rules. The answer settles the asking vault's pending ask.

use serde::{Deserialize, Serialize};

use crate::authority::{
    AuthorityFold, AuthoritySignature, AuthorityVaultId, FederationPactState, FederationPactStatus,
    HostSlipIssuer, PrivacyDirection, WorldPrivacy, verify_authority_signature,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::federation::{ScopeAxis, ScopeId};
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::{EntityId, Vault};

use super::foreign::is_foreign;
use super::record::{
    ForeignWorldPrivacyLink, NOTICE_PRODUCER, NewRequest, WorldPrivacyRequest,
    WorldPrivacyRequestKind as Kind, WorldPrivacyRequestStatus,
};
use super::{NO_HOLDER, direction_in_txn, unanimity, world_holders_in_txn};

/// The domain a leg's transcript is signed under.
const CARRY_DOMAIN: &str = "oneiron/world-privacy/connect-carry/v1";
/// A leg that does not match a live Connect with its sender.
const NOT_CARRIED: &str =
    "this world-settings delivery does not match a live Connect with its sender";
/// A request with no leg to carry.
const NO_LEG: &str = "this world-privacy request has no leg to carry: only a pending ask on a \
                      world a connected vault owns, or a settled ask a connected vault's agent \
                      sent here";
/// An answer that differs from the one already kept for the same ask.
const ANSWERED: &str = "the owning vault already answered this ask otherwise";
/// The notice this vault's owners get when its holders answered a connected
/// vault's ask: they carry the answer back.
const ANSWER_NOTICE: &str = "this world's holders answered a connected vault's ask; export the \
                             answer (vault.federation.connect.world_privacy.export) and carry \
                             it back to that vault";

fn not_carried() -> Error {
    Error::InvalidConfig(NOT_CARRIED.to_owned())
}

fn hex32(hex: &str) -> Result<[u8; 32]> {
    crate::deletion::parse_hex(hex).ok_or_else(not_carried)
}

fn entity(hex: &str) -> Result<EntityId> {
    EntityId::from_hex(hex).map_err(|_| not_carried())
}

/// Which way a carried leg goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ForeignWorldPrivacyLeg {
    /// An agent's ask, from the vault that received the world to the vault
    /// that owns it.
    Ask,
    /// The owning vault's answer, back to the asking vault.
    Answer,
}

/// The signed body of one leg.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForeignWorldPrivacyCarry {
    pub leg: ForeignWorldPrivacyLeg,
    /// The pact, as 64 hex.
    pub pact: String,
    /// The pact's consent epoch when the leg was signed.
    pub epoch: u64,
    /// The vault whose host signed, as 64 hex.
    pub source_vault: String,
    /// The vault the leg is for, as 64 hex.
    pub recipient_vault: String,
    /// The world as its owning vault names it, as hex.
    pub world: String,
    /// The asking vault's request, as hex: both legs name it.
    pub ask: String,
    /// The agent that asked, as hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// The settings asked for.
    pub settings: WorldPrivacy,
    /// On an answer: how the owning vault's holders settled the ask.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<WorldPrivacyRequestStatus>,
}

impl ForeignWorldPrivacyCarry {
    /// What the sending host signs: the body under its own domain.
    pub(crate) fn transcript(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(&(CARRY_DOMAIN, self))
            .map_err(|_| Error::InvalidConfig("world-settings delivery encoding failed".to_owned()))
    }
}

/// One signed leg, as an owner carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForeignWorldPrivacyDelivery {
    pub body: ForeignWorldPrivacyCarry,
    /// The sending host's signature over the body's transcript, as hex.
    pub signature: String,
}

/// `vault.federation.connect.world_privacy.export`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForeignWorldPrivacyExportRequest {
    /// The world-privacy request, as hex: a pending ask on a world a
    /// connected vault owns, or a settled one a connected vault's agent sent
    /// here.
    pub request: String,
}

/// The Active pact `pact`, from `fold`.
fn live_pact<'a>(fold: &'a AuthorityFold, pact: &[u8; 32]) -> Result<&'a FederationPactState> {
    fold.federation_pacts
        .get(pact)
        .filter(|state| state.status == FederationPactStatus::Active)
        .ok_or_else(not_carried)
}

/// This vault's id, and the live pact `delivery` rides once its sender,
/// recipient, epoch and signature check out: the peer owner key the pact
/// pinned signed its transcript.
fn verify_leg<'a>(
    fold: &'a AuthorityFold,
    delivery: &ForeignWorldPrivacyDelivery,
) -> Result<(AuthorityVaultId, &'a FederationPactState)> {
    let body = &delivery.body;
    let local = fold.vault_id.ok_or_else(not_carried)?;
    let state = live_pact(fold, &hex32(&body.pact)?)?;
    if hex32(&body.source_vault)? != state.peer_vault_id
        || hex32(&body.recipient_vault)? != local
        || body.epoch != state.pact_epoch
    {
        return Err(not_carried());
    }
    let signature = AuthoritySignature {
        suite: state.peer_owner_key.suite(),
        public_key: state.peer_owner_key.clone(),
        signature: crate::deletion::parse_hex::<64>(&delivery.signature)
            .ok_or_else(not_carried)?
            .to_vec(),
    };
    if !verify_authority_signature(&signature, &body.transcript()?) {
        return Err(not_carried());
    }
    Ok((local, state))
}

/// The connected vault's guest actor here: the member the pact's grant
/// names, the vault-resident actor that stands for that vault.
fn connect_guest_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, grant: EntityId) -> Result<EntityId> {
    let crate::vault::LiveEntityRow::Live {
        entity_type: crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
        body,
    } = crate::vault::live_entity_row_in_txn(&vault.store, txn, &grant)?
    else {
        return Err(not_carried());
    };
    Ok(crate::federation::decode_federation_grant_body(&body)?.member_ref)
}

impl Vault {
    /// Signs the leg `request` owes its connected vault, for an owner to
    /// carry there (FIX 4702): a pending agent's ask on a world a connected
    /// vault owns goes to that vault's holders, and this vault's holders'
    /// answer to an ask a connected vault's agent sent goes back. The pact
    /// must still be live; the leg names its current epoch.
    ///
    /// # Errors
    /// [`Error::EntityNotFound`] for no such request;
    /// [`Error::InvalidConfig`] for one with no leg to carry, or a pact that
    /// is no longer live; the owner proof's refusal.
    pub fn export_foreign_world_privacy(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        request: EntityId,
    ) -> Result<ForeignWorldPrivacyDelivery> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let stored = self
            .world_privacy_request_in_txn(&txn, request)?
            .ok_or(Error::EntityNotFound)?;
        let pending = stored.status == WorldPrivacyRequestStatus::Pending;
        let (leg, link, ask, agent, answer) = match (stored.owned_by, stored.asked_from) {
            (Some(link), None) if pending => (
                ForeignWorldPrivacyLeg::Ask,
                link,
                stored.request_id,
                stored.agent,
                None,
            ),
            (None, Some(mut link)) if !pending => {
                let ask = link.request.take().ok_or_else(not_carried)?;
                let agent = link.agent.take();
                (
                    ForeignWorldPrivacyLeg::Answer,
                    link,
                    ask,
                    agent,
                    Some(stored.status),
                )
            }
            _ => return Err(Error::InvalidConfig(NO_LEG.to_owned())),
        };
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        let local = fold.vault_id.ok_or_else(not_carried)?;
        let state = live_pact(&fold, &hex32(&link.pact)?)?;
        if hex32(&link.vault)? != state.peer_vault_id {
            return Err(not_carried());
        }
        let body = ForeignWorldPrivacyCarry {
            leg,
            pact: link.pact,
            epoch: state.pact_epoch,
            source_vault: bytes_to_hex_lower(&local),
            recipient_vault: link.vault,
            world: link.world,
            ask,
            agent,
            settings: stored.settings,
            answer,
        };
        Ok(ForeignWorldPrivacyDelivery {
            signature: issuer.sign_foreign_world_privacy(&body)?,
            body,
        })
    }

    /// Takes one leg a connected vault's host signed and an owner carried
    /// here (FIX 4702), once the live pact, its epoch and the pinned peer
    /// owner key check out. An ask opens a request on the named world for
    /// its holders here, as an agent's request does: a widen of the world's
    /// settings is an ask, under this vault's "widen needs every owner"
    /// setting, and anything else a proposal any one holder accepts. The
    /// connected vault's guest actor here is its author; an ask already
    /// filed answers the request it opened. An answer settles this vault's
    /// pending ask with the owning vault's verdict and wakes its waiters; on
    /// an ask a holder here cancelled first it is kept beside the cancel.
    ///
    /// # Errors
    /// [`Error::InvalidConfig`] for a leg that does not match a live
    /// Connect with its sender, a world this vault does not share with it,
    /// no holder who could answer, or an answer that differs from the one
    /// kept; [`Error::EntityNotFound`] for an answer to no ask here.
    pub fn receive_foreign_world_privacy(
        &self,
        owner: &AuthenticatedOwner,
        delivery: ForeignWorldPrivacyDelivery,
    ) -> Result<WorldPrivacyRequest> {
        let (request, filed) = self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let fold = self.authority_fold_readonly_in_txn(txn)?;
            let (local, state) = verify_leg(&fold, &delivery)?;
            match delivery.body.leg {
                ForeignWorldPrivacyLeg::Ask if delivery.body.answer.is_none() => {
                    self.file_foreign_ask_in_txn(txn, local, state, &delivery.body)
                }
                ForeignWorldPrivacyLeg::Answer => self
                    .settle_foreign_ask_in_txn(txn, &delivery.body)
                    .map(|settled| (settled, false)),
                ForeignWorldPrivacyLeg::Ask => Err(not_carried()),
            }
        })?;
        // A newly filed widen queues its in-moment ask after the commit.
        if filed && request.kind == Kind::WidenAsk {
            return self.queue_world_privacy_ask(request);
        }
        Ok(request)
    }

    /// Files `body`'s ask on this vault's world for its holders, or finds
    /// the request it opened before: `true` beside a newly filed one.
    fn file_foreign_ask_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        local: AuthorityVaultId,
        state: &FederationPactState,
        body: &ForeignWorldPrivacyCarry,
    ) -> Result<(WorldPrivacyRequest, bool)> {
        let world = entity(&body.world)?;
        let ask = entity(&body.ask)?;
        let agent = body.agent.as_deref().map(entity).transpose()?;
        // A world this vault shares with the asker: its own named world,
        // inside this vault's half of the pact's ceiling.
        let outbound = if local <= state.peer_vault_id {
            &state.pact_scope.lo_to_hi
        } else {
            &state.pact_scope.hi_to_lo
        };
        let shared = match &outbound.worlds {
            ScopeAxis::All => true,
            ScopeAxis::Some(worlds) => worlds.contains(&ScopeId(world)),
            ScopeAxis::Bottom => false,
        };
        if is_foreign(world) || !shared {
            return Err(not_carried());
        }
        let pact = bytes_to_hex_lower(&hex32(&body.pact)?);
        let vault = bytes_to_hex_lower(&state.peer_vault_id);
        if let Some(filed) = self.foreign_ask_filed_in_txn(txn, &pact, &vault, &ask.to_hex())? {
            return Ok((filed, false));
        }
        let holders = world_holders_in_txn(self, txn, world)?;
        if holders.is_empty() {
            return Err(Error::InvalidConfig(NO_HOLDER.to_owned()));
        }
        let (direction, current) = direction_in_txn(self, txn, world, &body.settings, None)?;
        let (kind, needs) = if direction == PrivacyDirection::Widen {
            (
                Kind::WidenAsk,
                unanimity::widen_needs_in_txn(self, txn, world)?,
            )
        } else {
            (Kind::Proposal, Vec::new())
        };
        let guest = connect_guest_in_txn(self, txn, state.grant_ref)?;
        let request = self.open_world_privacy_request_in_txn(
            txn,
            NewRequest {
                kind,
                agent: Some(guest),
                opener_lineage: Vec::new(),
                author: guest,
                world,
                settings: body.settings.clone(),
                seen: current,
                holders,
                needs,
                yes: Vec::new(),
                grant_omitted: None,
                owned_by: None,
                asked_from: Some(ForeignWorldPrivacyLink {
                    pact,
                    vault,
                    world: world.to_hex(),
                    request: Some(ask.to_hex()),
                    agent: agent.as_ref().map(EntityId::to_hex),
                    answer: None,
                }),
            },
        )?;
        Ok((request, true))
    }

    /// Settles this vault's pending ask with `body`'s answer, and wakes its
    /// waiters. The answer is kept on the ask's link either way, so a
    /// holder's cancel here stands beside what the owning vault did.
    fn settle_foreign_ask_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        body: &ForeignWorldPrivacyCarry,
    ) -> Result<WorldPrivacyRequest> {
        let answer = match &body.answer {
            Some(
                answer @ (WorldPrivacyRequestStatus::Applied { .. }
                | WorldPrivacyRequestStatus::Declined { .. }),
            ) => answer.clone(),
            _ => return Err(not_carried()),
        };
        let mut stored = self
            .world_privacy_request_in_txn(txn, entity(&body.ask)?)?
            .ok_or(Error::EntityNotFound)?;
        let Some(link) = stored.owned_by.as_mut() else {
            return Err(not_carried());
        };
        if hex32(&link.pact)? != hex32(&body.pact)?
            || hex32(&link.vault)? != hex32(&body.source_vault)?
            || entity(&link.world)? != entity(&body.world)?
        {
            return Err(not_carried());
        }
        if link.answer.as_ref().is_some_and(|kept| *kept != answer) {
            return Err(Error::InvalidConfig(ANSWERED.to_owned()));
        }
        link.answer = Some(answer.clone());
        let settles = stored.status == WorldPrivacyRequestStatus::Pending;
        if settles {
            stored.status = answer;
        }
        self.put_world_privacy_request_in_txn(txn, &stored)?;
        if settles {
            crate::task_verb::deliver_world_privacy_wait_in_txn(self, txn, &stored)?;
        }
        Ok(stored)
    }

    /// Tells this vault's live owners that its holders answered the
    /// connected vault's ask `request`, so one of them carries the answer
    /// back: one NOTIFICATION each, its own event beside the request's
    /// opening notice, replay-safe. Nothing for a request no connected vault
    /// sent.
    pub(super) fn notify_foreign_answer_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        request: &WorldPrivacyRequest,
    ) -> Result<()> {
        if request.asked_from.is_none() {
            return Ok(());
        }
        let world = request.world_id()?;
        let at = self.instant_in_txn(txn)?.secs();
        for owner in super::super::authority::owners_in_txn(self, txn)? {
            self.record_notification_in_txn(
                txn,
                &NotificationEvent {
                    kind: NotificationKind::Ask,
                    source: NotificationSource {
                        producer: NOTICE_PRODUCER.to_owned(),
                        event: format!("{}:answer:{}", request.request_id, owner.to_hex()),
                        result: Some(request.request_id.clone()),
                        detail: Some(ANSWER_NOTICE.to_owned()),
                        ..NotificationSource::default()
                    },
                    subject_refs: vec![world],
                    recipient: Some(owner),
                    created_at: at,
                    origin_conversation: None,
                },
            )?;
        }
        Ok(())
    }
}
