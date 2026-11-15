//! The owner's pile of identity-ramp graduation offers (ARCH-0063 [INB-04]
//! into [INB-03]'s "Waiting on you"; ARCH-0063:356 "approval surface =
//! INB-03's pile"): every standing offer, the INBOX rows that carry them, and
//! the owner's acceptance. Nothing here is stored: the offers are evaluated
//! from the reviewed outbound receipts and the evidence rows, as the lens
//! reads them.

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use crate::Vault;
use crate::agent_inbox_lens::AgentInboxLensItem;
use crate::channel_identity_selection::RelationshipContext;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::inbox::view_values::{AgentInboxItemKind, AgentInboxParticipant, InboxImpact};
use crate::receipt::ReceiptRecord;

use super::codec::{action_bound, address, key, mode_key, mode_value};
use super::graduation::scope_handle;
use super::invalid_autonomy;
use super::types::{
    ChannelIdentityAutonomyMode, ChannelIdentityAutonomyRung, GraduationOffer, GraduationScopeKey,
    PREDICATE_ACTION_ENVELOPE,
};

/// The prefix of a ramp offer's INBOX item id; the offer id follows it.
pub const RAMP_OFFER_ITEM_PREFIX: &str = "ramp:";

/// A ramp offer waits on the owner's answer, as a craft candidate does.
const RAMP_OFFER_INBOX_IMPACT: u16 = 100;

/// The only verb class a graduation offer is made on.
const OFFER_VERB_CLASS: &str = "mail.send";

impl GraduationScopeKey {
    /// The offer id: the hex of the handle this scope's evidence rows are
    /// keyed under. Its `ramp:` INBOX row carries it as the payload, and the
    /// owner answers by it.
    pub fn offer_id(&self) -> Result<String> {
        Ok(scope_handle(self)?.to_hex())
    }
}

impl Vault {
    /// Every standing identity graduation offer, in scope order: each
    /// `mail.send` scope a reviewed outbound receipt names, evaluated as
    /// [`Self::evaluate_graduation_offer`] evaluates it with the scope's
    /// policy row, else the pinned default streak of twelve. Reading grants
    /// nothing.
    pub fn channel_identity_graduation_offers(&self) -> Result<Vec<GraduationOffer>> {
        let receipts = self.every_outbound_receipt()?;
        self.graduation_offers_from_receipts(&receipts)
    }

    /// The standing offer `offer_id` names, if one stands now.
    pub fn channel_identity_graduation_offer(
        &self,
        offer_id: &str,
    ) -> Result<Option<GraduationOffer>> {
        for offer in self.channel_identity_graduation_offers()? {
            if offer.scope.offer_id()? == offer_id {
                return Ok(Some(offer));
            }
        }
        Ok(None)
    }

    /// The owner's "auto" on a standing identity graduation offer, in one
    /// write transaction: the offer is proved again, the owner's
    /// `mail.send` action grant is minted over the envelope the scope's
    /// current action grant binds (the offer's proposed envelope, so the
    /// volume bound stays), the mode moves to
    /// [`ChannelIdentityAutonomyRung::AutonomousWithinEnvelope`], and the
    /// acceptance joins the shared answer log, which clears the scope's
    /// decline ladder. It makes the checks of
    /// [`Self::mint_channel_identity_action_grant`] and
    /// [`Self::set_channel_identity_autonomy_mode`]: the envelope and the
    /// mode row must be this owner's. An offer that no longer stands
    /// changes nothing.
    pub fn accept_channel_identity_graduation_offer(
        &self,
        offer: &GraduationOffer,
        owner: &AuthenticatedOwner,
    ) -> Result<ChannelIdentityAutonomyMode> {
        self.autonomy_owner(owner)?;
        let scope = &offer.scope;
        let ramp = scope.ramp_scope()?;
        let now = self.store.authorization_now()?;
        let mut txn = self.store.env.write_txn()?;
        let owner_actor = owner.revalidate_in_txn(self, &txn)?;
        let Some(standing) =
            self.graduation_offer_in_txn(&txn, scope, &ramp, offer.unchanged_streak, now, now)?
        else {
            return Err(invalid_autonomy());
        };
        let mode = self.autonomy_mode_in_txn(
            &txn,
            scope.identity_ref,
            scope.relationship_context,
            now,
            now,
        )?;
        let state = self.autonomy_state(&txn, mode.clone(), now, now)?;
        let current = state.action_grant.ok_or_else(invalid_autonomy)?;
        let envelope = state.action_envelope.ok_or_else(invalid_autonomy)?;
        if envelope != standing.proposed_envelope {
            return Err(invalid_autonomy());
        }
        let mode_row = mode_key(scope.identity_ref, scope.relationship_context);
        let (mode_writer, mode_at, _) = self.autonomy_row(&txn, &mode_row)?;
        let (envelope_writer, envelope_at, _) = self.autonomy_row(
            &txn,
            &key(PREDICATE_ACTION_ENVELOPE, &current.envelope_ref.to_hex()),
        )?;
        if mode_writer != owner_actor
            || envelope_writer != owner_actor
            || mode_at > now
            || envelope_at > now
        {
            return Err(invalid_autonomy());
        }
        let frontier =
            crate::gate::resolve_policy_manifest(&self.store, &txn)?.read_frontier_hash()?;
        let bound = action_bound(
            scope.actor_ref,
            current.envelope_ref,
            &envelope,
            OFFER_VERB_CLASS,
            &frontier,
        )?;
        let grant_ref = address("action_grant", &Value::from(bound.digest().to_hex()))?;
        if let Some(grant) = self
            .autonomy_reader()
            .autonomy_action_grant_in_txn(&txn, grant_ref)?
        {
            self.validate_autonomy_action(&txn, &grant, now)?;
        } else {
            self.create_standing_grant_in_txn(&mut txn, owner, bound)?;
        }
        let graduated = ChannelIdentityAutonomyMode {
            rung: ChannelIdentityAutonomyRung::AutonomousWithinEnvelope,
            action_grant_ref: Some(grant_ref),
            ..mode
        };
        self.autonomy_state(&txn, graduated.clone(), now, now)?;
        self.write_autonomy_row(
            &mut txn,
            &mode_row,
            owner_actor,
            now,
            mode_value(&graduated),
        )?;
        crate::edit_distance::graduation::record_go_auto_answer_in_txn(
            self, &mut txn, owner, &ramp, now,
        )?;
        txn.commit()?;
        Ok(graduated)
    }

    /// The standing offers of the scopes `receipts` name, judged at the
    /// store's clock, with no write. A scope whose autonomy the gate does
    /// not prove (no mode row, a revoked or stale grant, an identity that is
    /// not Active or bound elsewhere) offers nothing.
    pub(crate) fn graduation_offers_from_receipts(
        &self,
        receipts: &[ReceiptRecord],
    ) -> Result<Vec<GraduationOffer>> {
        let scopes = reviewed_send_scopes(receipts);
        if scopes.is_empty() {
            return Ok(Vec::new());
        }
        let now = self.store.clock.now_recorded_at();
        let txn = self.store.env.read_txn()?;
        let mut offers = Vec::new();
        for scope in scopes {
            let standing = scope
                .ramp_scope()
                .and_then(|ramp| self.graduation_offer_in_txn(&txn, &scope, &ramp, 0, now, now));
            match standing {
                Ok(Some(offer)) => offers.push(offer),
                Ok(None) | Err(Error::Gate(_)) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(offers)
    }
}

/// The `mail.send` scopes the reviewed outbound receipts name: each receipt
/// that carries a review outcome beside the scope's fields. Evidence is
/// admitted only against such a receipt, so every scope that holds evidence
/// is among them.
fn reviewed_send_scopes(receipts: &[ReceiptRecord]) -> BTreeSet<GraduationScopeKey> {
    receipts
        .iter()
        .filter_map(|receipt| {
            let field = |name: &str| receipt.fields.get(name).map(String::as_str);
            if field("review_outcome").is_none() || field("verb_class")? != OFFER_VERB_CLASS {
                return None;
            }
            Some(GraduationScopeKey {
                actor_ref: EntityId::from_hex(receipt.actor.as_deref()?).ok()?,
                identity_ref: EntityId::from_hex(field("channel_identity_ref")?).ok()?,
                relationship_context: RelationshipContext::parse(field("relationship_context")?)?,
                verb_class: OFFER_VERB_CLASS.to_owned(),
                counterparty_class: field("counterparty_class").map(str::to_owned),
            })
        })
        .collect()
}

/// Each standing identity graduation offer as an INBOX row for the vault's
/// live owners (kind ApprovalRequired, so "Waiting on you"), on the scope's
/// identity and agent: item id `ramp:<offer id>`, the offer id as its
/// payload, at the newest review its streak counts. A vault with no live
/// owner has no one to ask and makes no row. Never folded into a thread.
pub(crate) fn graduation_offer_inbox_items(
    vault: &Vault,
    receipts: &[ReceiptRecord],
) -> Result<Vec<AgentInboxLensItem>> {
    let offers = vault.graduation_offers_from_receipts(receipts)?;
    if offers.is_empty() {
        return Ok(Vec::new());
    }
    let participants: Vec<_> = {
        let rtxn = vault.store.env.read_txn()?;
        crate::policy_model::owners_in_txn(vault, &rtxn)?
            .into_iter()
            .map(|owner| AgentInboxParticipant {
                identity_ref: Some(owner),
                actor_ref: owner,
            })
            .collect()
    };
    if participants.is_empty() {
        return Ok(Vec::new());
    }
    let reviewed_at: BTreeMap<&str, u64> = receipts
        .iter()
        .map(|receipt| (receipt.receipt_id.as_str(), receipt.occurred_at))
        .collect();
    offers
        .into_iter()
        .map(|offer| {
            let offer_id = offer.scope.offer_id()?;
            let occurred_at = offer
                .evidence_refs
                .iter()
                .filter_map(|reference| reviewed_at.get(reference.as_str()).copied())
                .max()
                .unwrap_or(offer.offered_at);
            Ok(AgentInboxLensItem {
                item_id: format!("{RAMP_OFFER_ITEM_PREFIX}{offer_id}"),
                kind: AgentInboxItemKind::ApprovalRequired,
                thread_ref: None,
                identity_ref: Some(offer.scope.identity_ref),
                actor_ref: offer.scope.actor_ref,
                facet_ref: None,
                participants: participants.clone(),
                impact: InboxImpact(RAMP_OFFER_INBOX_IMPACT),
                occurred_at,
                receipt_ref: None,
                payload_ref: Some(offer_id),
                approval_digest: None,
                concern: None,
                diary_review: None,
                sender: None,
                widening: None,
            })
        })
        .collect()
}
