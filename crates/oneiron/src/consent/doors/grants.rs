//! The owner's consent acts: approve once, standing grants, denials, revokes and reuse receipts;
//! and the standing outbound grants a system path derives from a setting the owner made.

use super::*;
use crate::failure_signals::FAILURE_SIGNALS_CHANNEL;
use crate::outbound_grant::StandingOutboundGrantScope;

impl Vault {
    /// Approves exactly one pending operation, identified by its exact
    /// engine-computed digest.
    ///
    /// Consumes only that digest: an approve-once receipt authorizes this op,
    /// now, and covers no other op and no future op. It mints no standing row.
    /// The mint is REPLAY-REJECTED: a spent marker keyed by the digest is
    /// claimed in the SAME write transaction as the receipt, so a second
    /// `approve_once` over the same digest — the owner re-tapping an
    /// already-answered ask, or a replayed digest — is refused with
    /// [`GateError::ConsentApproveOnceSpent`](crate::error::GateError::ConsentApproveOnceSpent). LMDB serializes writers, so a
    /// concurrent mint sees the committed marker and rolls back.
    ///
    /// # Errors
    ///
    /// Returns [`GateError::ConsentApproveOnceSpent`](crate::error::GateError::ConsentApproveOnceSpent) when the digest was already
    /// approved, and [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated) transitively
    /// from the owner-stamp check.
    pub fn approve_once(
        &self,
        owner: &AuthenticatedOwner,
        effect_digest: EffectDigest,
    ) -> Result<ConsentReceipt> {
        self.with_write_txn_grouped(|wtxn| self.approve_once_in_txn(wtxn, owner, effect_digest))
    }

    /// Composes the exact consent receipt with the effect it authorizes.
    pub(crate) fn approve_once_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        effect_digest: EffectDigest,
    ) -> Result<ConsentReceipt> {
        let decision_id = crate::store::GateDecisionId::from_bytes(self.store.clock.ulid()?);
        self.claim_approve_once_in_txn(wtxn, &effect_digest, decision_id)?;
        let receipt = ConsentReceipt::Approved {
            decision_id,
            grant: ConsentGrant::ApproveOnce(effect_digest),
        };
        self.append_consent_receipt_in_txn(wtxn, owner, &receipt)?;
        Ok(receipt)
    }

    /// The ONLY persistence door for a standing consent grant.
    ///
    /// Requires an [`AuthenticatedOwner`], rejects catastrophe-class bounds
    /// (the floor is non-rememberable — invariant 7), and writes the row and
    /// its Gate receipt in ONE transaction. Reuse never mutates a bound: a
    /// wider bound is a NEW owner decision that lands as a NEW row with its
    /// own receipt, which is also what "approve-and-stop-asking on a
    /// scope-exceed ask" mints.
    pub fn create_standing_grant(
        &self,
        owner: &AuthenticatedOwner,
        bound: GrantBound,
    ) -> Result<ConsentReceipt> {
        self.with_write_txn_grouped(|wtxn| self.create_standing_grant_in_txn(wtxn, owner, bound))
    }

    /// Transaction-composable [`Vault::create_standing_grant`].
    ///
    /// Exists so a caller whose PRECONDITION must hold at mint time can test
    /// it in the same transaction that writes the row: ONE-1748's graduation
    /// tap reads the scope's ramp posture here, so a stale tap cannot overtake
    /// the demotion that retracted the offer it is answering.
    pub(crate) fn create_standing_grant_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        bound: GrantBound,
    ) -> Result<ConsentReceipt> {
        if let Some(class) = bound_catastrophe_class(&bound) {
            return Err(Error::Gate(GateError::ConsentCatastropheNotRememberable(
                crate::gate::consent_floor_refusal(class),
            )));
        }
        self.write_standing_grant_in_txn(wtxn, owner, bound)
    }

    /// [`Self::create_standing_grant_in_txn`] for a standing outbound grant,
    /// whose class is an outbound verb class the owner's dial names: a class
    /// spelled like a catastrophe floor member names an outbound verb, not
    /// the floor op, and mints as it always has. The floor itself still asks
    /// every catastrophe op before any grant is read (`evaluate_consent`).
    pub(crate) fn create_outbound_standing_grant_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        bound: GrantBound,
    ) -> Result<ConsentReceipt> {
        self.write_standing_grant_in_txn(wtxn, owner, bound)
    }

    /// Mints a standing outbound grant a system path derives from a setting
    /// the owner made earlier (L02 04:5x), in the caller's transaction, with
    /// no owner present. `origin` admits only the bound its path mints, and
    /// the row is never a catastrophe class or a bypass. The row's stamp
    /// names the owner `setting`'s record names as its setter, else the
    /// vault's live owner (the first, when several are live), else its one
    /// recorded owner, under the principal `system:<component>.<action>`;
    /// its Approved receipt names the setting by `setting.receipt_ref`.
    /// `None`: the vault records no owner to stamp it, and nothing is
    /// written.
    ///
    /// # Errors
    ///
    /// [`GateError::InvalidConsentBound`] for a bound `origin`'s path never
    /// mints; storage errors.
    pub(crate) fn create_derived_outbound_standing_grant_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        origin: DerivedGrantOrigin,
        setting: &DerivedGrantSetting,
        bound: GrantBound,
    ) -> Result<Option<ConsentReceipt>> {
        if bound_catastrophe_class(&bound).is_some() || !origin.admits(&bound)? {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "a derived grant holds only the bound its path mints",
            )));
        }
        let Some(actor) = derived_grant_actor_in_txn(self, &*wtxn, setting.setter)? else {
            return Ok(None);
        };
        let decision_id = GateDecisionId::from_bytes(self.store.clock.ulid()?);
        let stamp = ConsentOwnerStamp {
            actor,
            principal_ref: origin.principal_ref(),
            decision_id,
        };
        let receipt =
            self.put_standing_grant_row_in_txn(wtxn, stamp.clone(), bound, decision_id)?;
        self.append_derived_grant_receipt_in_txn(wtxn, &stamp, setting, &receipt)?;
        Ok(Some(receipt))
    }

    /// Writes one standing grant row and its Approved receipt in the
    /// caller's transaction, once its door has admitted the bound.
    fn write_standing_grant_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        bound: GrantBound,
    ) -> Result<ConsentReceipt> {
        let decision_id = GateDecisionId::from_bytes(self.store.clock.ulid()?);
        let receipt =
            self.put_standing_grant_row_in_txn(wtxn, owner.stamp(), bound, decision_id)?;
        self.append_consent_receipt_in_txn(wtxn, owner, &receipt)?;
        Ok(receipt)
    }

    /// Writes one standing grant row under `owner_stamp` in the caller's
    /// transaction, and returns the Approved receipt `decision_id` names for
    /// its door to land beside it.
    fn put_standing_grant_row_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        owner_stamp: ConsentOwnerStamp,
        bound: GrantBound,
        decision_id: GateDecisionId,
    ) -> Result<ConsentReceipt> {
        let mutation_recorded_at = crate::ports::recorded_at_in_txn(&self.store, wtxn)?;
        let grant = StandingConsentGrant::from_bound(bound)?;
        let row = ConsentGrantRow {
            grant: grant.clone(),
            status: ConsentGrantStatus::Active,
            owner_stamp,
            created_at: mutation_recorded_at,
            bypass: None,
        };
        let receipt = ConsentReceipt::Approved {
            decision_id,
            grant: ConsentGrant::Standing(grant),
        };

        let grant_ref = row.grant_ref();
        // A same-bound re-mint is a NEW issuance, even with the same
        // AuthenticatedOwner. Its predecessor's reason and undo must not
        // authorize or revoke this replacement.
        super::super::owner_reason::retire_owner_reason_rules_in_txn(
            &self.store,
            wtxn,
            &grant_ref,
        )?;
        // Re-minting an identical bound is the owner re-affirming it; the row
        // is idempotent, and its door still lands the receipt so the act is
        // audit-visible.
        GRANTS.put(&self.store, wtxn, &grant_ref, &row)?;
        Ok(receipt)
    }

    /// Lands a derived grant's Approved receipt in the Gate receipt family:
    /// the system carried out the act, for the owner its stamp names, and
    /// the receipt names the stamp's principal and the setting it carried
    /// out.
    fn append_derived_grant_receipt_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        stamp: &ConsentOwnerStamp,
        setting: &DerivedGrantSetting,
        receipt: &ConsentReceipt,
    ) -> Result<()> {
        let record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id: receipt.decision_id(),
            created_at: crate::ports::recorded_at_in_txn(&self.store, wtxn)?,
            outcome: receipt.gate_outcome().to_owned(),
            reason_codes: vec![receipt.reason_code().to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: crate::store::GateSystemNoticeRecord::receipt_details(
                CONSENT_CONTENT_KIND,
                vec![
                    format!("principal:{}", stamp.principal_ref),
                    format!("setting:{}", setting.receipt_ref),
                ],
            ),
            actor_class: SYSTEM_ACTOR_CLASS.to_owned(),
            actor_ref: Some(stamp.actor.to_hex()),
            content_kind: CONSENT_CONTENT_KIND.to_owned(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            claim_id: None,
            grant_ref: receipt.grant_ref(),
            diff_handle: receipt.diff_handle(),
            read_frontier_hash: [0_u8; 32],
            context: Default::default(),
            redacted_at: None,
        };
        self.store.append_gate_decision_in_txn(wtxn, &record)
    }

    /// Denies one pending operation, recording the refusal in the receipt
    /// family so a denial is as legible as an approval.
    pub fn deny_consent(
        &self,
        owner: &AuthenticatedOwner,
        effect_digest: EffectDigest,
    ) -> Result<ConsentReceipt> {
        let mut wtxn = self.store.env.write_txn()?;
        let receipt = self.deny_consent_in_txn(&mut wtxn, owner, effect_digest)?;
        wtxn.commit()?;
        Ok(receipt)
    }

    /// Transaction-composable [`Vault::deny_consent`].
    pub(crate) fn deny_consent_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        effect_digest: EffectDigest,
    ) -> Result<ConsentReceipt> {
        let receipt = ConsentReceipt::Denied {
            decision_id: crate::store::GateDecisionId::from_bytes(self.store.clock.ulid()?),
            effect_digest,
        };
        // A refusal is the owner's decision: self-heal reads each denial as
        // an owner signal, so it takes the owner tier like every receipt.
        owner.revalidate_in_txn(self, &*wtxn)?;
        self.append_consent_gate_decision_in_txn(wtxn, &owner.stamp(), &receipt, None)?;
        Ok(receipt)
    }

    /// Revokes a standing grant. Revocation is immediate: the row flips to
    /// [`ConsentGrantStatus::Revoked`] in the same transaction as its receipt,
    /// so no in-flight read can observe a revoked row as live.
    pub fn revoke_consent_grant(
        &self,
        owner: &AuthenticatedOwner,
        grant_ref: &str,
    ) -> Result<ConsentReceipt> {
        let key = grant_ref.to_owned();
        let mut wtxn = self.store.env.write_txn()?;
        let Some(mut row) = GRANTS.get(&self.store, &wtxn, &key)? else {
            return Err(Error::Gate(GateError::ConsentGrantNotFound));
        };
        row.status = ConsentGrantStatus::Revoked;
        GRANTS.put(&self.store, &mut wtxn, &key, &row)?;
        super::super::owner_reason::retire_owner_reason_rules_in_txn(
            &self.store,
            &mut wtxn,
            grant_ref,
        )?;
        let receipt = ConsentReceipt::Revoked {
            decision_id: crate::store::GateDecisionId::from_bytes(self.store.clock.ulid()?),
            grant_ref: grant_ref.to_owned(),
        };
        self.append_consent_receipt_in_txn(&mut wtxn, owner, &receipt)?;
        wtxn.commit()?;
        Ok(receipt)
    }

    /// [`Self::revoke_consent_grant`] as one step of a larger owner act in
    /// the caller's write transaction (a pack's removal ends its setup
    /// grants). A row that is missing or no longer live writes nothing and
    /// returns `None`.
    pub(crate) fn revoke_consent_grant_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        grant_ref: &str,
    ) -> Result<Option<ConsentReceipt>> {
        if !revoke_standing_grant_in_txn(&self.store, wtxn, grant_ref)? {
            return Ok(None);
        }
        let receipt = ConsentReceipt::Revoked {
            decision_id: crate::store::GateDecisionId::from_bytes(self.store.clock.ulid()?),
            grant_ref: grant_ref.to_owned(),
        };
        self.append_consent_receipt_in_txn(wtxn, owner, &receipt)?;
        Ok(Some(receipt))
    }

    /// The engine's reduce-only revoke of one standing grant in the caller's
    /// write transaction ([`revoke_standing_grant_in_txn`]), with its Revoked
    /// receipt under the system's actor class: a system path withdrawing the
    /// grant it keeps, as a setting the owner made stops holding, records
    /// when the grant ended. `None`: the row was missing or not live, and
    /// nothing is written.
    pub(crate) fn revoke_standing_grant_as_engine_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        grant_ref: &str,
    ) -> Result<Option<ConsentReceipt>> {
        if !revoke_standing_grant_in_txn(&self.store, wtxn, grant_ref)? {
            return Ok(None);
        }
        let receipt = ConsentReceipt::Revoked {
            decision_id: GateDecisionId::from_bytes(self.store.clock.ulid()?),
            grant_ref: grant_ref.to_owned(),
        };
        let record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id: receipt.decision_id(),
            created_at: crate::ports::recorded_at_in_txn(&self.store, wtxn)?,
            outcome: receipt.gate_outcome().to_owned(),
            reason_codes: vec![receipt.reason_code().to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: SYSTEM_ACTOR_CLASS.to_owned(),
            actor_ref: None,
            content_kind: CONSENT_CONTENT_KIND.to_owned(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            claim_id: None,
            grant_ref: receipt.grant_ref(),
            diff_handle: receipt.diff_handle(),
            read_frontier_hash: [0_u8; 32],
            context: Default::default(),
            redacted_at: None,
        };
        self.store.append_gate_decision_in_txn(wtxn, &record)?;
        Ok(Some(receipt))
    }

    /// Records quiet in-bound standing reuse — the post-hoc receipt an owner
    /// sees for an auto-shared facet or an auto-run action.
    ///
    /// The reuse itself is authorized by `evaluate_consent`; this door only
    /// records it, and never widens or touches the grant row.
    pub fn record_standing_grant_use(
        &self,
        grant_ref: &str,
        effect_digest: EffectDigest,
    ) -> Result<ConsentReceipt> {
        let mut wtxn = self.store.env.write_txn()?;
        let receipt = self.record_standing_grant_use_in_txn(&mut wtxn, grant_ref, effect_digest)?;
        wtxn.commit()?;
        Ok(receipt)
    }

    /// [`Self::record_standing_grant_use`] inside the caller's write
    /// transaction, for a door that runs the reuse in that same transaction:
    /// a secret reveal (OF-560) delivers its value beside its receipt.
    pub(crate) fn record_standing_grant_use_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        grant_ref: &str,
        effect_digest: EffectDigest,
    ) -> Result<ConsentReceipt> {
        let Some(row) = GRANTS.get(&self.store, &*wtxn, &grant_ref.to_owned())? else {
            return Err(Error::Gate(GateError::ConsentGrantNotFound));
        };
        if !row.is_active() {
            return Err(Error::Gate(GateError::ConsentGrantRevoked));
        }
        let receipt = ConsentReceipt::Used {
            decision_id: crate::store::GateDecisionId::from_bytes(self.store.clock.ulid()?),
            grant_ref: grant_ref.to_owned(),
            effect_digest,
        };
        self.append_consent_gate_decision_in_txn(wtxn, &row.owner_stamp, &receipt, None)?;
        Ok(receipt)
    }
}

/// Every standing grant row with its reference, revoked rows included, read
/// on the caller's transaction: a door that reads its own kind of Grant off
/// the registry (an outbound grant's dial) filters these.
pub(crate) fn standing_grant_rows_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(String, ConsentGrantRow)>> {
    GRANTS.scan(store, txn)
}

/// [`Vault::record_standing_grant_use_in_txn`] for a door that holds the
/// store and not the vault: the Gate's external-effect record writes the
/// quiet reuse of the standing grant that covered an admitted effect beside
/// its Allow, under the stamp of the owner who minted that grant.
pub(crate) fn record_standing_grant_use_for_store_in_txn(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    grant_ref: &str,
    effect_digest: EffectDigest,
) -> Result<ConsentReceipt> {
    let Some(row) = GRANTS.get(store, &*wtxn, &grant_ref.to_owned())? else {
        return Err(Error::Gate(GateError::ConsentGrantNotFound));
    };
    if !row.is_active() {
        return Err(Error::Gate(GateError::ConsentGrantRevoked));
    }
    let receipt = ConsentReceipt::Used {
        decision_id: GateDecisionId::from_bytes(store.clock.ulid()?),
        grant_ref: grant_ref.to_owned(),
        effect_digest,
    };
    let record = GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id: receipt.decision_id(),
        created_at: crate::ports::recorded_at_in_txn(store, wtxn)?,
        outcome: receipt.gate_outcome().to_owned(),
        reason_codes: vec![receipt.reason_code().to_owned()],
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: CONSENT_ACTOR_CLASS.to_owned(),
        actor_ref: Some(row.owner_stamp.actor.to_hex()),
        content_kind: CONSENT_CONTENT_KIND.to_owned(),
        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
        claim_id: None,
        grant_ref: receipt.grant_ref(),
        diff_handle: receipt.diff_handle(),
        read_frontier_hash: [0_u8; 32],
        context: Default::default(),
        redacted_at: None,
    };
    store.append_gate_decision_in_txn(wtxn, &record)?;
    Ok(receipt)
}

/// The Gate `actor_class` of a consent act the system carries out: a derived
/// grant's mint, for the owner its `actor_ref` names, or the engine's revoke.
const SYSTEM_ACTOR_CLASS: &str = "system";

/// A system path that mints a standing outbound grant to carry out a setting
/// the owner made earlier (L02 04:5x). The set is closed: each variant is one
/// path, naming the component and action its grant's stamp records as
/// `system:<component>.<action>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DerivedGrantOrigin {
    /// "Help improve Oneiron" and the ED-08 publisher dial: one channel grant
    /// for the issue-signature sender while both are on.
    SignatureParticipation,
    /// The failure-signal export switch: one grant for the failure-signal
    /// sender on its own channel while it is on.
    FailureSignalParticipation,
    /// A published booking page: its one invite grant, minted at
    /// publication.
    BookingInvite,
}

impl DerivedGrantOrigin {
    /// The component whose path mints the grant.
    const fn component(self) -> &'static str {
        match self {
            Self::SignatureParticipation => "feedback_signature.participation",
            Self::FailureSignalParticipation => "failure_signals.participation",
            Self::BookingInvite => "booking.page_publish",
        }
    }

    /// The action of that component the grant carries out.
    const fn action(self) -> &'static str {
        match self {
            Self::SignatureParticipation => "send",
            Self::FailureSignalParticipation => "export",
            Self::BookingInvite => "publish_booking_page",
        }
    }

    /// The principal a derived grant's stamp records.
    fn principal_ref(self) -> String {
        format!("system:{}.{}", self.component(), self.action())
    }

    /// The connector class whose actor a participation grant lets send, as
    /// its path derives it: the issue-signature sender's class in
    /// `feedback::report::delivery`, and the failure-signal sender's.
    const fn sender_class(self) -> Option<&'static str> {
        match self {
            Self::SignatureParticipation => Some("feedback_signature"),
            Self::FailureSignalParticipation => Some(FAILURE_SIGNALS_CHANNEL),
            Self::BookingInvite => None,
        }
    }

    /// Whether `bound` is exactly a grant this path mints: a standing
    /// outbound grant's bound with the dial the path sets, the send class
    /// over one channel for participation and the invite class over one
    /// page for a booking page. A participation grant also lets only its own
    /// sender act, and the failure-signal grant rides only its own channel.
    fn admits(self, bound: &GrantBound) -> Result<bool> {
        let Some((_, _, principal_ref, dial)) = StandingOutboundGrantScope::from_bound(bound)
        else {
            return Ok(false);
        };
        let shape = match (self, &dial) {
            (Self::SignatureParticipation, StandingOutboundGrantScope::Channel { .. })
            | (Self::BookingInvite, StandingOutboundGrantScope::BookingPageInvites { .. }) => true,
            (Self::FailureSignalParticipation, StandingOutboundGrantScope::Channel { channel }) => {
                channel == FAILURE_SIGNALS_CHANNEL
            }
            _ => false,
        };
        let Some(class) = self.sender_class() else {
            return Ok(shape);
        };
        Ok(shape && principal_ref == crate::outbound::connector_actor_id(class)?.to_hex())
    }
}

/// The owner's earlier setting a derived grant carries out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DerivedGrantSetting {
    /// The record the setting lives in, which the grant's receipt names.
    pub(crate) receipt_ref: String,
    /// The owner that record names as the setting's setter, when it names
    /// one.
    pub(crate) setter: Option<EntityId>,
}

/// The owner a derived grant's stamp names: the setter the setting's record
/// names; else the vault's live owner, the first the census returns when
/// several are live (the receipt's setting then points at the act); else,
/// with no owner live, the one owner the vault records. `None`: the vault
/// records several owners and none is live.
fn derived_grant_actor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    setter: Option<EntityId>,
) -> Result<Option<EntityId>> {
    if setter.is_some() {
        return Ok(setter);
    }
    if let Some(owner) = crate::policy_model::owners_in_txn(vault, txn)?
        .first()
        .copied()
    {
        return Ok(Some(owner));
    }
    crate::policy_model::sole_recorded_owner_in_txn(vault, txn)
}
