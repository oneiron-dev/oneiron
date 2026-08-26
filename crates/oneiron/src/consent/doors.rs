use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};

use super::bound::{ActorBound, GrantBound};
use super::codec::{decode_consent_grant_row, encode_consent_grant_row};
use super::effect::{
    ApproveOnceAuthorization, CATASTROPHE_FLOOR_V1, CatastropheClass, ComposedEffect,
    ConsentDecision, EffectDigest,
};
use super::grant::{
    CONSENT_CONTENT_KIND, ConsentGrant, ConsentGrantRow, ConsentGrantStatus, ConsentOwnerStamp,
    ConsentReceipt, StandingConsentGrant,
};
use super::registry::{ConsentRegistry, ConsentRegistryQuery, ConsentRegistryRow};
use super::support::{
    CONSENT_APPROVE_ONCE_AVAILABLE, CONSENT_APPROVE_ONCE_SPENT, CONSENT_GRANT_KEY_PREFIX,
    consent_approve_once_key, consent_grant_key, decode_approve_once_marker,
    encode_approve_once_marker, normalized_ref,
};

// ---------------------------------------------------------------------------
// Owner authentication — invariant 2
// ---------------------------------------------------------------------------

/// Proof that the current human owner authenticated for one decision.
///
/// Fields are private and there is no public constructor from parts: the only
/// door is [`Vault::authenticate_owner`], which requires BOTH the store-truth
/// human-actor check and the GenUI principal-authentication result. A guard, a
/// preference, a claim, or a transcript line cannot produce one, which is what
/// makes "created ONLY by the authenticated owner" a type-level fact rather
/// than a review-time promise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedOwner {
    actor: EntityId,
    principal_ref: String,
    decision_id: GateDecisionId,
}

impl AuthenticatedOwner {
    /// The authenticated human actor.
    #[must_use]
    pub const fn actor(&self) -> EntityId {
        self.actor
    }

    /// The authenticated principal reference.
    #[must_use]
    pub fn principal_ref(&self) -> &str {
        &self.principal_ref
    }

    /// The Gate decision this AUTHENTICATION is bound to.
    ///
    /// This is the authentication's own decision, not the decision of any act
    /// performed under it: each consent act mints its own [`GateDecisionId`]
    /// (the ledger rejects a duplicate), and the authentication id rides the
    /// grant row's owner stamp as provenance for WHICH authentication the
    /// owner acted under.
    #[must_use]
    pub const fn decision_id(&self) -> GateDecisionId {
        self.decision_id
    }

    fn stamp(&self) -> ConsentOwnerStamp {
        ConsentOwnerStamp {
            actor: self.actor,
            principal_ref: self.principal_ref.clone(),
            decision_id: self.decision_id,
        }
    }
}

/// The pinned Gate `actor_class` for owner-authored consent decisions.
const CONSENT_ACTOR_CLASS: &str = "human";

// ---------------------------------------------------------------------------
// The Vault doors
// ---------------------------------------------------------------------------

impl Vault {
    /// Produces an [`AuthenticatedOwner`] from the independent checks DEC-0006
    /// requires: the store-truth human-actor check, the GenUI
    /// principal-authentication result, the entity's REGISTRY-ACTIVE state,
    /// and the principal↔actor binding.
    ///
    /// This is the ONLY constructor of [`AuthenticatedOwner`]. A guard, a
    /// preference, a claim, or a transcript line cannot reach it, so
    /// "owner-only minting" is an engine check rather than a UI promise.
    ///
    /// The registry-active assertion is load-bearing: a PERSON row that has
    /// been merged or split away is a redirect shell, not an owner — an
    /// `AuthenticatedOwner` minted on it would stamp grants on a dead
    /// identity. [`ActorBound::new`] then verifies the principal ref normalizes
    /// to a non-empty reference; and a hex principal ref must decode to THIS
    /// actor, so the ref that authenticated is the actor the grant lands for
    /// (no cross-actor principal substitution).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConsentOwnerNotAuthenticated`] when the principal did
    /// not authenticate, the principal ref normalizes empty, the named actor
    /// is not a store-truth human entity, the entity is registry-inactive
    /// (merged / split shell), or a hex principal ref binds to another actor.
    pub fn authenticate_owner(
        &self,
        actor: EntityId,
        principal_ref: &str,
        principal_authenticated: bool,
        decision_id: GateDecisionId,
    ) -> Result<AuthenticatedOwner> {
        if !principal_authenticated {
            return Err(Error::ConsentOwnerNotAuthenticated(
                "GenUI principal authentication did not succeed",
            ));
        }
        let principal_ref = normalized_ref("principal_ref", principal_ref.to_owned())
            .map_err(|_| Error::ConsentOwnerNotAuthenticated("principal_ref is empty"))?;
        // The ActorBound constructor is the lane's principal-shape check: an
        // unusable principal ref is a rejected authentication, not a stamped
        // grant on a malformed subject.
        ActorBound::new(principal_ref.as_str())
            .map_err(|_| Error::ConsentOwnerNotAuthenticated("principal_ref is unusable"))?;
        if !self.is_store_truth_human_actor(&actor)? {
            return Err(Error::ConsentOwnerNotAuthenticated(
                "actor is not a store-truth human entity",
            ));
        }
        // Registry-active: a merged or split shell is a redirect, not an
        // owner. The topology fold fails closed.
        match self
            .entity_lifecycle_state(&actor)
            .map_err(|_| Error::ConsentOwnerNotAuthenticated("actor lifecycle is unreadable"))?
        {
            crate::identity_topology::EntityLifecycleState::Active => {}
            crate::identity_topology::EntityLifecycleState::Merged
            | crate::identity_topology::EntityLifecycleState::Split => {
                return Err(Error::ConsentOwnerNotAuthenticated(
                    "actor is registry-inactive (merged/split shell), not an owner",
                ));
            }
        }
        // A hex principal ref is an entity reference: it must decode to THIS
        // actor, or the authenticated principal and the minted grant would
        // name different actors.
        if let Ok(principal_id) = EntityId::from_hex(principal_ref.as_str())
            && principal_id != actor
        {
            return Err(Error::ConsentOwnerNotAuthenticated(
                "principal_ref binds to a different actor entity",
            ));
        }
        Ok(AuthenticatedOwner {
            actor,
            principal_ref,
            decision_id,
        })
    }

    fn is_store_truth_human_actor(&self, actor: &EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, actor.as_bytes())? else {
            return Ok(false);
        };
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        Ok(header.entity_type == crate::registry::ENTITY_TYPE_PERSON)
    }

    /// Approves exactly one pending operation, identified by its exact
    /// engine-computed digest.
    ///
    /// Consumes only that digest: an approve-once receipt authorizes this op,
    /// now, and covers no other op and no future op. It mints no standing row.
    /// The mint is REPLAY-REJECTED: a spent marker keyed by the digest is
    /// claimed in the SAME write transaction as the receipt, so a second
    /// `approve_once` over the same digest — the owner re-tapping an
    /// already-answered ask, or a replayed digest — is refused with
    /// [`Error::ConsentApproveOnceSpent`]. LMDB serializes writers, so a
    /// concurrent mint sees the committed marker and rolls back.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConsentApproveOnceSpent`] when the digest was already
    /// approved, and [`Error::ConsentOwnerNotAuthenticated`] transitively
    /// from the owner-stamp check.
    pub fn approve_once(
        &self,
        owner: &AuthenticatedOwner,
        effect_digest: EffectDigest,
    ) -> Result<ConsentReceipt> {
        let mut wtxn = self.store.env.write_txn()?;
        let decision_id = GateDecisionId::now();
        self.claim_approve_once_in_txn(&mut wtxn, &effect_digest, decision_id)?;
        let receipt = ConsentReceipt::Approved {
            decision_id,
            grant: ConsentGrant::ApproveOnce(effect_digest),
        };
        self.append_consent_receipt_in_txn(&mut wtxn, owner, &receipt)?;
        wtxn.commit()?;
        Ok(receipt)
    }

    /// Claims the approve-once slot for `digest` inside `wtxn`, or fails when
    /// any marker already exists. The available marker carries the approving
    /// [`GateDecisionId`], so a contested mint names its evidence; delivery
    /// preserves that id while atomically changing the state to spent. LMDB
    /// serializes writers, so two racing mints cannot both win.
    fn claim_approve_once_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        digest: &EffectDigest,
        decision_id: GateDecisionId,
    ) -> Result<()> {
        let key = consent_approve_once_key(digest);
        if self.store.vault_meta.get(&*wtxn, &key)?.is_some() {
            return Err(Error::ConsentApproveOnceSpent(
                "this op digest already carries an approve-once receipt",
            ));
        }
        let marker = encode_approve_once_marker(CONSENT_APPROVE_ONCE_AVAILABLE, decision_id);
        self.store.vault_meta.put(wtxn, &key, &marker)?;
        Ok(())
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
        self.with_write_txn(|wtxn| self.create_standing_grant_in_txn(wtxn, owner, bound))
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
        if bound_catastrophe_class(&bound).is_some() {
            return Err(Error::ConsentCatastropheNotRememberable(
                "the catastrophe floor is non-rememberable; no standing grant may cover it",
            ));
        }
        let grant = StandingConsentGrant::from_bound(bound)?;
        let row = ConsentGrantRow {
            grant: grant.clone(),
            status: ConsentGrantStatus::Active,
            owner_stamp: owner.stamp(),
            created_at: crate::unix_seconds_now(),
        };
        let receipt = ConsentReceipt::Approved {
            decision_id: GateDecisionId::now(),
            grant: ConsentGrant::Standing(grant),
        };

        let key = consent_grant_key(&row.grant_ref());
        let data = encode_consent_grant_row(&row)?;
        // Re-minting an identical bound is the owner re-affirming it; the row
        // is idempotent, and the receipt is still written so the act is
        // audit-visible.
        self.store.vault_meta.put(wtxn, &key, &data)?;
        self.append_consent_receipt_in_txn(wtxn, owner, &receipt)?;
        Ok(receipt)
    }

    /// Denies one pending operation, recording the refusal in the receipt
    /// family so a denial is as legible as an approval.
    pub fn deny_consent(
        &self,
        owner: &AuthenticatedOwner,
        effect_digest: EffectDigest,
    ) -> Result<ConsentReceipt> {
        let receipt = ConsentReceipt::Denied {
            decision_id: GateDecisionId::now(),
            effect_digest,
        };
        let mut wtxn = self.store.env.write_txn()?;
        self.append_consent_receipt_in_txn(&mut wtxn, owner, &receipt)?;
        wtxn.commit()?;
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
        let key = consent_grant_key(grant_ref);
        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw) = self.store.vault_meta.get(&wtxn, &key)? else {
            return Err(Error::ConsentGrantNotFound);
        };
        let mut row = decode_consent_grant_row(&raw)?;
        row.status = ConsentGrantStatus::Revoked;
        let data = encode_consent_grant_row(&row)?;
        self.store.vault_meta.put(&mut wtxn, &key, &data)?;
        let receipt = ConsentReceipt::Revoked {
            decision_id: GateDecisionId::now(),
            grant_ref: grant_ref.to_owned(),
        };
        self.append_consent_receipt_in_txn(&mut wtxn, owner, &receipt)?;
        wtxn.commit()?;
        Ok(receipt)
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
        let key = consent_grant_key(grant_ref);
        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw) = self.store.vault_meta.get(&wtxn, &key)? else {
            return Err(Error::ConsentGrantNotFound);
        };
        let row = decode_consent_grant_row(&raw)?;
        if !row.is_active() {
            return Err(Error::ConsentGrantRevoked);
        }
        let receipt = ConsentReceipt::Used {
            decision_id: GateDecisionId::now(),
            grant_ref: grant_ref.to_owned(),
            effect_digest,
        };
        self.append_consent_gate_decision_in_txn(&mut wtxn, &row.owner_stamp, &receipt)?;
        wtxn.commit()?;
        Ok(receipt)
    }

    /// Reads one standing consent-grant row.
    pub fn consent_grant(&self, grant_ref: &str) -> Result<Option<ConsentGrantRow>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self
            .store
            .vault_meta
            .get(&rtxn, &consent_grant_key(grant_ref))?
        else {
            return Ok(None);
        };
        decode_consent_grant_row(&raw).map(Some)
    }

    /// Every ACTIVE standing grant, for the evaluator.
    ///
    /// Revoked rows are filtered here rather than at the call site so a
    /// revocation is immediate for every consumer.
    pub fn active_standing_consent_grants(&self) -> Result<Vec<StandingConsentGrant>> {
        let rtxn = self.store.env.read_txn()?;
        self.active_standing_consent_grants_in_txn(&rtxn)
    }

    /// Transaction-composable [`Vault::active_standing_consent_grants`].
    ///
    /// Reads on the caller's transaction (read or write — an `RwTxn`
    /// derefs here), so a door composing the consent context INSIDE its own
    /// write txn sees the same snapshot the enclosing commit is decided on.
    pub fn active_standing_consent_grants_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<StandingConsentGrant>> {
        load_active_standing_grants(&self.store, txn)
    }

    /// The DEC-0006 door: evaluates one composed effect against the owner's
    /// current remembered state and returns both the verdict and the Gate
    /// reason codes that explain it.
    ///
    /// This is what a write door calls to opt onto the unified consent path.
    /// It loads the ACTIVE grants itself, so a caller cannot pass a stale or
    /// hand-picked grant set, and it routes through the one evaluator, so no
    /// door re-implements the ladder. `pending_approve_once` is the exact
    /// engine-emitted digest of an approve-once receipt already in hand for this
    /// op, if any. Digest equality alone is not authority: this door reads the
    /// marker, evaluates the ladder, and changes an admitted marker to spent in
    /// one write transaction. A replay is refused before another `Auto` can be
    /// returned.
    ///
    /// The returned reason codes are empty exactly when the verdict is
    /// [`ConsentDecision::Auto`].
    pub fn evaluate_consent_for(
        &self,
        effect: &ComposedEffect,
        pending_approve_once: Option<&EffectDigest>,
    ) -> Result<ConsentEvaluation> {
        let mut wtxn = self.store.env.write_txn()?;
        let grants = self.active_standing_consent_grants_in_txn(&wtxn)?;
        let approve_once = pending_approve_once
            .map(|digest| approve_once_authorization_in_txn(&self.store, &wtxn, digest))
            .transpose()?
            .flatten();
        let context =
            crate::gate::ConsentGateContext::evaluate(effect, approve_once.as_ref(), &grants);
        if context.decision == ConsentDecision::Auto
            && let Some(authorization) = approve_once.as_ref()
        {
            spend_approve_once_in_txn(&self.store, &mut wtxn, authorization)?;
        }
        let evaluation = ConsentEvaluation {
            decision: context.decision,
            reason_codes: crate::gate::consent_gate_reason_codes(&context),
        };
        wtxn.commit()?;
        Ok(evaluation)
    }

    /// The unified consent registry — surface (b) of invariant 9.
    ///
    /// Review and one-tap revoke for BOTH domains in one place. There is no
    /// third surface and no settings screen: the in-moment ask (`genui.rs`) is
    /// surface (a), and this is surface (b).
    pub fn consent_registry(&self, query: ConsentRegistryQuery) -> Result<ConsentRegistry> {
        let mut rows: Vec<ConsentRegistryRow> = self
            .consent_grant_rows()?
            .iter()
            .filter(|row| query.include_revoked || row.is_active())
            .map(ConsentRegistryRow::from_row)
            .collect();
        rows.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| left.grant_ref.cmp(&right.grant_ref))
        });
        rows.truncate(query.limit);
        Ok(ConsentRegistry { rows })
    }

    fn consent_grant_rows(&self) -> Result<Vec<ConsentGrantRow>> {
        let rtxn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for entry in self
            .store
            .vault_meta
            .prefix_iter(&rtxn, CONSENT_GRANT_KEY_PREFIX)?
        {
            let (_, value) = entry?;
            rows.push(decode_consent_grant_row(&value)?);
        }
        Ok(rows)
    }

    fn append_consent_receipt_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        receipt: &ConsentReceipt,
    ) -> Result<()> {
        self.append_consent_gate_decision_in_txn(wtxn, &owner.stamp(), receipt)
    }

    /// Projects a [`ConsentReceipt`] into the existing Gate receipt family.
    ///
    /// `diff_handle` holds the effect/bound digest and `grant_ref` joins
    /// standing use, exactly as every other Gate receipt does — no second
    /// receipt ledger is minted.
    fn append_consent_gate_decision_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        stamp: &ConsentOwnerStamp,
        receipt: &ConsentReceipt,
    ) -> Result<()> {
        let record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id: receipt.decision_id(),
            created_at: crate::unix_seconds_now(),
            outcome: receipt.gate_outcome().to_owned(),
            reason_codes: vec![receipt.reason_code().to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: CONSENT_ACTOR_CLASS.to_owned(),
            actor_ref: Some(stamp.actor.to_hex()),
            content_kind: CONSENT_CONTENT_KIND.to_owned(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            claim_id: None,
            grant_ref: receipt.grant_ref(),
            diff_handle: receipt.diff_handle(),
            read_frontier_hash: [0_u8; 32],
            redacted_at: None,
        };
        self.store.append_gate_decision_in_txn(wtxn, &record)
    }
}

/// One consent verdict plus the Gate reason codes that explain it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentEvaluation {
    /// The evaluator's verdict.
    pub decision: ConsentDecision,
    /// Stable `gate.`-namespaced pending reason codes; empty iff `decision`
    /// is [`ConsentDecision::Auto`].
    pub reason_codes: Vec<String>,
}

/// The catastrophe class a bound would cover, if any.
///
/// Used to reject catastrophe bounds from standing-grant minting. The match is
/// on the bound's action class against the closed floor's pinned strings, so
/// adding a floor member automatically extends the rejection.
#[must_use]
pub fn bound_catastrophe_class(bound: &GrantBound) -> Option<CatastropheClass> {
    let class = bound.class().as_str();
    CATASTROPHE_FLOOR_V1
        .into_iter()
        .find(|catastrophe| catastrophe.as_str() == class)
}

/// Every ACTIVE standing grant, read on the caller's transaction.
///
/// This is the `Store`-level projection a write door (which holds the store
/// and its in-flight write txn, not the `Vault`) uses to compose a
/// `crate::gate::ConsentGateContext`. Reading on the SAME transaction the
/// enclosing commit rides on keeps a revocation inside that txn visible to
/// the verdict.
///
/// Revoked rows are filtered here rather than at the call site so a
/// revocation is immediate for every consumer — the `RoTxn` bound accepts a
/// `&RwTxn` by deref.
pub fn load_active_standing_grants(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<StandingConsentGrant>> {
    let mut grants = Vec::new();
    for entry in store
        .vault_meta
        .prefix_iter(txn, CONSENT_GRANT_KEY_PREFIX)?
    {
        let (_, value) = entry?;
        let row = decode_consent_grant_row(&value)?;
        if row.is_active() {
            grants.push(row.grant);
        }
    }
    Ok(grants)
}

/// Whether one standing grant row exists and is live, on the caller's
/// transaction.
///
/// The consent registry is the single truth for "is this bound graduated": a
/// consumer that needs the answer reads THIS row rather than keeping a second
/// copy that could disagree with it (ONE-1748's ramp derives
/// [`crate::consent_graduation::RampState`] here).
pub(crate) fn standing_grant_is_active_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    grant_ref: &str,
) -> Result<bool> {
    let Some(raw) = store.vault_meta.get(txn, &consent_grant_key(grant_ref))? else {
        return Ok(false);
    };
    Ok(decode_consent_grant_row(&raw)?.is_active())
}

/// Flips one standing grant to [`ConsentGrantStatus::Revoked`] inside the
/// caller's write transaction, reporting whether a live row was actually
/// revoked.
///
/// Deliberately owner-free, unlike [`Vault::revoke_consent_grant`]: REDUCING
/// authority is safe for anyone to do, and only GRANTING requires an
/// [`AuthenticatedOwner`]. The caller owns the receipt — this door writes none,
/// so an engine-side self-demotion records exactly one act (ONE-1748) instead
/// of a revocation receipt and a demotion receipt describing the same event.
pub(crate) fn revoke_standing_grant_in_txn(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    grant_ref: &str,
) -> Result<bool> {
    let key = consent_grant_key(grant_ref);
    let Some(raw) = store.vault_meta.get(&*wtxn, &key)? else {
        return Ok(false);
    };
    let mut row = decode_consent_grant_row(&raw)?;
    if !row.is_active() {
        return Ok(false);
    }
    row.status = ConsentGrantStatus::Revoked;
    let data = encode_consent_grant_row(&row)?;
    store.vault_meta.put(wtxn, &key, &data)?;
    Ok(true)
}

/// Reads one approve-once marker from the caller's transaction.
///
/// An available marker yields an unforgeable authorization. A spent marker is
/// a replay and fails typed. Absence yields `None`, so a caller-supplied digest
/// with no receipt never reaches the evaluator's approve-once `Auto` arm.
pub(crate) fn approve_once_authorization_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    digest: &EffectDigest,
) -> Result<Option<ApproveOnceAuthorization>> {
    let key = consent_approve_once_key(digest);
    let Some(raw) = store.vault_meta.get(txn, &key)? else {
        return Ok(None);
    };
    let (state, _) = decode_approve_once_marker(&raw)?;
    match state {
        CONSENT_APPROVE_ONCE_AVAILABLE => Ok(Some(ApproveOnceAuthorization {
            effect_digest: *digest,
        })),
        CONSENT_APPROVE_ONCE_SPENT => Err(Error::ConsentApproveOnceSpent(
            "this approve-once authorization already delivered its effect",
        )),
        _ => Err(Error::CorruptedIndex("consent approve-once marker state")),
    }
}

/// Changes one store-attested approve-once marker to spent in `wtxn`.
///
/// The caller performs this only when the enclosing authorization is `Auto`.
/// Because the state transition shares the effect's write transaction, aborting
/// that transaction restores the available tap; committing it makes every
/// replay fail before authorization.
pub(crate) fn spend_approve_once_in_txn(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    authorization: &ApproveOnceAuthorization,
) -> Result<()> {
    let key = consent_approve_once_key(&authorization.effect_digest);
    let Some(raw) = store.vault_meta.get(&*wtxn, &key)? else {
        return Err(Error::ConsentApproveOnceSpent(
            "approve-once authorization has no live marker",
        ));
    };
    let (state, decision_id) = decode_approve_once_marker(&raw)?;
    if state == CONSENT_APPROVE_ONCE_SPENT {
        return Err(Error::ConsentApproveOnceSpent(
            "this approve-once authorization already delivered its effect",
        ));
    }
    if state != CONSENT_APPROVE_ONCE_AVAILABLE {
        return Err(Error::CorruptedIndex("consent approve-once marker state"));
    }
    let marker = encode_approve_once_marker(CONSENT_APPROVE_ONCE_SPENT, decision_id);
    store.vault_meta.put(wtxn, &key, &marker)?;
    Ok(())
}
