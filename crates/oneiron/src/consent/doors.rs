use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};

use super::bound::{ActorBound, GrantBound};
use super::codec::GRANTS;
use super::effect::{
    ApproveOnceAuthorization, CATASTROPHE_FLOOR_V2, CatastropheClass, ComposedEffect,
    ConsentDecision, EffectDigest,
};
use super::grant::{
    CONSENT_CONTENT_KIND, ConsentGrant, ConsentGrantRow, ConsentGrantStatus, ConsentOwnerStamp,
    ConsentReceipt, StandingConsentGrant,
};
use super::registry::{ConsentRegistry, ConsentRegistryQuery, ConsentRegistryRow};
use super::support::{
    APPROVE_ONCE_MARKERS, ApproveOnceMarker, CONSENT_APPROVE_ONCE_AVAILABLE,
    CONSENT_APPROVE_ONCE_SPENT, normalized_ref,
};
use crate::error::GateError;

mod decision_slot;
mod grants;
mod lineage;
mod owner;
mod person_credential;
mod queue_check;
mod read;
mod request_credential;

pub(crate) use queue_check::QueuedCheckApproval;

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
    /// The vault that authenticated this principal. A proof from a different
    /// vault must never authorize reading or acting on this vault's records.
    vault_path: std::path::PathBuf,
    /// The open of that vault (`StoreCore::open_nonce`): a path names a
    /// place, and another vault may open there after a close.
    vault_open: [u8; 16],
    /// The verified capability that carried this owner's request, when a
    /// transport bound one ([`Vault::bind_owner_credential`]). Every
    /// revalidation then also requires that capability to be live and the
    /// actor to be an owner of this vault.
    credential: Option<Box<crate::authority::VerifiedSlip>>,
    /// The person's own verified capability that carried a request from
    /// someone who need not own this vault, when a transport bound one
    /// ([`Vault::bind_person_credential`], FIX 4707). Every person-tier
    /// revalidation then also requires it to be live; it adds no owner
    /// authority, so every owner-tier door refuses the proof.
    person_credential: Option<Box<crate::authority::VerifiedSlip>>,
    /// The slip a person's request arrived with, a liveness guard alone
    /// ([`Vault::bind_request_credential`], FIX 4328).
    request_credential: Option<Box<crate::authority::VerifiedSlip>>,
    /// The host action this owner was authenticated from, when a host
    /// authenticated a self-hosted root or the local dev mode as the owner
    /// ([`Vault::authenticate_host_action_owner`], FIX 2222). Every
    /// revalidation then also requires that action to still hold.
    host_action: Option<Box<crate::authority::HostActionGuard>>,
}

impl AuthenticatedOwner {
    /// The authenticated human actor, for tests that inspect a proof. A door
    /// takes it from [`Self::revalidate_in_txn`] or [`Self::actor_for_read`].
    #[cfg(test)]
    #[must_use]
    pub const fn actor(&self) -> EntityId {
        self.actor
    }

    /// The authenticated principal reference, for tests that inspect a proof.
    #[cfg(test)]
    #[must_use]
    pub fn principal_ref(&self) -> &str {
        &self.principal_ref
    }

    /// The actor for a pure read: this proof belongs to `vault`. Never for an
    /// act of owner authority, which takes its actor from
    /// `revalidate_in_txn` inside the acting transaction.
    pub fn actor_for_read(&self, vault: &Vault) -> Result<EntityId> {
        self.check_vault(vault)?;
        Ok(self.actor)
    }

    /// [`Self::actor_for_read`] for the principal reference: never for an
    /// act of owner authority.
    pub fn principal_ref_for_read(&self, vault: &Vault) -> Result<&str> {
        self.check_vault(vault)?;
        Ok(&self.principal_ref)
    }

    /// [`Self::revalidate`] for a door that names its actor by principal
    /// reference and has no transaction of its own.
    pub fn revalidate_principal_ref(&self, vault: &Vault) -> Result<&str> {
        self.revalidate(vault)?;
        Ok(&self.principal_ref)
    }

    /// [`Self::revalidate_person`] for a door that names its actor by
    /// principal reference.
    pub fn revalidate_person_principal_ref(&self, vault: &Vault) -> Result<&str> {
        self.revalidate_person(vault)?;
        Ok(&self.principal_ref)
    }

    /// [`Self::revalidate_in_txn`], for a door that names its actor by
    /// principal reference.
    pub(crate) fn principal_ref_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<&str> {
        self.revalidate_in_txn(vault, txn)?;
        Ok(&self.principal_ref)
    }

    /// [`Self::revalidate_person_in_txn`], for a door that names its actor
    /// by principal reference.
    pub(crate) fn person_principal_ref_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<&str> {
        self.revalidate_person_in_txn(vault, txn)?;
        Ok(&self.principal_ref)
    }

    fn check_vault(&self, vault: &Vault) -> Result<()> {
        if self.vault_path.as_path() != vault.store.env.path()
            || self.vault_open != vault.store.open_nonce
        {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "owner proof belongs to another vault",
            )));
        }
        Ok(())
    }

    /// Whether this proof was authenticated by `vault`'s own open, the
    /// first thing every revalidation asks.
    pub(crate) fn belongs_to(&self, vault: &Vault) -> bool {
        self.check_vault(vault).is_ok()
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

    /// `revalidate_in_txn` in its own read transaction, for a door that
    /// checks its owner before it opens its writer. A door never rebuilds a
    /// proof from its public fields instead: a proof another vault
    /// authenticated for the same PERSON id would pass that.
    pub fn revalidate(&self, vault: &Vault) -> Result<EntityId> {
        let txn = vault.store.env.read_txn()?;
        self.revalidate_in_txn(vault, &txn)
    }

    /// `revalidate_person_in_txn` in its own read transaction.
    pub fn revalidate_person(&self, vault: &Vault) -> Result<EntityId> {
        let txn = vault.store.env.read_txn()?;
        self.revalidate_person_in_txn(vault, &txn)
    }

    /// The actor of an act of owner authority: this proof belongs to `vault`,
    /// its person is live and owns this vault, and the credential it carried
    /// is still live, all in the acting transaction. A native host's proof
    /// shows a live person, not whose vault this is, so every door asks for
    /// both unless it is one of the few a person uses on their own behalf
    /// ([`Self::revalidate_person_in_txn`]).
    pub(crate) fn revalidate_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<EntityId> {
        let actor = self.revalidate_person_in_txn(vault, txn)?;
        // A person credential carries no owner authority, even an owner's:
        // a narrowed slip of his never acts at an owner-tier door through
        // the holders' door (FIX 4707).
        if self.person_credential.is_some() {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "a person credential carries no owner authority",
            )));
        }
        // A bound credential's check above already asked for an owner.
        if self.credential.is_none()
            && !crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &actor)?
        {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "authenticated actor is not an owner of this vault",
            )));
        }
        Ok(actor)
    }

    /// The actor of a door a live person uses on their own behalf, owner of
    /// this vault or not: their own refusal, preference, feedback label,
    /// saved digest, assigned answer or private session, or a door whose own
    /// membership and named-grant check is the authorization. This proof
    /// belongs to `vault`, its person is live, and a credential it carried is
    /// still live and still an owner's, or a person credential it carried is
    /// still live, all in the acting transaction. Every other door takes
    /// [`Self::revalidate_in_txn`].
    pub(crate) fn revalidate_person_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<EntityId> {
        self.check_vault(vault)?;
        if !person_is_live_in_txn(vault, txn, &self.actor)? {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "authenticated owner is no longer active",
            )));
        }
        if let Some(action) = &self.host_action {
            // Rechecked in the caller's transaction (FIX 2222): a root
            // revoked or a binding withdrawn while the request waited for the
            // writer commits nothing. Off a self-hosted vault the typed
            // refusal stands as it is.
            action.holds_in(vault, txn).map_err(|error| match error {
                Error::Claim(crate::error::ClaimError::ScopedReadOwnerNotLive(_)) => {
                    Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                        "the host action this owner was authenticated from no longer holds",
                    ))
                }
                other => other,
            })?;
        }
        if let Some(credential) = &self.credential {
            // Rechecked in the caller's transaction: a capability revoked, or
            // an owner removed, while the request waited for the writer
            // commits nothing.
            if !vault.capability_slip_is_live_in_txn(txn, credential)? {
                return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                    "owner credential is no longer live",
                )));
            }
            if !crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &self.actor)? {
                return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                    "authenticated actor is no longer an owner of this vault",
                )));
            }
        }
        if let Some(credential) = &self.person_credential
            && !vault.capability_slip_is_live_in_txn(txn, credential)?
        {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "person credential is no longer live",
            )));
        }
        self.request_credential_holds_in_txn(vault, txn)?;
        Ok(self.actor)
    }

    /// [`Self::revalidate_in_txn`], under the name the doors that asked for
    /// the owner tier before it was every door's default still call.
    pub(crate) fn revalidate_as_vault_owner_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<EntityId> {
        self.revalidate_in_txn(vault, txn)
    }

    /// Revalidates this proof as the vault's owner in the writing
    /// transaction and names the write it authors as the owner's own.
    ///
    /// Owner-authored writes carry their own confirmation: a critical claim
    /// this write lands attaches no confirm. A bound credential must be the
    /// owner's own unattenuated, undelegated slip (a logged child mint is a
    /// delegation even when it keeps the owner's scope). A proof that no
    /// longer holds refuses the write rather than downgrading it.
    pub(crate) fn owner_authored_write_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<OwnerAuthoredWrite> {
        if self.credential.as_ref().is_some_and(|credential| {
            !credential.is_full_vault_owner_grade() || credential.claims().parent_id.is_some()
        }) {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "owner credential is narrowed or delegated",
            )));
        }
        self.revalidate_as_vault_owner_in_txn(vault, txn)?;
        Ok(OwnerAuthoredWrite { actor: self.actor })
    }

    /// This proof as an owner-tier answer to a claim's owner-answer
    /// obligation, revalidated in the answering transaction: the vault
    /// owner's own unattenuated, undelegated credential. A narrowed or
    /// delegated credential, or a person who no longer owns the vault,
    /// answers nothing (`None`), and the door acts as it did before.
    pub(crate) fn owner_answer_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<OwnerAuthoredWrite>> {
        match self.owner_authored_write_in_txn(vault, txn) {
            Ok(write) => Ok(Some(write)),
            Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_))) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Whether the credential this proof was carried under is a support
    /// slip (OF-606). A support person or agent never acts as the owner, so
    /// the support grant doors refuse such a proof outright, whatever else
    /// it would pass.
    pub(crate) fn carried_by_support_slip(&self) -> bool {
        self.carried_slip()
            .is_some_and(|credential| credential.claims().delegation.is_some())
    }

    /// The slip a transport bound this proof to: the owner's credential, or
    /// a person's ([`Vault::bind_person_credential`]).
    fn carried_slip(&self) -> Option<&crate::authority::VerifiedSlip> {
        self.credential
            .as_deref()
            .or(self.person_credential.as_deref())
    }

    pub(super) fn stamp(&self) -> ConsentOwnerStamp {
        ConsentOwnerStamp {
            actor: self.actor,
            principal_ref: self.principal_ref.clone(),
            decision_id: self.decision_id,
        }
    }
}

/// A claim write the vault's authenticated owner made in person, revalidated
/// in the transaction that writes it.
///
/// Only [`AuthenticatedOwner::owner_authored_write_in_txn`] builds one, and
/// it is neither `Clone` nor stored: the writing door takes it by value into
/// that transaction's gate mode, so no later write can inherit it.
#[derive(Debug)]
pub(crate) struct OwnerAuthoredWrite {
    actor: EntityId,
}

impl OwnerAuthoredWrite {
    /// The owner who authored the write.
    pub(crate) const fn actor(&self) -> EntityId {
        self.actor
    }
}

/// The authentication door's liveness test: the id names a PERSON whose
/// identity lifecycle is Active (not merged or split) and that is not deleted.
/// A plain user delete keeps the PERSON shell and its Active lifecycle; only
/// the deletion tombstone says the owner is gone.
pub(crate) fn person_is_live_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    person_is_live_with(&vault.store, txn, id, || {
        vault.entity_lifecycle_state_in_txn(txn, id)
    })
}

/// [`person_is_live_in_txn`] for a reader that holds a `Store` and no `Vault`
/// (FIX 7461): the same test, the lifecycle read through its store form.
pub(crate) fn person_is_live_for_store_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    person_is_live_with(store, txn, id, || {
        crate::identity_topology::entity_lifecycle_state_for_store_in_txn(store, txn, id)
    })
}

/// The liveness test, `id`'s lifecycle read by `lifecycle` only once its row
/// is a PERSON.
fn person_is_live_with(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    lifecycle: impl FnOnce() -> Result<crate::identity_topology::EntityLifecycleState>,
) -> Result<bool> {
    let human = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?
        .and_then(|raw| crate::batch::EntityMetadataHeader::parse(&raw))
        .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_PERSON);
    Ok(human
        && lifecycle()? == crate::identity_topology::EntityLifecycleState::Active
        && !crate::ports::TombstoneStoreRead::port_deletion_state(store, txn, id)?.deleted)
}

/// The pinned Gate `actor_class` for owner-authored consent decisions.
const CONSENT_ACTOR_CLASS: &str = "human";

// ---------------------------------------------------------------------------
// The Vault doors
// ---------------------------------------------------------------------------

impl Vault {
    fn is_store_truth_human_actor(&self, actor: &EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.port_entity_record(&rtxn, actor)? else {
            return Ok(false);
        };

        Ok(raw.entity_type == crate::registry::ENTITY_TYPE_PERSON)
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
        if APPROVE_ONCE_MARKERS
            .get(&self.store, &*wtxn, digest.as_bytes())?
            .is_some()
        {
            return Err(Error::Gate(GateError::ConsentApproveOnceSpent(
                "this op digest already carries an approve-once receipt",
            )));
        }
        let marker = ApproveOnceMarker {
            state: CONSENT_APPROVE_ONCE_AVAILABLE,
            decision_id,
        };
        APPROVE_ONCE_MARKERS.put(&self.store, wtxn, digest.as_bytes(), &marker)?;
        Ok(())
    }

    /// One quiet reuse receipt joined to the reason row that justified it.
    /// The caller holds the matching rule and the active-grant read in this txn.
    pub(super) fn record_owner_reason_use_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        grant_ref: &str,
        rule_decision_id: [u8; 16],
        reason: &str,
        effect_digest: EffectDigest,
    ) -> Result<ConsentReceipt> {
        let row = self
            .consent_grant_in_txn(&*txn, grant_ref)?
            .ok_or(Error::Gate(GateError::ConsentGrantNotFound))?;
        if !row.is_active() {
            return Err(Error::Gate(GateError::ConsentGrantRevoked));
        }
        let receipt = ConsentReceipt::Used {
            decision_id: GateDecisionId::from_bytes(self.store.clock.ulid()?),
            grant_ref: grant_ref.to_owned(),
            effect_digest,
        };
        let rule_id = GateDecisionId::from_bytes(rule_decision_id).to_hex();
        self.append_consent_gate_decision_in_txn(
            txn,
            &row.owner_stamp,
            &receipt,
            Some((&rule_id, reason)),
        )?;
        Ok(receipt)
    }

    fn consent_grant_rows(&self) -> Result<Vec<ConsentGrantRow>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(GRANTS
            .scan(&self.store, &rtxn)?
            .into_iter()
            .map(|(_, row)| row)
            .collect())
    }

    /// Every owner-authored consent act (a grant, an approval, a denial, a
    /// revocation) lands its receipt here, in the transaction that writes the
    /// act. The proof is rechecked in that transaction: one from another
    /// vault, or whose owner or credential has gone, fails the act and the
    /// transaction commits none of it.
    pub(super) fn append_consent_receipt_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        receipt: &ConsentReceipt,
    ) -> Result<()> {
        owner.revalidate_in_txn(self, &*wtxn)?;
        self.append_consent_gate_decision_in_txn(wtxn, &owner.stamp(), receipt, None)
    }

    /// Appends one code consent wait receipt (DOOR-079) into the consent
    /// Gate family, in the writer that records the act it receipts.
    /// `answered_by` is the authenticated answer it follows, when one was:
    /// its provenance, not a currently present owner. A settlement no person
    /// answered (the call's expiry, or its own gate releasing it) is the
    /// engine's own record.
    pub(crate) fn append_code_wait_receipt_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        receipt: &ConsentReceipt,
        answered_by: Option<&ConsentOwnerStamp>,
    ) -> Result<()> {
        if let Some(stamp) = answered_by {
            return self.append_consent_gate_decision_in_txn(wtxn, stamp, receipt, None);
        }
        let record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id: receipt.decision_id(),
            created_at: crate::ports::recorded_at_in_txn(&self.store, wtxn)?,
            outcome: receipt.gate_outcome().to_owned(),
            reason_codes: vec![receipt.reason_code().to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: "system".to_owned(),
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
        self.store.append_gate_decision_in_txn(wtxn, &record)
    }

    /// Projects a [`ConsentReceipt`] into the existing Gate receipt family.
    ///
    /// `diff_handle` holds the effect/bound digest and `grant_ref` joins
    /// standing use, exactly as every other Gate receipt does — no second
    /// receipt ledger is minted.
    pub(super) fn append_consent_gate_decision_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        stamp: &ConsentOwnerStamp,
        receipt: &ConsentReceipt,
        owner_reason: Option<(&str, &str)>,
    ) -> Result<()> {
        let mutation_recorded_at = crate::ports::recorded_at_in_txn(&self.store, wtxn)?;
        let record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id: receipt.decision_id(),
            created_at: mutation_recorded_at,
            outcome: receipt.gate_outcome().to_owned(),
            reason_codes: {
                let mut codes = vec![receipt.reason_code().to_owned()];
                if let Some((rule_id, _)) = owner_reason {
                    codes.push(format!("gate.consent.owner_reason.{rule_id}"));
                }
                codes
            },
            receipt_reasons: Vec::new(),
            system_notices: owner_reason.map_or_else(Vec::new, |(rule_id, reason)| {
                vec![crate::store::GateSystemNoticeRecord {
                    notice_type: "owner_reason".to_owned(),
                    channel: "receipt".to_owned(),
                    voice: "neutral".to_owned(),
                    audience: "owner".to_owned(),
                    body: reason.to_owned(),
                    row_ref: Some(rule_id.to_owned()),
                    setting_change_offer: None,
                    policy_plane: None,
                    policy_version: None,
                    docs_url: None,
                }]
            }),
            actor_class: CONSENT_ACTOR_CLASS.to_owned(),
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
}

/// One consent verdict plus the Gate reason codes that explain it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentEvaluation {
    /// The evaluator's verdict.
    pub decision: ConsentDecision,
    /// Stable `gate.`-namespaced pending reason codes; empty iff `decision`
    /// is [`ConsentDecision::Auto`].
    pub reason_codes: Vec<String>,
    /// The bypass grant this op ran under instead of asking, if one did.
    pub bypassed_by: Option<String>,
}

/// The catastrophe class a bound would cover, if any.
///
/// Used to reject catastrophe bounds from standing-grant minting. The match is
/// on the bound's action class against the closed floor's pinned strings, so
/// adding a floor member automatically extends the rejection.
#[must_use]
pub fn bound_catastrophe_class(bound: &GrantBound) -> Option<CatastropheClass> {
    let class = bound.class().as_str();
    CATASTROPHE_FLOOR_V2
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
    Ok(GRANTS
        .scan(store, txn)?
        .into_iter()
        // A bypass row covers only catastrophe-floor ops inside its scope,
        // through the bypass arm; it is never an ordinary standing grant.
        .filter_map(|(_, row)| (row.is_active() && row.bypass.is_none()).then_some(row.grant))
        .collect())
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
    let Some(row) = GRANTS.get(store, txn, &grant_ref.to_owned())? else {
        return Ok(false);
    };
    Ok(row.is_active())
}

/// One standing grant row by its ref, whatever its status, on the caller's
/// transaction: [`Vault::consent_grant_in_txn`] for a reader that holds a
/// `Store`.
pub(crate) fn standing_grant_row_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    grant_ref: &str,
) -> Result<Option<ConsentGrantRow>> {
    GRANTS.get(store, txn, &grant_ref.to_owned())
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
    let key = grant_ref.to_owned();
    let Some(mut row) = GRANTS.get(store, &*wtxn, &key)? else {
        return Ok(false);
    };
    if !row.is_active() {
        return Ok(false);
    }
    row.status = ConsentGrantStatus::Revoked;
    GRANTS.put(store, wtxn, &key, &row)?;
    super::owner_reason::retire_owner_reason_rules_in_txn(store, wtxn, grant_ref)?;
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
    let Some(marker) = APPROVE_ONCE_MARKERS.get(store, txn, digest.as_bytes())? else {
        return Ok(None);
    };
    match marker.state {
        CONSENT_APPROVE_ONCE_AVAILABLE => Ok(Some(ApproveOnceAuthorization {
            effect_digest: *digest,
        })),
        CONSENT_APPROVE_ONCE_SPENT => Err(Error::Gate(GateError::ConsentApproveOnceSpent(
            "this approve-once authorization already delivered its effect",
        ))),
        _ => Err(Error::CorruptedIndex("consent approve-once marker state")),
    }
}

/// The approving decision an approve-once marker names, read in `txn`.
pub(crate) fn approve_once_decision_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    digest: &EffectDigest,
) -> Result<Option<GateDecisionId>> {
    Ok(APPROVE_ONCE_MARKERS
        .get(store, txn, digest.as_bytes())?
        .map(|marker| marker.decision_id))
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
    let key = *authorization.effect_digest.as_bytes();
    let Some(marker) = APPROVE_ONCE_MARKERS.get(store, &*wtxn, &key)? else {
        return Err(Error::Gate(GateError::ConsentApproveOnceSpent(
            "approve-once authorization has no live marker",
        )));
    };
    if marker.state == CONSENT_APPROVE_ONCE_SPENT {
        return Err(Error::Gate(GateError::ConsentApproveOnceSpent(
            "this approve-once authorization already delivered its effect",
        )));
    }
    if marker.state != CONSENT_APPROVE_ONCE_AVAILABLE {
        return Err(Error::CorruptedIndex("consent approve-once marker state"));
    }
    let spent = ApproveOnceMarker {
        state: CONSENT_APPROVE_ONCE_SPENT,
        decision_id: marker.decision_id,
    };
    APPROVE_ONCE_MARKERS.put(store, wtxn, &key, &spent)?;
    Ok(())
}
