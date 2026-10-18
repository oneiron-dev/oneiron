//! OF-606: the customer's support grant. Owner ruling "A + support"
//! (2026-10-18): on our hosted cloud the operator root acts as nobody inside
//! a customer's vault (FIX 2222); to fix something there, the customer gives
//! our support person or agent a grant that is time-limited, revocable and
//! recorded like any other grant.
//!
//! The grant is the logged capability slip itself (`AUTHORITY_LOG`
//! SlipMint / SlipRevoke): no side table, no new entity kind, and no TTL on
//! any consent row. Its holder is a live, non-owner PERSON of the vault (a
//! human for a named support person, an agent for a support agent) that the
//! customer selected or authored the ordinary way, bound to the support
//! party's own public key; the mint makes no membership, machine enrolment,
//! pact or shared-vault conversion. Its signed delegation names the purpose,
//! the ticket, the approving owner and a wall deadline on the recording
//! clock (`support_admission`). Only the customer's owner mints, lists and
//! revokes, each revalidated in its own transaction; the host signs only as
//! issuer, after that revalidation. A support credential never passes these
//! doors, its own grant included. Each mint and revoke lands its Gate
//! receipt in the same writer (`support_receipt`).
//!
//! Owner-only repair operations stay the owner's: a support slip carries
//! read and, when the customer selects them, propose or write, and reads
//! through the ordinary non-owner lane.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::slip_vault::{random_slip_id, require_host};
use super::support_receipt::{
    SUPPORT_GRANT_REASON_MINTED, SUPPORT_GRANT_REASON_REVOKED, SupportReceipt, slip_hex,
};
use super::*;
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::federation::{Scope, ScopeAxis};
use crate::store::GateDecisionId;

/// The command a registry row's one-tap revoke names for a support grant:
/// the support revoke door, never the consent grant revoke.
pub const SUPPORT_GRANT_REVOKE_COMMAND: &str = "vault.support_grants.revoke";
/// The Gate actor class of the customer's own mint and revoke.
const OWNER_ACTOR_CLASS: &str = "human";
const MINT_DIGEST_CONTEXT: &[u8] = b"oneiron/support-grant/mint/v1\0";
const REVOKE_DIGEST_CONTEXT: &[u8] = b"oneiron/support-grant/revoke/v1\0";

/// Which kind of support party a grant names: a named support person
/// (`human`) or a support agent (`agent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SupportHolderClass {
    Human,
    Agent,
}

impl SupportHolderClass {
    /// The actor class the slip carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
        }
    }
}

/// What the customer's owner approves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportGrantRequest {
    /// The support PERSON: live, of this vault, and no owner of it.
    pub holder: EntityId,
    pub holder_class: SupportHolderClass,
    /// The support party's own Ed25519 public key; it keeps the private key.
    pub holder_key: [u8; 32],
    /// The exact bounds. Its verbs axis names the classes: `read` always,
    /// `propose` or `write` only when named; bottom is read-only.
    pub scope: Scope,
    /// Exact records the grant reads (empty: every record inside `scope`).
    /// A relationship's rows open to support only when named here.
    pub records: BTreeSet<EntityId>,
    /// Lifetime in seconds; [`SUPPORT_GRANT_DEFAULT_TTL_SECS`] when `None`.
    pub ttl_secs: Option<u64>,
    pub purpose: String,
    pub ticket_ref: Option<String>,
}

/// Where a support grant stands, as its list and the registry show it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SupportGrantStatus {
    /// It admits its holder now.
    Active,
    /// Its wall deadline or its slip lifetime has passed.
    Expired,
    /// The customer revoked it.
    Revoked,
    /// It no longer stands for another reason: its holder is gone, or the
    /// host that minted it no longer stands.
    Ended,
}

/// One support grant, read from its logged mint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportGrantRow {
    pub slip_id: [u8; 32],
    pub holder: EntityId,
    pub holder_class: String,
    pub scope: Scope,
    pub records: BTreeSet<String>,
    pub delegation: SupportDelegation,
    /// The slip's own lifetime end, on the authority clock.
    pub expires_at: u64,
    pub status: SupportGrantStatus,
}

/// A minted support grant: the credential for the support party (no private
/// key) and the Gate receipt of the customer's mint.
#[derive(Debug, Clone)]
pub struct SupportGrantMinted {
    pub slip: CapabilitySlip,
    pub grant: SupportGrantRow,
    pub decision_id: GateDecisionId,
}

/// What one support revoke did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportGrantRevoked {
    pub slip_id: [u8; 32],
    pub holder: EntityId,
    /// False when the grant was already revoked and this call changed
    /// nothing.
    pub changed: bool,
    /// The recording time of this revoke; `None` when it changed nothing.
    pub revoked_at: Option<u64>,
    /// The Gate receipt of this revoke; `None` when it changed nothing.
    pub decision_id: Option<GateDecisionId>,
}

/// How many support grants a list answers, and whether ended ones count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupportGrantQuery {
    pub limit: usize,
    pub include_inactive: bool,
}

impl Vault {
    /// Mints one support grant (OF-606): the customer owner's act, under the
    /// host's `issuer`, which signs only after the owner is revalidated in
    /// this writer. Refuses a holder that is not a live, non-owner PERSON, a
    /// class other than human or agent, a key that is the host's, a roster
    /// or bound actor key, or already holds an owner-grade or another
    /// holder's credential, bounds outside the support policy hook
    /// ([`support_scope_admissible`]), and a lifetime of zero or over
    /// [`SUPPORT_GRANT_MAX_TTL_SECS`]. The wall deadline is host recording
    /// time plus the lifetime; no caller names a `now`.
    ///
    /// # Errors
    ///
    /// The owner refusal, a typed refusal naming the bound that failed, or
    /// a storage failure.
    pub fn mint_support_grant(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        request: SupportGrantRequest,
    ) -> Result<SupportGrantMinted> {
        let ttl = request.ttl_secs.unwrap_or(SUPPORT_GRANT_DEFAULT_TTL_SECS);
        if ttl == 0 || ttl > SUPPORT_GRANT_MAX_TTL_SECS {
            return Err(refused(
                "a support grant lasts between one second and SUPPORT_GRANT_MAX_TTL_SECS",
            ));
        }
        let scope = support_slip_scope(request.scope)?;
        let records: BTreeSet<String> = request.records.iter().map(EntityId::to_hex).collect();
        support_scope_admissible(&scope, &records, &BTreeSet::new()).map_err(refused)?;
        let mut txn = self.store.env.write_txn()?;
        let approver = support_owner_in_txn(owner, self, &txn)?;
        let vault_id = {
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            require_host(&fold, issuer)?;
            require_support_key(&fold, issuer, request.holder_key, request.holder, approver)?;
            fold.vault_id.ok_or_else(invalid_authority)?
        };
        self.require_support_holder_in_txn(&txn, request.holder, approver)?;
        let approved_at = crate::ports::observe_clock_floor_in_txn(&self.store, &mut txn)?;
        let now = self.instant_in_txn(&txn)?.secs();
        let overflow = || refused("the support grant's deadline overflows the clock");
        let claims = SlipClaims {
            slip_id: random_slip_id(),
            vault_id,
            parent_id: None,
            holder_ref: request.holder.to_hex(),
            binding_key: request.holder_key,
            scope,
            issued_at: now,
            expires_at: now.checked_add(ttl).ok_or_else(overflow)?,
            ttl_secs: ttl,
            single_use: false,
            records,
            channels: BTreeSet::new(),
            actor_class: Some(request.holder_class.as_str().to_owned()),
            org_ref: None,
            grant_ref: None,
            invitation_ref: None,
            delegation: Some(SupportDelegation {
                purpose: request.purpose,
                ticket_ref: request.ticket_ref,
                owner_ref: approver.to_hex(),
                approved_at,
                wall_expires_at: approved_at.checked_add(ttl).ok_or_else(overflow)?,
            }),
        };
        claims.validate().map_err(|_| {
            refused("the support grant's purpose, ticket or bounds are not well formed")
        })?;
        let digest = claims_digest(MINT_DIGEST_CONTEXT, &claims)?;
        let slip = self.mint_slip_in_txn(&mut txn, issuer, claims)?;
        let grant = support_row(&slip.claims, SupportGrantStatus::Active)?;
        let decision_id = self.append_support_receipt_in_txn(
            &mut txn,
            SupportReceipt {
                reason: SUPPORT_GRANT_REASON_MINTED,
                outcome: "approved",
                actor: approver,
                actor_class: OWNER_ACTOR_CLASS.to_owned(),
                slip_id: grant.slip_id,
                digest,
                details: grant_details(&grant),
            },
        )?;
        txn.commit()?;
        Ok(SupportGrantMinted {
            slip,
            grant,
            decision_id,
        })
    }

    /// The vault's support grants, newest first (OF-606): the customer
    /// owner's read, revalidated in its snapshot. Active ones only, unless
    /// `query` asks for every one. A support credential lists nothing.
    ///
    /// # Errors
    ///
    /// The owner refusal, or a storage failure.
    pub fn list_support_grants(
        &self,
        owner: &AuthenticatedOwner,
        query: SupportGrantQuery,
    ) -> Result<Vec<SupportGrantRow>> {
        self.store.authorization_now()?;
        let txn = self.store.env.read_txn()?;
        support_owner_in_txn(owner, self, &txn)?;
        let mut rows = self.support_grant_rows_in_txn(&txn)?;
        rows.retain(|row| query.include_inactive || row.status == SupportGrantStatus::Active);
        rows.sort_by(|left, right| {
            right
                .delegation
                .approved_at
                .cmp(&left.delegation.approved_at)
                .then_with(|| left.slip_id.cmp(&right.slip_id))
        });
        rows.truncate(query.limit);
        Ok(rows)
    }

    /// Revokes one support grant (OF-606): the customer owner's act, which
    /// appends the slip's signed revoke under the host's `issuer` and its
    /// Gate receipt in one writer. A repeat changes nothing and answers
    /// `changed: false`. A slip that is no support grant is not found. What
    /// support already read, and outside effects already completed, are not
    /// recalled.
    ///
    /// # Errors
    ///
    /// The owner refusal, [`Error::EntityNotFound`], or a storage failure.
    pub fn revoke_support_grant(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        slip_id: [u8; 32],
    ) -> Result<SupportGrantRevoked> {
        let mut txn = self.store.env.write_txn()?;
        let approver = support_owner_in_txn(owner, self, &txn)?;
        let (grant, already) = {
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            require_host(&fold, issuer)?;
            let claims = fold
                .slips
                .mints
                .get(&slip_id)
                .map(|mint| &mint.action.claims)
                .filter(|claims| claims.delegation.is_some())
                .ok_or(Error::EntityNotFound)?;
            (
                support_row(claims, SupportGrantStatus::Revoked)?,
                fold.slips.explicit_revoked.contains(&slip_id),
            )
        };
        if already {
            return Ok(SupportGrantRevoked {
                slip_id,
                holder: grant.holder,
                changed: false,
                revoked_at: None,
                decision_id: None,
            });
        }
        self.append_slip_op_in_txn(&mut txn, issuer, AuthorityOp::SlipRevoke { slip_id })?;
        let revoked_at = crate::ports::observe_clock_floor_in_txn(&self.store, &mut txn)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(REVOKE_DIGEST_CONTEXT);
        hasher.update(&slip_id);
        let decision_id = self.append_support_receipt_in_txn(
            &mut txn,
            SupportReceipt {
                reason: SUPPORT_GRANT_REASON_REVOKED,
                outcome: "revoked",
                actor: approver,
                actor_class: OWNER_ACTOR_CLASS.to_owned(),
                slip_id,
                digest: *hasher.finalize().as_bytes(),
                details: vec![
                    format!("holder:{}", grant.holder.to_hex()),
                    format!("class:{}", grant.holder_class),
                ],
            },
        )?;
        txn.commit()?;
        Ok(SupportGrantRevoked {
            slip_id,
            holder: grant.holder,
            changed: true,
            revoked_at: Some(revoked_at),
            decision_id: Some(decision_id),
        })
    }

    /// Every support grant the fold holds, each with where it stands in
    /// `txn`: the owner list's rows and the consent registry's projection.
    pub(crate) fn support_grant_rows_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<SupportGrantRow>> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let recording_now = crate::ports::job_recorded_at_in_txn(&self.store, txn)?;
        let instant = self.instant_in_txn(txn)?;
        let mut rows = Vec::new();
        for (id, mint) in &fold.slips.mints {
            let claims = &mint.action.claims;
            let Some(delegation) = &claims.delegation else {
                continue;
            };
            let status = if fold.slips.explicit_revoked.contains(id) {
                SupportGrantStatus::Revoked
            } else if recording_now >= delegation.wall_expires_at
                || instant.secs() >= claims.expires_at
            {
                SupportGrantStatus::Expired
            } else if fold.slip_is_live_at(id, instant)
                && self.support_delegation_stands_in_txn(txn, claims)?
            {
                SupportGrantStatus::Active
            } else {
                SupportGrantStatus::Ended
            };
            rows.push(support_row(claims, status)?);
        }
        Ok(rows)
    }

    /// The support holder is a live PERSON of this vault and no owner of it:
    /// never the approving owner, the embedded owner, or any live owner.
    fn require_support_holder_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        holder: EntityId,
        approver: EntityId,
    ) -> Result<()> {
        if !crate::consent::person_is_live_in_txn(self, txn, &holder)? {
            return Err(refused(
                "the support holder is not a live person of this vault",
            ));
        }
        if holder == approver
            || crate::vault::embedded_owner_actor_id().ok() == Some(holder)
            || crate::policy_model::is_live_vault_owner_in_txn(self, txn, &holder)?
        {
            return Err(refused(
                "an owner of this vault is never its support holder",
            ));
        }
        Ok(())
    }
}

/// The owner a support grant door acts for, revalidated in `txn`. A proof a
/// support slip carried is refused first: support never mints, lists or
/// revokes support grants, its own included.
fn support_owner_in_txn(
    owner: &AuthenticatedOwner,
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<EntityId> {
    if owner.carried_by_support_slip() {
        return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
            "a support credential never acts as the owner",
        )));
    }
    owner.revalidate_in_txn(vault, txn)
}

/// The slip Scope of a request: its verbs axis plus `read`; bottom (no class
/// named) is read-only, and every class is refused.
fn support_slip_scope(scope: Scope) -> Result<Scope> {
    let mut verbs = match scope.verbs {
        ScopeAxis::Bottom => BTreeSet::new(),
        ScopeAxis::All => {
            return Err(refused(
                "a support grant names its classes one by one, never every class",
            ));
        }
        ScopeAxis::Some(verbs) => verbs,
    };
    verbs.insert("read".to_owned());
    Ok(Scope {
        verbs: ScopeAxis::Some(verbs),
        ..scope
    })
}

/// The support party's own key: a strong Ed25519 key that is not the host's,
/// no roster or actor-bound key, and held by no owner-grade credential nor
/// by another holder's.
fn require_support_key(
    fold: &AuthorityFold,
    issuer: &HostSlipIssuer,
    key: [u8; 32],
    holder: EntityId,
    approver: EntityId,
) -> Result<()> {
    strong_ed25519_key(&key)
        .map_err(|_| refused("the support holder key is not an Ed25519 public key"))?;
    let authority_key = AuthorityKey::Ed25519(key);
    let (holder, approver) = (holder.to_hex(), approver.to_hex());
    let held_elsewhere = fold.slips.mints.values().any(|mint| {
        let claims = &mint.action.claims;
        claims.binding_key == key
            && (claims.holder_ref != holder
                || claims.holder_ref == approver
                || claims.scope == Scope::top())
    });
    if key == issuer.binding_key()
        || fold.roster.contains_key(&authority_key)
        || fold.actor_bindings.contains_key(&authority_key)
        || held_elsewhere
    {
        return Err(refused(
            "the support holder key must be the support party's own, bound to no owner, host or other credential",
        ));
    }
    Ok(())
}

/// One logged support mint as a row standing at `status`.
fn support_row(claims: &SlipClaims, status: SupportGrantStatus) -> Result<SupportGrantRow> {
    let delegation = claims.delegation.clone().ok_or_else(invalid_authority)?;
    Ok(SupportGrantRow {
        slip_id: claims.slip_id,
        holder: EntityId::from_hex(&claims.holder_ref).map_err(|_| invalid_authority())?,
        holder_class: claims.actor_class.clone().ok_or_else(invalid_authority)?,
        scope: claims.scope.clone(),
        records: claims.records.clone(),
        delegation,
        expires_at: claims.expires_at,
        status,
    })
}

/// The `key:value` details a mint receipt carries.
fn grant_details(grant: &SupportGrantRow) -> Vec<String> {
    let mut details = vec![
        format!("holder:{}", grant.holder.to_hex()),
        format!("class:{}", grant.holder_class),
        format!("deadline:{}", grant.delegation.wall_expires_at),
        format!("slip:{}", slip_hex(&grant.slip_id)),
    ];
    if let Some(ticket) = &grant.delegation.ticket_ref {
        details.push(format!("ticket:{ticket}"));
    }
    details
}

fn claims_digest(context: &[u8], claims: &SlipClaims) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(context);
    hasher.update(&canonical(claims)?);
    Ok(*hasher.finalize().as_bytes())
}

fn refused(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
