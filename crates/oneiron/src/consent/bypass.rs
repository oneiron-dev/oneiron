//! The scoped catastrophe bypass (DEC-0006 invariant 7, `#bypass-grant`).
//!
//! A bypass grant is a standing grant that also covers one class on the
//! catastrophe floor. It is scoped to one project or bound to one thread,
//! never the whole vault, and nothing makes one by default. Only the vault's
//! owner creates it, by an explicit act after the one warning
//! [`Vault::bypass_grant_warning`] returns: what it allows and in which
//! scope. After that nothing inside the scope asks again. Every act under it
//! is receipted as bypassed, and one revoke from the registry ends it.
//!
//! No bypass covers an erase. None skips another Owner's objection window
//! either: a shared-vault act waits on its own act record
//! ([`Vault::start_authority_act`]), which a consent verdict never settles.

use rmpv::Value;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::store::GateDecisionId;

use super::bound::{BoundSubject, ConsentDomain, GrantBound, covers};
use super::codec::GRANTS;
use super::doors::AuthenticatedOwner;
use super::effect::{CatastropheClass, ComposedEffect, EffectDigest};
use super::grant::{
    ConsentGrantRow, ConsentGrantStatus, ConsentOwnerStamp, ConsentReceipt, StandingConsentGrant,
};
use super::support::invalid_bound;

const BYPASS_GRANT_REF_DOMAIN: &[u8] = b"oneiron.consent.bypass_grant.v1\0";

/// Where a bypass grant applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BypassScope {
    /// One project. The vault's root project is the whole vault, so it is
    /// never a bypass scope.
    Project(EntityId),
    /// One conversation thread.
    Thread(EntityId),
}

impl BypassScope {
    const fn kind(self) -> &'static str {
        match self {
            Self::Project(_) => "project",
            Self::Thread(_) => "thread",
        }
    }

    const fn id(self) -> EntityId {
        match self {
            Self::Project(id) | Self::Thread(id) => id,
        }
    }

    fn admits(self, effect: &ComposedEffect) -> bool {
        let place = effect.place();
        match self {
            Self::Project(id) => place.project == Some(id),
            Self::Thread(id) => place.thread == Some(id),
        }
    }
}

/// The bypass half of a persisted grant row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BypassExtent {
    /// Where the grant applies.
    pub scope: BypassScope,
    /// The catastrophe-floor row version the grant was created under.
    pub floor_version: u16,
}

impl BypassExtent {
    /// A bypass row's registry reference. Two bypasses of one bound in two
    /// scopes are two rows.
    pub(super) fn grant_ref(&self, bound: &GrantBound) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(BYPASS_GRANT_REF_DOMAIN);
        hasher.update(bound.digest().as_bytes());
        hasher.update(self.scope.kind().as_bytes());
        hasher.update(self.scope.id().as_bytes());
        hasher.update(&self.floor_version.to_be_bytes());
        hasher.finalize().to_hex().to_string()
    }

    pub(super) fn encode_value(&self) -> Value {
        Value::Map(vec![
            (Value::from("scope"), Value::from(self.scope.kind())),
            (Value::from("id"), Value::from(self.scope.id().to_hex())),
            (
                Value::from("floor_version"),
                Value::from(self.floor_version),
            ),
        ])
    }

    pub(super) fn decode_value(value: &Value) -> Option<Self> {
        let Value::Map(fields) = value else {
            return None;
        };
        if fields.len() != 3 {
            return None;
        }
        let field = |name: &str| {
            fields
                .iter()
                .find(|(key, _)| key.as_str() == Some(name))
                .map(|(_, value)| value)
        };
        let id = EntityId::from_hex(field("id")?.as_str()?).ok()?;
        let scope = match field("scope")?.as_str()? {
            "project" => BypassScope::Project(id),
            "thread" => BypassScope::Thread(id),
            _ => return None,
        };
        Some(Self {
            scope,
            floor_version: u16::try_from(field("floor_version")?.as_u64()?).ok()?,
        })
    }
}

/// The one warning shown when a bypass grant is created: what it allows, for
/// whom, and in which scope. Only [`Vault::bypass_grant_warning`] makes one,
/// and [`Vault::create_bypass_grant`] takes nothing else. Its wording is UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BypassGrantWarning {
    owner: EntityId,
    bound: GrantBound,
    scope: BypassScope,
    allows: CatastropheClass,
    floor_version: u16,
}

impl BypassGrantWarning {
    /// The catastrophe-floor class the grant stops asking for.
    #[must_use]
    pub const fn allows(&self) -> CatastropheClass {
        self.allows
    }

    /// Where it stops asking.
    #[must_use]
    pub const fn scope(&self) -> BypassScope {
        self.scope
    }

    /// Whose acts it covers, and inside which envelope.
    #[must_use]
    pub const fn bound(&self) -> &GrantBound {
        &self.bound
    }

    /// The catastrophe-floor row version it was checked against.
    #[must_use]
    pub const fn floor_version(&self) -> u16 {
        self.floor_version
    }
}

/// The typed "bypass active" state: one live bypass grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BypassActive {
    /// The registry row; revoking it ends the bypass.
    pub grant_ref: String,
    /// Where it applies.
    pub scope: BypassScope,
    /// The catastrophe-floor class it covers.
    pub allows: CatastropheClass,
    /// Whose acts it covers.
    pub actor_ref: String,
    /// The catastrophe-floor row version it was created under.
    pub floor_version: u16,
    /// Creation time in Unix seconds.
    pub created_at: u64,
}

/// One live bypass row the evaluator may answer with.
pub(super) struct LiveBypass {
    pub(super) grant_ref: String,
    pub(super) owner_stamp: ConsentOwnerStamp,
    bound: GrantBound,
    extent: BypassExtent,
}

/// Every active bypass row, read on the caller's transaction.
pub(super) fn live_bypasses_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<LiveBypass>> {
    Ok(GRANTS
        .scan(store, txn)?
        .into_iter()
        .filter_map(|(grant_ref, row)| {
            let extent = row.bypass?;
            row.is_active().then(|| LiveBypass {
                grant_ref,
                owner_stamp: row.owner_stamp,
                bound: row.grant.bound().clone(),
                extent,
            })
        })
        .collect())
}

/// The live bypass that covers this op, if one does. It covers only a
/// catastrophe-floor op of its own class, inside its own scope, by an actor
/// and envelope its bound contains, and never an erase. A mixed op's
/// disclosure half still needs an ordinary standing grant.
pub(super) fn covering_bypass<'a>(
    effect: &ComposedEffect,
    floor: &super::effect::CatastropheFloor,
    bypasses: &'a [LiveBypass],
    grants: &[StandingConsentGrant],
) -> Option<&'a LiveBypass> {
    let catastrophe = effect
        .catastrophe()
        .filter(|class| floor.contains(*class))?;
    if effect.is_erase() {
        return None;
    }
    let action = effect.action_requirement()?;
    if effect
        .disclosure_requirement()
        .is_some_and(|required| !covers(grants, required))
    {
        return None;
    }
    bypasses.iter().find(|bypass| {
        bypass.bound.class().as_str() == catastrophe.as_str()
            && bypass.extent.scope.admits(effect)
            && bypass.bound.contains(action)
    })
}

impl Vault {
    /// The one warning a bypass grant's creation shows (DEC-0006
    /// `#bypass-grant`): it checks the request and names what the grant
    /// allows and in which scope. Pass it unchanged to
    /// [`Vault::create_bypass_grant`].
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] unless `owner` is a live
    /// owner of this vault; [`GateError::InvalidConsentBound`] unless `bound`
    /// is an action bound on one catastrophe-floor class and `scope` names a
    /// project other than the root or a conversation thread.
    pub fn bypass_grant_warning(
        &self,
        owner: &AuthenticatedOwner,
        bound: GrantBound,
        scope: BypassScope,
    ) -> Result<BypassGrantWarning> {
        let txn = self.store.env.read_txn()?;
        self.check_bypass_request_in_txn(&txn, owner, bound, scope)
    }

    /// Creates the scoped bypass grant its warning described. The owner and
    /// the request are checked again in the writing transaction; a warning
    /// for another owner, or one the floor or scope no longer matches, is
    /// refused. The row lands in the consent registry, where one revoke ends
    /// it, and its creation is receipted.
    ///
    /// # Errors
    /// As [`Vault::bypass_grant_warning`], plus
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the warning was made
    /// for a different owner or no longer matches.
    pub fn create_bypass_grant(
        &self,
        owner: &AuthenticatedOwner,
        warning: &BypassGrantWarning,
    ) -> Result<ConsentReceipt> {
        self.with_write_txn(|wtxn| {
            let current = self.check_bypass_request_in_txn(
                wtxn,
                owner,
                warning.bound.clone(),
                warning.scope,
            )?;
            if current != *warning {
                return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                    "the bypass warning was not shown to this owner for this grant",
                )));
            }
            let extent = BypassExtent {
                scope: warning.scope,
                floor_version: warning.floor_version,
            };
            let row = ConsentGrantRow {
                grant: StandingConsentGrant::from_bound(warning.bound.clone())?,
                status: ConsentGrantStatus::Active,
                owner_stamp: owner.stamp(),
                created_at: crate::ports::recorded_at_in_txn(&self.store, wtxn)?,
                bypass: Some(extent),
            };
            let grant_ref = row.grant_ref();
            GRANTS.put(&self.store, wtxn, &grant_ref, &row)?;
            let receipt = ConsentReceipt::BypassCreated {
                decision_id: GateDecisionId::from_bytes(self.store.clock.ulid()?),
                grant_ref,
                bound_digest: warning.bound.digest(),
            };
            self.append_consent_receipt_in_txn(wtxn, owner, &receipt)?;
            Ok(receipt)
        })
    }

    /// The typed "bypass active" state: every live bypass grant, newest
    /// first. Empty when none is live.
    pub fn active_bypass_grants(&self) -> Result<Vec<BypassActive>> {
        let txn = self.store.env.read_txn()?;
        let floor = crate::gate::resolve_policy_manifest(&self.store, &txn)?.catastrophe_floor();
        let mut active = Vec::new();
        for (grant_ref, row) in GRANTS.scan(&self.store, &txn)? {
            let Some(extent) = row.bypass.filter(|_| row.is_active()) else {
                continue;
            };
            let bound = row.grant.bound();
            let BoundSubject::Actor(actor) = bound.subject() else {
                return Err(Error::CorruptedIndex("consent bypass grant subject"));
            };
            let allows = floor
                .member_named(bound.class().as_str())
                .ok_or(Error::CorruptedIndex("consent bypass grant class"))?;
            active.push(BypassActive {
                grant_ref,
                scope: extent.scope,
                allows,
                actor_ref: actor.actor_ref().to_owned(),
                floor_version: extent.floor_version,
                created_at: row.created_at,
            });
        }
        active.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| left.grant_ref.cmp(&right.grant_ref))
        });
        Ok(active)
    }

    fn check_bypass_request_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &AuthenticatedOwner,
        bound: GrantBound,
        scope: BypassScope,
    ) -> Result<BypassGrantWarning> {
        owner.revalidate_in_txn(self, txn)?;
        // A person's yes is not enough here: only an owner of this vault
        // creates a bypass, so no agent and no member can self-grant one.
        if !crate::policy_model::is_live_vault_owner_in_txn(self, txn, &owner.actor())? {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "only the vault's owner creates a bypass grant",
            )));
        }
        if bound.domain() != ConsentDomain::Action {
            return Err(invalid_bound("a bypass grant covers actions"));
        }
        let floor = crate::gate::resolve_policy_manifest(&self.store, txn)?.catastrophe_floor();
        let allows = floor.member_named(bound.class().as_str()).ok_or_else(|| {
            invalid_bound("a bypass grant covers one class on the catastrophe floor")
        })?;
        let in_scope = match scope {
            BypassScope::Project(id) => {
                crate::workspace_roster::is_project_entity(&self.store, txn, id)?
                    && crate::workspace_roster::root_project_in(&self.store, txn)? != Some(id)
            }
            BypassScope::Thread(id) => {
                self.get_entity_type_in_txn(txn, &id)?
                    == Some(crate::registry::ENTITY_TYPE_CONVERSATION)
            }
        };
        if !in_scope {
            return Err(invalid_bound(
                "a bypass grant is scoped to one project or one thread, never the whole vault",
            ));
        }
        Ok(BypassGrantWarning {
            owner: owner.actor(),
            bound,
            scope,
            allows,
            floor_version: floor.version(),
        })
    }

    /// Receipts one act that ran under a live bypass instead of asking.
    pub(super) fn record_bypassed_act_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        bypass: &LiveBypass,
        effect_digest: EffectDigest,
    ) -> Result<()> {
        let receipt = ConsentReceipt::Bypassed {
            decision_id: GateDecisionId::from_bytes(self.store.clock.ulid()?),
            grant_ref: bypass.grant_ref.clone(),
            effect_digest,
        };
        self.append_consent_gate_decision_in_txn(wtxn, &bypass.owner_stamp, &receipt, None)
    }
}
