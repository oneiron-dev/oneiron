//! Who changes a world's settings, and how (FIX 4480: the owner's rulings of
//! 10-19 01:23 and 02:0x, under DEC-0005 "Who changes policy").
//!
//! - **Holders.** The world's settings right is held by the live Owners of
//!   its owning vault, and by any Admin or Delegate whose Grant includes the
//!   policy power (the holders resolver behind policy-row proposals). A
//!   holder's own change lands at once, in either direction, from any linked
//!   surface: `by: Owner`, `owner` = that holder PERSON.
//! - **Direction.** [`crate::authority::privacy_direction`] tells a tighten
//!   from a widen against every live head of the current settings.
//! - **An agent's tighten** applies directly only under a standing Grant line
//!   naming it (`by: Agent`). Otherwise it lands as a typed proposal to every
//!   holder and writes no settings; any one holder's yes applies it. Either
//!   way every holder is told, with the receipt and a one-tap undo.
//! - **An agent's widen** is always an in-moment ask to the holders, never an
//!   agent's act: it is irreversible in effect (the floor's
//!   `world_privacy_widen`, which no bypass and no standing grant covers).
//!   By default any one holder's yes applies it as his own act.
//! - **"Widen needs every owner"** ([`unanimity`]): when it is on, a widen
//!   lands only once every live Owner said yes; the author's own act counts
//!   as his. Tightening stays any one holder. Any one live Owner turns it on;
//!   turning it off while it is on takes every live Owner.
//! - **A foreign world** follows its owning vault's settings (DEC-0005 fix
//!   11): an agent's change of one is an ask to that vault's holders,
//!   carried over the Connect pact it arrived through ([`foreign`],
//!   [`carry`], FIX 4702). With no live pact naming it, the agent gets a
//!   typed refusal naming that rule.

mod agent;
mod answer;
mod carry;
mod foreign;
mod record;
mod sdk;
mod unanimity;
mod undo;

pub use answer::WorldPrivacyAnswer;
pub use carry::{
    ForeignWorldPrivacyCarry, ForeignWorldPrivacyDelivery, ForeignWorldPrivacyExportRequest,
    ForeignWorldPrivacyLeg,
};
pub use record::{
    ForeignWorldPrivacyLink, WorldPrivacyRequest, WorldPrivacyRequestKind,
    WorldPrivacyRequestStatus,
};
pub use sdk::{WorldPrivacySetInput, WorldPrivacySetOutput, WorldReadInput, WorldSealedInput};
pub use unanimity::{WidenUnanimity, WidenUnanimityOffRequest, WidenUnanimityOutcome};

pub(super) use record::parse_revision;

use crate::authority::{
    ActAuthority, ActSurface, PolicyRevision, PrivacyDirection, WorldEditAuthor, WorldPrivacy,
    privacy_direction,
};
use crate::check_in::{ActClass, AppliedCheckIn, CheckInDecision};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, GateError, Result};
use crate::{EntityId, Vault};

use super::world_privacy_switch::WorldPrivacyReceipt;
use record::{NewRequest, WorldPrivacyRequestKind as Kind};

/// The row reference a world's settings right is granted under: an Admin or
/// Delegate holds it through a `policy.change` action grant whose target is
/// `policy_row_grant_target(World(world), "world_privacy")`.
pub const WORLD_PRIVACY_ROW_REF: &str = "world_privacy";

/// What one world-settings act came to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorldPrivacyOutcome {
    /// The settings changed: the receipt.
    Applied(WorldPrivacyReceipt),
    /// An agent's tighten waits for a holder: the proposal.
    Proposed(WorldPrivacyRequest),
    /// A widen waits for the holders' yes: the ask.
    Asked(WorldPrivacyRequest),
}

impl WorldPrivacyOutcome {
    /// The receipt, when the settings changed.
    #[must_use]
    pub fn applied(self) -> Option<WorldPrivacyReceipt> {
        match self {
            Self::Applied(receipt) => Some(receipt),
            Self::Proposed(_) | Self::Asked(_) => None,
        }
    }
}

/// The door a holder's own change comes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HolderDoor {
    /// A door that takes only a receipt: a widen under "widen needs every
    /// owner" is refused before anything is written.
    Receipt,
    /// The settings door: such a widen opens an ask. `check_in_ref` is an
    /// asker's approved check-in the vault's Owner applies to a change that
    /// lands (2k11).
    Outcome { check_in_ref: Option<EntityId> },
}

/// A change of a world shared from another vault that its owning vault's
/// holders decide (DEC-0005 fix 11): a holder here does not apply it.
const FOREIGN_WORLD: &str =
    "this world follows its owning vault's settings; its holders there decide";
/// The caller holds no settings right on this world.
const NOT_HOLDER: &str = "only a holder of this world's settings right changes them";
/// A holder's own widen under "widen needs every owner", at a door that takes
/// only a receipt.
const NEEDS_EVERY_OWNER: &str = "this vault's \"widen needs every owner\" setting puts this widen \
                                 to every owner; open it as an ask, and it lands once every owner \
                                 said yes";
/// Nobody holds the world's settings right now, so no request can go to one.
const NO_HOLDER: &str = "no live holder of this world's settings right could answer a request";
/// A `check_in_ref` from another holder or an agent (2k11).
const OWNER_APPLIES_CHECK_IN: &str = "check_in_ref names an asker's approved check-in, which the \
                                      vault's Owner applies on their own proof; another holder's \
                                      change and an agent's act apply none";
/// A `check_in_ref` on a widen "widen needs every owner" puts to every owner
/// (2k11).
const UNANIMOUS_WIDEN_APPLIES_NO_CHECK_IN: &str = "this widen waits for every owner under \
                                                   \"widen needs every owner\"; an asker's \
                                                   check-in applies only to a change that lands \
                                                   at once, so open it without check_in_ref";

/// The saved verb a holder's own world-settings change is: the verb an
/// asker's check-in names for it (2k11).
const WORLD_PRIVACY_SET_VERB: &str = "vault.worlds.privacy.set";

/// The refusal of a `check_in_ref` from anyone but the vault's Owner, who
/// alone applies an asker's check-in to a world's settings (2k11).
pub(crate) fn world_privacy_check_in_refused() -> Error {
    Error::InvalidConfig(OWNER_APPLIES_CHECK_IN.to_owned())
}

pub(super) fn not_holder() -> Error {
    Error::Gate(GateError::ConsentOwnerNotAuthenticated(NOT_HOLDER))
}

fn foreign_world() -> Error {
    Error::InvalidConfig(FOREIGN_WORLD.to_owned())
}

/// The live holders of `world`'s settings right, by the one resolver behind
/// policy-row proposals: every live Owner, and each Admin or Delegate whose
/// membership scope admits the world and whom an Owner granted the
/// `policy.change` action on this world's settings row.
pub(super) fn world_holders_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    world: EntityId,
) -> Result<Vec<EntityId>> {
    let scope = crate::gate::PolicyRowScope::World(world.to_hex());
    let target = super::authority::row_target(&scope, WORLD_PRIVACY_ROW_REF);
    let now = vault.instant_in_txn(txn)?.secs();
    super::authority::holders_for_in_txn(vault, txn, now, &scope, &target)
}

/// `owner`'s PERSON, when it holds `world`'s settings right in the acting
/// transaction.
pub(crate) fn revalidate_holder_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: &AuthenticatedOwner,
    world: EntityId,
) -> Result<EntityId> {
    let actor = owner.revalidate_person_in_txn(vault, txn)?;
    if !world_holders_in_txn(vault, txn, world)?.contains(&actor) {
        return Err(not_holder());
    }
    Ok(actor)
}

/// The vault owner PERSON a world's key binds after `actor`'s change:
/// `actor` when he owns the vault, else its first live owner, since an
/// Admin's or a Delegate's change keeps the key the owner's.
pub(super) fn key_owner_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
) -> Result<EntityId> {
    if super::authority::is_live_vault_owner_in_txn(vault, txn, &actor)? {
        return Ok(actor);
    }
    super::authority::owners_in_txn(vault, txn)?
        .first()
        .copied()
        .ok_or_else(|| Error::InvalidConfig(NO_OWNER.to_owned()))
}

/// The vault has no live owner a world's key could bind.
const NO_OWNER: &str = "this vault has no live owner a world's key binds";

/// Which way `settings` moves `world` now, and its current revision. A `seen`
/// other than the current revision is a conflict, never a silent overwrite.
fn direction_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    world: EntityId,
    settings: &WorldPrivacy,
    seen: Option<PolicyRevision>,
) -> Result<(PrivacyDirection, PolicyRevision)> {
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    let current = fold.world_policy_revision(world);
    if seen.is_some_and(|seen| seen != current) {
        return Err(Error::ConcurrentWrite(
            "the world's settings changed since they were read",
        ));
    }
    let heads = vault.world_privacy_heads_in_txn(txn, world)?;
    Ok((privacy_direction(&heads, settings), current))
}

/// The check-in decision holder `actor`'s change of `world` to `settings`
/// from `seen` runs on, in `txn`, the change's writer, after every refusal
/// before the write (2k11; P25-SHAPE Q1 = A): the vault's Owner changes a
/// world's settings on their own proof, and with `check_in_ref` applies an
/// asker's approved check-in for exactly this change, spent here, so an
/// abort leaves it eligible. Another holder's change records none and
/// applies no ask: their Grant is the authority, as before.
///
/// # Errors
/// A `check_in_ref` from a holder who is not the vault's Owner; as
/// [`crate::check_in::owner_act_decision_in_txn`].
fn holder_check_in_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    world: EntityId,
    settings: &WorldPrivacy,
    seen: Option<&PolicyRevision>,
    check_in_ref: Option<&EntityId>,
) -> Result<Option<CheckInDecision>> {
    if !super::authority::is_live_vault_owner_in_txn(vault, txn, &actor)? {
        return match check_in_ref {
            Some(_) => Err(world_privacy_check_in_refused()),
            None => Ok(None),
        };
    }
    let applied = check_in_ref.map(|id| AppliedCheckIn {
        id: *id,
        verb: WORLD_PRIVACY_SET_VERB,
        effect_digest: crate::check_in::world_privacy_set_effect_digest(&world, settings, seen),
    });
    crate::check_in::owner_act_decision_in_txn(vault, txn, ActClass::WorldWiden, applied.as_ref())
        .map(Some)
}

impl Vault {
    /// The one world-settings door (mesh contract §1, FIX 4480): `authority`
    /// is a holder's own proof and surface, or an agent's act its live Grant
    /// names.
    ///
    /// A holder's change lands at once in either direction, but a widen
    /// under "widen needs every owner" opens an ask to every owner, with his
    /// own yes counted. An agent's tighten or equal change under its Grant
    /// applies as `by: Agent` and tells every holder, with the receipt and a
    /// one-tap undo; its widen opens an ask to the holders and applies
    /// nothing. An agent's change to a foreign world asks its owning vault's
    /// holders (FIX 4702).
    ///
    /// The vault's Owner changes a world's settings on their own proof: the
    /// receipt records the decision (`check_in`, act class `world_widen`;
    /// none on another holder's change). With `check_in_ref` the Owner
    /// applies an asker's approved check-in for exactly this change
    /// ([`crate::check_in::world_privacy_set_effect_digest`]), spent in the
    /// change's writer (2k11; P25-SHAPE Q1 = A).
    ///
    /// # Errors
    /// As [`Self::set_world_privacy_as`]; an authority refusal when the
    /// agent's Grant no longer names a tighten of this world; a foreign
    /// world refusal for an agent when no live Connect names the world.
    /// [`Error::InvalidConfig`] for a `check_in_ref` from an agent or a
    /// holder who is not the vault's Owner, on a widen that waits for every
    /// owner, or naming no eligible ask for this exact change: nothing is
    /// written and the check-in stays unspent.
    pub fn set_world_privacy_by(
        &self,
        authority: &ActAuthority,
        world: EntityId,
        settings: WorldPrivacy,
        seen: Option<PolicyRevision>,
        check_in_ref: Option<EntityId>,
    ) -> Result<WorldPrivacyOutcome> {
        match authority {
            ActAuthority::Owner(owner, surface) => self.holder_world_privacy(
                owner,
                *surface,
                world,
                settings,
                seen,
                HolderDoor::Outcome { check_in_ref },
            ),
            ActAuthority::Agent(_) if check_in_ref.is_some() => {
                Err(world_privacy_check_in_refused())
            }
            // An agent's act that reaches this door, not its run's
            // (`agent_world_privacy`), names no run credential: a Grant
            // carries none, so its ask has no opener lineage.
            ActAuthority::Agent(granted) => {
                self.granted_world_privacy(granted, Vec::new(), world, settings, seen)
            }
        }
    }

    /// A holder's own change, through `door`.
    pub(super) fn holder_world_privacy(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        world: EntityId,
        settings: WorldPrivacy,
        seen: Option<PolicyRevision>,
        door: HolderDoor,
    ) -> Result<WorldPrivacyOutcome> {
        let check_in_ref = match door {
            HolderDoor::Receipt => None,
            HolderDoor::Outcome { check_in_ref } => check_in_ref,
        };
        let outcome = self.with_world_settings_writer(|txn, secret| {
            let actor = revalidate_holder_in_txn(self, txn, owner, world)?;
            let (direction, current) = direction_in_txn(self, txn, world, &settings, seen)?;
            if direction == PrivacyDirection::Widen {
                let needs = unanimity::widen_needs_in_txn(self, txn, world)?;
                if needs.iter().any(|needed| *needed != actor) {
                    if door == HolderDoor::Receipt {
                        return Err(Error::InvalidConfig(NEEDS_EVERY_OWNER.to_owned()));
                    }
                    if check_in_ref.is_some() {
                        return Err(Error::InvalidConfig(
                            UNANIMOUS_WIDEN_APPLIES_NO_CHECK_IN.to_owned(),
                        ));
                    }
                    let yes = needs.iter().copied().filter(|o| *o == actor).collect();
                    let holders = world_holders_in_txn(self, txn, world)?;
                    // The opener's complete verified chains, read in this
                    // writer: they and their forks never settle it (FIX 5064).
                    let opener_lineage = owner.credential_lineage_in_txn(self, txn)?;
                    let request = self.open_world_privacy_request_in_txn(
                        txn,
                        NewRequest {
                            kind: Kind::WidenAsk,
                            agent: None,
                            opener_lineage,
                            author: actor,
                            world,
                            settings,
                            seen: current,
                            holders,
                            needs,
                            yes,
                            grant_omitted: None,
                            owned_by: None,
                            asked_from: None,
                        },
                    )?;
                    return Ok(WorldPrivacyOutcome::Asked(request));
                }
            }
            let check_in = holder_check_in_in_txn(
                self,
                txn,
                actor,
                world,
                &settings,
                seen.as_ref(),
                check_in_ref.as_ref(),
            )?;
            let author = WorldEditAuthor::holder(actor, surface);
            let mut receipt =
                self.write_world_privacy_in_txn(txn, author, world, settings, Some(current), None)?;
            // Stored with the key work's settlement, in this commit.
            receipt.check_in = check_in;
            let key_owner = key_owner_in_txn(self, txn, actor)?;
            let receipt = self.finish_world_key_work_in_txn(txn, key_owner, receipt, secret)?;
            Ok(WorldPrivacyOutcome::Applied(receipt))
        })?;
        self.queue_if_asked(outcome)
    }

    /// The live heads of `world`'s settings, as each edit states them: what a
    /// change's direction is judged against.
    pub(super) fn world_privacy_heads_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        world: EntityId,
    ) -> Result<Vec<WorldPrivacy>> {
        Ok(self
            .authority_view_readonly_in_txn(txn)?
            .worlds
            .get(&world)
            .map(|folded| folded.live_settings.values().cloned().collect())
            .unwrap_or_default())
    }
}

impl Vault {
    /// Refuses `actor`'s change of `world` to `settings` when it widens the
    /// world while "widen needs every owner" puts it to another owner too:
    /// the settings door's rule at a door that takes only a receipt, such as
    /// a world key re-assertion (FIX 8205). The owner opens it as an ask at
    /// the settings door instead.
    pub(crate) fn refuse_unanimous_widen_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: EntityId,
        world: EntityId,
        settings: &WorldPrivacy,
    ) -> Result<()> {
        let (direction, _) = direction_in_txn(self, txn, world, settings, None)?;
        if direction == PrivacyDirection::Widen
            && unanimity::widen_needs_in_txn(self, txn, world)?
                .iter()
                .any(|needed| *needed != actor)
        {
            return Err(Error::InvalidConfig(NEEDS_EVERY_OWNER.to_owned()));
        }
        Ok(())
    }
}
