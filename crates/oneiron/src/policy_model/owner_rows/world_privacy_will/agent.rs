//! An agent's change of a world's settings (FIX 4480). A tighten applies only
//! under a standing Grant line naming it; otherwise it lands as a proposal.
//! A widen is never an agent's act: it always asks the holders.

use crate::authority::{
    ActBy, ActSurface, GrantedAct, OwnerActKind, PolicyRevision, PrivacyDirection, WorldEditAuthor,
    WorldPrivacy,
};
use crate::error::{Error, Result};
use crate::inbox::NotificationKind;
use crate::{EdgeActorClass, EntityId, Vault, WriteActor};

use super::record::{NewRequest, WorldPrivacyRequestKind as Kind};
use super::{
    NO_HOLDER, WorldPrivacyOutcome, direction_in_txn, refuse_foreign_world_for_agent, unanimity,
    world_holders_in_txn,
};

/// The notice every holder gets when an agent's tighten applied, directly or
/// by a holder's yes: its one tap undoes it.
pub(super) const CHANGED_NOTICE: &str = "an agent made this world's settings stricter; one tap \
                                         undoes it";

impl Vault {
    /// An agent's world-settings request, as its run's door makes it: the
    /// agent `agent` (verified as the writer here, and an agent), the
    /// credential lineage that opened its run, the world, the settings and
    /// the revision the agent read. Under a live Grant line that names a
    /// tighten of this world it acts within it
    /// ([`crate::authority::ActAuthority::Agent`]); otherwise a tighten lands
    /// as a proposal and a widen as an ask, and no settings change. A Grant
    /// passed over on its lapsed pact membership alone leaves its typed code
    /// on that proposal or ask (FIX 7548). Every request it opens, a Grant's
    /// widen included, carries `opener_lineage` (FIX 4705): no answer from
    /// that lineage or a fork of it settles it.
    ///
    /// # Errors
    /// [`Error::InvalidConfig`] when `agent` is no agent, or the world is a
    /// foreign one, or no holder could answer; as
    /// [`Self::set_world_privacy_by`] otherwise.
    pub fn agent_world_privacy(
        &self,
        agent: &WriteActor,
        opener_lineage: Vec<[u8; 32]>,
        world: EntityId,
        settings: WorldPrivacy,
        seen: Option<PolicyRevision>,
    ) -> Result<WorldPrivacyOutcome> {
        if agent.actor_class() != EdgeActorClass::Agent {
            return Err(Error::InvalidConfig(
                "the agent world-settings door takes an agent".to_owned(),
            ));
        }
        refuse_foreign_world_for_agent(world)?;
        let grant = {
            let txn = self.store.env.read_txn()?;
            self.verify_write_actor_in_txn(&txn, agent)?;
            self.agent_world_grant_in_txn(&txn, agent.entity_ref(), world)?
        };
        match grant {
            Ok(grant) => {
                let granted =
                    self.granted_act(agent.entity_ref(), grant, OwnerActKind::WorldPrivacy)?;
                // The Grant's act, with the lineage that opened the run: its
                // widen asks the holders, and that lineage never settles it.
                self.granted_world_privacy(&granted, opener_lineage, world, settings, seen)
            }
            Err(no_standing) => self.propose_world_privacy(
                agent.entity_ref(),
                opener_lineage,
                world,
                settings,
                seen,
                crate::authority::grant_omission(no_standing),
            ),
        }
    }

    /// An agent's act its live Grant names. A tighten or an equal change
    /// applies as `by: Agent`, its Grant checked again in the same writer,
    /// and tells every holder with the receipt and a one-tap undo; a widen
    /// opens an ask to the holders, carrying `opener_lineage`, the credential
    /// lineage that opened the agent's run (FIX 4705): neither it nor a fork
    /// of it settles the ask (FIX 5064).
    pub(super) fn granted_world_privacy(
        &self,
        granted: &GrantedAct,
        opener_lineage: Vec<[u8; 32]>,
        world: EntityId,
        settings: WorldPrivacy,
        seen: Option<PolicyRevision>,
    ) -> Result<WorldPrivacyOutcome> {
        refuse_foreign_world_for_agent(world)?;
        let outcome = self.with_world_settings_writer(|txn, secret| {
            let owner = self.granted_world_act_owner_in_txn(txn, granted, world)?;
            let (direction, current) = direction_in_txn(self, txn, world, &settings, seen)?;
            if direction == PrivacyDirection::Widen {
                return self
                    .open_agent_request_in_txn(
                        txn,
                        granted.agent(),
                        opener_lineage,
                        world,
                        settings,
                        current,
                        None,
                    )
                    .map(WorldPrivacyOutcome::Asked);
            }
            let author = WorldEditAuthor {
                owner,
                by: ActBy::Agent {
                    agent: granted.agent(),
                    grant: granted.grant(),
                },
                surface: ActSurface::ThisInstall,
                answer: None,
            };
            let receipt = self.write_world_privacy_in_txn(
                txn,
                author,
                world,
                settings,
                Some(current),
                Some(granted.agent()),
            )?;
            let receipt = self.finish_world_key_work_in_txn(txn, owner, receipt, secret)?;
            let holders = world_holders_in_txn(self, txn, world)?;
            self.notify_world_holders_in_txn(
                txn,
                NotificationKind::WorldPrivacyChanged,
                &receipt.receipt_id,
                world,
                &holders,
                CHANGED_NOTICE,
            )?;
            Ok(WorldPrivacyOutcome::Applied(receipt))
        })?;
        self.queue_if_asked(outcome)
    }

    /// An agent's request no Grant line covers: a tighten (or an equal
    /// change) lands as a proposal, a widen as an ask, and neither writes a
    /// settings edit. `grant_omitted` is why a Grant that met the line was
    /// passed over (FIX 7548), when one was.
    fn propose_world_privacy(
        &self,
        agent: EntityId,
        opener_lineage: Vec<[u8; 32]>,
        world: EntityId,
        settings: WorldPrivacy,
        seen: Option<PolicyRevision>,
        grant_omitted: Option<&'static str>,
    ) -> Result<WorldPrivacyOutcome> {
        let outcome = self.with_write_txn(|txn| {
            let (direction, current) = direction_in_txn(self, txn, world, &settings, seen)?;
            let request = self.open_agent_request_in_txn(
                txn,
                agent,
                opener_lineage,
                world,
                settings,
                current,
                grant_omitted,
            )?;
            Ok(if direction == PrivacyDirection::Widen {
                WorldPrivacyOutcome::Asked(request)
            } else {
                WorldPrivacyOutcome::Proposed(request)
            })
        })?;
        self.queue_if_asked(outcome)
    }

    /// Opens an agent's request on `world` to its holders: an ask when the
    /// change widens (to every live Owner under "widen needs every owner"),
    /// else a proposal any one holder accepts. It records `grant_omitted`,
    /// why a Grant was passed over (FIX 7548).
    #[expect(clippy::too_many_arguments, reason = "one request's frozen fields")]
    fn open_agent_request_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        agent: EntityId,
        opener_lineage: Vec<[u8; 32]>,
        world: EntityId,
        settings: WorldPrivacy,
        current: PolicyRevision,
        grant_omitted: Option<&'static str>,
    ) -> Result<super::WorldPrivacyRequest> {
        let holders = world_holders_in_txn(self, txn, world)?;
        if holders.is_empty() {
            return Err(Error::InvalidConfig(NO_HOLDER.to_owned()));
        }
        let heads = self.world_privacy_heads_in_txn(txn, world)?;
        let widen =
            crate::authority::privacy_direction(&heads, &settings) == PrivacyDirection::Widen;
        let (kind, needs) = if widen {
            (
                Kind::WidenAsk,
                unanimity::widen_needs_in_txn(self, txn, world)?,
            )
        } else {
            (Kind::Proposal, Vec::new())
        };
        self.open_world_privacy_request_in_txn(
            txn,
            NewRequest {
                kind,
                agent: Some(agent),
                opener_lineage,
                author: agent,
                world,
                settings,
                seen: current,
                holders,
                needs,
                yes: Vec::new(),
                grant_omitted,
            },
        )
    }

    /// Queues the in-moment ask of an outcome that asks, after its commit.
    pub(super) fn queue_if_asked(
        &self,
        outcome: WorldPrivacyOutcome,
    ) -> Result<WorldPrivacyOutcome> {
        match outcome {
            WorldPrivacyOutcome::Asked(request) => Ok(WorldPrivacyOutcome::Asked(
                self.queue_world_privacy_ask(request)?,
            )),
            other => Ok(other),
        }
    }
}
