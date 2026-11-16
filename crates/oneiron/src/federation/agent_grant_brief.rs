//! The self brief's GRANT producer (FIX 17594, Engine ruling 21:47): the
//! owner's agent Grants that stand for one agent, each whole, with the
//! signed act that minted it.
//!
//! One read transaction carries the clock, the live-agent check, the Grant
//! census (each Grant standing on the owner's counted mint, pass 28 R3),
//! each Grant's standing for the agent and the mint's log time. It
//! writes nothing: no mint, no fold write, no clock floor. A census that
//! could not judge some row is unavailable, never a list that claims to be
//! complete. Every other federation Grant that names the agent is judged by
//! its own admission family, which has no producer here, so that list stays
//! unavailable.

use std::collections::BTreeMap;

use crate::Vault;
use crate::authority::{AgentGrantChange, AuthorityEntryHash, AuthorityOp};
use crate::context_board::{BriefGrant, BriefGrants};
use crate::error::Result;
use crate::write_envelope::WriteActor;

impl Vault {
    /// The Grants that stand for the host-bound agent `actor`, as one read
    /// transaction observes them, for its self brief. `as_of_secs` is the
    /// vault's authority instant in that read. `owner_agent_grants` is
    /// `None` when the census could not judge some row; every other
    /// federation Grant stays `None` (unavailable).
    ///
    /// # Errors
    /// A store, fold or clock failure, or an agent definition that does not
    /// decode.
    pub fn self_brief_grants(&self, actor: WriteActor) -> Result<BriefGrants> {
        let txn = self.store.env.read_txn()?;
        self.self_brief_grants_in_txn(&txn, actor)
    }

    /// [`Self::self_brief_grants`] in the caller's read transaction.
    ///
    /// # Errors
    /// As [`Self::self_brief_grants`].
    pub(crate) fn self_brief_grants_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: WriteActor,
    ) -> Result<BriefGrants> {
        let as_of_secs = self.instant_in_txn(txn)?.secs();
        Ok(BriefGrants {
            as_of_secs,
            owner_agent_grants: self.owner_agent_grants_in_txn(txn, actor, as_of_secs)?,
            other_federation_grants: None,
        })
    }

    /// The owner's agent Grants that stand for `actor` at `now` for at least
    /// one verb of their own explicit verb list, whole, in id order. A
    /// principal that is no live agent has none. `None` when a live
    /// FEDERATION_GRANT row did not decode, or when a Grant's pact
    /// membership could not be read.
    fn owner_agent_grants_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: WriteActor,
        now: u64,
    ) -> Result<Option<Vec<BriefGrant>>> {
        let agent = actor.entity_ref();
        if !crate::authority::live_agent_principal_in(&self.store, txn, agent, actor.actor_class())?
        {
            return Ok(Some(Vec::new()));
        }
        let (standings, undecoded) = self.agent_grants_reporting_in_txn(txn)?;
        if !undecoded.is_empty() {
            return Ok(None);
        }
        let owners = crate::policy_model::owners_in_txn(self, txn)?;
        let minted_at = self.agent_grant_mint_times_in_txn(txn)?;
        let mut grants = Vec::new();
        for standing in standings {
            match standing.stands_for_any_listed_verb_in_txn(self, txn, agent, now, &owners) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => {
                    tracing::warn!(
                        grant = %standing.id.to_hex(),
                        error_kind = ?error.kind(),
                        "an agent Grant's pact standing could not be read; the self brief names \
                         the owner's agent Grants unavailable"
                    );
                    return Ok(None);
                }
            }
            grants.push(BriefGrant {
                id: standing.id,
                act_hash: Some(crate::entity_id::bytes_to_hex_lower(&standing.act)),
                minted_at: minted_at.get(&standing.act).copied(),
                scope: standing.grant.authority_scope,
                repo_bounds: standing.grant.repo_bounds,
            });
        }
        Ok(Some(grants))
    }

    /// The log row time of each retained mint act the authority fold
    /// counted, by its entry hash: a Grant's mint is the act its line stands
    /// on ([`super::agent_grant::AgentGrantStanding::act`]), and a mint an
    /// adopted checkpoint covers has no resident row and no time here.
    fn agent_grant_mint_times_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<BTreeMap<AuthorityEntryHash, u64>> {
        Ok(self
            .counted_grant_acts_in_txn(txn)?
            .into_iter()
            .filter(|act| {
                matches!(
                    &act.op,
                    AuthorityOp::AgentGrantAct(record)
                        if matches!(record.change, AgentGrantChange::Mint { .. })
                )
            })
            .map(|act| (act.hash, act.recorded_at))
            .collect())
    }
}
