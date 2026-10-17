//! An agent's diary notes a change of its refusal dial (OF-533). On the
//! agent's first wake after its dial moved, the agent writes, as itself and
//! in its own diary, where the dial moved. Its first wake ever records the
//! dial and writes nothing: there is no change to note yet.

use serde::{Deserialize, Serialize};

use crate::agent_def::{RefusalDomain, resolve_refusal};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{ClaimError, Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::{Vault, WriteActor};

const SEEN: SideTable<EntityId, SeenDial, Named> =
    SideTable::new(&side_table::DREAMER_REFUSAL_DIAL_SEEN);
const DOMAINS: [RefusalDomain; 2] = [RefusalDomain::Bond, RefusalDomain::Logistics];

/// The level the agent's dial resolved to in each of [`DOMAINS`], by wire
/// name. Resolved, not stored: a vault-kind default the agent acts under is
/// its dial as much as an explicit setting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SeenDial(Vec<String>);

impl Vault {
    /// Notes in `agent`'s own diary that its refusal dial moved since its
    /// last wake. Returns whether a note was written.
    ///
    /// # Errors
    ///
    /// Storage errors; a diary write that fails other than by the agent's
    /// standing.
    pub fn note_refusal_dial_change(&self, agent: EntityId) -> Result<bool> {
        let Some(definition) = self.get_agent_definition(&agent)? else {
            return Ok(false);
        };
        let kind = self.vault_kind()?;
        let current = SeenDial(
            DOMAINS
                .iter()
                .map(|domain| {
                    resolve_refusal(&definition, kind, *domain)
                        .as_str()
                        .to_owned()
                })
                .collect(),
        );
        {
            let txn = self.store.env.read_txn()?;
            if SEEN.get(&self.store, &txn, &agent)?.as_ref() == Some(&current) {
                return Ok(false);
            }
        }
        // The seen row and the note commit in one write, so two wakes racing
        // over one change write one note and a failed write leaves the move
        // to the next wake. A note the agent's standing refuses rolls back
        // alone: the move is seen and the wake writes no note.
        self.with_write_txn(|txn| {
            let before = SEEN.get(&self.store, txn, &agent)?;
            if before.as_ref() == Some(&current) {
                return Ok(false);
            }
            SEEN.put(&self.store, txn, &agent, &current)?;
            let Some(before) = before else {
                return Ok(false);
            };
            let moved: Vec<String> = DOMAINS
                .iter()
                .zip(before.0.iter().zip(&current.0))
                .filter(|(_, (was, now))| was != now)
                .map(|(domain, (was, now))| format!("{} from {was} to {now}", domain.as_str()))
                .collect();
            let at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let mut savepoint = self.store.env.nested_write_txn(txn)?;
            match crate::memory::append_agent_diary_in_txn(
                self,
                &mut savepoint,
                WriteActor::new(agent, EdgeActorClass::Agent),
                format!(
                    "My refusal dial changed since I last woke: {}.",
                    moved.join("; ")
                ),
                at,
            ) {
                Ok(_) => {
                    savepoint.commit()?;
                    Ok(true)
                }
                Err(Error::Claim(ClaimError::ActorLacksClaimAuthority { .. })) => {
                    drop(savepoint);
                    Ok(false)
                }
                Err(error) => Err(error),
            }
        })
    }
}
