//! The narrower `ai.*` inference Grant (FIX 3208; Engine 10-29 09:36 on
//! L02's recommendation). The owner mints it per agent, through
//! `vault.agents.grants.mint`, as an owner agent Grant whose explicit verbs
//! name the `ai.*` operations the agent may call, one verb each:
//! [`AI_GRANT_VERB_PREFIX`] and the operation's wire name (`ai.text`,
//! `ai.image`, `ai.speech`, `ai.transcribe`, `ai.embed`, `ai.video`). The
//! server's `ai.options` lists the rows of those operations for the agent,
//! and each named `ai.*` call door admits it for them; a call so admitted is
//! the owner's, on his meter, as he minted it. Every other operation stays
//! the owner's alone.
use std::collections::BTreeSet;

use super::principal_standing::grant_pact_standing_lapsed_in_txn;
use super::withdrawn_grant::grant_known_withdrawn_in_txn;
use crate::federation::{ScopeAxis, decode_federation_grant_body};
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

/// What a Grant's verb names an `ai.*` operation by (CALLS `FIX 3208 ai
/// grant verbs`): this prefix, then the operation's wire name. One verb per
/// operation, so a Grant for embeddings never reaches video jobs; a Grant
/// over every verb names none.
pub(crate) const AI_GRANT_VERB_PREFIX: &str = "ai.";

impl Vault {
    /// The `ai.*` operations, by wire name, that a live Grant of `agent`
    /// names now (FIX 3208): a FEDERATION_GRANT row the owner minted his
    /// agent (`owner_agent`), whose member is `agent`, that confers now, is
    /// not known withdrawn (FIX 5107), lists `ai.<operation>` among an
    /// explicit verb set, and whose pact membership, on a shared vault,
    /// still stands (FIX 7548). Empty for an agent no such Grant names.
    ///
    /// # Errors
    ///
    /// A store read failure.
    pub fn agent_ai_operations(&self, agent: EntityId) -> crate::error::Result<BTreeSet<String>> {
        let txn = self.store.env.read_txn()?;
        let now = self.instant_in_txn(&txn)?.secs();
        let mut operations = BTreeSet::new();
        for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(
            &self.store,
            &txn,
            ENTITY_TYPE_FEDERATION_GRANT,
            None,
        )? {
            let id = id?;
            let LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_FEDERATION_GRANT,
                body,
            } = live_entity_row_in_txn(&self.store, &txn, &id)?
            else {
                continue;
            };
            let Ok(grant) = decode_federation_grant_body(&body) else {
                continue;
            };
            let ScopeAxis::Some(verbs) = &grant.authority_scope.verbs else {
                continue;
            };
            let named: Vec<&str> = verbs
                .iter()
                .filter_map(|verb| verb.strip_prefix(AI_GRANT_VERB_PREFIX))
                .collect();
            if named.is_empty()
                || !grant.owner_agent
                || grant.member_ref != agent
                || !grant.confers_at(now)
                || grant_known_withdrawn_in_txn(&self.store, &txn, id)
                || grant_pact_standing_lapsed_in_txn(self, &txn, id, grant.scope, grant.member_ref)
            {
                continue;
            }
            operations.extend(named.into_iter().map(str::to_owned));
        }
        Ok(operations)
    }
}
