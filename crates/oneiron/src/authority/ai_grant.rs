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
use crate::federation::decode_federation_grant_body;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};
use oneiron_authority::federation::ScopeAxis;

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
    /// explicit verb set or names a verb class that lists it (its own
    /// spelling or the owner's row for it, FIX 8735), and whose pact
    /// membership, on a shared vault, still stands (FIX 7548). Empty for an
    /// agent no such Grant names.
    ///
    /// # Errors
    ///
    /// A store read failure.
    pub fn agent_ai_operations(&self, agent: EntityId) -> crate::error::Result<BTreeSet<String>> {
        let txn = self.store.env.read_txn()?;
        let now = self.instant_in_txn(&txn)?.secs();
        let mut operations = BTreeSet::new();
        let mut class_rows: Option<crate::federation::AgentVerbClasses> = None;
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
            if !grant.owner_agent || grant.member_ref != agent {
                continue;
            }
            if !grant.verb_classes.is_empty() && class_rows.is_none() {
                class_rows = Some(crate::federation::AgentVerbClasses::for_grants_in_txn(
                    &self.store,
                    &txn,
                    [&grant],
                )?);
            }
            let classes = class_rows.as_ref();
            // The explicit set's `ai.*` verbs, then each class's: the
            // built-in outbound classes list no `ai.*` verb.
            let explicit = match &grant.authority_scope.verbs {
                ScopeAxis::Some(verbs) => Some(verbs.iter().map(String::as_str)),
                ScopeAxis::Bottom | ScopeAxis::All => None,
            };
            let classed = classes.into_iter().flat_map(|classes| {
                grant
                    .verb_classes
                    .iter()
                    .flat_map(move |class| classes.spelled_verbs(class))
            });
            let named: BTreeSet<&str> = explicit
                .into_iter()
                .flatten()
                .chain(classed)
                .filter_map(|verb| verb.strip_prefix(AI_GRANT_VERB_PREFIX))
                .collect();
            if named.is_empty()
                || !grant.confers_with_classes_at(
                    now,
                    classes.unwrap_or(&crate::federation::AgentVerbClasses::none()),
                )
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
