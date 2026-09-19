//! Scope ask recipients resolved from live, owner-stamped action grants.
use super::{ActionClass, ActionEnvelope, BoundSubject, GrantBound, StandingConsentGrant};
use crate::error::Result;
use crate::{EntityId, Vault};
use std::collections::BTreeSet;

impl Vault {
    /// Reads all holders of a requested action scope on the admission snapshot.
    /// Delegates precede granting owners. No caller-provided actor set is used.
    pub(crate) fn ask_authority_holders_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        class: &ActionClass,
        envelope: &ActionEnvelope,
    ) -> Result<Vec<EntityId>> {
        let mut delegates = BTreeSet::new();
        let mut owners = BTreeSet::new();
        for grant in self.active_standing_consent_grants_in_txn(txn)? {
            let StandingConsentGrant::Action(action) = grant else {
                continue;
            };
            let BoundSubject::Actor(subject) = action.bound().subject() else {
                continue;
            };
            let required = GrantBound::action(subject.clone(), class.clone(), envelope.clone())?;
            if !action.bound().contains(&required) {
                continue;
            }
            let reference = action.bound().digest().to_hex();
            let Some(row) = self.consent_grant_in_txn(txn, &reference)? else {
                continue;
            };
            if !row.is_active() {
                continue;
            }
            if let Ok(actor) = EntityId::from_hex(subject.actor_ref()) {
                // Only an actual actor entity is addressable. A principal label
                // is not guessed into an ACTOR. Its granting owner still is.
                if let Some(raw) = self.get_raw_in(txn, &actor)? {
                    let kind = crate::batch::EntityMetadataHeader::parse(&raw)
                        .ok_or(crate::error::Error::CorruptedIndex(
                            "ask holder entity header",
                        ))?
                        .entity_type;
                    // PERSON is also the shipped peer/connector actor kind;
                    // AGENT_DEF is the in-process actor kind. Match the same
                    // entity/class combinations as the Memory actor door.
                    let addressable = match subject.actor_class() {
                        None | Some("agent") => matches!(
                            kind,
                            crate::registry::ENTITY_TYPE_PERSON
                                | crate::registry::ENTITY_TYPE_AGENT_DEF
                        ),
                        Some("human") => kind == crate::registry::ENTITY_TYPE_PERSON,
                        _ => false,
                    };
                    if addressable {
                        delegates.insert(actor);
                    }
                }
            }
            owners.insert(row.owner_stamp.actor);
        }
        let mut holders: Vec<_> = delegates.iter().copied().collect();
        holders.extend(
            owners
                .into_iter()
                .filter(|owner| !delegates.contains(owner)),
        );
        Ok(holders)
    }
}
