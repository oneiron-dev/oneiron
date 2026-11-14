//! The hub doors' apply-shape check-in tests' shared fixture (P2.5 2k8d:
//! `check_in_hub_import_effects.rs`, `check_in_clawhub_import_effects.rs`):
//! a hub the Owner configures, a skill's one file, and the ref of the
//! Grant that admits a publisher.

use oneiron::consent::{ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, GrantBound};
use oneiron::skill_hub::{HubSyncPolicy, SkillHubKind, SkillHubTrustTier};
use oneiron::verbs::{SkillHubPutRequest, skill_hub_put_as_owner};
use oneiron::{EntityId, Vault};

/// A hub the Owner configures at `endpoint`.
pub(crate) fn configured_hub(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    kind: SkillHubKind,
    endpoint: &str,
    sync_policy: HubSyncPolicy,
) -> EntityId {
    let hub = EntityId::now();
    skill_hub_put_as_owner(
        vault,
        owner_proof,
        &SkillHubPutRequest {
            hub,
            kind,
            endpoint: endpoint.to_owned(),
            trust_tier: SkillHubTrustTier::Community,
            sync_policy,
        },
    )
    .expect("the Owner configures the hub");
    hub
}

/// A skill's SKILL.md, named `name`.
pub(crate) fn skill_md(name: &str) -> Vec<u8> {
    format!(
        "---\nname: {name}\ndescription: a check-in fixture\nversion: 1\n---\nThe {name} fixture.\n"
    )
    .into_bytes()
}

/// The ref of the one Grant that admits `identity` to offer from `hub`.
pub(crate) fn publisher_grant_ref(identity: &str, hub: EntityId) -> String {
    GrantBound::action(
        ActorBound::new(identity)
            .expect("an actor")
            .with_actor_class("foreign-publisher")
            .expect("its class"),
        ActionClass::new("skill.offer").expect("the offer class"),
        ActionEnvelope::new([format!("hub:{}", hub.to_hex())]).expect("the hub envelope"),
    )
    .expect("the publisher's Grant")
    .digest()
    .to_hex()
}
