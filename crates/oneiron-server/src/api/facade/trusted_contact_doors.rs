//! The host doors of the trusted-contact rows (DOOR-140 A, OF-527), beside
//! `shared_policy_doors`. The vault owner names a trusted contact, sets its
//! dial and a policy row's tier, and reads and answers the concern asks,
//! under the owner's proof (`owner_proof`). The named contact consents, and
//! either side lists and revokes, under their own person proof
//! (`shared_act_doors::person`): the contact is a separately credentialed,
//! live PERSON of this vault, so the owner never asserts the contact's
//! consent or adulthood. `door_admits` checks the same proof before the
//! row's hooks, and each door here takes it again for the engine call. The
//! engine's own checks decide the rest. `host_doors` re-exports them.
//!
//! Each row lists its rows (`host_door_lists`): the relations, asks and
//! tiers live in the engine's trusted-contact side tables, which hold no
//! listed row, so each lists none.
use std::sync::Arc;

use oneiron::counterparty_contact::{TrustedContact, TrustedContactAsk};
use oneiron::policy_model::PolicyModelConfig;
use oneiron::task_verb::sdk::{
    self, TrustedContactAsksRequest, TrustedContactAuthorization, TrustedContactAuthorizeRequest,
    TrustedContactConsentRequest, TrustedContactDialRequest, TrustedContactNameRequest,
    TrustedContactRevokeRequest, TrustedContactTierRequest, TrustedContactTierSet,
    TrustedContactsRequest,
};

use super::host_doors::{MaybeListed, owner_proof};
use super::shared_act_doors::{as_person_naming, person};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.trusted_contacts.name`: the owner names their trusted contact.
pub(crate) async fn vault_trusted_contacts_name(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: TrustedContactNameRequest,
) -> MaybeListed<TrustedContact> {
    const VERB: &str = "vault.trusted_contacts.name";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::name_trusted_contact(server.vault(), &owner, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.trusted_contacts.list`: every relation the caller is a side of.
pub(crate) async fn vault_trusted_contacts_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: TrustedContactsRequest,
) -> MaybeListed<Vec<TrustedContact>> {
    const VERB: &str = "vault.trusted_contacts.list";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, party| sdk::read_trusted_contacts(server.vault(), &party, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.trusted_contacts.consent`: the named contact accepts, as an adult.
pub(crate) async fn vault_trusted_contacts_consent(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: TrustedContactConsentRequest,
) -> MaybeListed<TrustedContact> {
    const VERB: &str = "vault.trusted_contacts.consent";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, contact| sdk::consent_trusted_contact(server.vault(), &contact, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.trusted_contacts.revoke`: either side ends the relation.
pub(crate) async fn vault_trusted_contacts_revoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: TrustedContactRevokeRequest,
) -> MaybeListed<TrustedContact> {
    const VERB: &str = "vault.trusted_contacts.revoke";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, party| sdk::revoke_trusted_contact(server.vault(), &party, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.trusted_contacts.dial.set`: the owner changes whether they are
/// asked first.
pub(crate) async fn vault_trusted_contacts_dial_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: TrustedContactDialRequest,
) -> MaybeListed<TrustedContact> {
    const VERB: &str = "vault.trusted_contacts.dial.set";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::set_trusted_contact_dial(server.vault(), &owner, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.trusted_contacts.tier.set`: the owner names one policy row's tier.
pub(crate) async fn vault_trusted_contacts_tier_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: TrustedContactTierRequest,
) -> MaybeListed<TrustedContactTierSet> {
    const VERB: &str = "vault.trusted_contacts.tier.set";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::set_trusted_contact_tier(server.vault(), &owner, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.trusted_contacts.concern.asks`: the owner's open concern asks.
pub(crate) async fn vault_trusted_contacts_concern_asks(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: TrustedContactAsksRequest,
) -> MaybeListed<Vec<TrustedContactAsk>> {
    const VERB: &str = "vault.trusted_contacts.concern.asks";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::read_trusted_contact_asks(server.vault(), &owner, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.trusted_contacts.concern.authorize`: the owner answers one open
/// ask. A yes stages the fact-of-concern notice; it does not deliver it.
pub(crate) async fn vault_trusted_contacts_concern_authorize(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: TrustedContactAuthorizeRequest,
) -> MaybeListed<TrustedContactAuthorization> {
    const VERB: &str = "vault.trusted_contacts.concern.authorize";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| {
            sdk::authorize_trusted_contact_ask(
                server.vault(),
                &owner,
                input,
                &PolicyModelConfig::default(),
            )
        },
        |_| Some(Vec::new()),
    )
    .await
}
