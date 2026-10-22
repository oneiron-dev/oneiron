//! The host doors of the trusted-contact rows (DOOR-140 A, OF-527), beside
//! `shared_policy_doors`. A live person names their trusted contact, sets
//! its dial, and reads and answers their own concern asks under their own
//! proof ([`own_person`], FIX 8169); a policy row's tier stays under the
//! owner's proof (`owner_proof`). The named contact consents, and
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
//!
//! `.concern.authorize` and `.concern.propose` word their notices with the
//! host's owner-plane configuration ([`owner_policy_config`]), the one the
//! gate's own fire under `.concern.propose` reads too.
//!
//! DOOR-140 B: `.concern.propose` and `.concern.deliver` act on the
//! caller's own credential handle (`host_door_caller`), as `connector.call`
//! does. Propose reads the message under the caller's own read scope, for
//! the owner's proof, and lists the message it read. Deliver is the
//! caller's alone: no proof arm admits it, the caller is the sender, and it
//! sends only a notice whose stored sender is the caller, through this
//! server's served channel sink.
use std::sync::Arc;

use oneiron::counterparty_contact::{TrustedContact, TrustedContactAsk};
use oneiron::memory::MemoryError;
use oneiron::outbound::ServedChannelSink;
use oneiron::policy_model::PolicyModelConfig;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{
    self, TrustedContactAsksRequest, TrustedContactAuthorization, TrustedContactAuthorizeRequest,
    TrustedContactConcernProposal, TrustedContactConcernRequest, TrustedContactConsentRequest,
    TrustedContactDeliverRequest, TrustedContactDeliveryReceipt, TrustedContactDialRequest,
    TrustedContactNameRequest, TrustedContactRevokeRequest, TrustedContactTierRequest,
    TrustedContactTierSet, TrustedContactsRequest,
};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, MaybeListed, credential_listing, owner_proof, refused};
use super::shared_act_doors::{as_person_naming, person};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The one owner-plane policy configuration this host serves
/// (`SyncServer::with_owner_policy_config`), so a concern's notices, and
/// the gate's fire under `.concern.propose`, carry the host's wording, not
/// per-door defaults (FIX 4329, 4422).
fn owner_policy_config(server: &SyncServer) -> &PolicyModelConfig {
    &server.policy_doors.owner
}

/// The proof a person's own trusted-contact act runs under (FIX 8169):
/// naming their contact, their own dial, and reading, answering and
/// proposing their own concern. The owner's, as before; else any live
/// person's own, from their verified human slip ([`person`]), which every
/// engine door here revalidates as that person in its own transaction. A
/// caller with neither keeps the owner refusal it had. The shared policy
/// tier stays the owner's.
pub(super) fn own_person(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> oneiron::memory::MemoryResult<oneiron::consent::AuthenticatedOwner> {
    owner_proof(auth, server, verb)
        .or_else(|refusal| person(server, auth, verb).map_err(|_| refusal))
}

/// `vault.trusted_contacts.name`: a person names their trusted contact.
pub(crate) async fn vault_trusted_contacts_name(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: TrustedContactNameRequest,
) -> MaybeListed<TrustedContact> {
    const VERB: &str = "vault.trusted_contacts.name";
    as_person_naming(
        server,
        VERB,
        own_person(server, auth, VERB),
        move |server, person| sdk::name_trusted_contact(server.vault(), &person, input),
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

/// `vault.trusted_contacts.dial.set`: a person changes whether they are
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
        own_person(server, auth, VERB),
        move |server, person| sdk::set_trusted_contact_dial(server.vault(), &person, input),
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

/// `vault.trusted_contacts.concern.asks`: a person's own open concern asks.
pub(crate) async fn vault_trusted_contacts_concern_asks(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: TrustedContactAsksRequest,
) -> MaybeListed<Vec<TrustedContactAsk>> {
    const VERB: &str = "vault.trusted_contacts.concern.asks";
    as_person_naming(
        server,
        VERB,
        own_person(server, auth, VERB),
        move |server, person| sdk::read_trusted_contact_asks(server.vault(), &person, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.trusted_contacts.concern.authorize`: a person answers one of their
/// own open asks. A yes stages the fact-of-concern notice; it does not deliver it.
pub(crate) async fn vault_trusted_contacts_concern_authorize(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: TrustedContactAuthorizeRequest,
) -> MaybeListed<TrustedContactAuthorization> {
    const VERB: &str = "vault.trusted_contacts.concern.authorize";
    as_person_naming(
        server,
        VERB,
        own_person(server, auth, VERB),
        move |server, person| {
            sdk::authorize_trusted_contact_ask(
                server.vault(),
                &person,
                input,
                owner_policy_config(server),
            )
        },
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.trusted_contacts.concern.propose`: the owner's policy gate reads
/// one message the caller reads and, on a `RouteToHelp`, proposes the fact
/// of concern. Beside it, the message it read.
pub(crate) async fn vault_trusted_contacts_concern_propose(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: TrustedContactConcernRequest,
) -> Listed<TrustedContactConcernProposal> {
    const VERB: &str = "vault.trusted_contacts.concern.propose";
    let proof = match own_person(server, auth, VERB) {
        Ok(proof) => proof,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |server, _, memory| {
        sdk::propose_trusted_contact_concern(&memory, &proof, input, owner_policy_config(server))
    })
    .await
}

/// `vault.trusted_contacts.concern.deliver`: the caller delivers the next
/// notice it is the stored sender of, through this server's served channel
/// sink. `None` when none is eligible.
pub(crate) async fn vault_trusted_contacts_concern_deliver(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: TrustedContactDeliverRequest,
) -> Listed<Option<TrustedContactDeliveryReceipt>> {
    const VERB: &str = "vault.trusted_contacts.concern.deliver";
    credential_listing(server, auth, caller, VERB, move |server, _, memory| {
        let mut sink = ServedChannelSink::new(server.vault())
            .map_err(MemoryError::from)?
            .with_line_push_allowance(server.config.line.monthly_push_allowance());
        sdk::deliver_trusted_contact_notice(&memory, input, &mut sink)
    })
    .await
}
