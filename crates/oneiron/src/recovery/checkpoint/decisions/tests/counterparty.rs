//! Census cases for what a send reads about its counterparty.
use super::Case;
use crate::campaign::claims::{
    CommDoNotContactValue, DO_NOT_CONTACT_SCOPE_ALL, PREDICATE_COMM_DO_NOT_CONTACT,
    encode_do_not_contact_value,
};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::comm::{CommError, SendOverrideScope};
use crate::counterparty_contact::{CounterpartyContactRecord, CounterpartyFirstTouch};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::test_util::entity;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Error, Result, TimeRange, Vault, VaultConfig};

fn open_vault() -> (tempfile::TempDir, Vault) {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    crate::test_util::open_test_vault_with(config)
}

fn put_identity(vault: &Vault, id: EntityId, address: &str) -> Result<()> {
    let identity = crate::test_util::self_held_identity_in_state(
        "email",
        address,
        crate::channel_identity::SelfHeldShape::DedicatedAddress,
        crate::channel_identity::ChannelIdentityBinding::agent(entity(0x6F)),
        crate::channel_identity::ChannelIdentityState::Active,
        1,
    );
    vault.create_channel_identity(&id, &identity)
}

fn comm(error: CommError) -> Error {
    match error {
        CommError::Engine(error) => error,
        other => Error::InvalidConfig(format!("{other:?}")),
    }
}

/// A party the backup does not name, which no decision reads anything about.
fn new_party(vault: &Vault) -> Result<()> {
    crate::comm::resolve_or_create_comm_party(vault, "kai@example.com")
        .map(drop)
        .map_err(comm)
}

/// The first contact the send gate reads for a party decides whether a
/// native-mail send to it is cold. A contact made since the backup that the
/// gate reads first, and that makes a known recipient cold, is one a
/// restore would drop; one the gate reads after changes nothing.
pub(super) fn send_contacts() -> Result<Case> {
    let (dir, vault) = open_vault();
    let (desk, inbox, studio) = (entity(0x8A), entity(0x8B), entity(0x8C));
    put_identity(&vault, desk, "desk@example.com")?;
    put_identity(&vault, inbox, "inbox@example.com")?;
    put_identity(&vault, studio, "studio@example.com")?;
    crate::test_util::put_native_mail_sender(
        &vault,
        entity(0x8E),
        entity(0x6F),
        &[CounterpartyFirstTouch::UserIntroduction],
    )?;
    vault.create_counterparty_contact(
        &entity(0x91),
        &CounterpartyContactRecord::user_introduction(desk, "sora@example.com", 10)?,
    )?;
    Case::after_backup(
        "counterparty contacts and their consents",
        (dir, vault),
        move |vault| {
            vault.create_counterparty_contact(
                &entity(0x95),
                &CounterpartyContactRecord::inbound_first(studio, "sora@example.com", 20)?,
            )
        },
        move |vault| {
            vault.create_counterparty_contact(
                &entity(0x90),
                &CounterpartyContactRecord::inbound_first(inbox, "sora@example.com", 30)?,
            )
        },
    )
}

/// A ruling reaches a party through its person's `claim_of` edges. A ruling
/// that reaches another person since the backup, its body unchanged, is one
/// a restore would take off that person.
pub(super) fn do_not_contact() -> Result<Case> {
    let (dir, vault) = open_vault();
    let party = |name| crate::comm::resolve_or_create_comm_party(&vault, name).map_err(comm);
    let (sora, rin) = (party("sora@example.com")?, party("rin@example.com")?);
    let ruling = entity(0xB0);
    vault.put_claim(
        &ruling,
        &ClaimBody::new(
            PREDICATE_COMM_DO_NOT_CONTACT,
            ClaimSubject::Entity(rin),
            encode_do_not_contact_value(&CommDoNotContactValue {
                channel: None,
                scope: DO_NOT_CONTACT_SCOPE_ALL.to_owned(),
            }),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )?,
        TimeRange { start: 10, end: 10 },
        10,
    )?;
    Case::after_backup(
        "do-not-contact rulings",
        (dir, vault),
        new_party,
        move |vault| vault.put_edge(&ruling, EdgeKind::ClaimOf, &sora, 1.0),
    )
}

/// An owner's override reaches a party through its person's `claim_of`
/// edges. One taken off its person since the backup, its body unchanged, is
/// one a restore would put back.
pub(super) fn send_overrides() -> Result<Case> {
    let (dir, vault) = open_vault();
    let owner = entity(0x71);
    vault.put_entity(
        &owner,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let rin = crate::comm::resolve_or_create_comm_party(&vault, "rin@example.com").map_err(comm)?;
    let ruling = crate::comm::mint_send_override(
        &vault,
        "rin@example.com",
        None,
        SendOverrideScope::Standing,
        None,
        WriteActor::new(owner, EdgeActorClass::Human),
        20,
        None,
    )
    .map_err(comm)?;
    Case::after_backup("send overrides", (dir, vault), new_party, move |vault| {
        vault
            .delete_edge(&ruling, EdgeKind::ClaimOf, &rin)
            .map(drop)
    })
}
