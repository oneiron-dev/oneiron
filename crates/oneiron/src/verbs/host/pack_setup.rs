//! The pack setup verbs' inputs, answers and calls (OF-378):
//! `vault.packs.setup.prepare`, `.get`, `.answer` and `.verify`, each served
//! for the owner on the owner's proof, or for an agent acting for the owner.
use serde::{Deserialize, Serialize};

use crate::connector_key::{PackConnectionVerifier, PackSetupOwnerAsk, ProviderConnectionChecks};
use crate::consent::AuthenticatedOwner;
use crate::lens::GeneratedUiStateSnapshot;
use crate::memory::{MEMORY_CODE_INTERNAL, Memory, MemoryError, MemoryResult};
use crate::skill_hub::pack_catalog::{
    PackSetupActor, PackSetupAnswer, PackSetupCardAction, PackSetupView,
};

/// Where a credential value goes during a pack's setup: the owner secrets
/// door. No `vault.packs.setup.*` verb and no card ever carries a value.
pub const PACK_SETUP_SECRETS_DOOR: &str = "/v1/owner/secrets/register";

/// `vault.packs.setup.prepare` and `vault.packs.setup.get`'s input: one
/// pack's guided setup (OF-378), by name.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackSetupRequest {
    pub pack: String,
    /// One exact source by content hash; else the Active source, or the
    /// pack's one Candidate.
    #[serde(default)]
    pub source: Option<String>,
}

/// `vault.packs.setup.verify`'s input: the connection to check.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackSetupVerifyRequest {
    pub pack: String,
    #[serde(default)]
    pub source: Option<String>,
    pub connection: String,
}

/// `vault.packs.setup.answer`'s input: one typed answer, or one action from
/// the setup's cards with the card's `$state`; exactly one of them.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackSetupAnswerRequest {
    pub pack: String,
    #[serde(default)]
    pub source: Option<String>,
    /// `secret_stored` (pins the custody record the owner stored at the
    /// secrets door), `bind_key`, or `allow`, which is the owner's own
    /// decision: this verb puts it to the owner as an ask.
    #[serde(default)]
    #[schemars(with = "Option<serde_json::Map<String, serde_json::Value>>")]
    pub answer: Option<PackSetupAnswer>,
    #[serde(default)]
    pub card_action: Option<PackSetupCardActionInput>,
}

/// One action from a setup card: its action id and the card's `$state`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackSetupCardActionInput {
    pub action_id: String,
    #[serde(default)]
    #[schemars(with = "serde_json::Map<String, serde_json::Value>")]
    pub state: GeneratedUiStateSnapshot,
}

/// What each `vault.packs.setup.*` verb answers, as the owner door
/// `/v1/owner/packs/setup` serves it: the setup, its GenUI cards and its
/// plain text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackSetupReceipt {
    pub setup: PackSetupView,
    /// The setup's GenUI cards, as their wire JSON.
    pub cards: Vec<serde_json::Value>,
    pub text: String,
    /// Set when a card asked to store a credential: the owner stores the
    /// value at `door`, then a `secret_stored` answer pins its record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_secret: Option<PackSetupStoreSecret>,
    /// Set when an `allow` was put to the owner as an ask: the owner's yes
    /// at its door lands exactly its permissions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_ask: Option<PackSetupOwnerAsk>,
}

/// The owner secrets door to open for one declared credential name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackSetupStoreSecret {
    pub door: String,
    pub connection: String,
    pub name: String,
    /// The binding the stored credential needs, with the read scope.
    pub effector: String,
}

impl PackSetupReceipt {
    fn new(setup: PackSetupView) -> MemoryResult<Self> {
        let cards = setup
            .cards()?
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                MemoryError::new(
                    MEMORY_CODE_INTERNAL,
                    "the pack setup's cards did not encode",
                    &["Report this SDK host-door failure."],
                )
            })?;
        Ok(Self {
            cards,
            text: setup.text(),
            setup,
            store_secret: None,
            owner_ask: None,
        })
    }
}

/// `vault.packs.setup.prepare` under the owner's proof: opens, or resumes,
/// the setup through [`crate::Vault::prepare_pack_setup`]. Opening grants
/// nothing.
pub fn prepare_pack_setup_as_owner(
    vault: &crate::Vault,
    owner: &AuthenticatedOwner,
    input: &PackSetupRequest,
) -> MemoryResult<PackSetupReceipt> {
    prepare_pack_setup_as_actor(vault, PackSetupActor::Owner(owner), input)
}

/// `vault.packs.setup.prepare` for `actor`: the owner, or an agent acting
/// for the owner, which opens or resumes the owner's session
/// ([`crate::Vault::prepare_pack_setup_as`]).
pub fn prepare_pack_setup_as_actor(
    vault: &crate::Vault,
    actor: PackSetupActor<'_>,
    input: &PackSetupRequest,
) -> MemoryResult<PackSetupReceipt> {
    PackSetupReceipt::new(vault.prepare_pack_setup_as(
        actor,
        &input.pack,
        input.source.as_deref(),
    )?)
}

/// `vault.packs.setup.get` under the owner's proof: the setup as it stands.
pub fn pack_setup_as_owner(
    vault: &crate::Vault,
    owner: &AuthenticatedOwner,
    input: &PackSetupRequest,
) -> MemoryResult<PackSetupReceipt> {
    pack_setup_as_actor(vault, PackSetupActor::Owner(owner), input)
}

/// `vault.packs.setup.get` for `actor`: an agent acting for the owner reads
/// the owner's session.
pub fn pack_setup_as_actor(
    vault: &crate::Vault,
    actor: PackSetupActor<'_>,
    input: &PackSetupRequest,
) -> MemoryResult<PackSetupReceipt> {
    PackSetupReceipt::new(vault.pack_setup_as(actor, &input.pack, input.source.as_deref())?)
}

/// `vault.packs.setup.verify` under the owner's proof: the host's fixed
/// check for the connection's declared check name.
pub fn verify_pack_setup_as_owner(
    vault: &crate::Vault,
    owner: &AuthenticatedOwner,
    input: &PackSetupVerifyRequest,
    checks: &dyn PackConnectionVerifier,
) -> MemoryResult<PackSetupReceipt> {
    verify_pack_setup_as_actor(vault, PackSetupActor::Owner(owner), input, checks)
}

/// `vault.packs.setup.verify` for `actor`: an agent acting for the owner
/// checks the connection in the owner's session.
pub fn verify_pack_setup_as_actor(
    vault: &crate::Vault,
    actor: PackSetupActor<'_>,
    input: &PackSetupVerifyRequest,
    checks: &dyn PackConnectionVerifier,
) -> MemoryResult<PackSetupReceipt> {
    verify_pack_connection_as_actor(
        vault,
        actor,
        &input.pack,
        input.source.as_deref(),
        &input.connection,
        checks,
    )
}

/// `vault.packs.setup.answer` under the owner's proof, as
/// [`answer_pack_setup_as_actor`] takes it.
pub fn answer_pack_setup_as_owner(
    vault: &crate::Vault,
    owner: &AuthenticatedOwner,
    input: &PackSetupAnswerRequest,
    checks: &dyn PackConnectionVerifier,
) -> MemoryResult<PackSetupReceipt> {
    answer_pack_setup_as_actor(vault, PackSetupActor::Owner(owner), input, checks)
}

/// `vault.packs.setup.answer` for `actor`. A verb is an agent's door, so it
/// never lands `allow`: allowing a connection's permissions mints the
/// owner's standing consent grants. It puts the allow to the owner as an
/// ask ([`crate::Vault::ask_owner_to_allow_pack_connection`]) and answers
/// with it; the owner's yes at the ask's door lands exactly those
/// permissions, and the owner can still allow on the setup's review card or
/// at `POST /v1/owner/packs/setup/answer`. A card's store action answers
/// with the owner secrets door to open; a value never passes here.
pub fn answer_pack_setup_as_actor(
    vault: &crate::Vault,
    actor: PackSetupActor<'_>,
    input: &PackSetupAnswerRequest,
    checks: &dyn PackConnectionVerifier,
) -> MemoryResult<PackSetupReceipt> {
    let source = input.source.as_deref();
    let answer = match (&input.answer, &input.card_action) {
        (Some(answer), None) => answer.clone(),
        (None, Some(card)) => {
            let view = vault.pack_setup_as(actor, &input.pack, source)?;
            match view.card_action(&card.action_id, &card.state)? {
                PackSetupCardAction::Answer(answer) => answer,
                PackSetupCardAction::Verify { connection } => {
                    return verify_pack_connection_as_actor(
                        vault,
                        actor,
                        &input.pack,
                        source,
                        &connection,
                        checks,
                    );
                }
                PackSetupCardAction::StoreSecret {
                    connection,
                    secret,
                    effector,
                } => {
                    let mut receipt = PackSetupReceipt::new(view)?;
                    receipt.store_secret = Some(PackSetupStoreSecret {
                        door: PACK_SETUP_SECRETS_DOOR.to_owned(),
                        connection,
                        name: secret,
                        effector,
                    });
                    return Ok(receipt);
                }
            }
        }
        _ => {
            return Err(MemoryError::bad_request(
                "send exactly one of answer or card_action",
            ));
        }
    };
    if let PackSetupAnswer::Allow {
        connection,
        permissions,
    } = &answer
    {
        let (view, owner_ask) = vault.ask_owner_to_allow_pack_connection(
            actor,
            &input.pack,
            source,
            connection,
            permissions,
        )?;
        let mut receipt = PackSetupReceipt::new(view)?;
        receipt.owner_ask = owner_ask;
        return Ok(receipt);
    }
    PackSetupReceipt::new(vault.answer_pack_setup_as(actor, &input.pack, source, &answer)?)
}

fn verify_pack_connection_as_actor(
    vault: &crate::Vault,
    actor: PackSetupActor<'_>,
    pack: &str,
    source: Option<&str>,
    connection: &str,
    checks: &dyn PackConnectionVerifier,
) -> MemoryResult<PackSetupReceipt> {
    PackSetupReceipt::new(vault.verify_pack_connection_as(actor, pack, source, connection, checks)?)
}

/// `vault.packs.setup.prepare` on an embedded handle, as the vault's
/// embedded owner.
pub fn prepare_pack_setup_embedded(
    memory: &Memory<'_>,
    input: PackSetupRequest,
) -> MemoryResult<PackSetupReceipt> {
    let owner = memory.embedded_owner("vault.packs.setup.prepare")?;
    prepare_pack_setup_as_owner(memory.vault(), &owner, &input)
}

/// `vault.packs.setup.get` on an embedded handle, as the vault's embedded
/// owner.
pub fn pack_setup_embedded(
    memory: &Memory<'_>,
    input: PackSetupRequest,
) -> MemoryResult<PackSetupReceipt> {
    let owner = memory.embedded_owner("vault.packs.setup.get")?;
    pack_setup_as_owner(memory.vault(), &owner, &input)
}

/// `vault.packs.setup.answer` on an embedded handle, as the vault's
/// embedded owner; an `allow` is put to the owner as an ask here too.
pub fn answer_pack_setup_embedded(
    memory: &Memory<'_>,
    input: PackSetupAnswerRequest,
) -> MemoryResult<PackSetupReceipt> {
    let owner = memory.embedded_owner("vault.packs.setup.answer")?;
    let vault = memory.vault();
    off_async_runtime("vault.packs.setup.answer", || {
        answer_pack_setup_as_owner(vault, &owner, &input, &ProviderConnectionChecks::new()?)
    })
}

/// `vault.packs.setup.verify` on an embedded handle, as the vault's
/// embedded owner.
pub fn verify_pack_setup_embedded(
    memory: &Memory<'_>,
    input: PackSetupVerifyRequest,
) -> MemoryResult<PackSetupReceipt> {
    let owner = memory.embedded_owner("vault.packs.setup.verify")?;
    let vault = memory.vault();
    off_async_runtime("vault.packs.setup.verify", || {
        verify_pack_setup_as_owner(vault, &owner, &input, &ProviderConnectionChecks::new()?)
    })
}

/// A provider check is a blocking HTTPS call, which must not run on an
/// async runtime's thread: an embedded caller may be on one, so the call
/// runs on a thread of its own.
fn off_async_runtime<T: Send>(
    verb: &str,
    call: impl FnOnce() -> MemoryResult<T> + Send,
) -> MemoryResult<T> {
    std::thread::scope(|scope| scope.spawn(call).join()).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_INTERNAL,
            format!("{verb} did not finish"),
            &["Report this SDK host-door failure."],
        )
    })?
}
