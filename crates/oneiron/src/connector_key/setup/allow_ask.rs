//! An `allow` from a setup verb as the owner's ask (OF-378). Allowing a
//! connection's permissions mints the owner's standing grants, so a verb
//! never lands it: it puts the setup's permission review to the owner on the
//! decision-ask queue. The ask freezes the exact source, the connection and
//! the permissions proposed. The owner's yes, pressed on the owner's proof at
//! the owner's ask answer door before the answer is recorded, lands exactly
//! that allow through [`Vault::answer_pack_setup`] in the answering owner's
//! own session, each permission with its consent receipt. A no allows
//! nothing, and so does an answer at a door that holds no owner proof.

use serde::{Deserialize, Serialize};

use super::*;
use crate::llm::decision::{
    AnswerContract, AskTo, DecisionAnswer, DecisionClass, DecisionQuestion, DecisionRung,
    HumanAskReason, HumanDecisionRequest, ProviderPin,
};
use crate::skill_hub::pack_catalog::PackSetupAnswer;

/// The host-issued queue identity of a pack setup's allow ask.
pub const PACK_SETUP_ALLOW_ASK_QUEUE: &str = "skill_hub.pack_setup.allow";
const PACK_SETUP_ALLOW_ASK_QUEUE_VERSION: &str = "v1";
/// The version of the ask's question; bump it with its wording.
const PACK_SETUP_ALLOW_ASK_VERSION: u32 = 1;
/// The owner door whose yes lands an allow ask.
pub const PACK_SETUP_ALLOW_ASK_DOOR: &str = "/v1/owner/decisions/asks/answer";
/// The most bytes of question text the ask carries; the decision queue
/// keeps at most 16 KiB.
const MAX_ALLOW_ASK_TEXT_BYTES: usize = 16_000;

/// One allow put to the owner: the ask's arrival number and exactly what a
/// yes allows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackSetupOwnerAsk {
    /// The ask's arrival number on the decision-ask queue.
    pub seq: u64,
    /// The owner door whose yes lands it.
    pub door: String,
    pub connection: String,
    /// The connection's permissions a yes allows, exactly: any other one
    /// allowed before is withdrawn.
    pub permissions: Vec<String>,
}

/// What one allow ask freezes, kept as the ask's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenAllow {
    pack: String,
    content_hash: String,
    connection: String,
    permissions: Vec<String>,
}

impl FrozenAllow {
    /// The ask's question id and correlation: one per exact allow.
    fn reference(&self) -> Result<EntityId> {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron.pack-setup.allow-ask.v1");
        frame(&mut hasher, self.pack.as_bytes());
        frame(&mut hasher, self.content_hash.as_bytes());
        frame(&mut hasher, self.connection.as_bytes());
        for permission in &self.permissions {
            frame(&mut hasher, permission.as_bytes());
        }
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        Ok(EntityId::from_bytes(bytes)?)
    }
}

impl Vault {
    /// Puts an allow of exactly `permissions` of `connection` to the owner,
    /// for the session `actor` works, as one ask on the decision-ask queue,
    /// and returns the view with the ask. The same open ask answers its own
    /// arrival number. A connection that already holds exactly those
    /// permissions asks nothing. The owner's yes at
    /// [`PACK_SETUP_ALLOW_ASK_DOOR`] lands it ([`Self::press_pack_setup_allow`]).
    pub fn ask_owner_to_allow_pack_connection(
        &self,
        actor: PackSetupActor<'_>,
        pack: &str,
        content_hash: Option<&str>,
        connection: &str,
        permissions: &[String],
    ) -> Result<(PackSetupView, Option<PackSetupOwnerAsk>)> {
        let (view, frozen, text, source) = {
            let txn = self.store.env.read_txn()?;
            let principal = actor.principal_for_read(self, &txn, pack, content_hash)?;
            let binding = self.bind_pack_setup_in_txn(&txn, &principal, pack, content_hash)?;
            let session = self.require_pack_setup_in_txn(&txn, &binding)?;
            let declared = declared_connection(&binding.setup.connections, connection)?;
            check_allowed(declared, permissions)?;
            let view = self.pack_setup_view_in_txn(&txn, &binding, &session)?;
            let mut permissions = permissions.to_vec();
            permissions.sort();
            permissions.dedup();
            if holds_exactly(&view, &declared.id, &permissions) {
                return Ok((view, None));
            }
            let frozen = FrozenAllow {
                pack: binding.receipt.pack_name.clone(),
                content_hash: binding.receipt.content_hash.clone(),
                connection: declared.id.clone(),
                permissions,
            };
            let text = allow_ask_text(&frozen, declared);
            let source = EntityId::from_hex(&binding.receipt.source_id)?;
            (view, frozen, text, source)
        };
        let reference = frozen.reference()?;
        let state = serde_json::to_value(&frozen)
            .map_err(|_| invalid("the allow ask's state did not encode"))?;
        let request = allow_ask_request(reference, actor.entity_for_read(self)?, source, text);
        let seq = self.queue_decision_ask_with_state(&request, Some(&state))?;
        Ok((
            view,
            Some(PackSetupOwnerAsk {
                seq,
                door: PACK_SETUP_ALLOW_ASK_DOOR.to_owned(),
                connection: frozen.connection,
                permissions: frozen.permissions,
            }),
        ))
    }

    /// The owner's press on decision ask `seq`, before its answer is
    /// recorded: a yes to an open allow ask opens or resumes the answering
    /// owner's session of the frozen source and lands exactly the frozen
    /// allow through [`Self::answer_pack_setup`], each permission with its
    /// consent receipt. Any other ask, an ask no longer open, and any other
    /// answer are left alone, so the answer goes on as before.
    ///
    /// # Errors
    ///
    /// A proof that is not the owner's, a frozen source that is no longer
    /// live, an ask whose state does not match its question, and storage
    /// errors. Nothing is allowed then, and the caller records no answer, so
    /// the ask stays open.
    pub fn press_pack_setup_allow(
        &self,
        owner: &AuthenticatedOwner,
        seq: u64,
        answer: &DecisionAnswer,
    ) -> Result<()> {
        if !matches!(answer, DecisionAnswer::Noul(true)) {
            return Ok(());
        }
        let Some(ask) = self.decision_ask(seq)? else {
            return Ok(());
        };
        if ask.queue_pin.model != PACK_SETUP_ALLOW_ASK_QUEUE
            || ask.question.contract != AnswerContract::Noul
            || !ask.is_open()
        {
            return Ok(());
        }
        let frozen: FrozenAllow = ask
            .pack_state
            .and_then(|state| serde_json::from_value(state).ok())
            .ok_or_else(|| invalid("the allow ask's state is unreadable"))?;
        let reference = frozen.reference()?;
        if ask.question.id != reference || ask.correlation != Some(reference) {
            return Err(invalid("the allow ask's state does not match its question"));
        }
        let FrozenAllow {
            pack,
            content_hash,
            connection,
            permissions,
        } = frozen;
        self.prepare_pack_setup(owner, &pack, Some(&content_hash))?;
        self.answer_pack_setup(
            owner,
            &pack,
            Some(&content_hash),
            &PackSetupAnswer::Allow {
                connection,
                permissions,
            },
        )?;
        Ok(())
    }
}

/// Whether the view's `connection` holds exactly `permissions` allowed now.
fn holds_exactly(view: &PackSetupView, connection: &str, permissions: &[String]) -> bool {
    view.connections
        .iter()
        .find(|state| state.id == connection)
        .is_some_and(|state| {
            let mut granted: Vec<&str> = state
                .permissions
                .iter()
                .filter(|permission| permission.granted)
                .map(|permission| permission.id.as_str())
                .collect();
            granted.sort_unstable();
            granted
                .iter()
                .copied()
                .eq(permissions.iter().map(String::as_str))
        })
}

/// The owner ask for one frozen allow, put by `principal`, the agent or the
/// owner's person that asked, about the pack source `source`.
fn allow_ask_request(
    reference: EntityId,
    principal: EntityId,
    source: EntityId,
    text: String,
) -> HumanDecisionRequest {
    HumanDecisionRequest {
        question: DecisionQuestion {
            id: reference,
            version: PACK_SETUP_ALLOW_ASK_VERSION,
            text,
            class: DecisionClass::Judgment,
            contract: AnswerContract::Noul,
            accept_type: false,
        },
        principal,
        evidence: vec![source],
        reason: HumanAskReason::OwnerSelected,
        prior: None,
        prior_provider: None,
        queue_pin: ProviderPin {
            rung: DecisionRung::Human,
            model: PACK_SETUP_ALLOW_ASK_QUEUE.to_owned(),
            version: PACK_SETUP_ALLOW_ASK_QUEUE_VERSION.to_owned(),
        },
        to: AskTo::owner(),
        correlation: Some(reference),
    }
}

/// The wording of an allow ask: the one place it lives. It names the pack,
/// the connection and each permission with what it lets the pack do and its
/// risk, says that a yes allows exactly these, and where a yes counts.
fn allow_ask_text(frozen: &FrozenAllow, connection: &PackSetupConnection) -> String {
    let permissions = frozen
        .permissions
        .iter()
        .filter_map(|id| connection.permission(id))
        .map(|permission| {
            format!(
                "\n- {} ({} risk): {} Risk: {}",
                permission.id,
                permission.level.as_str(),
                permission.what,
                permission.risk
            )
        })
        .collect::<String>();
    let permissions = if permissions.is_empty() {
        "\n- none: every permission allowed before is withdrawn".to_owned()
    } else {
        permissions
    };
    let mut text = format!(
        "Your agent asks you to allow the {pack} pack's \"{label}\" connection exactly these \
         permissions:{permissions}\nAny other permission of this connection you allowed before \
         is withdrawn. A yes at {PACK_SETUP_ALLOW_ASK_DOOR} allows them, each with its own \
         consent receipt; a no allows nothing. You can also review them on the setup's card. \
         Allow them?",
        pack = frozen.pack,
        label = connection.label,
    );
    if text.len() > MAX_ALLOW_ASK_TEXT_BYTES {
        let mut cut = MAX_ALLOW_ASK_TEXT_BYTES;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
    }
    text
}
