//! How an ask is shown: candidate labels, options, its view and its card.
//! Entry: `options_in_txn`, `view_in_txn` and `card` (the GenUI choice card).
//! The view, option and card types are in the parent.

use rmpv::Value;
use serde_json::json;

use super::{
    IDENTITY_ANSWER_VERB, IS_PREFIX, IdentityAsk, IdentityAskView, IdentityCardCopy,
    IdentityOption, SOMEONE_NEW, key_hex,
};
use crate::lens::{
    ButtonControl, GeneratedLens, GeneratedUiActionDeclaration, GeneratedUiActionTier,
    GeneratedUiCard, GeneratedUiStateSnapshot, LensAtom, LensAtomId, LensNode, LensRenderId,
    LensText, SelfUiAction, SelfUiActionId, SelfUiControl, SelfUiControlId, SelfUiValue,
    VoiceLineAtom,
};
use crate::{EntityId, Result, Vault};

/// A candidate's name: a provisional entity's own, a stored person's
/// display name or name, else the short id.
fn label_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<String> {
    if let Some(entity) = crate::tagging::provisional_in_txn(&vault.store, txn, id)? {
        return Ok(entity.name);
    }
    let name =
        crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)?.and_then(|raw| {
            if crate::batch::EntityMetadataHeader::parse(&raw).is_none()
                || raw.len() <= crate::batch::ENTITY_METADATA_HEADER_LEN
            {
                return None;
            }
            let mut body = &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];
            let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut body) else {
                return None;
            };
            ["display_name", "name"].iter().find_map(|wanted| {
                entries.iter().find_map(|(key, value)| {
                    (key.as_str() == Some(*wanted))
                        .then(|| value.as_str())
                        .flatten()
                        .filter(|text| !text.trim().is_empty())
                        .map(str::to_owned)
                })
            })
        });
    Ok(name.unwrap_or_else(|| id.to_hex().chars().take(8).collect()))
}

/// The ask's options: each candidate, then someone new.
pub(super) fn options_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ask: &IdentityAsk,
) -> Result<Vec<IdentityOption>> {
    let mut options = Vec::with_capacity(ask.candidates.len() + 1);
    for id in &ask.candidates {
        let first_said = crate::tagging::provisional_in_txn(&vault.store, txn, id)?
            .map(|entity| entity.minted_at);
        options.push(IdentityOption {
            choice: format!("{IS_PREFIX}{}", id.to_hex()),
            entity: Some(id.to_hex()),
            label: label_in_txn(vault, txn, id)?,
            provisional: first_said.is_some(),
            first_said,
        });
    }
    options.push(IdentityOption {
        choice: SOMEONE_NEW.to_owned(),
        entity: None,
        label: String::new(),
        provisional: false,
        first_said: None,
    });
    Ok(options)
}

pub(super) fn view_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &[u8; 32],
    ask: &IdentityAsk,
) -> Result<IdentityAskView> {
    Ok(IdentityAskView {
        ask: key_hex(key),
        name: ask.name.clone(),
        turn: ask.turn.to_hex(),
        conversation: crate::conversation_dag::conversation_of(&vault.store, txn, &ask.turn)
            .ok()
            .map(|id| id.to_hex()),
        excerpt: ask.excerpt.clone(),
        options: options_in_txn(vault, txn, ask)?,
        reason: ask.reason,
        opened_at: ask.opened_at,
        escalated_at: ask.escalated_at,
        kept_separate_at: ask.kept_separate_at,
    })
}

/// A provisional candidate's button label: its name and the day it was first
/// said, in the copy's words when the host gave them, so it reads apart from
/// a real person of the same name.
fn provisional_label(name: &str, first_said: u64, copy: &IdentityCardCopy) -> String {
    let Some(day) = i64::try_from(first_said)
        .ok()
        .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0))
        .map(|at| at.format("%Y-%m-%d").to_string())
    else {
        return name.to_owned();
    };
    match &copy.provisional {
        Some(words) => words.replace("{name}", name).replace("{day}", &day),
        None => format!("{name} · {day}"),
    }
}

/// A one-tap choice card for an ask: the name and the question, then one
/// button per option. Each button answers through [`IDENTITY_ANSWER_VERB`]
/// with the ask and its option, so a click runs as the clicking person.
pub(super) fn card(
    key: &[u8; 32],
    ask: &IdentityAsk,
    options: &[IdentityOption],
    copy: &IdentityCardCopy,
) -> Result<GeneratedUiCard> {
    let ask_hex = key_hex(key);
    let mut root = LensNode::new(
        LensAtomId::new("identity-voice")?,
        LensAtom::VoiceLine(VoiceLineAtom {
            speaker: LensText::new(ask.name.clone())?,
            text: LensText::new(copy.prompt.clone())?,
            vad: None,
        }),
    );
    let mut actions = Vec::with_capacity(options.len());
    for (index, option) in options.iter().enumerate() {
        let element = LensAtomId::new(format!("identity-option-{index}"))?;
        let args = json!({ "ask": ask_hex, "choice": option.choice }).to_string();
        let action = SelfUiAction {
            command: SelfUiActionId::new(IDENTITY_ANSWER_VERB)?,
            args: vec![SelfUiValue::Text(LensText::new(args)?)],
        };
        let label = match (&option.entity, option.first_said) {
            (None, _) => copy.someone_new.clone(),
            (Some(_), Some(first_said)) => provisional_label(&option.label, first_said, copy),
            (Some(_), None) => option.label.clone(),
        };
        root.children.push(LensNode::new(
            element.clone(),
            LensAtom::SelfUi(SelfUiControl::Button(ButtonControl {
                id: SelfUiControlId::new(format!("identity-option-{index}"))?,
                label: LensText::new(label)?,
                action: action.clone(),
            })),
        ));
        actions.push(GeneratedUiActionDeclaration {
            element_id: element,
            action_id: SelfUiActionId::new(format!("{IDENTITY_ANSWER_VERB}.{index}"))?,
            // The arguments are engine-authored and a click carries no
            // client state; the verb checks the ask and the answerer.
            tier: GeneratedUiActionTier::DeterministicTool,
            action,
        });
    }
    GeneratedUiCard::interactive(
        LensRenderId::new(format!("identity-{ask_hex}"))?,
        GeneratedLens::new(root)?,
        actions,
        GeneratedUiStateSnapshot::default(),
    )
}
