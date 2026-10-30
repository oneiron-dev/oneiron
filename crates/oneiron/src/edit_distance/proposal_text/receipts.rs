//! Commit-envelope writer and read-time provenance fold for authored text.
//!
//! A receipt names its writer by the actor's stamp token (FIX 10930): its
//! process actor, and its process identity where that would spell the
//! actor's id. The fold resolves the token and reads each receipt back
//! naming the resolved actor.
use super::{ProposalTextArtifact, StampKind, parse_stamp};
use crate::EntityId;
use crate::edge::EdgeActorClass;
use crate::entity_doc::EntityDoc;
use crate::error::{Error, Result};
use crate::provenance::ActorStamp;
use crate::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess, MadeByTrigger,
};
use crate::provenance::text_commit::{RowProvenance, TextCommitReceipt};
use crate::write_envelope::WriteActor;
use loro::{ChangeMeta, CommitOptions, LoroDoc};
use sha2::{Digest, Sha256};
use std::ops::ControlFlow;

const RECEIPT_PREFIX: &str = "|made_by=";

impl ProposalTextArtifact {
    /// Creates generated text with a prompt row and a task/ask birth trigger.
    /// The same door serves summaries, lenses, code, UI and explainers.
    pub fn open_generated(
        vault: &crate::Vault,
        initial: &str,
        actor: &WriteActor,
        prompt: EntityId,
        trigger: MadeByTrigger,
        process: MadeByProcess,
    ) -> Result<Self> {
        if process.actor != actor.entity_ref()
            || process.class != MadeByClass::Concluded
            || !process.is_valid()
        {
            return Err(Error::InvalidConfig(
                "generated birth process must name its writing actor".into(),
            ));
        }
        if vault.get_entity_type(&prompt)?.is_none() || !trigger_is_valid(vault, &trigger)? {
            return Err(Error::InvalidConfig(
                "invalid generated birth input or trigger".into(),
            ));
        }
        let made_by = MadeBy {
            inputs: vec![MadeByInput {
                row: prompt,
                role: MadeByInputRole::Prompt,
            }],
            process,
            at: crate::unix_seconds_now(),
            trigger: Some(trigger),
        };
        Self::open_with_receipt(vault, initial, actor, Some(prompt), Some(made_by))
    }

    /// Folds the complete history. Missing or malformed receipts exclude the
    /// row rather than guessing that unreceipted text was stated by a person,
    /// and so does a receipt whose stamp token resolves to no one (FIX 10930).
    pub fn provenance(&self, vault: &crate::Vault) -> Result<Option<RowProvenance>> {
        let mut receipts = Vec::new();
        let mut authority_error = None;
        self.doc
            .doc
            .travel_change_ancestors(
                &self.doc.doc.oplog_frontiers().to_vec(),
                &mut |meta: ChangeMeta| {
                    let receipt = meta
                        .message
                        .as_deref()
                        .and_then(|message| message.split_once(RECEIPT_PREFIX))
                        .and_then(|(_, json)| serde_json::from_str::<MadeBy>(json).ok())
                        .filter(|made_by| Some(made_by.at) == u64::try_from(meta.timestamp).ok())
                        .and_then(|mut made_by| {
                            let (kind, stamp) = parse_stamp(meta.message.as_deref())?;
                            if stamp.token != made_by.process.actor
                                || (stamp.class != EdgeActorClass::Human
                                    && made_by.process.class == MadeByClass::Stated)
                            {
                                return None;
                            }
                            let required_rows: Vec<EntityId> = made_by
                                .inputs
                                .iter()
                                .filter(|input| input.role == MadeByInputRole::Prompt)
                                .map(|input| input.row)
                                .collect();
                            if let Some(trigger) = &made_by.trigger {
                                match trigger_is_valid(vault, trigger) {
                                    Ok(true) => {}
                                    Ok(false) => return None,
                                    Err(error) => {
                                        authority_error = Some(error);
                                        return None;
                                    }
                                }
                            }
                            for row in required_rows {
                                match vault.get_entity_type(&row) {
                                    Ok(Some(_)) => {}
                                    Ok(None) => return None,
                                    Err(error) => {
                                        authority_error = Some(error);
                                        return None;
                                    }
                                }
                            }
                            // A generated birth names a Prompt input and a valid trigger
                            // (FIX 9810); later edits may omit both.
                            let is_generated_birth = kind == StampKind::Open
                                && made_by.process.class == MadeByClass::Concluded;
                            let names_birth = made_by
                                .inputs
                                .iter()
                                .any(|input| input.role == MadeByInputRole::Prompt)
                                && made_by.trigger.is_some();
                            if is_generated_birth && !names_birth {
                                return None;
                            }
                            // The token resolves to an actor of the stamp's
                            // class, or the receipt names no one (FIX 10930).
                            let actor =
                                match crate::provenance::resolve_actor_stamp(vault, &stamp.token) {
                                    Ok(Some(actor)) if actor.actor_class() == stamp.class => actor,
                                    Ok(_) => return None,
                                    Err(error) => {
                                        authority_error = Some(error);
                                        return None;
                                    }
                                };
                            match crate::edit_distance::peer_actor_stamp_is_honored(
                                vault,
                                meta.id.peer,
                                made_by.at,
                                &actor,
                            ) {
                                Ok(true) => {}
                                Ok(false) => return None,
                                Err(error) => {
                                    authority_error = Some(error);
                                    return None;
                                }
                            }
                            resolve_process_actor(&mut made_by.process, stamp, actor);
                            Some(made_by)
                        })
                        .and_then(|made_by| {
                            let end = meta.id.counter.checked_add(i32::try_from(meta.len).ok()?)?;
                            Some(TextCommitReceipt {
                                document: self.artifact_ref.entity_id(),
                                peer: meta.id.peer,
                                start: meta.id.counter,
                                end,
                                made_by,
                            })
                        });
                    receipts.push(receipt);
                    ControlFlow::Continue(())
                },
            )
            .map_err(|_| Error::CorruptedIndex("text receipt history"))?;
        if let Some(error) = authority_error {
            return Err(error);
        }
        // Loro traverses ancestors from newest to oldest.
        receipts.reverse();
        Ok(RowProvenance::fold(self.artifact_ref.entity_id(), receipts))
    }

    pub(super) fn commit_receipted(
        &self,
        kind: StampKind,
        writer: (&WriteActor, ActorStamp),
        receipt: Option<MadeBy>,
    ) -> Result<()> {
        let at = crate::unix_seconds_now();
        let message = receipted_message(
            &self.doc.doc,
            kind,
            writer,
            self.source_turn_ref,
            receipt,
            at,
        )?;
        let timestamp = i64::try_from(at)
            .map_err(|_| Error::InvalidConfig("text commit timestamp overflow".into()))?;
        self.doc.doc.commit_with(
            CommitOptions::new()
                .timestamp(timestamp)
                .commit_msg(&message),
        );
        Ok(())
    }
}

/// One artifact commit's message: its stamp and its receipt, by `writer`,
/// the writing actor and its stamp token. The receipt, the caller's or the
/// default one, must name the actor, and is written naming its token (FIX
/// 10930).
pub(super) fn receipted_message(
    doc: &LoroDoc,
    kind: StampKind,
    (actor, stamp): (&WriteActor, ActorStamp),
    source_turn_ref: Option<EntityId>,
    receipt: Option<MadeBy>,
    at: u64,
) -> Result<String> {
    let mut receipt = receipt.unwrap_or_else(|| MadeBy {
        inputs: source_turn_ref
            .into_iter()
            .map(|row| MadeByInput {
                row,
                role: MadeByInputRole::Input,
            })
            .collect(),
        process: MadeByProcess {
            actor: actor.entity_ref(),
            class: if actor.actor_class() == EdgeActorClass::Human {
                MadeByClass::Stated
            } else {
                MadeByClass::Concluded
            },
            identity: actor.entity_ref().to_hex(),
            version: "1".into(),
            params_hash: format!("{:x}", Sha256::digest([])),
        },
        at,
        trigger: None,
    });
    receipt.at = at;
    if receipt.process.actor != actor.entity_ref() || !receipt.process.is_valid() {
        return Err(Error::InvalidConfig("invalid text commit process".into()));
    }
    // The receipt names the token in the actor's place (FIX 10930).
    if receipt.process.identity == actor.entity_ref().to_hex() {
        receipt.process.identity = stamp.token.to_hex();
    }
    receipt.process.actor = stamp.token;
    let encoded = serde_json::to_string(&receipt)
        .map_err(|_| Error::InvariantViolation("text receipt encoding"))?;
    // The prior frontier distinguishes even same-second edits by one actor:
    // Loro must not coalesce two commits with equal commit messages.
    let before = format!("{:x}", Sha256::digest(doc.oplog_frontiers().encode()));
    let message = format!(
        "{} before={before} {RECEIPT_PREFIX}{encoded}",
        super::stamp(kind, stamp)
    );
    Ok(message)
}

/// `process` read back naming `actor`, the actor `stamp`'s token resolved
/// to: its actor, and its identity where it spelled the token (FIX 10930).
fn resolve_process_actor(process: &mut MadeByProcess, stamp: ActorStamp, actor: WriteActor) {
    if process.identity == stamp.token.to_hex() {
        process.identity = actor.entity_ref().to_hex();
    }
    process.actor = actor.entity_ref();
}

/// The process the birth receipt of `doc` names: the receipt on its causally
/// earliest opening commit, kept only when it names that commit's stamp
/// token and is dated at the commit. Its actor is that token, which this
/// reader does not resolve (FIX 10930). `None` for an opening with no such
/// receipt, and for a history with no single earliest opening. It reads the
/// history alone and authenticates no peer stamp.
pub(crate) fn birth_process(doc: &EntityDoc) -> Option<MadeByProcess> {
    let (opening, _) = super::earliest_opening(&doc.doc).ok()?;
    let message = opening.message.as_deref()?;
    let (_, stamp) = parse_stamp(Some(message))?;
    let (_, json) = message.split_once(RECEIPT_PREFIX)?;
    let made_by = serde_json::from_str::<MadeBy>(json).ok()?;
    (made_by.process.actor == stamp.token
        && Some(made_by.at) == u64::try_from(opening.timestamp).ok())
    .then_some(made_by.process)
}

/// A message [`receipted_message`] spells (`<prefix> <open|edit>
/// actor=<id>.<class> before=<hash> |made_by=<json>`), cut around its stamp's
/// actor id: the stamp before the id, the id (any token, so an erased one
/// cuts too), the stamp's rest up to its receipt, and the receipt's JSON as
/// written. `None` for any other message. It reads a spelling only and
/// authenticates nothing (FIX 6479).
pub(crate) fn cut_receipted_message(message: &str) -> Option<(&str, &str, &str, &str)> {
    let (stamped, receipt) = message.split_once(RECEIPT_PREFIX)?;
    let rest = stamped
        .strip_prefix(crate::sync::window::PROPOSAL_TEXT_COMMIT_MSG_PREFIX)?
        .strip_prefix(' ')?;
    let (kind, rest) = rest.split_once(' ')?;
    StampKind::parse(kind)?;
    let id_on = rest.strip_prefix(super::STAMP_ACTOR_PREFIX)?;
    let (id, class_on) = id_on.split_once('.')?;
    let (class, before) = class_on.split_once(' ')?;
    crate::edit_distance::actor_class_from_token(class)?;
    let hash = before.strip_prefix("before=")?.strip_suffix(' ')?;
    if id.is_empty() || hash.is_empty() || hash.contains(' ') {
        return None;
    }
    let head = stamped.get(..stamped.len() - id_on.len())?;
    let tail = id_on.get(id.len()..)?;
    Some((head, id, tail, receipt))
}

fn trigger_is_valid(vault: &crate::Vault, trigger: &MadeByTrigger) -> Result<bool> {
    let (id, expected) = match trigger {
        MadeByTrigger::Task(id) => (id, crate::registry::ENTITY_TYPE_TASK),
        MadeByTrigger::Ask(id) => (id, crate::registry::ENTITY_TYPE_TURN),
        MadeByTrigger::Skill(id) => (id, crate::registry::ENTITY_TYPE_SKILL),
        MadeByTrigger::Run(id) => return crate::provenance::birth::run_exists(vault, id),
    };
    Ok(vault.get_entity_type(id)? == Some(expected))
}
