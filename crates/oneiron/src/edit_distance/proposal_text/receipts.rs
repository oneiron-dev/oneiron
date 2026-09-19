//! Commit-envelope writer and read-time provenance fold for authored text.
use super::{ProposalTextArtifact, StampKind, parse_stamp, stamp};
use crate::EntityId;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess, MadeByTrigger,
};
use crate::provenance::text_commit::{RowProvenance, TextCommitReceipt};
use crate::write_envelope::WriteActor;
use loro::{ChangeMeta, CommitOptions};
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
        if process.actor != actor.entity_ref() || process.class != MadeByClass::Concluded {
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
    /// row rather than guessing that unreceipted text was stated by a person.
    pub fn provenance(&self, vault: &crate::Vault) -> Result<Option<RowProvenance>> {
        let mut receipts = Vec::new();
        let mut authority_error = None;
        self.doc
            .travel_change_ancestors(
                &self.doc.oplog_frontiers().to_vec(),
                &mut |meta: ChangeMeta| {
                    let receipt = meta
                        .message
                        .as_deref()
                        .and_then(|message| message.split_once(RECEIPT_PREFIX))
                        .and_then(|(_, json)| serde_json::from_str::<MadeBy>(json).ok())
                        .filter(|made_by| Some(made_by.at) == u64::try_from(meta.timestamp).ok())
                        .filter(|made_by| {
                            let Some((_, actor)) = parse_stamp(meta.message.as_deref()) else {
                                return false;
                            };
                            if actor.entity_ref() != made_by.process.actor
                                || (actor.actor_class() != EdgeActorClass::Human
                                    && made_by.process.class == MadeByClass::Stated)
                            {
                                return false;
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
                                    Ok(false) => return false,
                                    Err(error) => {
                                        authority_error = Some(error);
                                        return false;
                                    }
                                }
                            }
                            for row in required_rows {
                                match vault.get_entity_type(&row) {
                                    Ok(Some(_)) => {}
                                    Ok(None) => return false,
                                    Err(error) => {
                                        authority_error = Some(error);
                                        return false;
                                    }
                                }
                            }
                            match crate::edit_distance::peer_actor_stamp_is_honored(
                                vault,
                                meta.id.peer,
                                made_by.at,
                                &actor,
                            ) {
                                Ok(honored) => honored,
                                Err(error) => {
                                    authority_error = Some(error);
                                    false
                                }
                            }
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
        actor: &WriteActor,
        receipt: Option<MadeBy>,
    ) -> Result<()> {
        let at = crate::unix_seconds_now();
        let mut receipt = receipt.unwrap_or_else(|| MadeBy {
            inputs: self
                .source_turn_ref
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
        if receipt.process.actor != actor.entity_ref()
            || receipt.process.identity.is_empty()
            || receipt.process.version.is_empty()
            || receipt.process.params_hash.is_empty()
        {
            return Err(Error::InvalidConfig("invalid text commit process".into()));
        }
        let encoded = serde_json::to_string(&receipt)
            .map_err(|_| Error::InvariantViolation("text receipt encoding"))?;
        // The prior frontier distinguishes even same-second edits by one actor:
        // Loro must not coalesce two commits with equal commit messages.
        let before = format!("{:x}", Sha256::digest(self.doc.oplog_frontiers().encode()));
        let message = format!(
            "{} before={before} {RECEIPT_PREFIX}{encoded}",
            stamp(kind, actor)
        );
        self.doc.commit_with(
            CommitOptions::new()
                .timestamp(at as i64)
                .commit_msg(&message),
        );
        Ok(())
    }
}

fn trigger_is_valid(vault: &crate::Vault, trigger: &MadeByTrigger) -> Result<bool> {
    let (id, expected) = match trigger {
        MadeByTrigger::Task(id) => (id, crate::registry::ENTITY_TYPE_TASK),
        MadeByTrigger::Ask(id) => (id, crate::registry::ENTITY_TYPE_TURN),
    };
    Ok(vault.get_entity_type(id)? == Some(expected))
}
