//! `vault.outbox.diverged.list` and `vault.outbox.diverged.answer` (FIX
//! 11739): a vault VM's outbox carrier members and the owner's answer to a
//! diverged copy, as `GET` and `POST /v1/owner/outbox/diverged` answer them
//! (FIX 11074, FIX 11242), for any live vault Owner. The page and the
//! answer are built here once, for the facade and the owner route alike.
//! Off Linux, where no vault VM runs, the page lists no carrier and an
//! answer is refused. Both read no row, so they list none.

use std::sync::Arc;

use oneiron::memory::{MEMORY_CODE_INVALID_STATE, MemoryError};
use oneiron::task_verb::sdk::{
    EmptyRequest, OutboxDivergedAnswerReceipt, OutboxDivergedAnswerRequest, OutboxDivergedPage,
};

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.outbox.diverged.list`: every member the carrier keeps typed, each
/// with its card.
pub(crate) async fn vault_outbox_diverged_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<OutboxDivergedPage> {
    as_owner_naming(
        server,
        auth,
        "vault.outbox.diverged.list",
        |_, _| Ok(diverged_page()),
        |_| Vec::new(),
    )
    .await
}

/// `vault.outbox.diverged.answer`: passes the owner's answer to the copy the
/// page lists with that digest to the companion.
pub(crate) async fn vault_outbox_diverged_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OutboxDivergedAnswerRequest,
) -> Listed<OutboxDivergedAnswerReceipt> {
    as_owner_naming(
        server,
        auth,
        "vault.outbox.diverged.answer",
        move |_, _| {
            answer_diverged_copy(input).map_err(|error| {
                MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    format!("{error:#}"),
                    &["Read the page again, then answer the copy it lists."],
                )
            })
        },
        |_| Vec::new(),
    )
    .await
}

/// The carrier's members as the owner sees them, each with its card; no
/// carrier when the companion does not answer.
pub(crate) fn diverged_page() -> OutboxDivergedPage {
    match carrier::members() {
        Some(members) => OutboxDivergedPage {
            carrier: true,
            members,
        },
        None => OutboxDivergedPage {
            carrier: false,
            members: Vec::new(),
        },
    }
}

/// Passes `request`, the owner's answer, to the companion for its carrier's
/// next turn.
pub(crate) fn answer_diverged_copy(
    request: OutboxDivergedAnswerRequest,
) -> anyhow::Result<OutboxDivergedAnswerReceipt> {
    carrier::pass_answer(&request)?;
    Ok(OutboxDivergedAnswerReceipt {
        kind: request.kind,
        member: request.member,
        held: request.held,
        answer: request.answer,
        queued: true,
    })
}

#[cfg(target_os = "linux")]
mod carrier {
    use oneiron::task_verb::sdk::{
        OutboxCardAction, OutboxCardKind, OutboxDivergedAnswer, OutboxDivergedAnswerRequest,
        OutboxDivergedMember, OutboxMemberStatus, OutboxOwnerCard,
    };
    use oneiron_vault_contract::vm_outbox::VmOutboxSide;

    use crate::managed::{
        DIVERGED_ANSWER_ROUTE, DivergedAnswer, DivergedOwnerAnswer, VmOutboxMemberStatus,
        answer_diverged, companion_member_statuses,
    };

    /// Each member the companion reports, with its card; `None` when it
    /// does not answer.
    pub(super) fn members() -> Option<Vec<OutboxDivergedMember>> {
        let statuses = companion_member_statuses()?;
        Some(
            statuses
                .into_iter()
                .map(|status| {
                    let status = status_view(status);
                    OutboxDivergedMember {
                        card: owner_card(&status),
                        status,
                    }
                })
                .collect(),
        )
    }

    /// Passes `request` to the companion.
    pub(super) fn pass_answer(request: &OutboxDivergedAnswerRequest) -> anyhow::Result<()> {
        answer_diverged(DivergedOwnerAnswer {
            kind: request.kind,
            member: request.member.clone(),
            held: request.held.clone(),
            answer: match request.answer {
                OutboxDivergedAnswer::Keep => DivergedAnswer::Keep,
                OutboxDivergedAnswer::Remove => DivergedAnswer::Remove,
            },
        })
    }

    fn status_view(status: VmOutboxMemberStatus) -> OutboxMemberStatus {
        match status {
            VmOutboxMemberStatus::DivergedUnagreed {
                kind,
                member,
                held_by,
                held,
                length,
                retired,
                answer,
            } => OutboxMemberStatus::DivergedUnagreed {
                kind,
                member,
                held_by,
                held,
                length,
                retired,
                answer: answer.map(|answer| match answer {
                    DivergedAnswer::Keep => OutboxDivergedAnswer::Keep,
                    DivergedAnswer::Remove => OutboxDivergedAnswer::Remove,
                }),
            },
            VmOutboxMemberStatus::SourceDigestMismatch {
                kind,
                member,
                recorded,
                read,
            } => OutboxMemberStatus::SourceDigestMismatch {
                kind,
                member,
                recorded,
                read,
            },
        }
    }

    /// One answer a card offers, by the owner route that takes it.
    fn action(label: &str, answer: OutboxDivergedAnswer) -> OutboxCardAction {
        OutboxCardAction {
            label: label.to_owned(),
            answer,
            route: DIVERGED_ANSWER_ROUTE.to_owned(),
        }
    }

    fn owner_card(status: &OutboxMemberStatus) -> OutboxOwnerCard {
        match status {
            OutboxMemberStatus::DivergedUnagreed {
                kind,
                member,
                held_by,
                answer,
                ..
            } => {
                let end = match held_by {
                    VmOutboxSide::Guest => "The vault VM",
                    VmOutboxSide::Host => "The vault's host",
                };
                let (headline, body, actions) = match answer {
                    None => (
                        format!("A {kind} outbox copy waits for your answer"),
                        format!(
                            "{end} keeps a copy of {member} that the carrier never agreed on, \
                             after the agreed version was retired. Nothing removes it without your \
                             answer: remove it, or keep it."
                        ),
                        vec![
                            action("Remove this copy", OutboxDivergedAnswer::Remove),
                            action("Keep it", OutboxDivergedAnswer::Keep),
                        ],
                    ),
                    Some(OutboxDivergedAnswer::Keep) => (
                        format!("A {kind} outbox copy kept"),
                        format!(
                            "You kept {end}'s copy of {member}, one the carrier never agreed on."
                        ),
                        vec![action("Remove this copy", OutboxDivergedAnswer::Remove)],
                    ),
                    Some(OutboxDivergedAnswer::Remove) => (
                        format!("A {kind} outbox copy is being removed"),
                        format!(
                            "You had {end}'s copy of {member} removed; the carrier carries it out \
                             at its next session."
                        ),
                        Vec::new(),
                    ),
                };
                OutboxOwnerCard {
                    kind: OutboxCardKind::OutboxDiverged,
                    headline,
                    body,
                    actions,
                }
            }
            OutboxMemberStatus::SourceDigestMismatch { kind, member, .. } => OutboxOwnerCard {
                kind: OutboxCardKind::OutboxSourceDamaged,
                headline: format!("A {kind} outbox file is held back"),
                body: format!(
                    "The vault VM's file {member} no longer matches its own recorded digest, so \
                     none of it is sent until it changes."
                ),
                actions: Vec::new(),
            },
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod carrier {
    use oneiron::task_verb::sdk::{OutboxDivergedAnswerRequest, OutboxDivergedMember};

    /// No vault VM runs off Linux: no carrier answers.
    pub(super) const fn members() -> Option<Vec<OutboxDivergedMember>> {
        None
    }

    /// No carrier takes an answer off Linux.
    pub(super) fn pass_answer(_: &OutboxDivergedAnswerRequest) -> anyhow::Result<()> {
        anyhow::bail!("no vault VM outbox carrier runs on this host")
    }
}
