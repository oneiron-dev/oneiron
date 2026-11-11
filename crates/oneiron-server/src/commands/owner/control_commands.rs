//! Owner control and consent commands for a stopped vault.
//! Runs the same typed engine doors and verb hooks as the current CLI.
//! Shared owner, actor, argument, and row helpers stay in the parent.

use std::collections::BTreeMap;

use super::{
    CallerLocality, GateConsentBundleAction, HandoffAlarmsCommand, RunsCommand, SpaceRow,
    declared_space, emit, hold_host_root, hold_id_arg, hold_targets, hooked_row, input_kind,
    local_host_actor, local_owner, memory_refusal, open_vault, owner_actor, resolve_serve_config,
};
use crate::owner::runs;

/// The saved fork alarms a held root handoff left, and the owner's
/// acknowledgement of one; `serve` answers the same at
/// `/v1/owner/authority/handoff-alarms`. Each operation runs its
/// `vault.authority.handoff_alarms` row's verb hooks once around the engine
/// door, as the route does (OF-580). The list still takes no owner proof
/// (Engine 10-18): its hooks run as the local host actor where this vault
/// holds one, and without one the read runs unhooked and logs a warning.
pub fn handoff_alarms(command: HandoffAlarmsCommand) -> anyhow::Result<()> {
    use oneiron::task_verb::sdk;

    let (serve, route) = match &command {
        HandoffAlarmsCommand::List(args) => (&args.serve, "GET /v1/owner/authority/handoff-alarms"),
        HandoffAlarmsCommand::Acknowledge(args) => (
            &args.serve,
            "POST /v1/owner/authority/handoff-alarms/acknowledge --data -",
        ),
    };
    let config = resolve_serve_config(serve)?;
    let vault = open_vault(&config, route)?;
    let answer = match command {
        HandoffAlarmsCommand::List(_) => match local_host_actor(&vault)? {
            Some(actor) => hooked_row(
                &vault,
                actor,
                "vault.authority.handoff_alarms",
                sdk::EmptyRequest {},
                |_| Ok(vault.authority_handoff_alarms()?),
            )?,
            None => {
                tracing::warn!(
                    verb = "vault.authority.handoff_alarms",
                    "this vault holds no local host actor, so the row's verb hooks did not run for this read"
                );
                serde_json::to_value(vault.authority_handoff_alarms()?)?
            }
        },
        HandoffAlarmsCommand::Acknowledge(args) => {
            let owner = local_owner(&vault)?;
            hooked_row(
                &vault,
                owner_actor(&vault)?,
                "vault.authority.handoff_alarms.acknowledge",
                sdk::HandoffAlarmRequest {
                    signer: args.signer,
                },
                |request: sdk::HandoffAlarmRequest| {
                    Ok(vault.acknowledge_authority_handoff_alarm(&owner, &request.signer)?)
                },
            )?
        }
    };
    emit(&answer)
}

/// The owner's learned-setting rows on a stopped vault; `serve` answers the
/// same at `/v1/owner/settings/learning`. Each operation runs its
/// `vault.settings.learning*` row's verb hooks once around the engine door,
/// as the route does (FIX 9479).
pub fn learning_settings(command: crate::cli::LearningSettingsCommand) -> anyhow::Result<()> {
    use crate::cli::{LearningSettingModeArg, LearningSettingsCommand};
    use oneiron::learning_setting_choice::SpawnChoice;
    use oneiron::learning_setting_doors::{
        self as doors, LearningChoiceValue, LearningSettingClear, LearningSettingMode,
        LearningSettingPut, LearningSettingsRequest,
    };
    let mode = |mode: LearningSettingModeArg| match mode {
        LearningSettingModeArg::Seed => LearningSettingMode::Seed,
        LearningSettingModeArg::Pin => LearningSettingMode::Pin,
    };
    let serve = match &command {
        LearningSettingsCommand::List(args) => &args.serve,
        LearningSettingsCommand::Put(args) => &args.serve,
        LearningSettingsCommand::Clear(args) => &args.serve,
    };
    let config = resolve_serve_config(serve)?;
    let vault = open_vault(&config, "GET /v1/owner/settings/learning")?;
    let owner = local_owner(&vault)?;
    let actor = owner_actor(&vault)?;
    let view = match command {
        LearningSettingsCommand::List(args) => hooked_row(
            &vault,
            actor,
            "vault.settings.learning",
            LearningSettingsRequest { key: args.key },
            |request: LearningSettingsRequest| {
                Ok(doors::learning_settings_as_owner(&vault, &owner, &request)?)
            },
        )?,
        LearningSettingsCommand::Put(args) => {
            let raw = args.value.trim();
            let (value, choice) = match SpawnChoice::from_key(&args.key) {
                Some(SpawnChoice::Model) => {
                    (None, Some(LearningChoiceValue::Model(raw.to_owned())))
                }
                Some(SpawnChoice::Pattern) => {
                    (None, Some(LearningChoiceValue::Pattern(raw.to_owned())))
                }
                Some(SpawnChoice::Width) => (
                    None,
                    Some(LearningChoiceValue::Width(raw.parse().map_err(|_| {
                        anyhow::anyhow!("a width is a whole count of agents")
                    })?)),
                ),
                Some(SpawnChoice::Budget) => (
                    None,
                    Some(LearningChoiceValue::Budget(raw.parse().map_err(|_| {
                        anyhow::anyhow!("a budget is a whole count of lease units")
                    })?)),
                ),
                None => (
                    Some(
                        raw.parse::<f64>()
                            .map_err(|_| anyhow::anyhow!("a catalog knob's value is a number"))?,
                    ),
                    None,
                ),
            };
            hooked_row(
                &vault,
                actor,
                "vault.settings.learning.put",
                LearningSettingPut {
                    key: args.key,
                    mode: mode(args.mode),
                    value,
                    choice,
                    weight_runs: args.weight_runs,
                    why: args.why,
                    goal: args.goal,
                    project: args.project,
                    task_type: args.task_type,
                },
                |request: LearningSettingPut| {
                    Ok(doors::put_learning_setting_as_owner(
                        &vault, &owner, request,
                    )?)
                },
            )?
        }
        LearningSettingsCommand::Clear(args) => hooked_row(
            &vault,
            actor,
            "vault.settings.learning.clear",
            LearningSettingClear {
                key: args.key,
                mode: mode(args.mode),
                goal: args.goal,
                project: args.project,
                task_type: args.task_type,
            },
            |request: LearningSettingClear| {
                Ok(doors::clear_learning_setting_as_owner(
                    &vault, &owner, request,
                )?)
            },
        )?,
    };
    emit(&view)
}

/// The context-widen proposals agents raised (OF-568), on a stopped vault;
/// `serve` answers the same at `/v1/owner/widen-proposals`. Approve and
/// decline act as the board above, so the local owner must own the board's
/// TASK. Each operation runs its `vault.widen_proposals*` row's verb hooks
/// once around the engine door, as the route does (FIX 9479).
pub fn widen_proposals(command: crate::cli::WidenProposalsCommand) -> anyhow::Result<()> {
    use crate::cli::{WidenProposalStateArg, WidenProposalsCommand};
    use oneiron::agent_dispatch::widen_doors::{
        self as doors, WidenProposalAnswer, WidenProposalState, WidenProposalsRequest,
    };
    let serve = match &command {
        WidenProposalsCommand::List(args) => &args.serve,
        WidenProposalsCommand::Approve(args) | WidenProposalsCommand::Decline(args) => &args.serve,
    };
    let config = resolve_serve_config(serve)?;
    let vault = open_vault(&config, "GET /v1/owner/widen-proposals")?;
    let owner = local_owner(&vault)?;
    let actor = owner_actor(&vault)?;
    let answer = match command {
        WidenProposalsCommand::List(args) => {
            let state = args.state.map(|state| match state {
                WidenProposalStateArg::Pending => WidenProposalState::Pending,
                WidenProposalStateArg::Approved => WidenProposalState::Approved,
                WidenProposalStateArg::Declined => WidenProposalState::Declined,
            });
            hooked_row(
                &vault,
                actor,
                "vault.widen_proposals",
                WidenProposalsRequest { state },
                |request: WidenProposalsRequest| {
                    Ok(doors::widen_proposals_as_owner(&vault, &owner, &request)?)
                },
            )?
        }
        WidenProposalsCommand::Approve(args) => hooked_row(
            &vault,
            actor,
            "vault.widen_proposals.approve",
            WidenProposalAnswer {
                proposal_id: args.proposal_id,
            },
            |answer: WidenProposalAnswer| {
                Ok(doors::approve_widen_proposal_as_owner(
                    &vault, &owner, &answer,
                )?)
            },
        )?,
        WidenProposalsCommand::Decline(args) => hooked_row(
            &vault,
            actor,
            "vault.widen_proposals.decline",
            WidenProposalAnswer {
                proposal_id: args.proposal_id,
            },
            |answer: WidenProposalAnswer| {
                Ok(doors::decline_widen_proposal_as_owner(
                    &vault, &owner, &answer,
                )?)
            },
        )?,
    };
    emit(&answer)
}

/// The owner's legal holds (OF-470) on a stopped vault; `serve` answers the
/// same at `/v1/owner/legal-holds`. Lifting a hold is only the one "Lift the
/// hold and erase?" confirm: its title and prompt are printed first, and it
/// acts only with `--yes`.
pub fn legal_holds(command: crate::cli::LegalHoldsCommand) -> anyhow::Result<()> {
    use crate::cli::{LegalHoldPlaceArgs, LegalHoldWidenArgs, LegalHoldsCommand};
    use oneiron::deletion::{LIFT_AND_ERASE_PROMPT, LIFT_AND_ERASE_TITLE};
    use oneiron::task_verb::sdk;

    let (serve, route) = match &command {
        LegalHoldsCommand::List(args) => (&args.serve, "GET /v1/owner/legal-holds"),
        LegalHoldsCommand::Log(args) => (&args.serve, "GET /v1/owner/legal-holds/log"),
        LegalHoldsCommand::Place(args) => (&args.serve, "POST /v1/owner/legal-holds --data -"),
        LegalHoldsCommand::Widen(args) => {
            (&args.serve, "POST /v1/owner/legal-holds/widen --data -")
        }
        LegalHoldsCommand::LiftAndErase(args) => {
            eprintln!("{LIFT_AND_ERASE_TITLE}\n{LIFT_AND_ERASE_PROMPT}");
            anyhow::ensure!(
                args.yes,
                "nothing was lifted or erased; run it again with --yes to confirm"
            );
            (
                &args.serve,
                "POST /v1/owner/legal-holds/lift-and-erase --data -",
            )
        }
    };
    let config = resolve_serve_config(serve)?;
    let vault = open_vault(&config, route)?;
    let owner = local_owner(&vault)?;
    let actor = owner_actor(&vault)?;
    // Each operation runs its `vault.legal_holds.*` row's verb hooks once
    // around the engine door, as the route does (FIX 1466).
    let answer = match command {
        LegalHoldsCommand::List(_) => hooked_row(
            &vault,
            actor,
            "vault.legal_holds.list",
            sdk::EmptyRequest {},
            |_| Ok(vault.legal_holds(&owner)?),
        )?,
        LegalHoldsCommand::Log(_) => hooked_row(
            &vault,
            actor,
            "vault.legal_holds.log",
            sdk::EmptyRequest {},
            |_| Ok(vault.legal_hold_log(&owner)?),
        )?,
        LegalHoldsCommand::Place(args) => {
            let LegalHoldPlaceArgs {
                targets,
                matter_ref,
                ..
            } = *args;
            let request = sdk::LegalHoldPlaceRequest {
                targets: hold_targets(&targets)?,
                matter_ref,
            };
            hooked_row(
                &vault,
                actor,
                "vault.legal_holds.place",
                request,
                |request: sdk::LegalHoldPlaceRequest| {
                    Ok(vault.place_legal_hold(&owner, request.targets, request.matter_ref)?)
                },
            )?
        }
        LegalHoldsCommand::Widen(args) => {
            let LegalHoldWidenArgs {
                hold_id, targets, ..
            } = *args;
            let request = sdk::LegalHoldWidenRequest {
                hold_id: hold_id_arg(&hold_id)?,
                targets: hold_targets(&targets)?,
            };
            hooked_row(
                &vault,
                actor,
                "vault.legal_holds.widen",
                request,
                |request: sdk::LegalHoldWidenRequest| {
                    Ok(vault.widen_legal_hold(&owner, request.hold_id, request.targets)?)
                },
            )?
        }
        LegalHoldsCommand::LiftAndErase(args) => {
            let records = args
                .records
                .iter()
                .map(|record| hold_id_arg(record))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let claim_free_partition = args.claim_free_partition;
            // The one confirm shows the holds it lifts, read once from this
            // vault, and acts only on what it showed (FIX 1462).
            let shown_state =
                vault.lift_and_erase_shown_state(&owner, &records, claim_free_partition)?;
            eprintln!("{}", serde_json::to_string_pretty(&shown_state.holds)?);
            let request = sdk::LegalHoldLiftAndEraseRequest {
                records,
                claim_free_partition,
                shown_state,
            };
            hooked_row(
                &vault,
                actor,
                "vault.legal_holds.lift_and_erase",
                request,
                |request: sdk::LegalHoldLiftAndEraseRequest| {
                    Ok(sdk::LegalHoldLiftAndErased::from(
                        vault.confirm_lift_legal_hold_and_erase(
                            &owner,
                            &request.records,
                            request.claim_free_partition,
                            &request.shown_state,
                        )?,
                    ))
                },
            )?
        }
    };
    emit(&answer)
}

/// The owner's embedding spaces (OF-370) on a stopped vault, through the SDK
/// fns the `vault.embedding_spaces.*` rows run, so each answers what the row
/// and `/v1/owner/embedding-spaces` answer. A move's check runs a server's
/// own probe towers, so only a running server checks one (`oneiron api raw
/// POST /v1/owner/embedding-spaces/move/check`).
pub fn embedding_spaces(command: crate::cli::EmbeddingSpacesCommand) -> anyhow::Result<()> {
    use crate::cli::{EmbeddingSpaceProbesCommand as Probes, EmbeddingSpacesCommand as Spaces};
    use oneiron::task_verb::sdk;

    let (serve, route) = match &command {
        Spaces::List(args) => (&args.serve, "GET /v1/owner/embedding-spaces"),
        Spaces::Declare(args) => (&args.serve, "PUT /v1/owner/embedding-spaces --data -"),
        Spaces::Bind(args) => (&args.serve, "POST /v1/owner/embedding-spaces/bind --data -"),
        Spaces::OneSpace(args) => (
            &args.serve,
            "POST /v1/owner/embedding-spaces/one-space --data -",
        ),
        Spaces::Retire(args) => (
            &args.serve,
            "POST /v1/owner/embedding-spaces/retire --data -",
        ),
        Spaces::Move(args) => (&args.serve, "POST /v1/owner/embedding-spaces/move --data -"),
        Spaces::MoveApprove(args) => (
            &args.serve,
            "POST /v1/owner/embedding-spaces/move/approve --data -",
        ),
        Spaces::MoveUndo(args) => (
            &args.serve,
            "POST /v1/owner/embedding-spaces/move/undo --data -",
        ),
        Spaces::MoveAbandon(args) => (
            &args.serve,
            "POST /v1/owner/embedding-spaces/move/abandon --data -",
        ),
        Spaces::Probes(Probes::List(args)) => {
            (&args.serve, "GET /v1/owner/embedding-spaces/probes")
        }
        Spaces::Probes(Probes::Put(args)) => (
            &args.serve,
            "POST /v1/owner/embedding-spaces/probes --data -",
        ),
        Spaces::Probes(Probes::Delete(args)) => (
            &args.serve,
            "POST /v1/owner/embedding-spaces/probes/delete --data -",
        ),
    };
    let config = resolve_serve_config(serve)?;
    let vault = open_vault(&config, route)?;
    let owner = local_owner(&vault)?;
    let actor = owner_actor(&vault)?;
    let candidate = |candidate: String| sdk::EmbeddingSpaceCandidateRequest { candidate };
    // Each operation runs its row's verb hooks once around the SDK fn the row
    // runs, as the route does (FIX 1953).
    let row = |verb: &'static str| SpaceRow {
        vault: &vault,
        owner: &owner,
        actor,
        verb,
    };
    let answer = match command {
        Spaces::List(_) => hooked_row(
            &vault,
            actor,
            "vault.embedding_spaces.list",
            sdk::EmptyRequest {},
            |_| sdk::read_embedding_spaces(&vault, &owner).map_err(memory_refusal),
        )?,
        Spaces::Declare(args) => row("vault.embedding_spaces.declare")
            .run(declared_space(*args), sdk::declare_embedding_space_as)?,
        Spaces::Bind(args) => row("vault.embedding_spaces.bind").run(
            sdk::EmbeddingSpaceBindRequest {
                kind: input_kind(args.kind),
                space: args.space,
            },
            sdk::bind_embedding_slot_as,
        )?,
        Spaces::OneSpace(args) => row("vault.embedding_spaces.one_space").run(
            sdk::EmbeddingSpaceRequest { space: args.space },
            sdk::bind_one_embedding_space_as,
        )?,
        Spaces::Retire(args) => row("vault.embedding_spaces.retire").run(
            sdk::EmbeddingSpaceRequest { space: args.space },
            sdk::retire_embedding_space_as,
        )?,
        Spaces::Move(args) => row("vault.embedding_spaces.move").run(
            sdk::EmbeddingSpaceMoveRequest {
                candidate: args.candidate,
                incumbent: args.incumbent,
                margin: args.margin,
            },
            sdk::begin_embedding_space_move_as,
        )?,
        Spaces::MoveApprove(args) => row("vault.embedding_spaces.move_approve").run(
            candidate(args.candidate),
            sdk::approve_embedding_space_move_as,
        )?,
        Spaces::MoveUndo(args) => row("vault.embedding_spaces.move_undo")
            .run(candidate(args.candidate), sdk::undo_embedding_space_move_as)?,
        Spaces::MoveAbandon(args) => row("vault.embedding_spaces.move_abandon").run(
            candidate(args.candidate),
            sdk::abandon_embedding_space_move_as,
        )?,
        Spaces::Probes(Probes::List(_)) => hooked_row(
            &vault,
            actor,
            "vault.embedding_spaces.probes.list",
            sdk::EmptyRequest {},
            |_| sdk::read_embedding_space_probes(&vault, &owner).map_err(memory_refusal),
        )?,
        Spaces::Probes(Probes::Put(args)) => {
            let args = *args;
            let family = hold_id_arg(&args.family)?;
            let targets = args
                .targets
                .iter()
                .map(|target| hold_id_arg(target))
                .collect::<anyhow::Result<Vec<_>>>()?;
            row("vault.embedding_spaces.probes.put").run(
                sdk::EmbeddingSpaceProbePutRequest {
                    kind: input_kind(args.kind),
                    query: args.query,
                    query_media: None,
                    family,
                    targets,
                    source_refs: Vec::new(),
                    author: args.author,
                },
                sdk::put_embedding_space_probe_as,
            )?
        }
        Spaces::Probes(Probes::Delete(args)) => row("vault.embedding_spaces.probes.delete").run(
            sdk::EmbeddingSpaceProbeDeleteRequest { id: args.id },
            sdk::delete_embedding_space_probe_as,
        )?,
    };
    emit(&answer)
}

/// The owner's ask guests (OF-232) on a stopped vault; `serve` answers the
/// same at `/v1/owner/guests/revoke`. A revoke signs each pact disconnect
/// with the host's own key, the config's auth secret `serve` signs with; a
/// config without one has no host key, and the revoke refuses. With
/// `--peer`, or a `peer` a verb hook put in its input, the committed revoke
/// queues the route's courtesy-delete asks with the same key (FIX 4185); an
/// ask that does not queue never undoes the revoke.
pub fn guests(command: crate::cli::GuestsCommand) -> anyhow::Result<()> {
    use crate::cli::GuestsCommand;
    use crate::owner::courtesy_delete::CourtesySender;
    use crate::owner::guest_revoke;
    match command {
        GuestsCommand::Revoke(args) => {
            let grant = hold_id_arg(&args.grant_ref)?;
            // A peer the owner typed that the ask would refuse is refused
            // before anything runs, as on the route (FIX 4186).
            guest_revoke::check_peer(args.peer.as_deref())?;
            let config = resolve_serve_config(&args.serve)?;
            let vault = open_vault(&config, "POST /v1/owner/guests/revoke --data -")?;
            let owner = local_owner(&vault)?;
            config
                .sync_server_config()
                .auth_secret
                .filter(|secret| !secret.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "the config names no auth secret, so this host has no key to sign the guest's pact disconnects"
                    )
                })?;
            // This install's own issuer seed signs them (FIX-LIST 3018).
            let issuer = super::host_issuer(&config, &vault, false)?;
            // The row's verb hooks run once around the engine door, as the
            // route's do (FIX 1752).
            let answer = hooked_row(
                &vault,
                owner_actor(&vault)?,
                "vault.guests.revoke",
                oneiron::task_verb::sdk::GuestRevokeRequest {
                    grant_ref: grant,
                    peer: args.peer,
                },
                |request: oneiron::task_verb::sdk::GuestRevokeRequest| {
                    let outcome = vault.revoke_guest_access(&owner, &issuer, request.grant_ref)?;
                    let mut revoked = oneiron::receipt::project_guest_revoke(outcome);
                    // The hook's final input names the peer, as the route
                    // reads it.
                    let sender = CourtesySender {
                        vault: &vault,
                        issuer: Some(&issuer),
                    };
                    guest_revoke::queue_courtesy_deletes_with(
                        &sender,
                        &owner,
                        request.peer.as_deref(),
                        &mut revoked,
                    );
                    Ok(revoked)
                },
            )?;
            emit(&answer)
        }
    }
}

pub fn runs(command: RunsCommand) -> anyhow::Result<()> {
    let serve = match &command {
        RunsCommand::Pending(args) => &args.serve,
        RunsCommand::Show(args) => &args.serve,
        RunsCommand::Approve(args) | RunsCommand::Decline(args) => &args.serve,
    };
    let config = resolve_serve_config(serve)?;
    let vault = open_vault(&config, "GET /v1/owner/runs")?;
    if matches!(command, RunsCommand::Approve(_) | RunsCommand::Decline(_)) {
        hold_host_root(&config, &vault)?;
    }
    match command {
        // The CLI runs on this device.
        RunsCommand::Pending(_) => emit(&runs::pending(&vault, CallerLocality::OnDevice)?),
        RunsCommand::Show(args) => {
            let run = runs::RunName::from_fields(args.run_id.as_deref(), args.run_ref.as_deref())?;
            emit(&runs::review(
                &vault,
                &local_owner(&vault)?,
                run,
                CallerLocality::OnDevice,
            )?)
        }
        RunsCommand::Approve(args) => {
            let run = runs::RunName::from_fields(args.run_id.as_deref(), args.run_ref.as_deref())?;
            let wordings = reminder_wordings(&args.wording)?;
            emit(&runs::resolve_with_wordings(
                &vault,
                &local_owner(&vault)?,
                run,
                &args.bundle,
                GateConsentBundleAction::Approve,
                CallerLocality::OnDevice,
                &wordings,
            )?)
        }
        RunsCommand::Decline(args) => {
            let run = runs::RunName::from_fields(args.run_id.as_deref(), args.run_ref.as_deref())?;
            emit(&runs::resolve(
                &vault,
                &local_owner(&vault)?,
                run,
                &args.bundle,
                GateConsentBundleAction::Decline,
                CallerLocality::OnDevice,
            )?)
        }
    }
}

/// Parses `--wording` repeats, each `CLAIM_ID=HASH`, into the
/// `reminder_wordings` map `runs::resolve_with_wordings` takes. A repeated
/// claim keeps its last entry.
fn reminder_wordings(entries: &[String]) -> anyhow::Result<BTreeMap<String, String>> {
    let mut wordings = BTreeMap::new();
    for entry in entries {
        let (claim, hash) = entry.split_once('=').unwrap_or(("", ""));
        if claim.is_empty() || hash.is_empty() {
            return Err(anyhow::anyhow!("--wording {entry:?} is not CLAIM_ID=HASH"));
        }
        wordings.insert(claim.to_owned(), hash.to_owned());
    }
    Ok(wordings)
}
