//! The owner's commitment reminder route on a stopped vault
//! (`oneiron::commitment_wake::CommitmentReminderRoute`); `serve` answers the
//! same at `/v1/owner/commitments/reminder-route`. Get reads the route (`null`
//! when unset), set writes the full route, clear removes it through the same
//! set verb with `null`. Each operation runs its
//! `vault.commitments.reminder_route.*` row's verb hooks once around the native
//! door, as the route does. Setting or clearing approves no reminder and
//! changes none already approved; native validation owns the route's shape.

use super::{emit, hooked_row, local_owner, open_vault, owner_actor, resolve_serve_config};

/// The owner's reminder route on a stopped vault: read it, set the full
/// route, or clear it. Output is the native reply as JSON on stdout.
pub fn reminder_route(command: crate::cli::ReminderRouteCommand) -> anyhow::Result<()> {
    use crate::cli::ReminderRouteCommand;
    use oneiron::commitment_wake::{CommitmentReminderRoute, CommitmentReminderVoice};
    use oneiron::memory::commitment_doors::{
        CommitmentReminderRouteReply, CommitmentReminderRouteSetRequest,
    };
    use oneiron::task_verb::sdk;

    let (serve, route) = match &command {
        ReminderRouteCommand::Get(args) => {
            (&args.serve, "GET /v1/owner/commitments/reminder-route")
        }
        ReminderRouteCommand::Set(args) => (
            &args.serve,
            "PUT /v1/owner/commitments/reminder-route --data -",
        ),
        ReminderRouteCommand::Clear(args) => (
            &args.serve,
            "PUT /v1/owner/commitments/reminder-route --data -",
        ),
    };
    let config = resolve_serve_config(serve)?;
    let vault = open_vault(&config, route)?;
    let owner = local_owner(&vault)?;
    let actor = owner_actor(&vault)?;
    let answer = match command {
        ReminderRouteCommand::Get(_) => hooked_row(
            &vault,
            actor,
            "vault.commitments.reminder_route.get",
            sdk::EmptyRequest {},
            |_: sdk::EmptyRequest| {
                Ok(CommitmentReminderRouteReply {
                    route: vault.commitment_reminder_route()?,
                })
            },
        )?,
        ReminderRouteCommand::Set(args) => {
            // `--persona-ref` implies voice; neither flag means no voice. No
            // new default: native validation owns labels and ranges.
            let voice = if args.voice || args.persona_ref.is_some() {
                Some(CommitmentReminderVoice {
                    persona_ref: args.persona_ref,
                })
            } else {
                None
            };
            let request = CommitmentReminderRouteSetRequest {
                route: Some(CommitmentReminderRoute {
                    channel: args.channel,
                    verb: args.verb,
                    target: args.target,
                    utc_offset_minutes: args.utc_offset_minutes,
                    iana_timezone: args.iana_timezone,
                    voice,
                }),
            };
            hooked_row(
                &vault,
                actor,
                "vault.commitments.reminder_route.set",
                request,
                |request: CommitmentReminderRouteSetRequest| {
                    vault.set_commitment_reminder_route(&owner, request.route.as_ref())?;
                    Ok(CommitmentReminderRouteReply {
                        route: request.route,
                    })
                },
            )?
        }
        ReminderRouteCommand::Clear(_) => hooked_row(
            &vault,
            actor,
            "vault.commitments.reminder_route.set",
            CommitmentReminderRouteSetRequest { route: None },
            |request: CommitmentReminderRouteSetRequest| {
                vault.set_commitment_reminder_route(&owner, request.route.as_ref())?;
                Ok(CommitmentReminderRouteReply {
                    route: request.route,
                })
            },
        )?,
    };
    emit(&answer)
}
