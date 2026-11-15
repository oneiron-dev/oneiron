//! The owner's commitment reminder route on a stopped vault: the catalogue key
//! `commitments.reminder_route`, whose value is an optional
//! `oneiron::commitment_wake::CommitmentReminderRoute`; `serve` answers the
//! same through `vault.settings.get` and `vault.settings.set`. Get reads the
//! value in force (`null` when unset), set writes the full route, clear
//! removes the row. Each operation runs its `vault.settings.*` row's verb
//! hooks once around the native door, as the verbs do, and prints the verb's
//! reply. Setting or clearing approves no reminder and changes none already
//! approved; the key's check owns the route's shape.

use super::{
    emit, hooked_row, memory_refusal, open_stopped_vault, owner_actor, resolve_serve_config,
};

/// The catalogue key the reminder route is.
const REMINDER_ROUTE_KEY: &str = "commitments.reminder_route";

/// The owner's reminder route on a stopped vault: read it, set the full
/// route, or clear it. Output is the setting verb's reply as JSON on stdout.
pub fn reminder_route(command: crate::cli::ReminderRouteCommand) -> anyhow::Result<()> {
    use crate::cli::ReminderRouteCommand;
    use oneiron::commitment_wake::{CommitmentReminderRoute, CommitmentReminderVoice};
    use oneiron::edge::EdgeActorClass;
    use oneiron::setting::SettingScope;
    use oneiron::task_verb::sdk::{self, SettingGetRequest, SettingSetRequest};

    let serve = match &command {
        ReminderRouteCommand::Get(args) => &args.serve,
        ReminderRouteCommand::Set(args) => &args.serve,
        ReminderRouteCommand::Clear(args) => &args.serve,
    };
    let config = resolve_serve_config(serve)?;
    let vault = open_stopped_vault(
        &config,
        &format!(
            "or ask it: `oneiron api call vault.settings.get --data '{{\"key\":\"{REMINDER_ROUTE_KEY}\"}}'`"
        ),
    )?;
    let actor = owner_actor(&vault)?;
    let memory = vault.memory(actor, EdgeActorClass::Human);
    let set = |value: Option<serde_json::Value>| {
        hooked_row(
            &vault,
            actor,
            "vault.settings.set",
            SettingSetRequest {
                key: REMINDER_ROUTE_KEY.to_owned(),
                item: None,
                scope: SettingScope::Vault,
                pin: false,
                value,
                expected_revision: None,
                why: None,
                check_in_ref: None,
            },
            |request: SettingSetRequest| {
                sdk::setting_set_embedded(&memory, request).map_err(memory_refusal)
            },
        )
    };
    let answer = match command {
        ReminderRouteCommand::Get(_) => hooked_row(
            &vault,
            actor,
            "vault.settings.get",
            SettingGetRequest {
                key: REMINDER_ROUTE_KEY.to_owned(),
                item: None,
                at: Vec::new(),
            },
            |request: SettingGetRequest| {
                sdk::setting_get_embedded(&memory, request).map_err(memory_refusal)
            },
        )?,
        ReminderRouteCommand::Set(args) => {
            // `--persona-ref` implies voice; neither flag means no voice. No
            // new default: the key's check owns labels and ranges.
            let voice = if args.voice || args.persona_ref.is_some() {
                Some(CommitmentReminderVoice {
                    persona_ref: args.persona_ref,
                })
            } else {
                None
            };
            let route = CommitmentReminderRoute {
                channel: args.channel,
                verb: args.verb,
                target: args.target,
                utc_offset_minutes: args.utc_offset_minutes,
                iana_timezone: args.iana_timezone,
                voice,
            };
            set(Some(serde_json::to_value(route)?))?
        }
        ReminderRouteCommand::Clear(_) => set(None)?,
    };
    emit(&answer)
}
