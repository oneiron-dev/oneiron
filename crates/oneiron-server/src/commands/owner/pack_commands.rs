//! Pack removal and channel subscription commands for a stopped vault.
//! Each runs the engine door its route uses, as the local owner.
//! Shared vault access and the id parser stay in the parent.

use serde::Serialize;

use super::{
    PackRemoveArgs, PacksCommand, SubscriptionListArgs, SubscriptionPutArgs,
    SubscriptionRevokeArgs, SubscriptionsCommand, emit, hold_id_arg, local_owner, open_vault,
    resolve_serve_config,
};

pub fn packs(command: PacksCommand) -> anyhow::Result<()> {
    match command {
        PacksCommand::Remove(args) => remove_pack(*args),
    }
}

/// Removes an installed pack through the engine door `POST
/// /v1/owner/packs/remove` uses, as the local owner (OF-519). It reads
/// nothing from stdin.
fn remove_pack(args: PackRemoveArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_vault(&config, "POST /v1/owner/packs/remove --data -")?;
    let owner = local_owner(&vault)?;
    emit(&vault.remove_pack(&owner, &args.pack)?)
}

pub fn subscriptions(command: SubscriptionsCommand) -> anyhow::Result<()> {
    match command {
        SubscriptionsCommand::Put(args) => emit(&subscribe(*args)?),
        SubscriptionsCommand::List(args) => list(*args),
        SubscriptionsCommand::Revoke(args) => revoke(*args),
    }
}

/// Subscribes the agent to the channel's messages through the engine door
/// `POST /v1/owner/connectors/subscriptions` uses, as the local owner
/// (OF-519). It reads nothing from stdin.
fn subscribe(
    args: SubscriptionPutArgs,
) -> anyhow::Result<oneiron::connector_key::ChannelMessageSubscription> {
    let agent = hold_id_arg(&args.agent)?;
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_vault(&config, "POST /v1/owner/connectors/subscriptions --data -")?;
    let owner = local_owner(&vault)?;
    Ok(vault.subscribe_agent_to_channel_messages(&owner, agent, &args.channel)?)
}

/// One row of `subscriptions list`, as `GET
/// /v1/owner/connectors/subscriptions` shows it.
#[derive(Serialize)]
struct SubscriptionRow {
    subscription: String,
    connector_key: String,
    connector: String,
    event_kind: Option<String>,
    predicate: Option<String>,
    active: bool,
}

/// An agent's subscriptions, as `GET
/// /v1/owner/connectors/subscriptions` shows them.
#[derive(Serialize)]
struct Subscriptions {
    agent: String,
    subscriptions: Vec<SubscriptionRow>,
}

/// Lists the agent's subscriptions through the engine door `GET
/// /v1/owner/connectors/subscriptions` uses, as the local owner (OF-519).
/// It reads nothing from stdin.
fn list(args: SubscriptionListArgs) -> anyhow::Result<()> {
    let agent = hold_id_arg(&args.agent)?;
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_vault(&config, "GET /v1/owner/connectors/subscriptions?agent=")?;
    let _owner = local_owner(&vault)?;
    let subscriptions = vault
        .connector_event_subscriptions(agent)?
        .into_iter()
        .map(|(id, row)| SubscriptionRow {
            subscription: id.to_hex(),
            connector_key: row.connector_key.to_hex(),
            connector: row.filter.connector,
            event_kind: row.filter.event_kind,
            predicate: row.filter.predicate,
            active: row.active,
        })
        .collect();
    emit(&Subscriptions {
        agent: agent.to_hex(),
        subscriptions,
    })
}

/// Revokes a subscription through the engine door `POST
/// /v1/owner/connectors/subscriptions/revoke` uses, as the local owner
/// (OF-519). It reads nothing from stdin.
fn revoke(args: SubscriptionRevokeArgs) -> anyhow::Result<()> {
    let id = hold_id_arg(&args.subscription)?;
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_vault(
        &config,
        "POST /v1/owner/connectors/subscriptions/revoke --data -",
    )?;
    let owner = local_owner(&vault)?;
    vault.revoke_connector_event_subscription(&owner, id)?;
    emit(&serde_json::json!({ "subscription": id.to_hex() }))
}
