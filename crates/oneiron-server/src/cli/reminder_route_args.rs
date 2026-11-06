//! `oneiron reminder-route`: the owner's commitment reminder route on a stopped
//! vault (`oneiron::commitment_wake::CommitmentReminderRoute`); a running server
//! answers the same at `/v1/owner/commitments/reminder-route`, and the SDK at
//! `vault.commitments.reminder_route.get` and `.set`.
//!
//! Set takes the full native route. `--persona-ref` implies voice: either
//! `--voice` or a persona makes `Some(voice)`, neither makes `None`. There is
//! no new default: native validation owns channel, verb, target, the UTC
//! offset range, timezone labels and voice labels.

use clap::{Args, Subcommand};

use crate::config::ServeArgs;

#[derive(Subcommand, Clone, Debug)]
pub enum ReminderRouteCommand {
    /// Read the route; `null` when none is set.
    Get(Box<ReminderRouteGetArgs>),
    /// Set the full route, replacing any row.
    Set(Box<ReminderRouteSetArgs>),
    /// Clear the route; reminders stop, approvals stand.
    Clear(Box<ReminderRouteClearArgs>),
}

#[derive(Args, Clone, Debug)]
pub struct ReminderRouteGetArgs {
    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct ReminderRouteSetArgs {
    /// The channel reminders travel on, as configured for this vault.
    #[arg(long)]
    pub channel: String,
    /// The verb reminders travel as.
    #[arg(long)]
    pub verb: String,
    /// Where on the channel reminders go.
    #[arg(long)]
    pub target: String,
    /// Fixed UTC offset in minutes, used when no zone resolves; negative
    /// values accepted, native validation owns the range.
    #[arg(long, allow_negative_numbers = true)]
    pub utc_offset_minutes: Option<i16>,
    /// IANA timezone label deciding the offset at each instant.
    #[arg(long)]
    pub iana_timezone: Option<String>,
    /// Word each reminder with the host's model before its send.
    #[arg(long)]
    pub voice: bool,
    /// The voice's persona ref; implies `--voice`.
    #[arg(long)]
    pub persona_ref: Option<String>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct ReminderRouteClearArgs {
    #[command(flatten)]
    pub serve: ServeArgs,
}
