//! `oneiron widen-proposals`: the context-widen proposals agents raised, on
//! a stopped vault (`oneiron::agent_dispatch::widen_doors`); a running server
//! answers the same at `/v1/owner/widen-proposals`.

use clap::{Args, Subcommand, ValueEnum};

use crate::config::ServeArgs;

#[derive(Subcommand, Clone, Debug)]
pub enum WidenProposalsCommand {
    /// The proposals, newest first.
    List(Box<WidenProposalListArgs>),
    /// Approve one as the board above: the parent's context widens and the
    /// child is enqueued.
    Approve(Box<WidenProposalAnswerArgs>),
    /// Decline one as the board above, for good.
    Decline(Box<WidenProposalAnswerArgs>),
}

/// Where a proposal stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum WidenProposalStateArg {
    Pending,
    Approved,
    Declined,
}

#[derive(Args, Clone, Debug)]
pub struct WidenProposalListArgs {
    /// Only proposals in this state.
    #[arg(long)]
    pub state: Option<WidenProposalStateArg>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct WidenProposalAnswerArgs {
    /// The proposal's id (64 hex), as the list names it.
    pub proposal_id: String,

    #[command(flatten)]
    pub serve: ServeArgs,
}
