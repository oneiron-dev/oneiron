//! The host's half of a vault VM's wake ledger transfers, both in bounded
//! pages (FIX 9549).
//!
//! A push arrives on the ledger socket: each accepted connection is a task
//! the runner owns (FIX 9502), which reads the report's pages in order, one
//! bounded line each, checks each against the vault's name and spawn token,
//! answers each with a receipt, and hands the complete report, its digest
//! checked, to the runner's loop, the wake schedule's one owner, to commit.
//! Its last answer, `committed`, goes only once that commit is durable, and
//! the commit stands whether or not the answer reaches the peer. A peer that
//! never completes a page holds only its own task: accepts, alarms, idle
//! handling and SIGTERM run on in the loop, and the runner's stop ends every
//! task. No deadline is put on a peer.
//!
//! A pull is a sleep's: the report `prepare_reap` names, read page by page
//! with `ledger_page` ([`VaultVm::pull_ledger`]).

use super::VaultVm;
use oneiron_vault_contract::{
    CtlRequest, CtlResponse, LedgerAck, LedgerPageRequest, LedgerReport, LedgerReportAssembly,
    LedgerReportHead, LedgerUpdate, MAX_CTL_LINE, TokenHex,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::{mpsc, oneshot};

/// How many ledger connections the runner serves at once. More wait in the
/// socket's backlog until one ends: a pacing bound on this vault's own
/// peers, never a refusal of a page or a report.
pub(super) const MAX_LEDGER_PEERS: usize = 8;

/// A complete report a peer hands the runner's loop, and where the commit's
/// outcome goes.
pub(super) struct LedgerCommit {
    pub(super) report: LedgerReport,
    pub(super) answer: oneshot::Sender<anyhow::Result<()>>,
}

/// One ledger connection, from its first page to its report's commit or its
/// first refusal, which ends it.
pub(super) async fn take_push(
    stream: UnixStream,
    vault: String,
    token: TokenHex,
    commits: mpsc::Sender<LedgerCommit>,
) {
    if let Err(error) = exchange(stream, &vault, &token, &commits).await {
        tracing::warn!(error = %format!("{error:#}"), "vault VM ledger push refused");
    }
}

async fn exchange(
    stream: UnixStream,
    vault: &str,
    token: &TokenHex,
    commits: &mpsc::Sender<LedgerCommit>,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut assembly: Option<LedgerReportAssembly> = None;
    loop {
        let mut line = String::new();
        if (&mut reader)
            .take(MAX_CTL_LINE as u64 + 2)
            .read_line(&mut line)
            .await?
            == 0
        {
            // The peer closed: a report it left unfinished is never
            // committed.
            return Ok(());
        }
        let update = match serde_json::from_str::<LedgerUpdate>(line.trim_end_matches(['\r', '\n']))
        {
            Ok(update) => update,
            Err(error) => {
                let error = anyhow::Error::from(error);
                answer(&mut writer, None, Err(&error)).await?;
                return Err(error);
            }
        };
        let page = (update.page.head(), update.page.offset);
        let taken = take_page(update, vault, token, &mut assembly);
        if let Err(error) = taken {
            answer(&mut writer, Some(page), Err(&error)).await?;
            return Err(error);
        }
        if assembly
            .as_ref()
            .is_some_and(|report| report.next_offset().is_some())
        {
            answer(&mut writer, Some(page), Ok(false)).await?;
            continue;
        }
        let complete = assembly
            .take()
            .ok_or_else(|| anyhow::anyhow!("the ledger report has no page"))
            .and_then(LedgerReportAssembly::finish);
        let committed = match complete {
            Ok(report) => commit(commits, report).await,
            Err(error) => Err(error),
        };
        answer(&mut writer, Some(page), committed.as_ref().map(|_| true)).await?;
        return committed;
    }
}

/// One parsed page: validated, from this vault with its token, and taken
/// into its report in order.
fn take_page(
    update: LedgerUpdate,
    vault: &str,
    token: &TokenHex,
    assembly: &mut Option<LedgerReportAssembly>,
) -> anyhow::Result<()> {
    update.validate()?;
    anyhow::ensure!(
        update.vault == vault && update.token.ct_eq(token),
        "foreign ledger push"
    );
    assembly
        .get_or_insert_with(|| LedgerReportAssembly::new(vault, update.page.head()))
        .accept(update.page)
}

/// Hands `report` to the runner's loop and waits for its commit.
async fn commit(commits: &mpsc::Sender<LedgerCommit>, report: LedgerReport) -> anyhow::Result<()> {
    let (answer, answered) = oneshot::channel();
    let stopped = || anyhow::anyhow!("the runner stopped before the ledger report's commit");
    commits
        .send(LedgerCommit { report, answer })
        .await
        .map_err(|_| stopped())?;
    answered.await.map_err(|_| stopped())?
}

/// One page's answer: its receipt, `committed` on the last page once the
/// report is durable, or the refusal that ends the connection.
async fn answer(
    writer: &mut OwnedWriteHalf,
    page: Option<(LedgerReportHead, u64)>,
    outcome: Result<bool, &anyhow::Error>,
) -> anyhow::Result<()> {
    let (report, offset) = page.map_or((None, None), |(head, offset)| (Some(head), Some(offset)));
    let ack = LedgerAck {
        ok: outcome.is_ok(),
        error: outcome.as_ref().err().map(|error| format!("{error:#}")),
        report,
        offset,
        committed: outcome.unwrap_or(false),
    };
    let mut line = serde_json::to_string(&ack)?;
    line.push('\n');
    writer.write_all(line.as_bytes()).await?;
    Ok(())
}

impl VaultVm {
    /// The whole report `head` names, which the guest's freeze holds, read
    /// page by page with `ledger_page` under `token`, in order, and its
    /// digest checked (FIX 9549).
    pub(super) async fn pull_ledger(
        &self,
        token: &TokenHex,
        head: LedgerReportHead,
    ) -> anyhow::Result<LedgerReport> {
        let mut assembly = LedgerReportAssembly::new(&self.vault, head);
        while let Some(offset) = assembly.next_offset() {
            let request = LedgerPageRequest {
                vault: self.vault.clone(),
                token: token.clone(),
                rev: assembly.head().rev,
                report_digest: assembly.head().report_digest.clone(),
                offset,
            };
            let CtlResponse::LedgerPage { ledger_page } =
                self.ctl(&CtlRequest::LedgerPage { request }).await?
            else {
                anyhow::bail!("ledger_page answered with another verb");
            };
            assembly.accept(ledger_page)?;
        }
        assembly.finish()
    }
}
