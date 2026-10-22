//! The wake ledger's report in bounded pages (FIX 9549): a ledger push and a
//! frozen pull carry one complete report, every wake entry and the training
//! setting at one revision, in pages of at most [`MAX_LEDGER_PAGE_ENTRIES`]
//! entries, however many entries the report holds. Nothing is cut, skipped
//! or refused for the report's size.
//!
//! A report is named by its revision and its digest, the BLAKE3 of the vault,
//! the revision, every entry in order and the training setting
//! ([`LedgerReportHead::of`]). Every page repeats the report's revision,
//! digest, entry count and training setting, and says where its entries
//! start; every page but the last holds exactly [`MAX_LEDGER_PAGE_ENTRIES`]
//! entries, and a report with none is one page with none. A receiver takes
//! the pages in order ([`LedgerReportAssembly`]) and holds the report only
//! once it is complete and its digest checks: no page alone is a report.
//!
//! Push: the vault sends a report's pages in order on one connection to its
//! supervisor socket, each a [`LedgerUpdate`](crate::LedgerUpdate) with the
//! spawn token, and reads a [`LedgerAck`](crate::LedgerAck) after each. Each
//! page's ack is a receipt; only the last page's, `committed`, says the
//! supervisor holds that report, or a later revision, durably.
//!
//! Pull: `prepare_reap` and `prepare_idle_reap` name the report the freeze
//! holds ([`LedgerReportHead`]); the supervisor reads its pages with
//! `ledger_page` ([`LedgerPageRequest`]) and, once it holds the report
//! durably, says so with `ledger_pulled` ([`LedgerPulledRequest`]). Both
//! carry the spawn token and the vault's name. The vault keeps the frozen
//! report until then, or until `reap_abort`.

use serde::{Deserialize, Serialize};

use super::ledger::lowercase_hex;
use super::{
    MAX_LEDGER_PAGE_ENTRIES, ManagedTrainingSetting, Schedule, TOKEN_LEN, TokenHex, WakeEntry, hex,
    valid_vault_name, validate_wake_entries,
};

/// The BLAKE3 key-derivation context a report's digest is computed under.
const REPORT_DIGEST_CONTEXT: &str = "oneiron wake-ledger report v1";

/// One report's identity: its revision, its digest and how many wake entries
/// it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerReportHead {
    pub rev: u64,
    /// The report's BLAKE3, 64 lowercase hex ([`LedgerReportHead::of`]).
    pub report_digest: String,
    /// How many wake entries the report holds.
    pub total: u64,
}

/// One page of a report: the report's identity and training setting, the
/// index of the page's first entry, and its entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerPage {
    pub rev: u64,
    pub report_digest: String,
    pub total: u64,
    /// The index in the report of this page's first entry: a multiple of
    /// [`MAX_LEDGER_PAGE_ENTRIES`].
    pub offset: u64,
    pub entries: Vec<WakeEntry>,
    /// The vault's training setting at `rev`, the same on every page.
    pub training: ManagedTrainingSetting,
}

/// A complete report, its digest checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerReport {
    pub head: LedgerReportHead,
    pub entries: Vec<WakeEntry>,
    pub training: ManagedTrainingSetting,
}

/// `ledger_page`: one page of the report a freeze holds, named by its
/// revision, digest and page offset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerPageRequest {
    pub vault: String,
    pub token: TokenHex,
    pub rev: u64,
    pub report_digest: String,
    pub offset: u64,
}

/// `ledger_pulled`: the supervisor holds the frozen report named here
/// durably, so the vault takes it as delivered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerPulledRequest {
    pub vault: String,
    pub token: TokenHex,
    pub rev: u64,
    pub report_digest: String,
}

impl LedgerReportHead {
    /// The head of the report `entries` and `training` make for `vault` at
    /// `rev`. Its digest covers each field with its length, so no two
    /// reports share one.
    #[must_use]
    pub fn of(
        vault: &str,
        rev: u64,
        entries: &[WakeEntry],
        training: &ManagedTrainingSetting,
    ) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(REPORT_DIGEST_CONTEXT);
        let mut field = |bytes: &[u8]| {
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        };
        field(vault.as_bytes());
        field(&rev.to_le_bytes());
        field(&(entries.len() as u64).to_le_bytes());
        for entry in entries {
            field(entry.id.as_bytes());
            match entry.at {
                Schedule::Exact { at } => {
                    field(b"exact");
                    field(&at.to_le_bytes());
                }
                Schedule::Window { start, end } => {
                    field(b"window");
                    field(&start.to_le_bytes());
                    field(&end.to_le_bytes());
                }
            }
            field(entry.reason_tag.as_bytes());
        }
        field(&[u8::from(training.on), u8::from(training.allow_opt_out)]);
        field(training.revision.as_bytes());
        match &training.set_by {
            Some(set_by) => {
                field(b"set_by");
                field(set_by.as_bytes());
            }
            None => field(b"none"),
        }
        Self {
            rev,
            report_digest: hex(hasher.finalize().as_bytes()),
            total: entries.len() as u64,
        }
    }

    /// Shape check: the digest is 64 lowercase hex.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            lowercase_hex(&self.report_digest, 64),
            "malformed ledger report digest"
        );
        Ok(())
    }

    /// Every page's offset, in order: one, 0, for a report with no entries.
    #[must_use]
    pub fn offsets(&self) -> std::iter::StepBy<std::ops::Range<u64>> {
        (0..self.total.max(1)).step_by(MAX_LEDGER_PAGE_ENTRIES)
    }

    /// The page at `offset` of the report this heads, cut from its
    /// `entries` and `training`. An offset that starts no page is refused.
    pub fn page(
        &self,
        entries: &[WakeEntry],
        training: &ManagedTrainingSetting,
        offset: u64,
    ) -> anyhow::Result<LedgerPage> {
        anyhow::ensure!(
            entries.len() as u64 == self.total,
            "the report's entries are not its head's"
        );
        let len = page_len(self.total, offset)
            .ok_or_else(|| anyhow::anyhow!("no page of this report starts at {offset}"))?;
        let start = usize::try_from(offset)?;
        Ok(LedgerPage {
            rev: self.rev,
            report_digest: self.report_digest.clone(),
            total: self.total,
            offset,
            entries: entries[start..start + len].to_vec(),
            training: training.clone(),
        })
    }
}

impl LedgerPage {
    /// The head of the report this page belongs to.
    #[must_use]
    pub fn head(&self) -> LedgerReportHead {
        LedgerReportHead {
            rev: self.rev,
            report_digest: self.report_digest.clone(),
            total: self.total,
        }
    }

    /// Reject-not-truncate shape check: the digest, an offset that starts a
    /// page, exactly the entries a page there holds, each entry's bounds and
    /// the training setting's shape.
    pub fn validate(&self) -> anyhow::Result<()> {
        self.head().validate()?;
        let len = page_len(self.total, self.offset)
            .ok_or_else(|| anyhow::anyhow!("a ledger page's offset starts no page"))?;
        anyhow::ensure!(
            self.entries.len() == len,
            "a ledger page holds other than its offset's entries"
        );
        validate_wake_entries(&self.entries)?;
        self.training.validate()
    }
}

/// How many entries the page at `offset` of a `total`-entry report holds,
/// or `None` when no page starts there.
fn page_len(total: u64, offset: u64) -> Option<usize> {
    let step = MAX_LEDGER_PAGE_ENTRIES as u64;
    if offset % step != 0 || (offset >= total && !(total == 0 && offset == 0)) {
        return None;
    }
    usize::try_from((total - offset).min(step)).ok()
}

/// A report a receiver takes page by page, in order, for `vault`. It holds
/// the report only once every page is in and the digest checks.
#[derive(Debug)]
pub struct LedgerReportAssembly {
    vault: String,
    head: LedgerReportHead,
    training: Option<ManagedTrainingSetting>,
    entries: Vec<WakeEntry>,
}

impl LedgerReportAssembly {
    /// The report `head` names, with no page yet.
    #[must_use]
    pub fn new(vault: &str, head: LedgerReportHead) -> Self {
        Self {
            vault: vault.to_owned(),
            head,
            training: None,
            entries: Vec::new(),
        }
    }

    #[must_use]
    pub fn head(&self) -> &LedgerReportHead {
        &self.head
    }

    /// The offset of the page still owed, or `None` once all are in.
    #[must_use]
    pub fn next_offset(&self) -> Option<u64> {
        let taken = self.entries.len() as u64;
        match self.training {
            None => Some(0),
            Some(_) if taken < self.head.total => Some(taken),
            Some(_) => None,
        }
    }

    /// Takes the next page: one of this report, validated, at the offset
    /// owed, with the training setting of the pages before it.
    pub fn accept(&mut self, page: LedgerPage) -> anyhow::Result<()> {
        page.validate()?;
        anyhow::ensure!(page.head() == self.head, "a ledger page of another report");
        anyhow::ensure!(
            Some(page.offset) == self.next_offset(),
            "a ledger page out of order"
        );
        if let Some(training) = &self.training {
            anyhow::ensure!(
                *training == page.training,
                "a ledger page's training setting differs from its report's"
            );
        }
        self.training = Some(page.training);
        self.entries.extend(page.entries);
        Ok(())
    }

    /// The complete report, refused while a page is owed or when its digest
    /// is not the head's.
    pub fn finish(self) -> anyhow::Result<LedgerReport> {
        anyhow::ensure!(
            self.next_offset().is_none(),
            "the ledger report is missing pages"
        );
        let training = self
            .training
            .ok_or_else(|| anyhow::anyhow!("the ledger report has no page"))?;
        let computed = LedgerReportHead::of(&self.vault, self.head.rev, &self.entries, &training);
        anyhow::ensure!(
            computed == self.head,
            "the ledger report's pages do not hash to its digest"
        );
        Ok(LedgerReport {
            head: self.head,
            entries: self.entries,
            training,
        })
    }
}

impl LedgerPageRequest {
    /// Shape check: the vault's name, the token's and the digest's.
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_pull(&self.vault, &self.token, &self.report_digest)
    }
}

impl LedgerPulledRequest {
    /// Shape check: the vault's name, the token's and the digest's.
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_pull(&self.vault, &self.token, &self.report_digest)
    }
}

fn validate_pull(vault: &str, token: &TokenHex, report_digest: &str) -> anyhow::Result<()> {
    anyhow::ensure!(valid_vault_name(vault), "bad vault name");
    let t = token.expose();
    anyhow::ensure!(
        t.len() == TOKEN_LEN * 2 && t.bytes().all(|b| b.is_ascii_hexdigit()),
        "malformed token"
    );
    anyhow::ensure!(
        lowercase_hex(report_digest, 64),
        "malformed ledger report digest"
    );
    Ok(())
}
