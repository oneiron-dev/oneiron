//! The wake ledger's report in bounded pages (FIX 9549): a ledger push and a
//! frozen pull carry every wake entry, the training setting and the logical
//! artifact origins at one revision. Each page holds at most
//! [`MAX_LEDGER_PAGE_ENTRIES`] rows across wake entries and artifact origins
//! together. Nothing is cut, skipped or refused for the report's size.
//!
//! A report is named by its revision and its digest, the BLAKE3 of the vault,
//! revision, entries, training setting and artifact origins in order
//! ([`LedgerReportHead::of`]). Page offsets traverse the wake entries first,
//! then the artifact origins. A report with no rows is one empty page. A
//! receiver takes every page in order ([`LedgerReportAssembly`]) and holds
//! the report only once its digest checks: no page alone is a report.
//!
//! Push: pages go over one supervisor connection as
//! [`LedgerUpdate`](crate::LedgerUpdate), with the spawn token. Each
//! [`LedgerAck`](crate::LedgerAck) receipts its page; only the last page's
//! `committed` says the supervisor durably holds this report or a later one.
//!
//! Pull: `prepare_reap` and `prepare_idle_reap` name the frozen report. The
//! supervisor reads its pages with [`LedgerPageRequest`], then acknowledges
//! durable receipt with [`LedgerPulledRequest`]. The vault holds the frozen
//! report until then or `reap_abort`.
//!
//! Build floor (FIX 11004): engine and supervisor builds must both include
//! the logical artifact-origin report fields introduced here. Contract
//! version 3 does not move; the new fields are required, with no old-format
//! reader or default. Origins are native publication facts, not public DNS,
//! Access authorization or proof that an artifact is currently available.

use serde::{Deserialize, Serialize};

use super::artifact_origin::valid_app_label;
use super::ledger::lowercase_hex;
use super::{
    MAX_LEDGER_PAGE_ENTRIES, ManagedTrainingSetting, Schedule, TOKEN_LEN, TokenHex, WakeEntry, hex,
    valid_vault_name, validate_wake_entries,
};

/// A logical artifact destination. The supervisor supplies its own public
/// domain and vault slug; the vault never receives or guesses those names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactOrigin {
    Vault,
    App { artifact_id: String },
}

impl ArtifactOrigin {
    /// A per-app alias only when the existing artifact-host codec names one.
    /// Other artifact ids remain reachable through the vault's path origin.
    #[must_use]
    pub fn app(artifact_id: String) -> Option<Self> {
        valid_app_label(&artifact_id).then_some(Self::App { artifact_id })
    }

    fn validate(&self) -> anyhow::Result<()> {
        if let Self::App { artifact_id } = self {
            anyhow::ensure!(valid_app_label(artifact_id), "bad artifact app label");
        }
        Ok(())
    }
}

/// The BLAKE3 key-derivation context a report's digest is computed under.
const REPORT_DIGEST_CONTEXT: &str = "oneiron wake-ledger report v1";

/// One report's identity and the counts of its two row families.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerReportHead {
    pub rev: u64,
    /// The report's BLAKE3, 64 lowercase hex ([`LedgerReportHead::of`]).
    pub report_digest: String,
    /// How many wake entries the report holds.
    pub total: u64,
    pub artifact_origins_total: u64,
}

/// One bounded page of wake entries followed by logical artifact origins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerPage {
    pub rev: u64,
    pub report_digest: String,
    pub total: u64,
    pub artifact_origins_total: u64,
    /// A multiple of [`MAX_LEDGER_PAGE_ENTRIES`] in the combined row stream.
    pub offset: u64,
    pub entries: Vec<WakeEntry>,
    pub artifact_origins: Vec<ArtifactOrigin>,
    /// The vault's training setting at `rev`, the same on every page.
    pub training: ManagedTrainingSetting,
}

/// A complete report, its digest checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerReport {
    pub head: LedgerReportHead,
    pub entries: Vec<WakeEntry>,
    pub training: ManagedTrainingSetting,
    pub artifact_origins: Vec<ArtifactOrigin>,
}

/// `ledger_page`: one page of the report a freeze holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerPageRequest {
    pub vault: String,
    pub token: TokenHex,
    pub rev: u64,
    pub report_digest: String,
    pub offset: u64,
}

/// `ledger_pulled`: the supervisor durably holds the frozen report named here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerPulledRequest {
    pub vault: String,
    pub token: TokenHex,
    pub rev: u64,
    pub report_digest: String,
}

impl LedgerReportHead {
    /// The complete report's head. Every field is length-delimited in the digest.
    #[must_use]
    pub fn of(
        vault: &str,
        rev: u64,
        entries: &[WakeEntry],
        training: &ManagedTrainingSetting,
        artifact_origins: &[ArtifactOrigin],
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
        field(&(artifact_origins.len() as u64).to_le_bytes());
        for origin in artifact_origins {
            match origin {
                ArtifactOrigin::Vault => field(b"vault"),
                ArtifactOrigin::App { artifact_id } => {
                    field(b"app");
                    field(artifact_id.as_bytes());
                }
            }
        }
        Self {
            rev,
            report_digest: hex(hasher.finalize().as_bytes()),
            total: entries.len() as u64,
            artifact_origins_total: artifact_origins.len() as u64,
        }
    }

    /// How many rows both families hold. Validation rejects an overflowing count.
    #[must_use]
    pub fn row_count(&self) -> u64 {
        self.total.saturating_add(self.artifact_origins_total)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            lowercase_hex(&self.report_digest, 64),
            "malformed ledger report digest"
        );
        anyhow::ensure!(
            self.total
                .checked_add(self.artifact_origins_total)
                .is_some(),
            "overflowing ledger report row count"
        );
        Ok(())
    }

    /// Every page's offset, including one empty page for a rowless report.
    #[must_use]
    pub fn offsets(&self) -> std::iter::StepBy<std::ops::Range<u64>> {
        (0..self.row_count().max(1)).step_by(MAX_LEDGER_PAGE_ENTRIES)
    }

    /// A page from these exact frozen lists, never a fresh per-page scan.
    pub fn page(
        &self,
        entries: &[WakeEntry],
        training: &ManagedTrainingSetting,
        artifact_origins: &[ArtifactOrigin],
        offset: u64,
    ) -> anyhow::Result<LedgerPage> {
        anyhow::ensure!(
            entries.len() as u64 == self.total
                && artifact_origins.len() as u64 == self.artifact_origins_total,
            "the report's rows are not its head's"
        );
        let (entry_len, origin_len) = page_counts(self, offset)
            .ok_or_else(|| anyhow::anyhow!("no page of this report starts at {offset}"))?;
        let entry_start = usize::try_from(offset.min(self.total))?;
        let origin_start = usize::try_from(offset.saturating_sub(self.total))?;
        Ok(LedgerPage {
            rev: self.rev,
            report_digest: self.report_digest.clone(),
            total: self.total,
            artifact_origins_total: self.artifact_origins_total,
            offset,
            entries: entries[entry_start..entry_start + entry_len].to_vec(),
            artifact_origins: artifact_origins[origin_start..origin_start + origin_len].to_vec(),
            training: training.clone(),
        })
    }
}

impl LedgerPage {
    #[must_use]
    pub fn head(&self) -> LedgerReportHead {
        LedgerReportHead {
            rev: self.rev,
            report_digest: self.report_digest.clone(),
            total: self.total,
            artifact_origins_total: self.artifact_origins_total,
        }
    }

    /// Reject malformed pages; never truncate either family to fit a page.
    pub fn validate(&self) -> anyhow::Result<()> {
        let head = self.head();
        head.validate()?;
        let (entry_len, origin_len) = page_counts(&head, self.offset)
            .ok_or_else(|| anyhow::anyhow!("a ledger page's offset starts no page"))?;
        anyhow::ensure!(
            self.entries.len() == entry_len && self.artifact_origins.len() == origin_len,
            "a ledger page holds other than its offset's rows"
        );
        validate_wake_entries(&self.entries)?;
        for origin in &self.artifact_origins {
            origin.validate()?;
        }
        self.training.validate()
    }
}

/// Family lengths at an offset in the concatenated entry/origin row stream.
fn page_counts(head: &LedgerReportHead, offset: u64) -> Option<(usize, usize)> {
    let total = head.total.checked_add(head.artifact_origins_total)?;
    let step = MAX_LEDGER_PAGE_ENTRIES as u64;
    if offset % step != 0 || (offset >= total && !(total == 0 && offset == 0)) {
        return None;
    }
    let len = (total - offset).min(step);
    let entry_len = (offset + len).min(head.total) - offset.min(head.total);
    Some((
        usize::try_from(entry_len).ok()?,
        usize::try_from(len - entry_len).ok()?,
    ))
}

/// A report received in order, held only after both row families and its digest check.
#[derive(Debug)]
pub struct LedgerReportAssembly {
    vault: String,
    head: LedgerReportHead,
    training: Option<ManagedTrainingSetting>,
    entries: Vec<WakeEntry>,
    artifact_origins: Vec<ArtifactOrigin>,
}

impl LedgerReportAssembly {
    #[must_use]
    pub fn new(vault: &str, head: LedgerReportHead) -> Self {
        Self {
            vault: vault.to_owned(),
            head,
            training: None,
            entries: Vec::new(),
            artifact_origins: Vec::new(),
        }
    }

    #[must_use]
    pub fn head(&self) -> &LedgerReportHead {
        &self.head
    }

    #[must_use]
    pub fn next_offset(&self) -> Option<u64> {
        let taken = (self.entries.len() as u64).saturating_add(self.artifact_origins.len() as u64);
        match self.training {
            None => Some(0),
            Some(_) if taken < self.head.row_count() => Some(taken),
            Some(_) => None,
        }
    }

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
        self.artifact_origins.extend(page.artifact_origins);
        Ok(())
    }

    pub fn finish(self) -> anyhow::Result<LedgerReport> {
        anyhow::ensure!(
            self.next_offset().is_none(),
            "the ledger report is missing pages"
        );
        let training = self
            .training
            .ok_or_else(|| anyhow::anyhow!("the ledger report has no page"))?;
        let computed = LedgerReportHead::of(
            &self.vault,
            self.head.rev,
            &self.entries,
            &training,
            &self.artifact_origins,
        );
        anyhow::ensure!(
            computed == self.head,
            "the ledger report's pages do not hash to its digest"
        );
        Ok(LedgerReport {
            head: self.head,
            entries: self.entries,
            training,
            artifact_origins: self.artifact_origins,
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
