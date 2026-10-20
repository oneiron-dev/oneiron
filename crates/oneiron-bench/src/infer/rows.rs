//! Result rows: one JSON line per finished (arm, case, rep), appended to
//! `--out` and flushed and fsynced one by one, so a run cut anywhere keeps
//! every row before the cut.
//!
//! On start the file is read back. A last line without its newline is a cut
//! write: it is ignored, and the next row starts on a fresh line. A
//! sequential run's row is done when it says `ok` under the same
//! `config_digest`; error rows run again. A concurrent run's rows come in
//! cohorts, one whole packet per rep: a rep is done only when one cohort holds
//! an `ok` row for every case of the packet, and any other cohort of it runs
//! again whole, under a new `cohort_id`. Rows land in completion order, one
//! writer appending them.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value as JsonValue;

use super::cases::Scorer;
use super::measure::Timing;
use super::request::Sent;
use super::scoring::Quality;

pub(super) const SCHEMA: &str = "oneiron.infer-bench.row.v1";

/// What every row of one run shares.
#[derive(Clone, Debug, Serialize)]
pub(super) struct RunIdentity {
    pub(super) arm_id: String,
    pub(super) transport: &'static str,
    /// `--model` as given.
    pub(super) model: String,
    /// The engine id the router served it under, and its provider revision.
    pub(super) served_model: String,
    pub(super) served_revision: String,
    pub(super) role_added: Option<String>,
    pub(super) cases_digest: String,
    pub(super) config_digest: String,
    pub(super) git_sha: Option<String>,
    pub(super) checkout_sha: Option<String>,
    pub(super) hostname: String,
    pub(super) sampling: &'static str,
    pub(super) schema_flag: bool,
    pub(super) cache_bust: bool,
    pub(super) engine_cmd: Option<String>,
    /// Names only: the values are in `config_digest`.
    pub(super) engine_env_keys: Vec<String>,
    pub(super) engine_pid: Option<u32>,
    pub(super) engine_load_ms: Option<f64>,
    pub(super) gpu_index: u32,
    pub(super) gpu_name: Option<String>,
    pub(super) gpu_uuid: Option<String>,
    pub(super) vram_total_mib: Option<u64>,
    pub(super) vram_poll_ms: u64,
    /// Sampled before the bench started the engine; null when it did not.
    pub(super) vram_idle_mib: Option<u64>,
    /// Sampled once the engine was healthy, before the warmup.
    pub(super) vram_loaded_mib: Option<u64>,
    /// This `infer run` invocation.
    pub(super) session_id: String,
    /// `--concurrency` and `--stagger-ms`.
    pub(super) concurrency: u32,
    pub(super) stagger_ms: u64,
    /// `--draft-depth`, as declared; the engine's own report is in `native`.
    pub(super) draft_depth: Option<u32>,
}

/// One case's row.
#[derive(Serialize)]
pub(super) struct Row<'a> {
    pub(super) schema: &'static str,
    #[serde(flatten)]
    pub(super) run: &'a RunIdentity,
    pub(super) case_id: &'a str,
    pub(super) case_kind: &'a str,
    pub(super) scorer: Scorer,
    pub(super) case_digest: &'a str,
    pub(super) case_prompt_tokens: Option<u64>,
    pub(super) case_approx_input_tokens: Option<u64>,
    pub(super) rep: u32,
    /// The worker task that made the call.
    pub(super) worker_id: usize,
    /// The case's place in the selected packet order.
    pub(super) queue_index: usize,
    /// The cohort the call ran in, and how many calls it has: one per case of
    /// the packet when concurrent, one when sequential.
    pub(super) cohort_id: &'a str,
    pub(super) cohort_size: usize,
    /// The call's `t0` and its end, in ms after the session's post-warmup
    /// epoch.
    pub(super) start_offset_ms: f64,
    pub(super) end_offset_ms: f64,
    pub(super) started_at: String,
    pub(super) status: &'static str,
    pub(super) error: Option<String>,
    #[serde(flatten)]
    pub(super) sent: &'a Sent,
    #[serde(flatten)]
    pub(super) timing: Timing,
    /// The whole card's highest sampled reading during this case's call,
    /// whatever else was in flight.
    pub(super) vram_case_peak_mib: Option<u64>,
    pub(super) quality: Option<Quality>,
}

/// The parseable rows of this schema in `path`, in file order, how many
/// complete lines did not parse, and whether the file ends mid-line. A
/// missing file has none.
pub(super) fn read(path: &Path) -> Result<(Vec<JsonValue>, usize, bool), String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    let cut = bytes.last().is_some_and(|byte| *byte != b'\n');
    let complete = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(&[][..], |end| &bytes[..end]);
    let mut rows = Vec::new();
    let mut unreadable = 0;
    for line in complete.split(|byte| *byte == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match serde_json::from_slice::<JsonValue>(line) {
            Ok(row) if row["schema"] == SCHEMA => rows.push(row),
            _ => unreadable += 1,
        }
    }
    Ok((rows, unreadable, cut))
}

/// The (arm, case, rep) keys `rows` holds an `ok` row for under
/// `config_digest`.
pub(super) fn done(rows: &[JsonValue], config_digest: &str) -> BTreeSet<(String, String, u32)> {
    rows.iter()
        .filter(|row| row["status"] == "ok" && row["config_digest"] == config_digest)
        .filter_map(|row| {
            Some((
                row["arm_id"].as_str()?.to_owned(),
                row["case_id"].as_str()?.to_owned(),
                u32::try_from(row["rep"].as_u64()?).ok()?,
            ))
        })
        .collect()
}

/// The reps of `arm_id` under `config_digest` that one cohort finished
/// clean: an `ok` row for each `(queue_index, case_id, case_digest)` of
/// `packet` and no other.
pub(super) fn clean_cohort_reps(
    rows: &[JsonValue],
    config_digest: &str,
    arm_id: &str,
    packet: &[(usize, &str, &str)],
) -> BTreeSet<u32> {
    let mut cohorts: BTreeMap<&str, Vec<&JsonValue>> = BTreeMap::new();
    for row in rows
        .iter()
        .filter(|row| row["config_digest"] == config_digest && row["arm_id"] == arm_id)
    {
        if let Some(cohort) = row["cohort_id"].as_str() {
            cohorts.entry(cohort).or_default().push(row);
        }
    }
    let want: BTreeSet<(usize, &str, &str)> = packet.iter().copied().collect();
    let mut reps = BTreeSet::new();
    for members in cohorts.values() {
        let Some(rep) = members.first().and_then(|row| row["rep"].as_u64()) else {
            continue;
        };
        let clean = members
            .iter()
            .all(|row| row["status"] == "ok" && row["rep"].as_u64() == Some(rep));
        let got: BTreeSet<(usize, &str, &str)> = members
            .iter()
            .filter_map(|row| {
                Some((
                    usize::try_from(row["queue_index"].as_u64()?).ok()?,
                    row["case_id"].as_str()?,
                    row["case_digest"].as_str()?,
                ))
            })
            .collect();
        if clean
            && members.len() == packet.len()
            && got == want
            && let Ok(rep) = u32::try_from(rep)
        {
            reps.insert(rep);
        }
    }
    reps
}

/// The append-only result file.
pub(super) struct Writer {
    file: File,
}

impl Writer {
    /// Opens `path` for appending; `cut` puts a newline after a last line
    /// a cut write left unterminated.
    pub(super) fn open(path: &Path, cut: bool) -> Result<Self, String> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("open --out {}: {e}", path.display()))?;
        let mut writer = Self { file };
        if cut {
            writer.write(b"\n")?;
        }
        Ok(writer)
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.file
            .write_all(bytes)
            .and_then(|()| self.file.flush())
            .and_then(|()| self.file.sync_data())
            .map_err(|e| format!("write --out: {e}"))
    }

    pub(super) fn append(&mut self, row: &Row<'_>) -> Result<(), String> {
        let mut line = serde_json::to_vec(row).map_err(|e| format!("encode a row: {e}"))?;
        line.push(b'\n');
        self.write(&line)
    }
}

/// UTC now as RFC 3339 with milliseconds.
pub(super) fn now_rfc3339() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let (year, month, day) = civil_from_days(i64::try_from(secs / 86_400).unwrap_or(0));
    let (hour, minute, second) = (secs % 86_400 / 3_600, secs % 3_600 / 60, secs % 60);
    let millis = now.subsec_millis();
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Days since 1970-01-01 as a proleptic Gregorian date (H. Hinnant's
/// `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// This machine's name: the kernel's, else `$HOSTNAME`, else `hostname`.
pub(super) fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| {
            std::process::Command::new("hostname")
                .stdin(std::process::Stdio::null())
                .output()
                .ok()
                .and_then(|out| String::from_utf8(out.stdout).ok())
        })
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}
