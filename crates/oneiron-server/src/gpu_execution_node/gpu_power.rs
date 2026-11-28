//! The card's power limit during a run (row GPU-QUIET-LEASE, ANSWER
//! GPU-QUIET-LEASE-FLEET = A): a template's `gpu_power_watts` (neon's timing
//! jobs: 450 W on mel's 4090).
//!
//! Only the job unit's root steps touch the limit, never the engine's
//! account, and the unit's end is the service manager's, not the engine's:
//! - the prepare step (`ExecStartPre=+`), as its last act before the
//!   workload can exist, reads each leased card's limit, writes a root record
//!   of it under [`POWER_RECORDS_DIR`], and only then sets the template's
//!   watts. A card that refuses the limit ends the prepare step
//!   `power_not_applied`, with every limit it set put back;
//! - the end step (`ExecStopPost=+`) puts back each limit its own instance
//!   set and removes its record. The service manager runs it after every end
//!   of the unit: an exit, the cutoff timer's stop at the time limit, the
//!   engine's stop at a revoke or a stop, and a prepare step that failed. An
//!   engine that crashes mid-job does not end the unit, whose end step still
//!   runs at its end;
//! - a record that outlives its end step (one that died, or a card that
//!   refused the put-back) is put back by the next prepare step on that card,
//!   before it reads the card, whatever that run's template asks. The records
//!   live in `/run`, which a host reset empties as the driver resets each
//!   card's limit.
//!
//! The limit put back is the one the card had before the run (`power.limit`
//! as the prepare step read it), so a limit the host's owner set stays.
//! NVIDIA cards only: the limit is `nvidia-smi -i <id> -pl <watts>`.

use std::io::Write as _;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::jobs::LaunchFile;
use super::node_settings::NodeTemplate;
use super::scope_systemd::systemd_unit::run_tool;

/// The root-owned directory (mode 0700) of the power records, one per card a
/// run set: `<device id>.json`.
pub const POWER_RECORDS_DIR: &str = "/run/oneiron-gpu-power";

/// The longest one `nvidia-smi` call may take.
const POWER_TOOL_TIMEOUT: Duration = Duration::from_secs(15);

/// The largest power record, in bytes.
const RECORD_MAX_BYTES: u64 = 4096;

/// The card's power limits, in milliwatts, as its driver reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerLimits {
    pub current_mw: u64,
    pub min_mw: u64,
    pub max_mw: u64,
}

/// Reads and sets a card's power limit.
pub trait PowerTool {
    /// The card's limits now.
    ///
    /// # Errors
    ///
    /// The tool did not answer, or its answer does not read.
    fn limits(&self, device: &str) -> Result<PowerLimits, String>;

    /// Sets the card's limit to `mw` milliwatts.
    ///
    /// # Errors
    ///
    /// The tool refused or did not answer.
    fn set_limit(&self, device: &str, mw: u64) -> Result<(), String>;
}

/// The shipped tool: `nvidia-smi`, found in the system's tool directories and
/// run with a clean environment.
#[derive(Debug, Clone, Copy, Default)]
pub struct NvidiaSmiPower;

impl PowerTool for NvidiaSmiPower {
    fn limits(&self, device: &str) -> Result<PowerLimits, String> {
        let text = run_tool(
            "nvidia-smi",
            &[
                "-i",
                device,
                "--query-gpu=power.limit,power.min_limit,power.max_limit",
                "--format=csv,noheader,nounits",
            ],
            POWER_TOOL_TIMEOUT,
        )?;
        parse_limits(&text)
    }

    fn set_limit(&self, device: &str, mw: u64) -> Result<(), String> {
        run_tool(
            "nvidia-smi",
            &["-i", device, "-pl", &watts_text(mw)],
            POWER_TOOL_TIMEOUT,
        )
        .map(drop)
    }
}

/// `nvidia-smi`'s one line `<limit>, <min>, <max>`, in watts.
///
/// # Errors
///
/// The text is not one line of three wattages.
pub fn parse_limits(text: &str) -> Result<PowerLimits, String> {
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    let (Some(line), None) = (lines.next(), lines.next()) else {
        return Err(format!("power limits not one line: {text:?}"));
    };
    let values: Vec<u64> = line
        .split(',')
        .map(|word| milliwatts(word.trim()))
        .collect::<Option<_>>()
        .ok_or_else(|| format!("power limits not wattages: {line:?}"))?;
    match values[..] {
        [current_mw, min_mw, max_mw] => Ok(PowerLimits {
            current_mw,
            min_mw,
            max_mw,
        }),
        _ => Err(format!("power limits not three wattages: {line:?}")),
    }
}

/// `450.00` (watts, at most three decimals) in milliwatts.
fn milliwatts(text: &str) -> Option<u64> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty()
        || fraction.len() > 3
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let fraction = format!("{fraction:0<3}");
    whole
        .parse::<u64>()
        .ok()?
        .checked_mul(1000)?
        .checked_add(fraction.parse::<u64>().ok()?)
}

/// `mw` as `nvidia-smi -pl` takes it, in watts.
fn watts_text(mw: u64) -> String {
    match mw % 1000 {
        0 => (mw / 1000).to_string(),
        rest => format!("{}.{rest:03}", mw / 1000),
    }
}

/// What a run set on one card, and the limit it found there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PowerRecord {
    /// The job unit's instance that set it.
    pub instance: String,
    pub device: String,
    /// The card's limit before the run, in milliwatts: what goes back.
    pub before_mw: u64,
    /// The limit the run set, in milliwatts.
    pub set_mw: u64,
}

/// The prepare step's power act, its last before the workload: the
/// template's `gpu_power_watts` on each card `launch` leases.
///
/// # Errors
///
/// `power_not_applied: ...` (or `power_not_restored: ...` for a record an
/// earlier run left that its card refused to take back), with every limit
/// this step set put back.
pub fn apply_at_prepare(
    launch: &LaunchFile,
    template: &NodeTemplate,
    instance: &str,
) -> Result<(), String> {
    let devices: Vec<String> = launch
        .devices
        .iter()
        .map(|lease| lease.device_id.clone())
        .collect();
    apply(
        &NvidiaSmiPower,
        Path::new(POWER_RECORDS_DIR),
        instance,
        &devices,
        template.gpu_power_watts,
    )
}

/// The end step's power act: puts back every limit `instance` set. A
/// failure is written to the unit's journal and its record stays for the
/// card's next prepare step.
pub fn restore_at_end(instance: &str) {
    if let Err(why) = restore(&NvidiaSmiPower, Path::new(POWER_RECORDS_DIR), instance) {
        journal(&format!("job-ended: {instance}: {why}"));
    }
}

/// Sets `watts` on each of `devices` for `instance`, recorded under `dir`
/// first. Each card's record from an earlier run is put back before, with or
/// without `watts`.
///
/// # Errors
///
/// As [`apply_at_prepare`].
pub fn apply(
    tool: &dyn PowerTool,
    dir: &Path,
    instance: &str,
    devices: &[String],
    watts: Option<u32>,
) -> Result<(), String> {
    for device in devices {
        if let Err(why) = restore_device(tool, dir, device) {
            if watts.is_some() {
                return Err(format!("power_not_restored: {why}"));
            }
            journal(&format!("job-prepare: {instance}: {why}"));
        }
    }
    let Some(watts) = watts else {
        return Ok(());
    };
    let set = devices
        .iter()
        .try_for_each(|device| set_device(tool, dir, instance, device, watts));
    if let Err(why) = set {
        if let Err(back) = restore(tool, dir, instance) {
            journal(&format!("job-prepare: {instance}: {back}"));
        }
        return Err(format!("power_not_applied: {why}"));
    }
    Ok(())
}

fn set_device(
    tool: &dyn PowerTool,
    dir: &Path,
    instance: &str,
    device: &str,
    watts: u32,
) -> Result<(), String> {
    let path = record_path(dir, device)?;
    let limits = tool
        .limits(device)
        .map_err(|why| format!("{device}: {why}"))?;
    let set_mw = u64::from(watts).saturating_mul(1000);
    if set_mw < limits.min_mw || set_mw > limits.max_mw {
        return Err(format!(
            "{device}: {watts} W is outside the card's {} to {} W",
            watts_text(limits.min_mw),
            watts_text(limits.max_mw)
        ));
    }
    let record = PowerRecord {
        instance: instance.to_owned(),
        device: device.to_owned(),
        before_mw: limits.current_mw,
        set_mw,
    };
    write_record(dir, &path, &record).map_err(|why| format!("{device}: record: {why}"))?;
    if let Err(why) = tool.set_limit(device, set_mw) {
        // A failed call may still have changed the card (the deadline killed
        // the tool after the driver took the limit). The record goes only
        // while the card reads at the limit it had; otherwise it stays for
        // the put-back, which removes it once the card takes its limit back.
        let _ = std::fs::remove_file(&path);
        return Err(format!("{device}: {why}"));
    }
    Ok(())
}

/// Puts back every limit `instance` set under `dir` and removes each record
/// put back.
///
/// # Errors
///
/// The records do not list, or a card refused its limit back: its record
/// stays.
pub fn restore(tool: &dyn PowerTool, dir: &Path, instance: &str) -> Result<(), String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("power records not listed: {error}")),
    };
    let mut failed = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        match read_record(&path) {
            Ok(record) if record.instance == instance => {
                if let Err(why) = put_back(tool, &path, &record) {
                    failed.push(why);
                }
            }
            Ok(_) => {}
            Err(why) => failed.push(why),
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("power_not_restored: {}", failed.join("; ")))
    }
}

/// Puts back the limit a record under `dir` holds for `device`, whichever
/// run wrote it.
fn restore_device(tool: &dyn PowerTool, dir: &Path, device: &str) -> Result<(), String> {
    let path = record_path(dir, device)?;
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("{device}: record: {error}")),
    }
    let record = read_record(&path)?;
    put_back(tool, &path, &record)
}

fn put_back(tool: &dyn PowerTool, path: &Path, record: &PowerRecord) -> Result<(), String> {
    tool.set_limit(&record.device, record.before_mw)
        .map_err(|why| format!("{}: {why}", record.device))?;
    std::fs::remove_file(path).map_err(|error| format!("{}: record: {error}", record.device))
}

/// `<dir>/<device>.json`, for a device id of plain characters only.
fn record_path(dir: &Path, device: &str) -> Result<PathBuf, String> {
    let plain = !device.is_empty()
        && device.len() <= 128
        && !device.starts_with('.')
        && device
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'));
    if plain {
        Ok(dir.join(format!("{device}.json")))
    } else {
        Err(format!("power_device_id_unusable: {device:?}"))
    }
}

fn read_record(path: &Path) -> Result<PowerRecord, String> {
    let file = std::fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(file, RECORD_MAX_BYTES), &mut bytes)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))
}

/// Writes the record whole beside its place and renames it in, in a
/// directory of mode 0700.
fn write_record(dir: &Path, path: &Path, record: &PowerRecord) -> Result<(), String> {
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.to_string()),
    }
    let bytes = serde_json::to_vec(record).map_err(|error| error.to_string())?;
    let staged = path.with_extension("json.new");
    let mut file = std::fs::File::create(&staged).map_err(|error| error.to_string())?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    std::fs::rename(&staged, path).map_err(|error| error.to_string())
}

/// One line to standard error, which the service manager files under the
/// step's unit.
fn journal(line: &str) {
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use super::*;

    const CARD: &str = "GPU-8b0c3d1e-0000-4000-8000-000000004090";
    const INSTANCE: &str = "0123456789abcdef0123456789abcdef";
    /// The limit the host's owner left on the card.
    const OWNER_MW: u64 = 300_000;

    /// Cards as a driver holds them: each limit, the cards that refuse a new
    /// one, and the cards whose next call takes the limit and still fails.
    #[derive(Default)]
    struct ScriptedCards {
        limits: Mutex<BTreeMap<String, u64>>,
        refusing: Mutex<Vec<String>>,
        taking_then_failing: Mutex<Vec<String>>,
    }

    impl ScriptedCards {
        fn limit(&self, device: &str) -> u64 {
            self.limits.lock().expect("the scripted cards")[device]
        }

        fn refuse(&self, device: &str) {
            self.refusing
                .lock()
                .expect("the scripted cards")
                .push(device.to_owned());
        }

        fn accept(&self, device: &str) {
            self.refusing
                .lock()
                .expect("the scripted cards")
                .retain(|id| id != device);
        }

        /// The card's next call takes the limit, then fails as a call the
        /// tool's deadline killed.
        fn take_then_fail(&self, device: &str) {
            self.taking_then_failing
                .lock()
                .expect("the scripted cards")
                .push(device.to_owned());
        }
    }

    impl PowerTool for ScriptedCards {
        fn limits(&self, device: &str) -> Result<PowerLimits, String> {
            let current_mw = *self
                .limits
                .lock()
                .expect("ok")
                .get(device)
                .ok_or_else(|| format!("no card {device}"))?;
            Ok(PowerLimits {
                current_mw,
                min_mw: 150_000,
                max_mw: 450_000,
            })
        }

        fn set_limit(&self, device: &str, mw: u64) -> Result<(), String> {
            let mut taking = self.taking_then_failing.lock().expect("the scripted cards");
            if let Some(at) = taking.iter().position(|id| id == device) {
                taking.remove(at);
                self.limits
                    .lock()
                    .expect("the scripted cards")
                    .insert(device.to_owned(), mw);
                return Err("nvidia-smi timed out after 15 s".to_owned());
            }
            drop(taking);
            if self
                .refusing
                .lock()
                .expect("the scripted cards")
                .iter()
                .any(|id| id == device)
            {
                return Err("Changing power management limit is not supported".to_owned());
            }
            self.limits
                .lock()
                .expect("the scripted cards")
                .insert(device.to_owned(), mw);
            Ok(())
        }
    }

    fn cards(list: &[(&str, u64)]) -> ScriptedCards {
        let cards = ScriptedCards::default();
        cards
            .limits
            .lock()
            .expect("ok")
            .extend(list.iter().map(|(id, mw)| ((*id).to_owned(), *mw)));
        cards
    }

    fn records(dir: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(dir)
            .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default()
    }

    fn devices(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|id| (*id).to_owned()).collect()
    }

    /// Exit, time limit, revoke and stop: each ends the unit, and the service
    /// manager then runs its end step, which puts back the limit the run
    /// found and leaves no record.
    #[test]
    fn a_run_sets_the_cards_power_and_its_end_step_puts_the_owners_limit_back() {
        let dir = tempfile::tempdir().expect("ok");
        let cards = cards(&[(CARD, OWNER_MW)]);
        apply(&cards, dir.path(), INSTANCE, &devices(&[CARD]), Some(450)).expect("ok");
        assert_eq!(cards.limit(CARD), 450_000);
        let record = read_record(&dir.path().join(format!("{CARD}.json"))).expect("ok");
        assert_eq!(
            record,
            PowerRecord {
                instance: INSTANCE.to_owned(),
                device: CARD.to_owned(),
                before_mw: OWNER_MW,
                set_mw: 450_000,
            }
        );

        // Another instance's end step changes nothing.
        restore(&cards, dir.path(), "ffffffffffffffffffffffffffffffff").expect("ok");
        assert_eq!(cards.limit(CARD), 450_000);

        restore(&cards, dir.path(), INSTANCE).expect("ok");
        assert_eq!(cards.limit(CARD), OWNER_MW);
        assert!(records(dir.path()).is_empty());
        // A second run of the end step finds nothing to do.
        restore(&cards, dir.path(), INSTANCE).expect("ok");
        assert_eq!(cards.limit(CARD), OWNER_MW);
    }

    /// A refused prepare: a card that takes no new limit ends the step
    /// `power_not_applied`, and the limit already set on the run's other card
    /// goes back before the step returns.
    #[test]
    fn a_refused_prepare_puts_back_every_limit_it_set() {
        let dir = tempfile::tempdir().expect("ok");
        let second = "GPU-8b0c3d1e-0000-4000-8000-000000004091";
        let cards = cards(&[(CARD, OWNER_MW), (second, 250_000)]);
        cards.refuse(second);
        let why = apply(
            &cards,
            dir.path(),
            INSTANCE,
            &devices(&[CARD, second]),
            Some(450),
        )
        .expect_err("refused");
        assert!(why.starts_with("power_not_applied: "), "{why}");
        assert_eq!(cards.limit(CARD), OWNER_MW);
        assert_eq!(cards.limit(second), 250_000);
        assert!(records(dir.path()).is_empty());

        // A limit outside the card's range is refused before anything is set.
        let why =
            apply(&cards, dir.path(), INSTANCE, &devices(&[CARD]), Some(600)).expect_err("refused");
        assert!(
            why.contains("600 W is outside the card's 150 to 450 W"),
            "{why}"
        );
        assert_eq!(cards.limit(CARD), OWNER_MW);
        assert!(records(dir.path()).is_empty());
    }

    /// A crash mid-job whose end step never put the limit back: the record
    /// stays, and the next prepare step on that card puts it back before it
    /// reads the card, for a run that sets its own limit and for one that
    /// sets none.
    #[test]
    fn a_limit_a_dead_end_step_left_is_put_back_at_the_next_start_on_that_card() {
        let dir = tempfile::tempdir().expect("ok");
        let cards = cards(&[(CARD, OWNER_MW)]);
        apply(&cards, dir.path(), INSTANCE, &devices(&[CARD]), Some(450)).expect("ok");
        // The end step dies: nothing puts the limit back.

        // The next run on the card sets no limit: the card goes back to the
        // owner's limit and no record stays.
        let next = "11111111111111111111111111111111";
        apply(&cards, dir.path(), next, &devices(&[CARD]), None).expect("ok");
        assert_eq!(cards.limit(CARD), OWNER_MW);
        assert!(records(dir.path()).is_empty());

        // The same with a run that sets its own: its record names the
        // owner's limit, not the dead run's.
        apply(&cards, dir.path(), INSTANCE, &devices(&[CARD]), Some(450)).expect("ok");
        apply(&cards, dir.path(), next, &devices(&[CARD]), Some(400)).expect("ok");
        assert_eq!(cards.limit(CARD), 400_000);
        let record = read_record(&dir.path().join(format!("{CARD}.json"))).expect("ok");
        assert_eq!(record.before_mw, OWNER_MW);
        assert_eq!(record.instance, next);
        restore(&cards, dir.path(), next).expect("ok");
        assert_eq!(cards.limit(CARD), OWNER_MW);
    }

    /// A card that refuses its limit back keeps its record, so the next
    /// prepare step tries again; a run that sets its own limit is then
    /// refused rather than record a wrong limit to put back.
    #[test]
    fn a_limit_the_card_refuses_back_keeps_its_record_for_the_next_start() {
        let dir = tempfile::tempdir().expect("ok");
        let cards = cards(&[(CARD, OWNER_MW)]);
        apply(&cards, dir.path(), INSTANCE, &devices(&[CARD]), Some(450)).expect("ok");
        cards.refuse(CARD);
        let why = restore(&cards, dir.path(), INSTANCE).expect_err("refused");
        assert!(why.starts_with("power_not_restored: "), "{why}");
        assert_eq!(records(dir.path()).len(), 1);
        let why = apply(
            &cards,
            dir.path(),
            "22222222222222222222222222222222",
            &devices(&[CARD]),
            Some(400),
        )
        .expect_err("refused");
        assert!(why.starts_with("power_not_restored: "), "{why}");
        assert_eq!(records(dir.path()).len(), 1);
    }

    /// A card that took the new limit although the call failed (the tool's
    /// deadline killed it after the driver took the limit) keeps its record:
    /// the prepare step's put-back restores the owner's limit and only then
    /// removes it. When the card refuses that too, the record stays for the
    /// end step and the card's next start.
    #[test]
    fn a_limit_the_card_took_before_its_call_failed_is_put_back_from_its_record() {
        let dir = tempfile::tempdir().expect("ok");
        let cards = cards(&[(CARD, OWNER_MW)]);
        cards.take_then_fail(CARD);
        let why =
            apply(&cards, dir.path(), INSTANCE, &devices(&[CARD]), Some(450)).expect_err("failed");
        assert!(why.starts_with("power_not_applied: "), "{why}");
        assert_eq!(cards.limit(CARD), OWNER_MW);
        assert!(records(dir.path()).is_empty());

        cards.take_then_fail(CARD);
        cards.refuse(CARD);
        let why =
            apply(&cards, dir.path(), INSTANCE, &devices(&[CARD]), Some(450)).expect_err("failed");
        assert!(why.starts_with("power_not_applied: "), "{why}");
        assert_eq!(cards.limit(CARD), 450_000);
        let record = read_record(&dir.path().join(format!("{CARD}.json"))).expect("the record");
        assert_eq!(record.before_mw, OWNER_MW);
        cards.accept(CARD);
        restore(&cards, dir.path(), INSTANCE).expect("ok");
        assert_eq!(cards.limit(CARD), OWNER_MW);
        assert!(records(dir.path()).is_empty());
    }

    #[test]
    fn nvidia_smi_limits_read_in_milliwatts_and_go_back_in_watts() {
        assert_eq!(
            parse_limits("450.00, 150.00, 600.00\n").expect("ok"),
            PowerLimits {
                current_mw: 450_000,
                min_mw: 150_000,
                max_mw: 600_000,
            }
        );
        assert!(parse_limits("[N/A], 150.00, 600.00").is_err());
        assert!(parse_limits("450.00, 150.00\n450.00, 150.00, 600.00").is_err());
        assert_eq!(watts_text(450_000), "450");
        assert_eq!(watts_text(287_500), "287.500");
        assert!(record_path(Path::new("/run/x"), "../etc/passwd").is_err());
        assert!(record_path(Path::new("/run/x"), "00000000:01:00.0").is_ok());
    }
}
