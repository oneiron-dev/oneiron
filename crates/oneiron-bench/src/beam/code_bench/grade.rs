//! `beam code-bench <attempts.json>`: grade what the writers left. Canon
//! (ARCH-0042 #code-bench): "Grading costs no prompts. The PR's tests, plus
//! diff size, elapsed time, turns, tokens and files opened. A failed run is
//! kept and counted." The grader is sealed from the writer: the PR's tests
//! are copied from its merge commit over whatever the writer left at those
//! paths, so a writer's own copy of a sealed test never grades.

use std::{
    collections::BTreeSet,
    fs::File,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use super::super::BeamResult;
use super::manifest::{Manifest, Task, invalid};
use super::pack::{git_ok, plan_manifest, world_subject};
use super::profile::{Arm, Check};
use super::transcript::{self, TranscriptMetrics};

const REPORT_SCHEMA: &str = "code-bench-report-v1";
const POLL: Duration = Duration::from_millis(200);

/// Paths are relative to this file's folder unless absolute.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptsFile {
    /// The run plan the cells were packed from.
    plan: PathBuf,
    attempts: Vec<Attempt>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    cell: String,
    /// The tree the writer left; for a collaboration writer, the integrated
    /// tree of its arm.
    tree: PathBuf,
    #[serde(default)]
    transcript: Option<PathBuf>,
    /// A repair names its own cell. Its first attempt stays in the report.
    #[serde(default)]
    repair_of: Option<String>,
}

struct CellRef {
    check: Check,
    task: String,
    arm: Arm,
    writer: Option<String>,
}

#[derive(Debug, Serialize)]
pub(in super::super) struct GradeReport {
    schema: &'static str,
    rows: Vec<Row>,
    arms: Vec<ArmSummary>,
}

/// One attempt, kept whether it passed or not.
#[derive(Debug, Serialize)]
struct Row {
    cell: String,
    check: Check,
    task: String,
    arm: Arm,
    writer: Option<String>,
    repair: bool,
    tests_pass: bool,
    timed_out: bool,
    profile_breach: bool,
    /// The sealed tests pass and no call left the arm's profile.
    pass: bool,
    /// Against the world, the sealed paths excluded.
    diff: DiffSize,
    transcript: Option<TranscriptMetrics>,
    /// The sealed tests' output.
    log: PathBuf,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
struct DiffSize {
    files: u64,
    added: u64,
    removed: u64,
}

/// One arm of one check. No statistics beyond medians and paired deltas:
/// "a clear gap is a finding; a small gap is 'no difference yet'" is the
/// reader's call on the result page.
#[derive(Debug, Serialize)]
struct ArmSummary {
    check: Check,
    arm: Arm,
    baseline: bool,
    attempts: usize,
    passes: usize,
    failures: usize,
    breaches: usize,
    repairs: usize,
    median: Medians,
    /// Per task, this arm's first attempts against the baseline arm's.
    paired: Vec<PairedTask>,
}

#[derive(Debug, Default, Serialize)]
struct Medians {
    diff_lines: Option<f64>,
    elapsed_secs: Option<f64>,
    turns: Option<f64>,
    tokens: Option<f64>,
    files_opened: Option<f64>,
}

#[derive(Debug, Serialize)]
struct PairedTask {
    task: String,
    pass: bool,
    baseline_pass: bool,
    /// This arm's median less the baseline's, per metric.
    delta: Medians,
}

pub(in super::super) fn grade(path: &Path) -> BeamResult<GradeReport> {
    let file: AttemptsFile = serde_json::from_slice(&std::fs::read(path)?)?;
    let folder = path.parent().unwrap_or(Path::new("."));
    let (manifest, repo) = plan_manifest(&folder.join(&file.plan))?;
    let cells = file
        .attempts
        .iter()
        .map(|attempt| parse_cell(&manifest, &attempt.cell))
        .collect::<BeamResult<Vec<_>>>()?;
    check_repairs(&manifest, &file.attempts, &cells)?;
    let mut rows = Vec::new();
    for (index, (attempt, cell)) in file.attempts.iter().zip(cells).enumerate() {
        rows.push(grade_attempt(
            &manifest, &repo, folder, attempt, cell, index,
        )?);
    }
    let arms = summarize(&manifest, &rows);
    Ok(GradeReport {
        schema: REPORT_SCHEMA,
        rows,
        arms,
    })
}

/// `<check>/<task>/<arm>` or `<check>/<task>/<arm>/<writer>`, as the pack
/// names its cells.
fn parse_cell(manifest: &Manifest, id: &str) -> BeamResult<CellRef> {
    let refuse = || invalid(format!("attempt cell `{id}` is not a cell of the manifest"));
    let parts: Vec<&str> = id.split('/').collect();
    let (check, task, arm, writer) = match parts.as_slice() {
        [check, task, arm] => (*check, *task, *arm, None),
        [check, task, arm, writer] => (*check, *task, *arm, Some(*writer)),
        _ => return Err(refuse()),
    };
    let check = Check::from_name(check).ok_or_else(refuse)?;
    let arm = Arm::from_name(arm).ok_or_else(refuse)?;
    let task = manifest.task(task).ok_or_else(refuse)?;
    let checks = &manifest.checks;
    let listed = match check {
        Check::Memory => checks.memory.arms.contains(&arm),
        Check::Navigation => checks.navigation.arms.contains(&arm),
        Check::Collaboration => checks.collaboration.arms.contains(&arm),
    };
    let writer_fits = match (check, writer) {
        (Check::Collaboration, Some(writer)) => {
            task.id == checks.collaboration.task
                && task
                    .collaboration
                    .as_ref()
                    .is_some_and(|split| split.parts.iter().any(|part| part.writer == writer))
        }
        (Check::Collaboration, None) => false,
        (_, writer) => writer.is_none(),
    };
    if !listed || !writer_fits {
        return Err(refuse());
    }
    Ok(CellRef {
        check,
        task: task.id.clone(),
        arm,
        writer: writer.map(str::to_owned),
    })
}

/// At most one repair per arm group, at most `repairs_max` in all, and a
/// repair stands beside its first attempt. A collaboration repair reruns
/// every writer of its arm, so each writer cell may carry one.
fn check_repairs(manifest: &Manifest, attempts: &[Attempt], cells: &[CellRef]) -> BeamResult<()> {
    let mut groups = BTreeSet::new();
    let mut repaired = BTreeSet::new();
    let mut repairs = 0;
    for (attempt, cell) in attempts.iter().zip(cells) {
        let Some(of) = &attempt.repair_of else {
            continue;
        };
        if *of != attempt.cell {
            return Err(invalid(format!(
                "attempt `{}` names repair_of `{of}`; a repair names its own cell",
                attempt.cell
            )));
        }
        if !attempts
            .iter()
            .any(|first| first.cell == attempt.cell && first.repair_of.is_none())
        {
            return Err(invalid(format!(
                "the repair of `{of}` has no first attempt beside it"
            )));
        }
        let group = format!("{}/{}", cell.check.as_str(), cell.arm.as_str());
        let new_cell = repaired.insert(attempt.cell.as_str());
        let new_group = groups.insert(group.clone());
        if !(new_group || (cell.check == Check::Collaboration && new_cell)) {
            return Err(invalid(format!(
                "a second repair in arm group {group}: at most one per arm group"
            )));
        }
        if new_group {
            repairs += 1;
        }
        if repairs > manifest.checks.repairs_max {
            return Err(invalid(format!(
                "{repairs} repairs exceed repairs_max {}",
                manifest.checks.repairs_max
            )));
        }
    }
    Ok(())
}

fn grade_attempt(
    manifest: &Manifest,
    repo: &Path,
    folder: &Path,
    attempt: &Attempt,
    cell: CellRef,
    index: usize,
) -> BeamResult<Row> {
    let task = manifest
        .task(&cell.task)
        .ok_or_else(|| invalid(format!("no task `{}`", cell.task)))?;
    let tree = folder.join(&attempt.tree);
    check_world(&tree, task)?;
    let diff = diff_size(&tree, &task.sealed)?;
    let log = folder.join(format!("code-bench-grade-{index}.log"));
    let (tests_pass, timed_out) = run_sealed_tests(repo, task, &tree, manifest.cap_minutes, &log)?;
    let transcript = attempt
        .transcript
        .as_ref()
        .map(|path| transcript::read(&folder.join(path), cell.arm))
        .transpose()?;
    let profile_breach = transcript
        .as_ref()
        .is_some_and(|metrics| !metrics.breaches.is_empty());
    Ok(Row {
        cell: attempt.cell.clone(),
        check: cell.check,
        task: cell.task,
        arm: cell.arm,
        writer: cell.writer,
        repair: attempt.repair_of.is_some(),
        tests_pass,
        timed_out,
        profile_breach,
        pass: tests_pass && !profile_breach,
        diff,
        transcript,
        log,
    })
}

/// The tree must grow from the task's world: its one root commit is the
/// commit `world.sh` made.
fn check_world(tree: &Path, task: &Task) -> BeamResult<()> {
    let expected = world_subject(task);
    let roots = git_stdout(tree, &["log", "--max-parents=0", "--format=%s", "HEAD"])?;
    if roots.as_deref().map(str::trim) != Some(expected.as_str()) {
        return Err(invalid(format!(
            "tree {} does not grow from the world of task `{}` (root commit `{expected}`)",
            tree.display(),
            task.id
        )));
    }
    Ok(())
}

/// Files changed and lines added and removed against the world, new files
/// included, the sealed paths excluded.
fn diff_size(tree: &Path, sealed: &[String]) -> BeamResult<DiffSize> {
    let root = git_stdout(tree, &["rev-list", "--max-parents=0", "HEAD"])?
        .and_then(|roots| roots.lines().next().map(str::to_owned))
        .ok_or_else(|| invalid(format!("no root commit in {}", tree.display())))?;
    if !git_ok(tree, &["add", "--intent-to-add", "--", "."])? {
        return Err(invalid(format!(
            "git add --intent-to-add failed in {}",
            tree.display()
        )));
    }
    let mut args = vec![
        "diff".to_owned(),
        "--numstat".to_owned(),
        root,
        "--".to_owned(),
        ".".to_owned(),
    ];
    args.extend(sealed.iter().map(|path| format!(":(exclude){path}")));
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let numstat = git_stdout(tree, &args)?
        .ok_or_else(|| invalid(format!("git diff failed in {}", tree.display())))?;
    let mut diff = DiffSize::default();
    for line in numstat.lines() {
        let mut fields = line.split('\t');
        let (Some(added), Some(removed), Some(_)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        diff.files += 1;
        // Binary files show `-`: counted as a file, with no lines.
        diff.added += added.parse::<u64>().unwrap_or(0);
        diff.removed += removed.parse::<u64>().unwrap_or(0);
    }
    Ok(diff)
}

/// Copies each sealed test from the merge commit over the tree (a path the
/// merge commit lacks is removed), then runs the PR's tests in the tree
/// within the cap. Returns (pass, timed out).
fn run_sealed_tests(
    repo: &Path,
    task: &Task,
    tree: &Path,
    cap_minutes: u32,
    log: &Path,
) -> BeamResult<(bool, bool)> {
    for path in &task.sealed {
        let target = sealed_target(tree, path)?;
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .arg("show")
            .arg(format!("{}:{path}", task.merged))
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()?;
        if output.status.success() {
            std::fs::write(&target, &output.stdout)?;
        }
    }
    let mut log_file = File::create(log)?;
    let deadline = Instant::now() + Duration::from_secs(u64::from(cap_minutes) * 60);
    for test in &task.tests {
        let Some((program, args)) = test.argv.split_first() else {
            return Ok((false, false));
        };
        let spawned = Command::new(program)
            .args(args)
            .envs(&test.env)
            .current_dir(tree)
            .stdin(Stdio::null())
            .stdout(log_file.try_clone()?)
            .stderr(log_file.try_clone()?)
            .spawn();
        let mut child = match spawned {
            Ok(child) => child,
            Err(error) => {
                writeln!(log_file, "code-bench: `{program}` did not start: {error}")?;
                return Ok((false, false));
            }
        };
        loop {
            if let Some(status) = child.try_wait()? {
                if !status.success() {
                    return Ok((false, false));
                }
                break;
            }
            if Instant::now() >= deadline {
                // The child may have exited between the two checks.
                let _ = child.kill();
                child.wait()?;
                writeln!(
                    log_file,
                    "code-bench: the {cap_minutes}-minute cap ended the tests"
                )?;
                return Ok((false, true));
            }
            std::thread::sleep(POLL);
        }
    }
    Ok((true, false))
}

/// The sealed path inside the tree, its folders made real: a writer's
/// symlink or file in the way is removed, so the grader's copy never lands
/// outside the tree. Whatever the writer left at the path itself is removed.
fn sealed_target(tree: &Path, relative: &str) -> BeamResult<PathBuf> {
    let mut at = tree.to_path_buf();
    let mut parts = relative.split('/').peekable();
    while let Some(part) = parts.next() {
        at.push(part);
        if parts.peek().is_none() {
            break;
        }
        match std::fs::symlink_metadata(&at) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                std::fs::remove_file(&at)?;
                std::fs::create_dir(&at)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir(&at)?,
            Err(error) => return Err(error.into()),
        }
    }
    match std::fs::symlink_metadata(&at) {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(&at)?,
        Ok(_) => std::fs::remove_file(&at)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(at)
}

/// Git's stdout, or `None` when the command fails.
fn git_stdout(tree: &Path, args: &[&str]) -> BeamResult<Option<String>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(tree)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    Ok(output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned()))
}

fn summarize(manifest: &Manifest, rows: &[Row]) -> Vec<ArmSummary> {
    let checks = &manifest.checks;
    let mut lines: Vec<(Check, Arm)> = Vec::new();
    lines.extend(checks.memory.arms.iter().map(|arm| (Check::Memory, *arm)));
    lines.extend(
        checks
            .navigation
            .arms
            .iter()
            .map(|arm| (Check::Navigation, *arm)),
    );
    lines.push((Check::Navigation, checks.navigation.third));
    lines.extend(
        checks
            .collaboration
            .arms
            .iter()
            .map(|arm| (Check::Collaboration, *arm)),
    );
    lines
        .into_iter()
        .map(|(check, arm)| summarize_arm(manifest, rows, check, arm))
        .collect()
}

/// A row counts for a check's arm; the navigation check's third arm is the
/// memory check's cell, run once.
fn counts_for(row: &Row, check: Check, arm: Arm, third: Arm) -> bool {
    row.arm == arm
        && (row.check == check
            || (check == Check::Navigation && arm == third && row.check == Check::Memory))
}

fn summarize_arm(manifest: &Manifest, rows: &[Row], check: Check, arm: Arm) -> ArmSummary {
    let third = manifest.checks.navigation.third;
    let baseline = check.baseline();
    let mine: Vec<&Row> = rows
        .iter()
        .filter(|row| counts_for(row, check, arm, third))
        .collect();
    let mut paired = Vec::new();
    if arm != baseline {
        for task in &manifest.tasks {
            let first = |line_arm: Arm| {
                rows.iter()
                    .filter(|row| {
                        counts_for(row, check, line_arm, third)
                            && row.task == task.id
                            && !row.repair
                    })
                    .collect::<Vec<&Row>>()
            };
            let (ours, theirs) = (first(arm), first(baseline));
            if ours.is_empty() || theirs.is_empty() {
                continue;
            }
            paired.push(PairedTask {
                task: task.id.clone(),
                pass: ours.iter().all(|row| row.pass),
                baseline_pass: theirs.iter().all(|row| row.pass),
                delta: medians(&ours).minus(&medians(&theirs)),
            });
        }
    }
    let passes = mine.iter().filter(|row| row.pass).count();
    ArmSummary {
        check,
        arm,
        baseline: arm == baseline,
        attempts: mine.len(),
        passes,
        failures: mine.len() - passes,
        breaches: mine.iter().filter(|row| row.profile_breach).count(),
        repairs: mine.iter().filter(|row| row.repair).count(),
        median: medians(&mine),
        paired,
    }
}

fn medians(rows: &[&Row]) -> Medians {
    let metric =
        |value: fn(&Row) -> Option<f64>| median(rows.iter().filter_map(|row| value(row)).collect());
    Medians {
        diff_lines: metric(|row| Some((row.diff.added + row.diff.removed) as f64)),
        elapsed_secs: metric(|row| row.transcript.as_ref()?.elapsed_secs),
        turns: metric(|row| Some(row.transcript.as_ref()?.turns as f64)),
        tokens: metric(|row| {
            let transcript = row.transcript.as_ref()?;
            Some((transcript.input_tokens + transcript.output_tokens) as f64)
        }),
        files_opened: metric(|row| Some(row.transcript.as_ref()?.files_opened as f64)),
    }
}

fn median(mut values: Vec<f64>) -> Option<f64> {
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    match values.len() {
        0 => None,
        length if length.is_multiple_of(2) => Some((values[middle - 1] + values[middle]) / 2.0),
        _ => Some(values[middle]),
    }
}

impl Medians {
    fn minus(&self, other: &Self) -> Self {
        let delta = |ours: Option<f64>, theirs: Option<f64>| {
            ours.zip(theirs).map(|(ours, theirs)| ours - theirs)
        };
        Self {
            diff_lines: delta(self.diff_lines, other.diff_lines),
            elapsed_secs: delta(self.elapsed_secs, other.elapsed_secs),
            turns: delta(self.turns, other.turns),
            tokens: delta(self.tokens, other.tokens),
            files_opened: delta(self.files_opened, other.files_opened),
        }
    }
}
