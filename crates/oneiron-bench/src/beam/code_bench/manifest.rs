//! The CODE-BENCH task manifest (`fixtures/code_bench.tasks.v1.json`): three
//! merged PRs of our repo, each with its world, intent and sealed tests, and
//! ARCH-0042's table as data. Canon: "A task is more than a trace. Each task
//! carries its world (a commit to rebuild), its intent, its tools and its
//! grader: the PR's own tests."

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::super::{BeamError, BeamResult};
use super::profile::{Arm, Check};

const MANIFEST_VERSION: u32 = 1;
/// Canon: "3 merged PRs from our repos, after a cut date".
const TASK_COUNT: usize = 3;
/// The name a manifest refusal carries.
const MANIFEST_ID: &str = "code-bench";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    version: u32,
    pub(super) repo: String,
    /// RFC 3339. Every task merged after it; no memory may reach past it.
    pub(super) cut: String,
    /// The same cap holds in every arm.
    pub(super) cap_minutes: u32,
    /// Canon: "about 30 agent prompts in total".
    pub(super) prompt_budget: usize,
    pub(super) tasks: Vec<Task>,
    pub(super) checks: Checks,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Task {
    /// A path component of every cell of the task.
    pub(super) id: String,
    pub(super) pr: u64,
    /// The PR's first parent: the world the writer starts from.
    pub(super) base: String,
    /// The PR's merge commit: the grader copies the sealed tests from it.
    pub(super) merged: String,
    /// Written by the task's prep prompt; `null` marks every cell of the
    /// task not ready.
    pub(super) intent: Option<String>,
    /// The PR's own tests; pass means every command exits 0.
    pub(super) tests: Vec<TestCommand>,
    /// The PR's test files: never in the writer's world.
    pub(super) sealed: Vec<String>,
    #[serde(default)]
    pub(super) collaboration: Option<Collaboration>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TestCommand {
    pub(super) argv: Vec<String>,
    #[serde(default)]
    pub(super) env: BTreeMap<String, String>,
}

/// The collaboration task split into one part per writer.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Collaboration {
    pub(super) parts: Vec<WriterPart>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WriterPart {
    /// A path component of the writer's cell.
    pub(super) writer: String,
    pub(super) intent: Option<String>,
    /// The files this part changes; the parts overlap by design.
    pub(super) files: Vec<String>,
}

/// ARCH-0042's table: memory, navigation and collaboration, the prep
/// prompts and the repairs cap.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Checks {
    pub(super) memory: ArmCheck,
    pub(super) navigation: NavigationCheck,
    pub(super) collaboration: CollaborationCheck,
    /// One prompt per task: rebuild the world, check the tests grade it,
    /// write the intent.
    pub(super) prep: usize,
    /// "At most one per arm group", capped in all.
    pub(super) repairs_max: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArmCheck {
    pub(super) arms: Vec<Arm>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NavigationCheck {
    pub(super) arms: Vec<Arm>,
    /// Canon: "the codemap run is the third arm": the memory check's cell,
    /// run once and shared.
    pub(super) third: Arm,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CollaborationCheck {
    pub(super) arms: Vec<Arm>,
    /// The task with overlapping files.
    pub(super) task: String,
    pub(super) writers: usize,
}

/// The prompts the manifest plans: cells, prep and the repairs cap.
#[derive(Debug, Clone, Copy, Serialize)]
pub(super) struct PromptPlan {
    pub(super) cells: usize,
    pub(super) prep: usize,
    pub(super) repairs_max: usize,
    pub(super) planned: usize,
    pub(super) budget: usize,
}

impl Manifest {
    pub(super) fn parse(text: &str) -> BeamResult<Self> {
        let manifest: Self = serde_json::from_str(text)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub(super) fn task(&self, id: &str) -> Option<&Task> {
        self.tasks.iter().find(|task| task.id == id)
    }

    /// The cut, in seconds since the Unix epoch.
    pub(super) fn cut_seconds(&self) -> BeamResult<i64> {
        rfc3339_seconds(&self.cut)
            .ok_or_else(|| invalid(format!("cut `{}` is not RFC 3339", self.cut)))
    }

    pub(super) fn prompt_plan(&self) -> PromptPlan {
        let tasks = self.tasks.len();
        let checks = &self.checks;
        let cells = checks.memory.arms.len() * tasks
            + checks.navigation.arms.len() * tasks
            + checks.collaboration.arms.len() * checks.collaboration.writers;
        PromptPlan {
            cells,
            prep: checks.prep,
            repairs_max: checks.repairs_max,
            planned: cells + checks.prep + checks.repairs_max,
            budget: self.prompt_budget,
        }
    }

    fn validate(&self) -> BeamResult<()> {
        if self.version != MANIFEST_VERSION {
            return Err(invalid(format!(
                "version {}; expected {MANIFEST_VERSION}",
                self.version
            )));
        }
        self.cut_seconds()?;
        if self.cap_minutes == 0 {
            return Err(invalid("cap_minutes must be above 0".to_owned()));
        }
        if self.tasks.len() != TASK_COUNT {
            return Err(invalid(format!(
                "{} tasks; the table names exactly {TASK_COUNT}",
                self.tasks.len()
            )));
        }
        let mut ids = BTreeSet::new();
        for task in &self.tasks {
            validate_task(task)?;
            if !ids.insert(task.id.as_str()) {
                return Err(invalid(format!("task `{}` is listed twice", task.id)));
            }
        }
        self.validate_checks()?;
        let plan = self.prompt_plan();
        if plan.planned > plan.budget {
            return Err(invalid(format!(
                "{} planned prompts ({} cells + {} prep + repairs_max {}) exceed prompt_budget {}",
                plan.planned, plan.cells, plan.prep, plan.repairs_max, plan.budget
            )));
        }
        Ok(())
    }

    fn validate_checks(&self) -> BeamResult<()> {
        let checks = &self.checks;
        check_arms(Check::Memory, &checks.memory.arms)?;
        check_arms(Check::Navigation, &checks.navigation.arms)?;
        check_arms(Check::Collaboration, &checks.collaboration.arms)?;
        if !checks.memory.arms.contains(&checks.navigation.third) {
            return Err(invalid(format!(
                "navigation's third arm `{}` is not a memory arm, so no cell runs it",
                checks.navigation.third.as_str()
            )));
        }
        let collaboration = &checks.collaboration;
        if collaboration.writers == 0 {
            return Err(invalid("collaboration needs writers".to_owned()));
        }
        let task = self.task(&collaboration.task).ok_or_else(|| {
            invalid(format!(
                "collaboration names task `{}`, which is not listed",
                collaboration.task
            ))
        })?;
        let parts = task
            .collaboration
            .as_ref()
            .map_or(0, |split| split.parts.len());
        if parts != collaboration.writers {
            return Err(invalid(format!(
                "collaboration task `{}` has {parts} writer parts; the check names {} writers",
                task.id, collaboration.writers
            )));
        }
        if let Some(other) = self
            .tasks
            .iter()
            .find(|other| other.id != task.id && other.collaboration.is_some())
        {
            return Err(invalid(format!(
                "task `{}` has writer parts, but the collaboration check names `{}`",
                other.id, task.id
            )));
        }
        Ok(())
    }
}

fn validate_task(task: &Task) -> BeamResult<()> {
    if !is_path_name(&task.id) {
        return Err(invalid(format!(
            "task id `{}` must be lower-case letters, digits and dashes",
            task.id
        )));
    }
    for (field, commit) in [("base", &task.base), ("merged", &task.merged)] {
        if !is_full_commit(commit) {
            return Err(invalid(format!(
                "task `{}` {field} `{commit}` is not a full 40-hex commit",
                task.id
            )));
        }
    }
    if task.sealed.is_empty() {
        return Err(invalid(format!("task `{}` seals no test", task.id)));
    }
    for path in &task.sealed {
        if !is_relative_path(path) {
            return Err(invalid(format!(
                "task `{}` sealed path `{path}` must be relative, inside the tree",
                task.id
            )));
        }
    }
    if task.tests.is_empty() || task.tests.iter().any(|test| test.argv.is_empty()) {
        return Err(invalid(format!(
            "task `{}` needs at least one test command, each with an argv",
            task.id
        )));
    }
    if let Some(split) = &task.collaboration {
        let mut writers = BTreeSet::new();
        for part in &split.parts {
            if !is_path_name(&part.writer) || !writers.insert(part.writer.as_str()) {
                return Err(invalid(format!(
                    "task `{}` writer `{}` must be a unique lower-case name",
                    task.id, part.writer
                )));
            }
            if part.files.iter().any(|path| !is_relative_path(path)) {
                return Err(invalid(format!(
                    "task `{}` writer `{}` names a file outside the tree",
                    task.id, part.writer
                )));
            }
        }
    }
    Ok(())
}

fn check_arms(check: Check, arms: &[Arm]) -> BeamResult<()> {
    let distinct: BTreeSet<_> = arms.iter().collect();
    if arms.is_empty() || distinct.len() != arms.len() {
        return Err(invalid(format!(
            "the {} check needs distinct arms",
            check.as_str()
        )));
    }
    if let Some(arm) = arms.iter().find(|arm| arm.check() != check) {
        return Err(invalid(format!(
            "arm `{}` is not a {} arm",
            arm.as_str(),
            check.as_str()
        )));
    }
    Ok(())
}

pub(super) fn invalid(reason: String) -> BeamError {
    BeamError::InvalidManifest {
        run_id: MANIFEST_ID.to_owned(),
        reason,
    }
}

/// A task id or writer name: it becomes one path component.
pub(super) fn is_path_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !name.starts_with('-')
}

fn is_full_commit(commit: &str) -> bool {
    commit.len() == 40
        && commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A path inside the tree: relative, with no `..`, `.` or empty component.
fn is_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// Seconds since the Unix epoch of an RFC 3339 time.
pub(super) fn rfc3339_seconds(text: &str) -> Option<i64> {
    rfc3339_millis(text).map(|millis| millis.div_euclid(1_000))
}

/// Milliseconds since the Unix epoch of an RFC 3339 time,
/// `YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)`.
pub(super) fn rfc3339_millis(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || !matches!(bytes.get(10), Some(b'T' | b't'))
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return None;
    }
    let number = |from: usize, to: usize| -> Option<i64> {
        let part = text.get(from..to)?;
        if part.bytes().all(|byte| byte.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut rest = text.get(19..)?;
    let mut millis = 0;
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        let lead = fraction.get(..digits.min(3))?;
        let scale = match lead.len() {
            1 => 100,
            2 => 10,
            _ => 1,
        };
        millis = lead.parse::<i64>().ok()? * scale;
        rest = fraction.get(digits..)?;
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes().first() {
                Some(b'+') => 1,
                Some(b'-') => -1,
                _ => return None,
            };
            if rest.len() != 6 || rest.as_bytes().get(3) != Some(&b':') {
                return None;
            }
            let digits = |from: usize, to: usize| -> Option<i64> {
                let part = rest.get(from..to)?;
                if part.bytes().all(|byte| byte.is_ascii_digit()) {
                    part.parse().ok()
                } else {
                    None
                }
            };
            let (offset_hours, offset_minutes) = (digits(1, 3)?, digits(4, 6)?);
            if offset_hours > 23 || offset_minutes > 59 {
                return None;
            }
            sign * (offset_hours * 3_600 + offset_minutes * 60)
        }
    };
    let days = days_from_civil(year, month, day);
    Some((days * 86_400 + hour * 3_600 + minute * 60 + second - offset) * 1_000 + millis)
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_from_march = (month + 9) % 12;
    let day_of_year = (153 * month_from_march + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}
