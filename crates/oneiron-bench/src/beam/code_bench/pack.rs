//! `beam code-bench-pack <plan.json>`: materialize every ready cell for the
//! run's driver, and list every cell that is not ready with what it lacks.
//!
//! A cell's world is a fresh repository holding only the task's base, with
//! the sealed tests removed: a worktree of the repo would share its object
//! store, and with it the merged commit and the tests the grader runs.

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use serde::{Deserialize, Serialize};

use super::super::{BeamResult, report_model::NotReadyState};
use super::manifest::{Manifest, PromptPlan, Task, WriterPart, invalid, rfc3339_seconds};
use super::profile::{Arm, Check, Piece};

const PACK_SCHEMA: &str = "code-bench-pack-v1";
const CELL_SCHEMA: &str = "code-bench-cell-v1";

/// The run plan. Paths are relative to the plan's folder unless absolute.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackPlan {
    manifest: PathBuf,
    /// Must be empty or absent: stale cells of an older plan never mix in.
    out: PathBuf,
    /// The repository the tasks' commits are read from.
    repo_dir: PathBuf,
    #[serde(default)]
    memory_vault: Option<MemoryVault>,
    #[serde(default)]
    code_snapshot: Option<CodeSnapshot>,
    #[serde(default)]
    oneiron_code_path: Option<WorkServer>,
}

/// The dev vault's MCP server. `token_env` names the environment variable
/// that holds the token; the token itself is never written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryVault {
    url: String,
    token_env: String,
    /// RFC 3339: the newest record the vault holds. After the cut, the
    /// memory could hold the answer.
    seeded_through: String,
}

/// The MCP server holding code snapshots of the tasks' bases.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeSnapshot {
    url: String,
    token_env: String,
    /// The engine commit the server runs: the arm's verb rows must be in it.
    engine_commit: String,
    /// The base commits it holds a snapshot of.
    bases: Vec<String>,
}

/// The MCP server of an Oneiron that serves the shared work path.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkServer {
    url: String,
    token_env: String,
    engine_commit: String,
}

#[derive(Debug, Serialize)]
pub(in super::super) struct PackIndex {
    schema: &'static str,
    repo: String,
    cut: String,
    cap_minutes: u32,
    tasks: Vec<IndexTask>,
    arms: [Arm; 6],
    prompts: PromptPlan,
    cells: Vec<CellEntry>,
    /// Cells a check reuses from another check: run once, graded for both.
    shared: Vec<SharedCell>,
}

#[derive(Debug, Serialize)]
struct IndexTask {
    id: String,
    pr: u64,
    base: String,
}

#[derive(Debug, Serialize)]
struct CellEntry {
    id: String,
    check: Check,
    task: String,
    arm: Arm,
    writer: Option<String>,
    ready: bool,
    /// The cell's folder; only a ready cell has one.
    dir: Option<PathBuf>,
    /// The script that makes the cell's world.
    world: Option<PathBuf>,
    not_ready: Vec<NotReadyState>,
}

#[derive(Debug, Serialize)]
struct SharedCell {
    check: Check,
    task: String,
    arm: Arm,
    cell: String,
}

/// What every cell reads: the plan, the manifest and the folders.
struct Pack<'a> {
    plan: &'a PackPlan,
    manifest: &'a Manifest,
    repo: PathBuf,
    out: PathBuf,
    cut: i64,
    snapshot_verbs_gap: Option<String>,
    work_verbs_gap: Option<String>,
}

pub(in super::super) fn write_pack(plan_path: &Path) -> BeamResult<PackIndex> {
    let plan: PackPlan = serde_json::from_slice(&std::fs::read(plan_path)?)?;
    let folder = plan_path.parent().unwrap_or(Path::new("."));
    let manifest = Manifest::parse(&std::fs::read_to_string(folder.join(&plan.manifest))?)?;
    plan.validate_servers()?;
    let repo = folder.join(&plan.repo_dir);
    if !git_ok(&repo, &["rev-parse", "--git-dir"])? {
        return Err(invalid(format!(
            "run plan repo_dir {} is not a Git repository",
            repo.display()
        )));
    }
    let out = folder.join(&plan.out);
    if folder_has_entries(&out)? {
        return Err(invalid(format!(
            "run plan out {} is not empty",
            out.display()
        )));
    }
    std::fs::create_dir_all(&out)?;
    let snapshot_verbs_gap = match &plan.code_snapshot {
        Some(snapshot) => verbs_gap(&repo, &snapshot.engine_commit, Arm::SymbolGraph.verbs())?,
        None => None,
    };
    let work_verbs_gap = match &plan.oneiron_code_path {
        Some(work) => verbs_gap(&repo, &work.engine_commit, Arm::OneironWriters.verbs())?,
        None => None,
    };
    let pack = Pack {
        plan: &plan,
        cut: manifest.cut_seconds()?,
        manifest: &manifest,
        repo,
        out,
        snapshot_verbs_gap,
        work_verbs_gap,
    };
    let index = pack.write()?;
    std::fs::write(
        pack.out.join("index.json"),
        serde_json::to_string_pretty(&index)?,
    )?;
    Ok(index)
}

impl PackPlan {
    fn validate_servers(&self) -> BeamResult<()> {
        let servers = [
            (
                "memory_vault",
                self.memory_vault
                    .as_ref()
                    .map(|piece| (&piece.url, &piece.token_env)),
            ),
            (
                "code_snapshot",
                self.code_snapshot
                    .as_ref()
                    .map(|piece| (&piece.url, &piece.token_env)),
            ),
            (
                "oneiron_code_path",
                self.oneiron_code_path
                    .as_ref()
                    .map(|piece| (&piece.url, &piece.token_env)),
            ),
        ];
        for (field, server) in servers {
            let Some((url, token_env)) = server else {
                continue;
            };
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(invalid(format!(
                    "run plan {field}.url must be an http(s) URL"
                )));
            }
            if !is_env_name(token_env) {
                return Err(invalid(format!(
                    "run plan {field}.token_env must name an environment variable \
                     (upper-case letters, digits, underscores), never hold the token"
                )));
            }
        }
        Ok(())
    }
}

impl Pack<'_> {
    fn write(&self) -> BeamResult<PackIndex> {
        let manifest = self.manifest;
        let checks = &manifest.checks;
        let mut cells = Vec::new();
        let mut shared = Vec::new();
        for task in &manifest.tasks {
            for arm in &checks.memory.arms {
                cells.push(self.solo_cell(Check::Memory, task, *arm)?);
            }
        }
        for task in &manifest.tasks {
            for arm in &checks.navigation.arms {
                cells.push(self.solo_cell(Check::Navigation, task, *arm)?);
            }
            shared.push(SharedCell {
                check: Check::Navigation,
                task: task.id.clone(),
                arm: checks.navigation.third,
                cell: cell_id(Check::Memory, &task.id, checks.navigation.third, None),
            });
        }
        if let Some(task) = manifest.task(&checks.collaboration.task) {
            for arm in &checks.collaboration.arms {
                cells.extend(self.writer_cells(task, *arm)?);
            }
        }
        Ok(PackIndex {
            schema: PACK_SCHEMA,
            repo: manifest.repo.clone(),
            cut: manifest.cut.clone(),
            cap_minutes: manifest.cap_minutes,
            tasks: manifest
                .tasks
                .iter()
                .map(|task| IndexTask {
                    id: task.id.clone(),
                    pr: task.pr,
                    base: task.base.clone(),
                })
                .collect(),
            arms: Arm::ALL,
            prompts: manifest.prompt_plan(),
            cells,
            shared,
        })
    }

    fn solo_cell(&self, check: Check, task: &Task, arm: Arm) -> BeamResult<CellEntry> {
        let id = cell_id(check, &task.id, arm, None);
        let not_ready = self.not_ready(task, arm, &[])?;
        let mut entry = CellEntry {
            id,
            check,
            task: task.id.clone(),
            arm,
            writer: None,
            ready: not_ready.is_empty(),
            dir: None,
            world: None,
            not_ready,
        };
        if entry.ready {
            let dir = self.out.join(&entry.id);
            std::fs::create_dir_all(&dir)?;
            self.write_cell_files(&dir, &entry.id, check, task, arm, None)?;
            let world = dir.join("world.sh");
            std::fs::write(&world, self.world_script(&entry.id, task, &[]))?;
            entry.dir = Some(dir);
            entry.world = Some(world);
        }
        Ok(entry)
    }

    /// One cell per writer. The writers share one world, so the arm is ready
    /// for all of them or for none.
    fn writer_cells(&self, task: &Task, arm: Arm) -> BeamResult<Vec<CellEntry>> {
        let parts: &[WriterPart] = task
            .collaboration
            .as_ref()
            .map_or(&[], |split| split.parts.as_slice());
        let not_ready = self.not_ready(task, arm, parts)?;
        let arm_id = cell_id(Check::Collaboration, &task.id, arm, None);
        let arm_dir = self.out.join(&arm_id);
        let world = arm_dir.join("world.sh");
        let ready = not_ready.is_empty();
        if ready {
            std::fs::create_dir_all(&arm_dir)?;
            let writers: Vec<&str> = parts.iter().map(|part| part.writer.as_str()).collect();
            std::fs::write(&world, self.world_script(&arm_id, task, &writers))?;
        }
        let mut cells = Vec::new();
        for part in parts {
            let id = cell_id(Check::Collaboration, &task.id, arm, Some(&part.writer));
            let dir = self.out.join(&id);
            if ready {
                std::fs::create_dir_all(&dir)?;
                self.write_cell_files(&dir, &id, Check::Collaboration, task, arm, Some(part))?;
            }
            cells.push(CellEntry {
                id,
                check: Check::Collaboration,
                task: task.id.clone(),
                arm,
                writer: Some(part.writer.clone()),
                ready,
                dir: ready.then_some(dir),
                world: ready.then(|| world.clone()),
                not_ready: not_ready.clone(),
            });
        }
        Ok(cells)
    }

    /// Everything the cell lacks; empty means ready.
    fn not_ready(
        &self,
        task: &Task,
        arm: Arm,
        parts: &[WriterPart],
    ) -> BeamResult<Vec<NotReadyState>> {
        let mut states = Vec::new();
        if task.intent.is_none() {
            states.push(state(
                "intent",
                format!("intent not written for task `{}`", task.id),
            ));
        }
        for part in parts.iter().filter(|part| part.intent.is_none()) {
            states.push(state(
                "intent",
                format!(
                    "intent not written for writer `{}` of task `{}`",
                    part.writer, task.id
                ),
            ));
        }
        let mut world_present = true;
        for (field, commit) in [("base", &task.base), ("merged", &task.merged)] {
            if !git_ok(
                &self.repo,
                &["cat-file", "-e", &format!("{commit}^{{commit}}")],
            )? {
                world_present = false;
                states.push(state(
                    "world",
                    format!(
                        "task `{}` {field} {commit} is not in repo_dir {}",
                        task.id,
                        self.repo.display()
                    ),
                ));
            }
        }
        for piece in arm.pieces() {
            if let Some(reason) = self.piece_gap(*piece, task, world_present)? {
                states.push(state(piece.as_str(), reason));
            }
        }
        Ok(states)
    }

    fn piece_gap(
        &self,
        piece: Piece,
        task: &Task,
        world_present: bool,
    ) -> BeamResult<Option<String>> {
        let name = piece.as_str();
        Ok(match piece {
            Piece::Codemap => {
                let codemap = format!("{}:docs/codemap", task.base);
                (world_present && !git_ok(&self.repo, &["cat-file", "-e", &codemap])?)
                    .then(|| format!("docs/codemap/ is not in base {}", task.base))
            }
            Piece::MemoryVault => match &self.plan.memory_vault {
                None => Some(format!("no {name} in the run plan")),
                Some(vault) => match rfc3339_seconds(&vault.seeded_through) {
                    None => Some(format!(
                        "{name} seeded_through `{}` is not RFC 3339",
                        vault.seeded_through
                    )),
                    Some(seeded) if seeded > self.cut => Some(format!(
                        "{name} seeded_through {} is after the cut {}: the memory could hold \
                         the answer",
                        vault.seeded_through, self.manifest.cut
                    )),
                    Some(_) => None,
                },
            },
            Piece::CodeSnapshot => match &self.plan.code_snapshot {
                None => Some(format!("no {name} in the run plan")),
                Some(snapshot) if !snapshot.bases.contains(&task.base) => {
                    Some(format!("{name} holds no snapshot of base {}", task.base))
                }
                Some(_) => self.snapshot_verbs_gap.clone(),
            },
            Piece::OneironCodePath => match &self.plan.oneiron_code_path {
                None => Some(format!("no {name} in the run plan")),
                Some(_) => self.work_verbs_gap.clone(),
            },
        })
    }

    fn write_cell_files(
        &self,
        dir: &Path,
        id: &str,
        check: Check,
        task: &Task,
        arm: Arm,
        part: Option<&WriterPart>,
    ) -> BeamResult<()> {
        std::fs::write(dir.join("PROMPT.md"), self.prompt(id, task, arm, part))?;
        std::fs::write(
            dir.join("mcp.json"),
            serde_json::to_string_pretty(&self.mcp_config(arm))?,
        )?;
        let settings = serde_json::json!({
            "permissions": { "allow": arm.allowed_tools(), "deny": arm.denied_tools() },
        });
        std::fs::write(
            dir.join("settings.json"),
            serde_json::to_string_pretty(&settings)?,
        )?;
        let cell = serde_json::json!({
            "schema": CELL_SCHEMA,
            "id": id,
            "check": check,
            "task": task.id,
            "arm": arm,
            "writer": part.map(|part| part.writer.as_str()),
            "base": task.base,
            "cap_minutes": self.manifest.cap_minutes,
            "mcp_server": arm.server(),
            "mcp_verbs": arm.verbs(),
            "mcp_tool_prefixes": arm.tool_prefixes(),
        });
        std::fs::write(dir.join("cell.json"), serde_json::to_string_pretty(&cell)?)?;
        Ok(())
    }

    fn prompt(&self, id: &str, task: &Task, arm: Arm, part: Option<&WriterPart>) -> String {
        let mut text = format!("# CODE-BENCH cell `{id}`\n\n## Your task\n\n");
        text.push_str(task.intent.as_deref().unwrap_or_default());
        text.push('\n');
        if let Some(part) = part {
            let writers = task
                .collaboration
                .as_ref()
                .map_or(0, |split| split.parts.len());
            let files = part
                .files
                .iter()
                .map(|file| format!("`{file}`"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = write!(
                text,
                "\n### Your part (writer `{}` of {writers})\n\n{}\n\nThe files of your part: \
                 {files}. The other writers change the other parts at the same time, and the \
                 parts overlap.\n",
                part.writer,
                part.intent.as_deref().unwrap_or_default()
            );
        }
        let _ = write!(
            text,
            "\n## Your tools\n\n{}\n\n## Rules\n\n- Work only in your tree, `tree/` beside this \
             file. `world.sh` made it from base {}.\n- You have {} minutes.\n- Leave your change \
             in the tree when you stop: it is graded after you stop.\n",
            arm.rules(),
            short(&task.base),
            self.manifest.cap_minutes
        );
        text
    }

    fn mcp_config(&self, arm: Arm) -> serde_json::Value {
        let entry = |url: &str, token_env: &str| {
            serde_json::json!({
                "type": "http",
                "url": url,
                "headers": { "Authorization": format!("Bearer ${{{token_env}}}") },
            })
        };
        let server = match arm {
            Arm::VaultMemory => self
                .plan
                .memory_vault
                .as_ref()
                .map(|piece| entry(&piece.url, &piece.token_env)),
            Arm::SymbolGraph => self
                .plan
                .code_snapshot
                .as_ref()
                .map(|piece| entry(&piece.url, &piece.token_env)),
            Arm::OneironWriters => self
                .plan
                .oneiron_code_path
                .as_ref()
                .map(|piece| entry(&piece.url, &piece.token_env)),
            Arm::NoMemory | Arm::GrepOnly | Arm::GitWorktrees => None,
        };
        let mut servers = serde_json::Map::new();
        if let (Some(name), Some(server)) = (arm.server(), server) {
            servers.insert(name.to_owned(), server);
        }
        serde_json::json!({ "mcpServers": servers })
    }

    /// The world: a fresh repository of the base's tree, one commit, the
    /// sealed paths removed. With writers, each gets a worktree of it on
    /// its own branch, beside a shared `integration` branch.
    fn world_script(&self, id: &str, task: &Task, writers: &[&str]) -> String {
        let repo = sh_quote(&self.repo.display().to_string());
        let mut script = format!(
            "#!/bin/sh\n# CODE-BENCH {id}: task `{task_id}` at base {base}, in a fresh repository with \
             no history past the base, the sealed tests removed.\nset -eu\nhere=$(cd \"$(dirname \
             \"$0\")\" && pwd)\n",
            task_id = task.id,
            base = task.base,
        );
        let root = if writers.is_empty() {
            "$here/tree"
        } else {
            "$here/repo"
        };
        let _ = write!(
            script,
            "root=\"{root}\"\nif [ -e \"$root\" ]; then echo \"world.sh: $root exists\" >&2; exit 1; fi\n\
             mkdir \"$root\"\ngit -C {repo} archive --format=tar -o \"$here/world.tar\" {base}\n\
             tar -x -f \"$here/world.tar\" -C \"$root\"\nrm -f \"$here/world.tar\"\n",
            base = task.base,
        );
        for path in &task.sealed {
            let _ = writeln!(script, "rm -rf \"$root\"/{}", sh_quote(path));
        }
        let _ = write!(
            script,
            "git -C \"$root\" init -q\ngit -C \"$root\" add -A\ngit -C \"$root\" -c user.name=code-bench \
             -c user.email=code-bench@example.invalid -c commit.gpgsign=false commit -q -m {}\n",
            sh_quote(&format!("code-bench world: {} at {}", task.id, task.base)),
        );
        if !writers.is_empty() {
            script.push_str("git -C \"$root\" branch integration\n");
            for writer in writers {
                let _ = writeln!(
                    script,
                    "git -C \"$root\" worktree add -q -b {writer} \"$here/{writer}/tree\""
                );
            }
        }
        script
    }
}

fn state(component: &str, reason: String) -> NotReadyState {
    NotReadyState {
        component: component.to_owned(),
        reason,
        retryable: true,
    }
}

fn cell_id(check: Check, task: &str, arm: Arm, writer: Option<&str>) -> String {
    let id = format!("{}/{task}/{}", check.as_str(), arm.as_str());
    match writer {
        Some(writer) => format!("{id}/{writer}"),
        None => id,
    }
}

/// The first verb row missing at the serving engine's commit, if any.
fn verbs_gap(repo: &Path, engine_commit: &str, verbs: &[&str]) -> BeamResult<Option<String>> {
    if !git_ok(
        repo,
        &["cat-file", "-e", &format!("{engine_commit}^{{commit}}")],
    )? {
        return Ok(Some(format!(
            "engine_commit {engine_commit} is not in repo_dir {}",
            repo.display()
        )));
    }
    for verb in verbs {
        let row = format!("{engine_commit}:scripts/sdk/verbs/{verb}.json");
        if !git_ok(repo, &["cat-file", "-e", &row])? {
            return Ok(Some(format!(
                "verb row scripts/sdk/verbs/{verb}.json is not at engine_commit {engine_commit}"
            )));
        }
    }
    Ok(None)
}

fn git_ok(repo: &Path, args: &[&str]) -> BeamResult<bool> {
    Ok(Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success())
}

fn folder_has_entries(path: &Path) -> BeamResult<bool> {
    match std::fs::read_dir(path) {
        Ok(mut entries) => Ok(entries.next().is_some()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn is_env_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(|first: char| first.is_ascii_digit())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn sh_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn short(commit: &str) -> &str {
    commit.get(..12).unwrap_or(commit)
}
