//! `beam code-bench-pack <plan.json>`: materialize every ready cell for the
//! run's driver, and list every cell that is not ready with what it lacks.
//!
//! A cell's world is a fresh repository holding only the task's base, with
//! the sealed tests removed, built here before any writer starts: a
//! worktree of the repo would share its object store, and with it the
//! merged commit and the tests the grader runs. No file of a cell names the
//! source repository except the sandbox rules of its `settings.json`, which
//! deny every read of it.

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use serde::{Deserialize, Serialize};

use super::super::{BeamResult, report_model::NotReadyState};
use super::manifest::{Manifest, PromptPlan, Task, WriterPart, invalid, rfc3339_seconds};
use super::mcp_probe;
use super::profile::{Arm, Check, Piece, names_verb};

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
    /// The writer's tree, built before the writer starts.
    tree: Option<PathBuf>,
    /// The world's one root commit: the grader refuses an attempt that does
    /// not grow from it.
    world_root: Option<String>,
    not_ready: Vec<NotReadyState>,
}

#[derive(Debug, Serialize)]
struct SharedCell {
    check: Check,
    task: String,
    arm: Arm,
    cell: String,
}

/// What a declared MCP server listed to the pack's probe, or why it is not
/// ready.
type Listing = Result<Vec<String>, String>;

/// What every cell reads: the plan, the manifest and the folders.
struct Pack<'a> {
    plan: &'a PackPlan,
    manifest: &'a Manifest,
    repo: PathBuf,
    out: PathBuf,
    cut: i64,
    snapshot_verbs_gap: Option<String>,
    work_verbs_gap: Option<String>,
    memory_tools: Option<Listing>,
    snapshot_tools: Option<Listing>,
    work_tools: Option<Listing>,
    /// The source repository's folders, absolute: no writer may read them.
    sealed_sources: Vec<PathBuf>,
}

/// A ready cell's built world, as its files name it.
struct CellWorld {
    /// The cell's folder.
    dir: PathBuf,
    /// The writer's tree.
    tree: PathBuf,
    /// The world's one root commit.
    root: String,
    /// The folder the writer reads: its cell, or its collaboration arm's.
    read: PathBuf,
    /// The folders the writer writes: its cell, and for a collaboration
    /// writer the arm's shared repository, where its worktree's commits land.
    write: Vec<PathBuf>,
}

pub(in super::super) fn write_pack(plan_path: &Path) -> BeamResult<PackIndex> {
    let (plan, folder) = read_plan(plan_path)?;
    let (manifest, repo) = plan.open(&folder)?;
    let out = folder.join(&plan.out);
    if folder_has_entries(&out)? {
        return Err(invalid(format!(
            "run plan out {} is not empty",
            out.display()
        )));
    }
    std::fs::create_dir_all(&out)?;
    let out = std::fs::canonicalize(&out)?;
    let snapshot_verbs_gap = match &plan.code_snapshot {
        Some(snapshot) => verbs_gap(&repo, &snapshot.engine_commit, Arm::SymbolGraph.verbs())?,
        None => None,
    };
    let work_verbs_gap = match &plan.oneiron_code_path {
        Some(work) => verbs_gap(&repo, &work.engine_commit, Arm::OneironWriters.verbs())?,
        None => None,
    };
    let probe = |piece: Piece, server: Option<(&String, &String)>| {
        server.map(|(url, token_env)| mcp_probe::list_tools(piece.as_str(), url, token_env))
    };
    let memory_tools = probe(
        Piece::MemoryVault,
        plan.memory_vault
            .as_ref()
            .map(|piece| (&piece.url, &piece.token_env)),
    );
    let snapshot_tools = probe(
        Piece::CodeSnapshot,
        plan.code_snapshot
            .as_ref()
            .map(|piece| (&piece.url, &piece.token_env)),
    );
    let work_tools = probe(
        Piece::OneironCodePath,
        plan.oneiron_code_path
            .as_ref()
            .map(|piece| (&piece.url, &piece.token_env)),
    );
    let sealed_sources = source_folders(&repo)?;
    let pack = Pack {
        plan: &plan,
        cut: manifest.cut_seconds()?,
        manifest: &manifest,
        repo,
        out,
        snapshot_verbs_gap,
        work_verbs_gap,
        memory_tools,
        snapshot_tools,
        work_tools,
        sealed_sources,
    };
    let index = pack.write()?;
    std::fs::write(
        pack.out.join("index.json"),
        serde_json::to_string_pretty(&index)?,
    )?;
    Ok(index)
}

/// What the grader reads of a run plan: its manifest, the repository the
/// tasks' commits are read from, and the folder the pack wrote the cells to.
pub(super) struct PackedPlan {
    pub(super) manifest: Manifest,
    pub(super) repo: PathBuf,
    pub(super) out: PathBuf,
}

pub(super) fn packed_plan(plan_path: &Path) -> BeamResult<PackedPlan> {
    let (plan, folder) = read_plan(plan_path)?;
    let (manifest, repo) = plan.open(&folder)?;
    Ok(PackedPlan {
        manifest,
        repo,
        out: folder.join(&plan.out),
    })
}

fn read_plan(plan_path: &Path) -> BeamResult<(PackPlan, PathBuf)> {
    let plan: PackPlan = serde_json::from_slice(&std::fs::read(plan_path)?)?;
    let folder = plan_path.parent().unwrap_or(Path::new(".")).to_path_buf();
    Ok((plan, folder))
}

impl PackPlan {
    /// Reads the manifest, checks the MCP pieces and finds the repository.
    fn open(&self, folder: &Path) -> BeamResult<(Manifest, PathBuf)> {
        let manifest = Manifest::parse(&std::fs::read_to_string(folder.join(&self.manifest))?)?;
        self.validate_servers()?;
        let repo = folder.join(&self.repo_dir);
        if !git_ok(&repo, &["rev-parse", "--git-dir"])? {
            return Err(invalid(format!(
                "run plan repo_dir {} is not a Git repository",
                repo.display()
            )));
        }
        Ok((manifest, repo))
    }

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
            tree: None,
            world_root: None,
            not_ready,
        };
        if entry.ready {
            let dir = self.out.join(&entry.id);
            std::fs::create_dir_all(&dir)?;
            let tree = dir.join("tree");
            let world = CellWorld {
                root: self.build_world(&tree, task, &[])?,
                tree,
                read: dir.clone(),
                write: vec![dir.clone()],
                dir,
            };
            self.write_cell_files(&entry.id, check, task, arm, None, &world)?;
            entry.dir = Some(world.dir);
            entry.tree = Some(world.tree);
            entry.world_root = Some(world.root);
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
        let arm_dir = self
            .out
            .join(cell_id(Check::Collaboration, &task.id, arm, None));
        let shared = arm_dir.join("repo");
        let root = if not_ready.is_empty() {
            std::fs::create_dir_all(&arm_dir)?;
            let writers: Vec<&str> = parts.iter().map(|part| part.writer.as_str()).collect();
            Some(self.build_world(&shared, task, &writers)?)
        } else {
            None
        };
        let mut cells = Vec::new();
        for part in parts {
            let id = cell_id(Check::Collaboration, &task.id, arm, Some(&part.writer));
            let dir = self.out.join(&id);
            let world = root.as_ref().map(|root| CellWorld {
                tree: dir.join("tree"),
                root: root.clone(),
                read: arm_dir.clone(),
                write: vec![dir.clone(), shared.clone()],
                dir,
            });
            if let Some(world) = &world {
                self.write_cell_files(&id, Check::Collaboration, task, arm, Some(part), world)?;
            }
            cells.push(CellEntry {
                id,
                check: Check::Collaboration,
                task: task.id.clone(),
                arm,
                writer: Some(part.writer.clone()),
                ready: world.is_some(),
                dir: world.as_ref().map(|world| world.dir.clone()),
                tree: world.as_ref().map(|world| world.tree.clone()),
                world_root: world.map(|world| world.root),
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
                    Some(_) => listing_gap(piece, self.memory_tools.as_ref(), Arm::VaultMemory),
                },
            },
            Piece::CodeSnapshot => match &self.plan.code_snapshot {
                None => Some(format!("no {name} in the run plan")),
                Some(snapshot) if !snapshot.bases.contains(&task.base) => {
                    Some(format!("{name} holds no snapshot of base {}", task.base))
                }
                Some(_) => self
                    .snapshot_verbs_gap
                    .clone()
                    .or_else(|| listing_gap(piece, self.snapshot_tools.as_ref(), Arm::SymbolGraph)),
            },
            Piece::OneironCodePath => match &self.plan.oneiron_code_path {
                None => Some(format!("no {name} in the run plan")),
                Some(_) => self
                    .work_verbs_gap
                    .clone()
                    .or_else(|| listing_gap(piece, self.work_tools.as_ref(), Arm::OneironWriters)),
            },
        })
    }

    /// The tools the arm's MCP server listed to the probe; none when the arm
    /// has no server or the server did not answer.
    fn listed_tools(&self, arm: Arm) -> &[String] {
        let listing = match arm {
            Arm::VaultMemory => self.memory_tools.as_ref(),
            Arm::SymbolGraph => self.snapshot_tools.as_ref(),
            Arm::OneironWriters => self.work_tools.as_ref(),
            Arm::NoMemory | Arm::GrepOnly | Arm::GitWorktrees => None,
        };
        listing
            .and_then(|listing| listing.as_ref().ok())
            .map_or(&[], Vec::as_slice)
    }

    fn write_cell_files(
        &self,
        id: &str,
        check: Check,
        task: &Task,
        arm: Arm,
        part: Option<&WriterPart>,
        world: &CellWorld,
    ) -> BeamResult<()> {
        let dir = &world.dir;
        std::fs::write(dir.join("PROMPT.md"), self.prompt(id, task, arm, part))?;
        std::fs::write(
            dir.join("mcp.json"),
            serde_json::to_string_pretty(&self.mcp_config(arm))?,
        )?;
        std::fs::write(
            dir.join("settings.json"),
            serde_json::to_string_pretty(&self.settings(arm, world))?,
        )?;
        let cell = serde_json::json!({
            "schema": CELL_SCHEMA,
            "id": id,
            "check": check,
            "task": task.id,
            "arm": arm,
            "writer": part.map(|part| part.writer.as_str()),
            "base": task.base,
            "tree": world.tree.display().to_string(),
            "world_root": world.root,
            "cap_minutes": self.manifest.cap_minutes,
            "mcp_server": arm.server(),
            "mcp_verbs": arm.verbs(),
            "mcp_tool_prefixes": arm.tool_prefixes(),
        });
        std::fs::write(dir.join("cell.json"), serde_json::to_string_pretty(&cell)?)?;
        Ok(())
    }

    /// Claude Code's settings for the cell: the arm's tools, and a sandbox
    /// that must start (`failIfUnavailable`), so no command of the writer
    /// reads the source repository, whose merge commit holds the answer and
    /// the sealed tests, or writes outside the cell's world. The Read and
    /// Edit tools follow the permission rules, not the sandbox.
    fn settings(&self, arm: Arm, world: &CellWorld) -> serde_json::Value {
        let sources: Vec<String> = self
            .sealed_sources
            .iter()
            .map(|folder| folder.display().to_string())
            .collect();
        let mut deny = arm.denied_tools();
        for folder in &sources {
            // `//` starts an absolute path in a permission rule.
            deny.push(format!("Read(/{folder}/**)"));
            deny.push(format!("Edit(/{folder}/**)"));
        }
        let write: Vec<String> = world
            .write
            .iter()
            .map(|folder| folder.display().to_string())
            .collect();
        serde_json::json!({
            "permissions": {
                "allow": arm.allowed_tools(self.listed_tools(arm)),
                "deny": deny,
            },
            "sandbox": {
                "enabled": true,
                "failIfUnavailable": true,
                "allowUnsandboxedCommands": false,
                "filesystem": {
                    "denyRead": sources,
                    "allowRead": [world.read.display().to_string()],
                    "allowWrite": write,
                },
            },
        })
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
             file. It was made from base {} before you started.\n- You have {} minutes.\n- Leave \
             your change in the tree when you stop: it is graded after you stop.\n",
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

    /// Builds the world at `root`: a fresh repository of the base's tree,
    /// one commit, the sealed paths removed. `add -f` keeps tracked files
    /// that match an ignore rule. With writers, each gets a worktree of it
    /// on its own branch at `<arm folder>/<writer>/tree`, beside a shared
    /// `integration` branch. Returns the root commit.
    fn build_world(&self, root: &Path, task: &Task, writers: &[&str]) -> BeamResult<String> {
        std::fs::create_dir(root)?;
        let mut archive = git(&self.repo)
            .args(["archive", "--format=tar", &task.base])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let tar_input = archive
            .stdout
            .take()
            .ok_or_else(|| invalid("git archive gave no output pipe".to_owned()))?;
        let unpacked = Command::new("tar")
            .args(["-x", "-f", "-", "-C"])
            .arg(root)
            .stdin(tar_input)
            .stderr(Stdio::null())
            .status()?;
        let archived = archive.wait()?;
        if !(archived.success() && unpacked.success()) {
            return Err(invalid(format!(
                "the world of task `{}`: git archive of base {} into {} failed",
                task.id,
                task.base,
                root.display()
            )));
        }
        for path in &task.sealed {
            remove_path(&root.join(path))?;
        }
        run_git(root, &["init", "-q"])?;
        run_git(root, &["add", "-A", "-f"])?;
        run_git(
            root,
            &[
                "-c",
                "user.name=code-bench",
                "-c",
                "user.email=code-bench@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "--no-verify",
                "-m",
                &world_subject(task),
            ],
        )?;
        let commit = git_stdout(root, &["rev-parse", "HEAD"])?
            .map(|commit| commit.trim().to_owned())
            .ok_or_else(|| invalid(format!("no world commit in {}", root.display())))?;
        if !writers.is_empty() {
            run_git(root, &["branch", "integration"])?;
            let arm_dir = root.parent().unwrap_or(root);
            for writer in writers {
                let tree = arm_dir.join(writer).join("tree");
                let added = git(root)
                    .args(["worktree", "add", "-q", "-b", writer])
                    .arg(&tree)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()?;
                if !added.success() {
                    return Err(invalid(format!(
                        "git worktree add of writer `{writer}` at {} failed",
                        tree.display()
                    )));
                }
            }
        }
        Ok(commit)
    }
}

/// The subject of a world's one root commit.
pub(super) fn world_subject(task: &Task) -> String {
    format!("code-bench world: {} at {}", task.id, task.base)
}

/// Why the probed server cannot serve `arm`: it did not answer, it lacks
/// one of the arm's verbs, or it lists none of the arm's tools.
fn listing_gap(piece: Piece, listing: Option<&Listing>, arm: Arm) -> Option<String> {
    let name = piece.as_str();
    match listing {
        None => Some(format!("no {name} in the run plan")),
        Some(Err(reason)) => Some(reason.clone()),
        Some(Ok(tools)) => {
            let missing = arm
                .verbs()
                .iter()
                .find(|verb| !tools.iter().any(|tool| names_verb(tool, verb)));
            match missing {
                Some(verb) => Some(format!("{name} does not list the tool {verb}")),
                None => (!tools.iter().any(|tool| arm.admits_tool(tool)))
                    .then(|| format!("{name} lists none of the tools of arm {}", arm.as_str())),
            }
        }
    }
}

/// The source repository's work tree and Git folder, absolute; a linked
/// worktree keeps its objects in its main repository's folder.
fn source_folders(repo: &Path) -> BeamResult<Vec<PathBuf>> {
    let mut folders = vec![std::fs::canonicalize(repo)?];
    let common = git_stdout(
        repo,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )?;
    if let Some(common) = common {
        let common = std::fs::canonicalize(common.trim())?;
        if !folders.iter().any(|folder| common.starts_with(folder)) {
            folders.push(common);
        }
    }
    Ok(folders)
}

/// Removes a sealed path from the world, whatever it is; a path the base
/// lacks is no error.
fn remove_path(path: &Path) -> BeamResult<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(path)?,
        Ok(_) => std::fs::remove_file(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
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

/// Git in `dir`, reading no stdin.
fn git(dir: &Path) -> Command {
    let mut command = Command::new("git");
    command.arg("-C").arg(dir).stdin(Stdio::null());
    command
}

pub(super) fn git_ok(repo: &Path, args: &[&str]) -> BeamResult<bool> {
    Ok(git(repo)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success())
}

/// Git's stdout, or `None` when the command fails.
fn git_stdout(dir: &Path, args: &[&str]) -> BeamResult<Option<String>> {
    let output = git(dir).args(args).stderr(Stdio::null()).output()?;
    Ok(output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned()))
}

fn run_git(dir: &Path, args: &[&str]) -> BeamResult<()> {
    let output = git(dir).args(args).output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(invalid(format!(
        "git {} in {} failed: {}",
        args.join(" "),
        dir.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    )))
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

fn short(commit: &str) -> &str {
    commit.get(..12).unwrap_or(commit)
}
