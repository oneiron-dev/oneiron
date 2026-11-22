//! The files of one cell beside its world: the prompt, the MCP server
//! config and the Claude Code settings.

use std::fmt::Write as _;

use crate::beam::BeamResult;

use super::super::manifest::{Task, WriterPart};
use super::super::profile::{Arm, Check};
use super::{CELL_SCHEMA, CellWorld, Pack};

impl Pack<'_> {
    pub(super) fn write_cell_files(
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
}

fn short(commit: &str) -> &str {
    commit.get(..12).unwrap_or(commit)
}
