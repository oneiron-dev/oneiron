# Session hooks for Codex, Cursor and GitHub Copilot

The same hook lanes as [Claude Code hooks](claude-code-hooks.md), for the
clients that take the shared Agent Plugins package
([Connect an agent](connect-an-agent.md)): when a session starts it binds a
vault, is told which in one line, and gets a short recall for the project;
as it goes, its log is queued for import. Each client runs `oneiron hook
--host <client> <event>`, which reads that client's event on stdin and
answers it in that client's format.

Agent Plugins 1.0 defines no hooks; a client's own files sit in the
package's top-level folder named for the client's namespace (spec §8.2).
So the hooks stay per client:

| Client | Hook file | Read from |
|---|---|---|
| Codex | `plugins/agent-plugins/com.openai/hooks/hooks.json` | the shared package; its `plugin.json` names the file in `extensions.com.openai.hooks` |
| GitHub Copilot (VS Code, the Copilot CLI) | `plugins/agent-plugins/com.github.copilot/hooks/hooks.json` | the shared package's `com.github.copilot` folder |
| Cursor | `plugins/cursor/hooks/hooks.json` | the Cursor plugin `plugins/cursor/` (Cursor reads hooks only from a Cursor plugin, never from an Agent Plugins package) |

| Lane | Codex | Copilot | Cursor | `oneiron hook` |
|---|---|---|---|---|
| Session start | `SessionStart` | `SessionStart` | `sessionStart` | `session-start` |
| Before compaction | `PreCompact` | `PreCompact` | `preCompact` | `hand-over` |
| End of each turn | `Stop` | `Stop` | `stop` | `hand-over` |
| Session end | `SessionEnd` | none: Copilot's `SessionEnd` names no log | `sessionEnd` | `hand-over` |

What the session is told goes into its context, as with Claude Code: Codex
adds the hook's plain text as developer context; Copilot reads one JSON
object and adds its `additionalContext`; Cursor reads one JSON object and
adds its `additional_context` to the conversation's initial context. No
client shows it as a message of its own; the agent sees it. Cursor's
`sessionStart` names no `cwd`, so the project is the first of its
`workspace_roots`.

No client here wires the prompt lane. Copilot drops a command hook's output
for a prompt, and Cursor's prompt hook takes no context. Codex would add it;
add a `UserPromptSubmit` entry running `oneiron hook --host codex prompt
--credential-file <file>` if you want a recall for each prompt.

## Set up

Turn on the import queue in `serve`'s config
([Claude Code hooks, step 1](claude-code-hooks.md#1-turn-on-the-import-queue)),
then for each client:

1. **Mint the hooks' credential** with `serve` stopped, under the client's
   name and at the path its hook file reads:

   ```bash
   oneiron token agent --name codex-hooks --tier read-only \
     --out ~/.config/oneiron/codex-hooks.cred
   ```

   Use `copilot-hooks` and `cursor-hooks` for the others. The hooks only
   read, so the credential is read-only. It is separate from the agent
   credential the MCP entry reads (`agent.cred` in the plugin's data folder),
   so you can revoke either alone.
2. **Let `serve` read the client's logs.** A Codex hand-over queues a rollout
   under `~/.codex/sessions` (or `codex_root`). Copilot and Cursor hand over
   a hook transcript, which `serve` reads only under a folder listed in
   `[import] hook_transcript_roots`
   ([Import history](import-history.md#a-coding-agents-hook-transcript-github-copilot-and-cursor)).
   Cursor names no transcript when its transcripts are off; the hand-over
   then does nothing.
3. **Install the hooks.**
   - Codex: install the shared package as a local plugin, then trust its
     hooks: Codex runs none until you review them (`/hooks` in the CLI,
     **Review hooks** in the app), and asks again when they change.
   - Copilot: install the shared package (in VS Code, `chat.pluginLocations`,
     as [Connect an agent](connect-an-agent.md) says). Its hooks run with
     the plugin, and stop when you disable it.
   - Cursor: install `plugins/cursor/` beside the shared package, the way
     Cursor installs a local plugin. It carries the hooks alone; the tools
     and the skill stay in the shared package.

Each hook runs `oneiron` from the `PATH` the client runs hooks with, and
reads the credential at `$HOME/.config/oneiron/<client>-hooks.cred`. The
files write `$HOME`, never `${HOME}`: a client reads `${...}` as its own
placeholder (Cursor fills its plugin variables there), and `$HOME` is left
to the shell. Add `--url <origin>` to `session-start` to pin a vault, and
`--config /path/to/oneiron.toml` to each `hand-over` when `serve` reads
another config and may be stopped when a session ends.

## Timeouts

Each hook gives up before its client would stop it, so it exits 0 on its
own. The session start allows 15 s and each hand-over 10 s; Codex gives a
`SessionEnd` hook at most 3 s, so that one gives up after 2 s, and Cursor's
`sessionEnd` after 4 s of its 5.
