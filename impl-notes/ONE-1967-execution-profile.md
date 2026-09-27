# ONE-1967 Git execution profile (banked choice A)

Owner review pending. The orchestrator banked A in its external owner-rulings file: admitted, immutable SHA-1 Git execution profiles for files and reftable, with pre-mutation refusal of unsupported profiles. This note is implementation context, not a canon amendment.

## Invariant

The child never reads a repository-selected executable program from mutable local or worktree config. The private execution view preserves admitted object/ref identity and non-executable file meaning. A profile whose observed semantics or layout cannot be represented is refused *before* the operation mutates an index, ref, or worktree. A worktree receipt is Applied only when the registered worktree resolves the requested commit **and** retains the admitted worktree-scoped semantics after private state is gone. Recovery checks the same durable semantic digest.

## Closed contexts

- Proven local repository: canonical common dir, repo root or linked worktree root, pinned SHA-1 commit, expected ref backend. `FrozenGitArgv` supplies the typed operation/effect class; the validated repo-mutation bridge supplies its closed verb; no launcher argv scan determines trust.
- Engine-owned bare hub scratch: its validated `--git-dir=repo` selector, persistent `remote.origin` config and fixed network-read profile stay intact. It never checks out a worktree, so it never needs the attribute-consuming shadow.
- Discovery reads before proof (`rev-parse`, object identity) may run under the fixed GitWire environment without an attribute-consuming profile; they cannot certify a write.

## Admission matrix for attribute-consuming commands

| Observed input | Decision |
|---|---|
| SHA-1 object format, `core.repositoryformatversion=0` + files refs | Preserve as typed `Files` layout; refs/objects/worktrees/logs/packed-refs are bound to proven common dir. |
| SHA-1, `core.repositoryformatversion=1` + `extensions.refStorage=reftable` | Preserve as typed `Reftable` layout; shadow config declares version 1/refStorage, and both common and linked-worktree reftable stores are bound. |
| Unknown object format, ref backend, repository-format version, extension, sparse checkout/index, or unmodeled shape | Reject before mutation. No files-backend fallback. |
| Effective `core.filemode` and `core.symlinks` booleans (common and worktree precedence) | Parse and freeze normalized values in one snapshot; emit exactly those booleans. Typed worktree-scoped overrides are persisted in the new registration before success and checked by the journal digest on recovery. |
| Tracked `.gitattributes` without external filter configuration | Preserve; `text eol=crlf` remains effective. `.git/info/attributes` with nonempty unsupported content is refused, not silently dropped. |
| Local/worktree `filter.*`, includes, `merge.renormalize`, executable helpers not already pinned by the fixed environment | Reject for attribute consumers, including the `merge-tree --write-tree` conflict-preparation verb. A source-only preflight is not the security boundary; the consuming child gets a private config and info/attributes for its whole lifetime. |
| Engine-fixed policy keys (`GIT_CONFIG_COUNT`, 18 pairs) | Apply the existing explicit override. These are not copied from mutable source. |
| Keys irrelevant to the admitted operation (e.g. user/remote/branch names for local checkout/status) | Retain only the command-independent data the command needs; categorize explicitly, never blindly copy raw config. |

## Test matrix

Retain every prior red/green regression. Add: filemode false/true and worktree override; symlinks false/true and worktree override; CRLF checkout/status; SHA-1 files and reftable public `add_worktree` + HEAD postcondition; explicit unsupported config/layout pre-effect refusal; deterministic config-change and conditional-filter marker refusal; `RecordConflict` merge-tree filter refusal and a post-snapshot mutation; durable before-add worktree overrides with clean inspection/staging and recovery refusal on semantic drift; hub skill and pack imports. Reftable Rust fixture runs only on Git with `init --ref-format=reftable`; Git 2.43 Linux hosts cannot create it, so use the Git 2.54 native receipt and a capable reviewer host for that branch.
