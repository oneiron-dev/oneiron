//! Every `GIT_WIRE_*` constant: schema, domain, bounds, env baseline, closed config policy.

use std::time::Duration;

/// Schema version of the durable GitWire record.
pub const GIT_WIRE_SCHEMA_VERSION: u8 = 2;

/// Domain separator of every GitWire derived key.
pub const GIT_WIRE_DOMAIN: &[u8] = b"oneiron:git-wire:v2";

/// `vault_meta` keyspace of GitWire records. Rows are repo-scoped
/// (`<prefix><repo-identity>:<record-key>`) so one unreadable row can only
/// affect the repository that wrote it.
pub const GIT_WIRE_RECORD_KEY_PREFIX: &[u8] = b"git_wire:record:v2:";

/// Namespace of the protected keep-refs that hold engine object sets alive.
pub const GIT_WIRE_KEEP_REF_PREFIX: &str = "refs/oneiron/keep/";

/// Directory name of the private, repository-scoped checkout root.
pub const GIT_WIRE_CHECKOUT_ROOT_NAME: &str = "oneiron-checkout";

/// Advisory lock file, in the canonical git common directory, that serializes
/// every engine ref/worktree effect across threads and processes.
pub const GIT_WIRE_REPO_LOCK_FILE_NAME: &str = "oneiron-repo-mutation.lock";

/// The process baseline a git child may inherit. `GIT_CONFIG_*`,
/// `GIT_TERMINAL_PROMPT`, and the other pinned keys are deliberately absent:
/// GitWire assigns them fixed values after `env_clear`, so an ambient value can
/// never reach a child.
pub const GIT_WIRE_INHERITED_ENV_KEYS: [&str; 4] = ["PATH", "TMPDIR", "LANG", "LC_ALL"];

/// Environment pairs forced on every child regardless of the ambient
/// environment. `GIT_NO_LAZY_FETCH` keeps a partial-clone read from becoming a
/// network fetch and an object write; `GIT_OPTIONAL_LOCKS` keeps inspection
/// from taking or refreshing an index lock.
pub const GIT_WIRE_FIXED_ENV: [(&str, &str); 8] = [
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_SYSTEM", "/dev/null"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_OPTIONAL_LOCKS", "0"),
    ("GIT_NO_LAZY_FETCH", "1"),
    ("GIT_ATTR_NOSYSTEM", "1"),
    ("GIT_PAGER", "cat"),
];

/// The closed configuration policy. It is delivered through
/// `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_<n>`/`GIT_CONFIG_VALUE_<n>`, which git
/// treats with command-line precedence, so no repository-local or system
/// setting can reintroduce an executable hook, filter, helper, or signer — and
/// the policy also reaches any git child a git child spawns.
pub const GIT_WIRE_CONFIG_POLICY: [(&str, &str); 18] = [
    ("core.hooksPath", "/dev/null"),
    ("core.fsmonitor", ""),
    ("core.askPass", ""),
    ("core.editor", "false"),
    ("core.pager", "cat"),
    ("core.sshCommand", "false"),
    ("core.attributesFile", "/dev/null"),
    ("core.autocrlf", "false"),
    ("credential.helper", ""),
    ("diff.external", ""),
    ("gc.auto", "0"),
    ("maintenance.auto", "false"),
    ("gpg.program", "false"),
    ("gpg.ssh.program", "false"),
    ("gpg.x509.program", "false"),
    ("commit.gpgSign", "false"),
    ("uploadpack.packObjectsHook", ""),
    ("protocol.allow", "never"),
];

pub(super) const GIT_WIRE_DEFAULT_BINARY: &str = "git";

pub(super) const GIT_WIRE_DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

pub(super) const GIT_WIRE_DEFAULT_MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

pub(super) const GIT_WIRE_MAX_ARG_BYTES: usize = 65_536;

pub(super) const GIT_WIRE_MAX_ARGS: usize = 64;

pub(super) const GIT_WIRE_MAX_REF_BYTES: usize = 200;

pub(super) const GIT_WIRE_MAX_PLAN_OBJECTS: usize = 256;

pub(super) const GIT_WIRE_MAX_PUBLICATIONS: usize = 64;

pub(super) const GIT_WIRE_OID_HEX_LEN: usize = 40;

pub(super) const GIT_WIRE_READ_CHUNK_BYTES: usize = 8192;

pub(super) const GIT_WIRE_POLL_INTERVAL: Duration = Duration::from_millis(2);

/// The only `-c <key>=<value>` pairs the migration bridge accepts ahead of the
/// verb; the closed policy itself is applied by GitWire, not by callers.
pub(super) const GIT_WIRE_BRIDGED_CONFIG_KEYS: [&str; 2] = ["user.name", "user.email"];

/// Commit-object headers a caller may never shadow through `extra_headers`.
pub(super) const GIT_WIRE_RESERVED_COMMIT_HEADERS: [&str; 7] = [
    "tree",
    "parent",
    "author",
    "committer",
    "encoding",
    "gpgsig",
    "mergetag",
];
