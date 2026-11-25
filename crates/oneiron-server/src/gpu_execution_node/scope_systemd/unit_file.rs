//! The job unit template (pass 33, section 7.6) and the rule that lets the
//! engine's account start and stop its instances, as `install` writes them.
//!
//! One list of unit properties ([`sandbox_properties`]) makes both the
//! template and the transient probe unit of `execution-node check`, so the
//! probe proves exactly the bounds a job gets.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use super::{EXCHANGE_ROOT, PAYLOAD_ROOT};

/// What a unit template is made from: the paths and accounts `install`
/// resolved, and the node's settings that are unit properties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitInputs {
    /// The `oneiron` binary the unit's steps run: absolute, root-owned.
    pub binary: PathBuf,
    /// The node's `[execution_node]` file: absolute, root-owned.
    pub node_file: PathBuf,
    /// The account `oneiron serve` runs as.
    pub engine_account: String,
    /// The account the job runs as.
    pub job_account: String,
    pub state_dir: PathBuf,
    pub work_dir: PathBuf,
    /// Paths no job may open, besides `state_dir`: the vault's trees, the
    /// keystore, the engine account's home.
    pub protected: Vec<PathBuf>,
    /// The largest `max_secs` of any template: the unit's last backstop.
    pub runtime_max_secs: u64,
    /// The stop grace (TERM, then KILL after it), inside each maximum.
    pub stop_grace_secs: u64,
    /// The longest the unit's start (prepare, the proofs, the gate) may take.
    pub start_timeout_secs: u64,
}

/// The unit's sandbox and life-cycle properties, as `(name, value)` pairs in
/// the order the template lists them. `instance` is `%i` in the template and
/// the probe's id in a probe unit.
#[must_use]
pub fn sandbox_properties(inputs: &UnitInputs, instance: &str) -> Vec<(String, String)> {
    let mut properties: Vec<(String, String)> = Vec::new();
    let mut set = |name: &str, value: String| properties.push((name.to_owned(), value));
    set("Type", "exec".to_owned());
    set("User", inputs.job_account.clone());
    set("Group", inputs.job_account.clone());
    set("Restart", "no".to_owned());
    set("KillMode", "control-group".to_owned());
    set("OOMPolicy", "stop".to_owned());
    set("TimeoutStartSec", inputs.start_timeout_secs.to_string());
    set("TimeoutStopSec", inputs.stop_grace_secs.to_string());
    set("RuntimeMaxSec", inputs.runtime_max_secs.to_string());
    set("MemorySwapMax", "0".to_owned());
    set("NoNewPrivileges", "yes".to_owned());
    set("PrivateNetwork", "yes".to_owned());
    set("PrivateIPC", "yes".to_owned());
    set("PrivateTmp", "yes".to_owned());
    set("DevicePolicy", "closed".to_owned());
    set("ProtectProc", "invisible".to_owned());
    set("ProtectSystem", "strict".to_owned());
    set("ProtectKernelTunables", "yes".to_owned());
    set("ProtectKernelModules", "yes".to_owned());
    set("ProtectKernelLogs", "yes".to_owned());
    set("ProtectControlGroups", "yes".to_owned());
    set("ProtectClock", "yes".to_owned());
    set("ProtectHostname", "yes".to_owned());
    set("RestrictSUIDSGID", "yes".to_owned());
    set("RestrictRealtime", "yes".to_owned());
    set("LockPersonality", "yes".to_owned());
    set("CapabilityBoundingSet", String::new());
    set("AmbientCapabilities", String::new());
    set("UMask", "0022".to_owned());
    set("KeyringMode", "private".to_owned());
    let mut inaccessible = vec![quote_path(&inputs.state_dir)];
    for path in &inputs.protected {
        inaccessible.push(format!("-{}", quote_path(path)));
    }
    set("InaccessiblePaths", inaccessible.join(" "));
    // Each job sees its own payload and exchange directories and no other
    // job's: an empty read-only tmpfs over each root, with this instance's
    // directory bound back in (systemd.exec(5), TemporaryFileSystem=). The
    // payload comes from its root-owned bind source, never from the engine's
    // path (review r2 R2-12). Each source is optional (`-`): the service
    // manager gives the `+` root steps these mounts too, and the prepare step
    // that makes the sources runs before they exist (qualification q1,
    // systemd 262). A job whose sources are missing finds no exec.json and
    // no payload, and refuses before any workload exists.
    set(
        "TemporaryFileSystem",
        format!("{}:ro {EXCHANGE_ROOT}:ro", quote_path(&inputs.work_dir)),
    );
    let payload = inputs.work_dir.join(instance);
    set(
        "BindPaths",
        format!(
            "-{}:{}",
            quote_path(&Path::new(PAYLOAD_ROOT).join(instance)),
            quote_path(&payload)
        ),
    );
    set("ReadWritePaths", format!("-{}", quote_path(&payload)));
    set(
        "BindReadOnlyPaths",
        format!("-{}", quote_path(&Path::new(EXCHANGE_ROOT).join(instance))),
    );
    properties
}

/// The unit template `install` writes to `oneiron-job@.service`.
#[must_use]
pub fn render_job_unit(inputs: &UnitInputs) -> String {
    let binary = quote_path(&inputs.binary);
    let root_args = format!(
        "--node-file {} --engine-account {}",
        quote_path(&inputs.node_file),
        inputs.engine_account
    );
    let mut text = String::new();
    text.push_str(
        "# Written by `oneiron execution-node install` (pass 33, section 7.6); root-owned.\n\
         # Do not edit: install writes it again, and the prepare step refuses a job whose\n\
         # maximum is past this file's RuntimeMaxSec.\n\
         [Unit]\n\
         Description=Oneiron job %i\n\n\
         [Service]\n",
    );
    let _ = writeln!(text, "ExecStartPre=+{binary} job-prepare {root_args} %i");
    let _ = writeln!(text, "ExecStart={binary} job-exec %i");
    let _ = writeln!(
        text,
        "ExecStartPost=+{binary} job-prepare --after-exec {root_args} %i"
    );
    let _ = writeln!(text, "ExecStopPost=+{binary} job-ended {root_args} %i");
    for (name, value) in sandbox_properties(inputs, "%i") {
        let _ = writeln!(text, "{name}={value}");
    }
    text
}

/// The polkit rule: the engine's account may start and stop units named
/// `oneiron-job@<32 hex>.service`, and nothing else. Every other unit, verb
/// and account falls through to the system's own rules.
#[must_use]
pub fn render_polkit_rule(engine_account: &str) -> String {
    format!(
        "// Written by `oneiron execution-node install` (pass 33, section 7.6); root-owned.\n\
         // The engine's account may start and stop instances of the job unit template, and nothing else.\n\
         polkit.addRule(function(action, subject) {{\n    \
             if (action.id == \"org.freedesktop.systemd1.manage-units\" &&\n        \
                 subject.user == \"{engine_account}\" &&\n        \
                 /^oneiron-job@[0-9a-f]{{32}}\\.service$/.test(action.lookup(\"unit\")) &&\n        \
                 (action.lookup(\"verb\") == \"start\" || action.lookup(\"verb\") == \"stop\")) {{\n        \
                 return polkit.Result.YES;\n    \
             }}\n\
         }});\n"
    )
}

/// The value of `RuntimeMaxSec=` in an installed template, if it has one.
#[must_use]
pub fn installed_runtime_max_secs(unit_text: &str) -> Option<u64> {
    unit_text
        .lines()
        .find_map(|line| line.strip_prefix("RuntimeMaxSec="))
        .and_then(|value| value.trim().parse().ok())
}

/// A path as one unit-file word: systemd splits these settings on spaces, so
/// a path with a space or a quote is refused at install instead.
fn quote_path(path: &Path) -> String {
    path.display().to_string()
}

/// Why a path cannot stand in the unit file: it must be absolute and hold
/// no space, quote, backslash, `%` or control character.
///
/// # Errors
///
/// The reason, naming the path.
pub fn unit_path_word(path: &Path) -> Result<(), String> {
    let text = path.display().to_string();
    if !path.is_absolute() {
        return Err(format!("{text}: the unit file needs an absolute path"));
    }
    if text.chars().any(|ch| {
        ch.is_whitespace() || ch.is_control() || matches!(ch, '"' | '\'' | '\\' | '%' | ';')
    }) {
        return Err(format!(
            "{text}: the unit file cannot hold a path with a space, a quote, a backslash, '%' or ';'"
        ));
    }
    Ok(())
}

/// Whether an account name is one the unit file and the rule may hold.
#[must_use]
pub fn plain_account(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
        && !name.starts_with('-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> UnitInputs {
        UnitInputs {
            binary: "/usr/bin/oneiron".into(),
            node_file: "/etc/oneiron/execution-node.toml".into(),
            engine_account: "oneiron".to_owned(),
            job_account: "oneiron-job".to_owned(),
            state_dir: "/var/lib/oneiron/jobs".into(),
            work_dir: "/data/oneiron-jobs".into(),
            protected: vec!["/var/lib/oneiron".into()],
            runtime_max_secs: 172_800,
            stop_grace_secs: 10,
            start_timeout_secs: 60,
        }
    }

    #[test]
    fn the_template_runs_the_three_root_steps_and_the_job_as_its_own_account() {
        let text = render_job_unit(&inputs());
        assert!(text.contains("ExecStartPre=+/usr/bin/oneiron job-prepare --node-file /etc/oneiron/execution-node.toml --engine-account oneiron %i\n"));
        assert!(text.contains("ExecStart=/usr/bin/oneiron job-exec %i\n"));
        assert!(text.contains("ExecStopPost=+/usr/bin/oneiron job-ended "));
        assert!(text.contains("User=oneiron-job\n"));
        assert!(text.contains("PrivateNetwork=yes\n"));
        assert!(text.contains("BindPaths=-/run/oneiron-payloads/%i:/data/oneiron-jobs/%i\n"));
        assert!(text.contains("BindReadOnlyPaths=-/run/oneiron-jobs/%i\n"));
        assert_eq!(installed_runtime_max_secs(&text), Some(172_800));
    }

    #[test]
    fn the_rule_names_only_job_units_and_only_start_and_stop() {
        let rule = render_polkit_rule("oneiron");
        assert!(rule.contains("subject.user == \"oneiron\""));
        assert!(rule.contains("/^oneiron-job@[0-9a-f]{32}\\.service$/"));
        assert!(rule.contains("action.lookup(\"verb\") == \"stop\""));
    }
}
