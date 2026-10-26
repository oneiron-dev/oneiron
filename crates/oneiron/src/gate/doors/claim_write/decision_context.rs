//! A claim decision's context, computed once from the full candidate before
//! its record is built (FIX 7499, 7500, 7801): the candidate's read context,
//! the Dreamer run that wrote it, and the ruled risk vector over its value,
//! evidence, scope and session tag (ARCH-0040 `dr:SK07`). Every part is
//! metadata. No result here decides, holds or refuses a write, and nothing
//! is computed after the record is appended.

use rmpv::Value;

use crate::claim::ClaimBody;
use crate::entity_id::EntityId;
use crate::store::{
    GateAnalysisCoverage, GateDecisionAnalysis, GateDecisionContext, GateDecisionReadContext,
    GateLoopLink, GateLoopOrigin, GateLoopSource, GateRiskAxis, GateRiskState,
};

/// The rule set the risk vector below is computed by (CALLS "FIX 7801 risk
/// rule set"): secret shapes by the batch write door's own scan; paths and
/// commands only under the structured keys below, never in free prose.
pub(crate) const GATE_RISK_RULES: &str = "gate.risk.v1";

/// The map keys whose values the path rules read.
const PATH_KEYS: &[&str] = &[
    "path",
    "paths",
    "file",
    "files",
    "file_path",
    "filepath",
    "filename",
    "cwd",
    "dir",
    "directory",
];

/// The map keys whose values the command rules read: an argv list, or one
/// command line in no shell grammar.
const COMMAND_KEYS: &[&str] = &["command", "cmd", "argv", "command_line", "commandline"];

/// Characters that make a command line shell grammar the rules do not read.
const SHELL_GRAMMAR: &[char] = &[
    '|', ';', '&', '$', '`', '(', ')', '<', '>', '*', '?', '{', '}', '[', ']', '\'', '"', '\\',
    '\n',
];

/// The context of the decision on claim `id` written as `body`, by the run
/// `run` when a Dreamer run wrote it.
pub(super) fn claim_decision_context(
    id: &EntityId,
    body: &ClaimBody,
    run: Option<&str>,
) -> GateDecisionContext {
    GateDecisionContext {
        read: GateDecisionReadContext::claim(id, body).into_iter().collect(),
        links: run
            .map(|run| {
                GateLoopLink::action(
                    GateLoopSource::Runner,
                    Some(run.to_owned()),
                    None,
                    GateLoopOrigin::Unresolved,
                )
            })
            .into_iter()
            .collect(),
        analysis: Some(claim_analysis(body)),
    }
}

/// The ruled risk vector of `body`: its value, evidence and scope, each
/// walked for path and command keys and scanned for secret shapes, and its
/// session tag scanned as text. The envelope names each surface read; the
/// predicate, a grammar-checked name, is not one.
pub(crate) fn claim_analysis(body: &ClaimBody) -> GateDecisionAnalysis {
    let mut paths = AxisScan::default();
    let mut commands = AxisScan::default();
    let mut secrets = AxisScan::default();
    let mut surfaces = Vec::new();
    let structured = [
        ("value", Some(&body.value)),
        ("evidence", body.evidence.as_ref()),
        ("scope", body.scope.as_ref()),
    ];
    for (surface, value) in structured {
        let Some(value) = value else {
            continue;
        };
        walk(value, &mut paths, &mut commands);
        let mut bytes = Vec::new();
        if rmpv::encode::write_value(&mut bytes, value).is_err() {
            secrets.unread += 1;
            continue;
        }
        surfaces.push(surface.to_owned());
        secrets.read += 1;
        if let Some(code) = crate::batch::secret_scan::write_payload_hit(&bytes) {
            secrets.hit(code);
        }
    }
    if let Some(tag) = &body.session_tag {
        surfaces.push("session_tag".to_owned());
        secrets.read += 1;
        if let Some(code) = crate::batch::secret_scan::write_payload_hit(tag.as_bytes()) {
            secrets.hit(code);
        }
    }
    GateDecisionAnalysis {
        rules: GATE_RISK_RULES.to_owned(),
        surfaces,
        sensitive_path: paths.into_axis(),
        secret_argument: secrets.into_axis(),
        dangerous_command: commands.into_axis(),
    }
}

/// What one axis's rules read and found.
#[derive(Default)]
struct AxisScan {
    /// Surfaces read whole.
    read: usize,
    /// Surfaces in a form the rules do not read.
    unread: usize,
    matched: Vec<&'static str>,
}

impl AxisScan {
    fn hit(&mut self, rule: &'static str) {
        if !self.matched.contains(&rule) {
            self.matched.push(rule);
        }
    }

    /// A hit stands whatever was left unread; no hit is `NoHit` only when
    /// every surface was read, else `NotAnalysed`, never a clean stamp.
    fn into_axis(self) -> GateRiskAxis {
        let state = if !self.matched.is_empty() {
            GateRiskState::Hit
        } else if self.unread > 0 {
            GateRiskState::NotAnalysed
        } else if self.read > 0 {
            GateRiskState::NoHit
        } else {
            GateRiskState::NotApplicable
        };
        let coverage = match (self.read, self.unread) {
            (_, 0) => GateAnalysisCoverage::Complete,
            (0, _) => GateAnalysisCoverage::None,
            _ => GateAnalysisCoverage::Partial,
        };
        GateRiskAxis {
            state,
            coverage,
            matched: self.matched.into_iter().map(str::to_owned).collect(),
        }
    }
}

/// Every map entry in `value`, at any depth, whose key names a path or a
/// command, through the axis that reads it.
fn walk(value: &Value, paths: &mut AxisScan, commands: &mut AxisScan) {
    match value {
        Value::Map(entries) => {
            for (key, value) in entries {
                if let Some(key) = key.as_str().map(str::to_ascii_lowercase) {
                    if PATH_KEYS.contains(&key.as_str()) {
                        read_paths(value, paths);
                    } else if COMMAND_KEYS.contains(&key.as_str()) {
                        read_command(value, commands);
                    }
                }
                walk(value, paths, commands);
            }
        }
        Value::Array(items) => {
            for item in items {
                walk(item, paths, commands);
            }
        }
        _ => {}
    }
}

fn read_paths(value: &Value, scan: &mut AxisScan) {
    match value {
        Value::Nil => {}
        Value::Array(items) => {
            for item in items {
                read_paths(item, scan);
            }
        }
        _ => match value.as_str() {
            Some(path) => {
                scan.read += 1;
                path_rules(path, scan);
            }
            None => scan.unread += 1,
        },
    }
}

/// `.env` files and the `.ssh` and `.aws` credential directories.
fn path_rules(path: &str, scan: &mut AxisScan) {
    let parts: Vec<&str> = path
        .trim()
        .split(['/', '\\'])
        .filter(|part| !part.is_empty())
        .collect();
    if parts
        .last()
        .is_some_and(|name| *name == ".env" || name.starts_with(".env."))
    {
        scan.hit("path.dotenv");
    }
    if parts.contains(&".ssh") {
        scan.hit("path.ssh");
    }
    if parts.contains(&".aws") {
        scan.hit("path.aws");
    }
}

fn read_command(value: &Value, scan: &mut AxisScan) {
    match value {
        Value::Nil => {}
        Value::Array(items) => {
            let argv: Option<Vec<&str>> = items.iter().map(Value::as_str).collect();
            match argv {
                Some(argv) => {
                    scan.read += 1;
                    command_rules(&argv, scan);
                }
                None => scan.unread += 1,
            }
        }
        _ => match value.as_str() {
            Some(line) if !line.contains(SHELL_GRAMMAR) => {
                scan.read += 1;
                command_rules(&line.split_whitespace().collect::<Vec<_>>(), scan);
            }
            _ => scan.unread += 1,
        },
    }
}

/// Recursive forced `rm`, `dd` onto a device, and filesystem format or wipe.
fn command_rules(argv: &[&str], scan: &mut AxisScan) {
    let argv = match argv.split_first() {
        Some((first, rest)) if program_name(first) == "sudo" => rest,
        _ => argv,
    };
    let Some((first, args)) = argv.split_first() else {
        return;
    };
    let program = program_name(first);
    let short = |flag: char| {
        args.iter()
            .any(|arg| arg.starts_with('-') && !arg.starts_with("--") && arg.contains(flag))
    };
    let long = |flag: &str| args.contains(&flag);
    if program == "rm"
        && (short('r') || short('R') || long("--recursive"))
        && (short('f') || long("--force"))
    {
        scan.hit("command.rm_recursive_force");
    }
    if program == "dd" && args.iter().any(|arg| arg.starts_with("of=/dev/")) {
        scan.hit("command.dd_device_output");
    }
    if program == "mkfs" || program.starts_with("mkfs.") || program == "wipefs" {
        scan.hit("command.filesystem_format");
    }
}

/// A command's program name, without its directory.
fn program_name(arg: &str) -> &str {
    arg.rsplit('/').next().unwrap_or(arg)
}
