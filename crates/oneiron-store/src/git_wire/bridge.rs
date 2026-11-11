//! `repo_mutation` migration bridge: validated arbitrary-argv entry plus failure redaction.

use std::ffi::OsString;
use std::path::Path;

use crate::git_wire::argv::bridged_argv_token;
use crate::git_wire::config::GIT_WIRE_BRIDGED_CONFIG_KEYS;
use crate::git_wire::config::GIT_WIRE_MAX_ARGS;
use crate::git_wire::failure::classify_diagnostics;
use crate::git_wire::failure::invalid;
use crate::git_wire::record::hex_lower;
use oneiron_base::error::Result;

/// The redacted description of a bridged git failure.
///
/// `repo_mutation` persists its failures in the durable oplog, so the same rule
/// that governs GitWire's own errors governs the bridge: a class, an exit code,
/// and a digest — never the child's diagnostics and never the argv, which can
/// carry absolute paths, commit messages, and ref labels.
pub fn redact_bridged_failure(args: &[String], code: Option<i32>, stderr: &[u8]) -> String {
    let verb = bridged_verb_index(args)
        .ok()
        .and_then(|index| args.get(index))
        .map_or("unknown", String::as_str);
    let class = classify_diagnostics(stderr).as_str();
    let digest = hex_lower(blake3::hash(stderr).as_bytes());
    let short = &digest[..16];
    let len = stderr.len();
    format!("git {verb} failed: class={class} exit={code:?} diag=blake3:{short} bytes={len}")
}

pub fn bridged_argv(args: &[String]) -> Result<Vec<OsString>> {
    if args.is_empty() || args.len() > GIT_WIRE_MAX_ARGS {
        return Err(invalid("git argv must be non-empty and bounded"));
    }
    let verb_index = bridged_verb_index(args)?;
    validate_bridged_prefix(&args[..verb_index])?;
    validate_forbidden_shape(&args[verb_index..])?;
    let mut argv = Vec::with_capacity(args.len());
    for arg in args {
        argv.push(bridged_argv_token(arg)?);
    }
    Ok(argv)
}

pub fn bridged_verb_index(args: &[String]) -> Result<usize> {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "-c" {
            index += 2;
            continue;
        }
        if arg.starts_with('-') {
            index += 1;
            continue;
        }
        return Ok(index);
    }
    Err(invalid("git argv must carry a verb"))
}

fn validate_bridged_prefix(prefix: &[String]) -> Result<()> {
    let mut index = 0;
    while index < prefix.len() {
        if prefix[index] != "-c" {
            return Err(invalid("git argv accepts only frozen -c identity pairs"));
        }
        let pair = prefix
            .get(index + 1)
            .ok_or_else(|| invalid("git -c option is missing its value"))?;
        let key = pair
            .split_once('=')
            .map(|(key, _)| key)
            .ok_or_else(|| invalid("git -c option must be key=value"))?;
        if !GIT_WIRE_BRIDGED_CONFIG_KEYS.contains(&key) {
            return Err(invalid("git -c option key is not an allowed identity key"));
        }
        index += 2;
    }
    Ok(())
}

fn validate_forbidden_shape(tail: &[String]) -> Result<()> {
    let verb = tail
        .first()
        .ok_or_else(|| invalid("git argv must carry a verb"))?;
    // The scan deliberately runs over `iter().skip(1)` rather than a `&tail[1..]`
    // slice: the forbidden shapes are argument *positions* after the verb, and
    // the iterator form keeps this a shape check rather than a slice membership
    // test over owned `String`s.
    let forbidden = match verb.as_str() {
        "clean" => true,
        "reset" => tail.iter().skip(1).any(|arg| arg == "--hard"),
        "checkout" => tail.iter().skip(1).any(|arg| arg == "."),
        _ => false,
    };
    if forbidden {
        return Err(invalid("git verb shape is forbidden for repo mutations"));
    }
    Ok(())
}
