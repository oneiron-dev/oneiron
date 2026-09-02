//! ONE-1579: capture the settings this artifact is ACTUALLY COMPILED with.
//!
//! Latency, throughput and RSS are properties of an artifact. The name of the
//! Cargo profile that requested a build says nothing about what the compiler
//! emitted: `[profile.release] opt-level = 0` still calls itself `release`,
//! and `[profile.release] overflow-checks = true` still calls itself
//! `release`. So the publication predicate must read the SETTINGS, and this
//! build script is where the stable, compile-time capture of them happens.
//!
//! Cargo hands a build script the settings it is compiling the package with:
//!
//! * `OPT_LEVEL` is the optimisation level itself — the value the crate is
//!   compiled at, not a profile name that claims one. It is embedded verbatim.
//! * `PROFILE` is the profile NAME. It is embedded as PROVENANCE only; nothing
//!   in the publication predicate is allowed to rest on it.
//! * overflow checks are not exported as a profile setting, so what is
//!   embedded here is only the part a build script can KNOW: an explicit
//!   `-C overflow-checks=…` in the build's rustflags (which is what rustc will
//!   honour last), or `CARGO_CFG_OVERFLOW_CHECKS` when the cfg reached this
//!   script. Anything else is embedded as `unknown` rather than guessed, and
//!   the crate itself then observes its own emitted code.
//!
//! `cfg!(overflow_checks)` is deliberately NOT used anywhere: it is unstable
//! (rustc E0658 / rust-lang#111466) and would not build on the pinned stable
//! toolchain.

use std::env;

/// The separator Cargo uses inside `CARGO_ENCODED_RUSTFLAGS`.
const ENCODED_SEPARATOR: char = '\u{1f}';

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    for variable in [
        "OPT_LEVEL",
        "PROFILE",
        "DEBUG",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTFLAGS",
        "CARGO_CFG_OVERFLOW_CHECKS",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }

    // The optimisation level this crate is being compiled AT. Cargo resolves
    // profile inheritance and per-profile overrides before it exports this, so
    // an unoptimised `release` build reports `0` here however it is named.
    let opt_level = env::var("OPT_LEVEL").unwrap_or_default();
    println!("cargo:rustc-env=ONEIRON_BENCH_COMPILED_OPT_LEVEL={opt_level}");

    // Provenance only: the profile NAME Cargo used for this compilation.
    let profile = env::var("PROFILE").unwrap_or_default();
    println!("cargo:rustc-env=ONEIRON_BENCH_COMPILED_PROFILE={profile}");

    let (overflow_checks, source) = overflow_checks();
    println!("cargo:rustc-env=ONEIRON_BENCH_COMPILED_OVERFLOW_CHECKS={overflow_checks}");
    println!("cargo:rustc-env=ONEIRON_BENCH_COMPILED_OVERFLOW_CHECKS_SOURCE={source}");
}

/// What the build environment can prove about overflow checks, plus where that
/// came from. Fail-open is not an option here: a setting this script cannot
/// establish is embedded as `unknown`, never as `off`.
fn overflow_checks() -> (&'static str, String) {
    if let Some(explicit) = rustflag_overflow_checks() {
        return (
            if explicit { "on" } else { "off" },
            "explicit -C overflow-checks in this build's rustflags, which rustc honours last"
                .to_owned(),
        );
    }
    if env::var_os("CARGO_CFG_OVERFLOW_CHECKS").is_some() {
        return (
            "on",
            "CARGO_CFG_OVERFLOW_CHECKS was exported to this build script".to_owned(),
        );
    }
    (
        "unknown",
        "no explicit -C overflow-checks and no CARGO_CFG_OVERFLOW_CHECKS reached the build \
         script, so the profile setting is unknown to it"
            .to_owned(),
    )
}

/// The LAST explicit `-C overflow-checks=…` in the build's rustflags, matching
/// rustc's own last-flag-wins resolution. `None` means the flag was not given.
fn rustflag_overflow_checks() -> Option<bool> {
    let tokens = rustflag_tokens();
    let mut resolved = None;
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        let value = if let Some(rest) = token.strip_prefix("-C").filter(|rest| !rest.is_empty()) {
            codegen_overflow_checks(rest)
        } else if let Some(rest) = token.strip_prefix("--codegen=") {
            codegen_overflow_checks(rest)
        } else if token == "-C" || token == "--codegen" {
            index += 1;
            tokens
                .get(index)
                .map(String::as_str)
                .and_then(codegen_overflow_checks)
        } else {
            None
        };
        if let Some(value) = value {
            resolved = Some(value);
        }
        index += 1;
    }
    resolved
}

/// Rustflags as separate arguments. `CARGO_ENCODED_RUSTFLAGS` is authoritative
/// when Cargo set it (it can encode arguments containing spaces); the
/// whitespace-split `RUSTFLAGS` is only a fallback for an older Cargo.
fn rustflag_tokens() -> Vec<String> {
    if let Ok(encoded) = env::var("CARGO_ENCODED_RUSTFLAGS") {
        return encoded
            .split(ENCODED_SEPARATOR)
            .filter(|token| !token.is_empty())
            .map(str::to_owned)
            .collect();
    }
    let Ok(raw) = env::var("RUSTFLAGS") else {
        return Vec::new();
    };
    raw.split_whitespace().map(str::to_owned).collect()
}

/// `overflow-checks`, `overflow-checks=on`, `overflow-checks=off` … inside one
/// codegen argument. A bare `-C overflow-checks` enables them, exactly as rustc
/// reads it.
fn codegen_overflow_checks(argument: &str) -> Option<bool> {
    let rest = argument.trim().strip_prefix("overflow-checks")?;
    if rest.is_empty() {
        return Some(true);
    }
    parse_flag(rest.strip_prefix('=')?)
}

fn parse_flag(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "y" | "yes" | "on" | "true" => Some(true),
        "n" | "no" | "off" | "false" => Some(false),
        _ => None,
    }
}
