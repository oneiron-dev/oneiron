//! Oracle comparison: the synthetic code-mode programs of the tsc-check
//! evidence give the same diagnostics on tsc-rs in process and on Microsoft's
//! TypeScript 7, and both equal `tests/fixtures/golden.txt`.
//!
//! Each program is checked against the engine's own declarations: the WIT
//! host verbs, the verb table's `self.memory` (kept equal to the engine's
//! rendering by `code_mode_declarations_file_is_the_verb_table`), and the
//! interpreter's functions.

use oneiron_code_check::{
    CheckFailure, CheckInput, CodeCheck, Declaration, MICROSOFT_TS_VERSION, MicrosoftTsc,
    TscRsBudget, TscRsWasm,
};
use sha2::{Digest, Sha512};
use std::path::PathBuf;
use std::process::Command;

const DECLARATIONS: [Declaration<'static>; 3] = [
    Declaration {
        name: "code-run.d.ts",
        text: include_str!("../../oneiron/wit/generated/code-run.d.ts"),
    },
    Declaration {
        name: "code-mode.d.ts",
        text: include_str!("../../oneiron/src/task_verb/code-mode.d.ts"),
    },
    Declaration {
        name: "runtime.d.ts",
        text: include_str!("../../../components/code-run-quickjs/runtime.d.ts"),
    },
];

/// Each program with the diagnostic codes the evidence measured on both
/// checkers. The last two are blind spots: both checkers pass them, and each
/// goes wrong at run time.
const FIXTURES: [(&str, &str, &[u32]); 7] = [
    ("01-correct", include_str!("fixtures/01-correct.js"), &[]),
    (
        "02-wrong-verb",
        include_str!("fixtures/02-wrong-verb.js"),
        &[2551],
    ),
    (
        "03-wrong-argument",
        include_str!("fixtures/03-wrong-argument.js"),
        &[2322],
    ),
    (
        "04-missing-await",
        include_str!("fixtures/04-missing-await.js"),
        &[2339],
    ),
    (
        "05-undefined-path",
        include_str!("fixtures/05-undefined-path.js"),
        &[18048],
    ),
    // `finish(value: unknown)` takes the unawaited Promise.
    (
        "06-floating-promise",
        include_str!("fixtures/06-floating-promise.js"),
        &[],
    ),
    // `JSON.parse` returns `any`, which hides the null.
    (
        "07-any-null-path",
        include_str!("fixtures/07-any-null-path.js"),
        &[],
    ),
];

const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/golden.txt");

/// Every program's diagnostics as `tsc --pretty false` prints them, in
/// program coordinates, under a `== name` line.
fn rendered(checker: &dyn CodeCheck) -> String {
    let mut out = String::new();
    for (name, program, codes) in FIXTURES {
        let report = checker
            .check(&CheckInput {
                declarations: &DECLARATIONS,
                program,
            })
            .unwrap_or_else(|failure| panic!("{name}: {failure}"));
        let found: Vec<u32> = report.diagnostics.iter().map(|d| d.code).collect();
        assert_eq!(found, codes, "{name}: {:#?}", report.diagnostics);
        out.push_str(&format!("== {name}\n"));
        for diagnostic in &report.diagnostics {
            out.push_str(&diagnostic.render());
            out.push('\n');
        }
    }
    out
}

#[test]
fn tsc_rs_in_process_gives_the_golden_diagnostics() {
    let checker = TscRsWasm::load(TscRsBudget::default()).unwrap();
    let actual = rendered(&checker);
    if std::env::var_os("ONEIRON_UPDATE_TEST_FIXTURES").is_some() {
        std::fs::write(GOLDEN, &actual).unwrap();
    }
    assert_eq!(actual, std::fs::read_to_string(GOLDEN).unwrap());
}

#[test]
fn microsoft_oracle_gives_the_golden_diagnostics() {
    let checker = MicrosoftTsc::new(oracle()).unwrap();
    assert_eq!(rendered(&checker), std::fs::read_to_string(GOLDEN).unwrap());
    // tsc resolves a module through the host's file system, so the native
    // backend leaves a program that names one unchecked.
    for program in [
        "const outside = await import('/etc/hostname');\nfinish(outside);",
        "/** @type {IMPORT('fs')} */\nconst fs = REQUIRE('fs');\nfinish(fs);",
        "const fs = requ\\u0069re('fs');\nfinish(fs);",
    ] {
        let checked = checker.check(&CheckInput {
            declarations: &DECLARATIONS,
            program,
        });
        assert_eq!(checked, Err(CheckFailure::Unsupported), "{program}");
    }
}

/// The registry's SHA-512 integrity of each platform package at the pin.
const ORACLE_PACKAGES: [(&str, &str, &str, &str); 3] = [
    (
        "linux",
        "x86_64",
        "linux-x64",
        "/O2ofLSO/VmT45ly/Zw1oHii2U5dxs+7zs4Fjg/qkpR9FWjyfidGhOptYX769l4yMw+MrHA5Fmv9pczayomo1A==",
    ),
    (
        "linux",
        "aarch64",
        "linux-arm64",
        "OPIt+zM2cH+trrG1IawPvR97DRuA0DS0uFVsMFzcfSBhS10TuWNStnWX0gPX/IGa6VRI4Vf80Sq7Pdu28bnjVA==",
    ),
    (
        "macos",
        "aarch64",
        "darwin-arm64",
        "wlbeCCvLUclm23v7IzenMIWrtWGhSW9cVxLgaDbqYL4CCePnPcJK8oxCz8k9eaUlx+W2AnMtZj4BEukm+b6I7A==",
    ),
];

/// Microsoft's native `tsc` at [`MICROSOFT_TS_VERSION`]: `ONEIRON_TSC_ORACLE`
/// when set, else the npm platform package, fetched once into the target
/// directory and checked against the registry's integrity before use.
fn oracle() -> PathBuf {
    if let Some(path) = std::env::var_os("ONEIRON_TSC_ORACLE") {
        return path.into();
    }
    let (_, _, platform, integrity) = ORACLE_PACKAGES
        .into_iter()
        .find(|(os, arch, ..)| *os == std::env::consts::OS && *arch == std::env::consts::ARCH)
        .expect("no pinned Microsoft tsc for this platform: set ONEIRON_TSC_ORACLE");
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("tsc-oracle-{MICROSOFT_TS_VERSION}-{platform}"));
    let tsc = root.join("package/lib/tsc");
    if tsc.exists() {
        return tsc;
    }
    let url = format!(
        "https://registry.npmjs.org/@typescript/typescript-{platform}/-/typescript-{platform}-{MICROSOFT_TS_VERSION}.tgz"
    );
    let staging = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).expect("staging directory");
    let archive = staging.path().join("package.tgz");
    let fetched = Command::new("curl")
        .args(["-fsSL", "--retry", "3", "-o"])
        .arg(&archive)
        .arg(&url)
        .status()
        .expect("curl runs");
    assert!(fetched.success(), "fetching {url} failed");
    let digest = Sha512::digest(std::fs::read(&archive).expect("fetched package"));
    assert_eq!(
        base64(&digest),
        integrity,
        "{url} fails its pinned integrity"
    );
    let unpacked = staging.path().join("unpacked");
    std::fs::create_dir(&unpacked).expect("unpack directory");
    let extracted = Command::new("tar")
        .arg("-xzf")
        .arg(&archive)
        .arg("-C")
        .arg(&unpacked)
        .status()
        .expect("tar runs");
    assert!(extracted.success(), "unpacking {url} failed");
    // A concurrent fetch may have won; either copy is the pinned one.
    let _ = std::fs::rename(&unpacked, &root);
    tsc
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let word = chunk.iter().enumerate().fold(0_u32, |word, (i, byte)| {
            word | (u32::from(*byte) << (16 - 8 * i))
        });
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                ALPHABET[((word >> (18 - 6 * i)) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}
