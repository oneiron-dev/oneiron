#!/usr/bin/env node
/**
 * Proves the shipped package majors still equal the MemoryPack schema version.
 *
 * `recall` returns the engine's `MemoryPack`, and a caller's only signal about
 * which pack shape they get is this package's semver MAJOR. So the two are
 * pinned together: `MEMORY_PACK_VERSION = 1` means npm `1.x` and PyPI `1.x`,
 * and a schema-major change cannot produce either package without an
 * intentional package-major change.
 *
 * The build scripts assert the same thing per crate. This check exists
 * ALONGSIDE them because a build script only runs when its crate is built: a
 * packaging job that assembles the npm tarball from cached artifacts would
 * otherwise never evaluate the constraint. Here all three numbers are read at
 * once, so drift is caught even when nothing was compiled.
 */

import { readFileSync } from "node:fs"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const repoRoot = resolve(packageRoot, "..", "..")

/** Reads a file, failing with a message that names what was being checked. */
function read(path, what) {
  try {
    return readFileSync(path, "utf8")
  } catch (error) {
    console.error(`SDK-major check FAILED: cannot read ${what} at ${path}: ${error.message}`)
    process.exit(1)
  }
}

/** `MEMORY_PACK_VERSION: u32 = <n>;` — the one source of truth. */
function packVersion() {
  const source = read(
    join(repoRoot, "crates/oneiron/src/memory/recall.rs"),
    "the engine MemoryPack version",
  )
  const match = source.match(/pub const MEMORY_PACK_VERSION: u32 = (\d+)\s*;/)
  if (!match) {
    console.error("SDK-major check FAILED: no MEMORY_PACK_VERSION declaration found")
    process.exit(1)
  }
  return Number(match[1])
}

/** The npm package's semver major. */
function npmMajor() {
  const manifest = JSON.parse(read(join(packageRoot, "package.json"), "the npm manifest"))
  return Number(String(manifest.version).split(".")[0])
}

/** The Python distribution's major, taken from Cargo as maturin does. */
function pythonMajor() {
  const manifest = read(join(repoRoot, "crates/oneiron-py/Cargo.toml"), "the oneiron-py manifest")
  // The FIRST `version = "..."` after the `[package]` header, so a dependency
  // pin further down cannot be mistaken for the crate's own version.
  const packageSection = manifest.split(/^\[/m).find((section) => section.startsWith("package]"))
  const match = packageSection?.match(/^\s*version\s*=\s*"(\d+)\./m)
  if (!match) {
    console.error("SDK-major check FAILED: oneiron-py declares no literal [package] version")
    process.exit(1)
  }
  return Number(match[1])
}

const pack = packVersion()
const npm = npmMajor()
const python = pythonMajor()

const failures = []
if (npm !== pack) failures.push(`npm major ${npm} != MEMORY_PACK_VERSION ${pack}`)
if (python !== pack) failures.push(`PyPI major ${python} != MEMORY_PACK_VERSION ${pack}`)

if (failures.length > 0) {
  console.error("SDK-major check FAILED:")
  for (const failure of failures) console.error(`  - ${failure}`)
  console.error(
    "  A MemoryPack schema-major change requires an intentional package-major change.",
  )
  process.exit(1)
}

console.log(`SDK-major check OK (MEMORY_PACK_VERSION=${pack}, npm=${npm}, PyPI=${python})`)
