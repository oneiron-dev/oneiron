/**
 * Single-writer ownership (ONE-1441 I8, §Test/Single-writer).
 *
 * Exclusion is a property BETWEEN processes, so it is tested with real ones. A
 * same-process test could only prove the registry shares a handle, which is
 * the opposite behaviour.
 */

import { spawnSync } from "node:child_process"
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

import { afterAll, describe, expect, test } from "bun:test"

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const roots: string[] = []

function tempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "oneiron-writer-"))
  roots.push(root)
  return root
}

afterAll(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true })
})

/**
 * Runs `source` in a fresh Bun process and returns its stdout.
 *
 * The child imports the package by relative path, so it exercises the same
 * build the suite does without needing a global install.
 */
function runChild(source: string, root: string): { stdout: string; status: number | null } {
  const scriptPath = join(root, `child-${Math.random().toString(36).slice(2)}.mjs`)
  writeFileSync(scriptPath, source, "utf8")
  const result = spawnSync(process.execPath, [scriptPath], {
    encoding: "utf8",
    cwd: packageRoot,
    timeout: 120_000,
  })
  return { stdout: result.stdout ?? "", status: result.status }
}

/** Emits the caught error's typed payload as one JSON line. */
const REPORT = `
function report(error) {
  console.log(JSON.stringify({ code: error.code, suggestions: error.suggestions ?? [] }))
}
`

describe("single-writer ownership", () => {
  test("a second process is refused with VAULT_LOCKED_SINGLE_WRITER", () => {
    const root = tempRoot()
    const vault = join(root, "vault")
    const marker = join(root, "ready")

    // Process A takes the lease, signals, and holds it until killed.
    const ownerSource = `
import { writeFileSync } from "node:fs"
import { Oneiron } from ${JSON.stringify(join(packageRoot, "src/index.ts"))}
Oneiron.open(${JSON.stringify(vault)})
writeFileSync(${JSON.stringify(marker)}, "ready")
setTimeout(() => {}, 60_000)
`
    const ownerPath = join(root, "owner.mjs")
    writeFileSync(ownerPath, ownerSource, "utf8")
    const owner = Bun.spawn([process.execPath, ownerPath], { cwd: packageRoot })

    try {
      const deadline = Date.now() + 60_000
      while (!existsSync(marker) && Date.now() < deadline) {
        spawnSync(process.execPath, ["-e", "Bun.sleepSync(50)"])
      }
      expect(existsSync(marker)).toBe(true)

      const { stdout } = runChild(
        `${REPORT}
import { Oneiron } from ${JSON.stringify(join(packageRoot, "src/index.ts"))}
try {
  Oneiron.open(${JSON.stringify(vault)})
  console.log(JSON.stringify({ code: "NO_ERROR", suggestions: [] }))
} catch (error) {
  report(error)
}
`,
        root,
      )
      const payload = JSON.parse(stdout.trim().split("\n").at(-1) ?? "{}")
      expect(payload.code).toBe("VAULT_LOCKED_SINGLE_WRITER")
      expect(payload.suggestions.join(" ")).toContain("connect")
    } finally {
      owner.kill()
    }

    // The pidfile is deliberately left in place: its contents carry no
    // authority, so a reopen after the owner exits must succeed anyway.
    expect(existsSync(join(vault, "oneiron.writer.lock"))).toBe(true)
    const reopened = runChild(
      `import { Oneiron } from ${JSON.stringify(join(packageRoot, "src/index.ts"))}
Oneiron.open(${JSON.stringify(vault)})
console.log("reopened")
`,
      root,
    )
    expect(reopened.stdout).toContain("reopened")
  }, 180_000)

  test("two opens in ONE process share the vault instead of refusing", () => {
    const root = tempRoot()
    const vault = join(root, "vault")
    const { stdout } = runChild(
      `import { Oneiron } from ${JSON.stringify(join(packageRoot, "src/index.ts"))}
const first = Oneiron.open(${JSON.stringify(vault)})
const second = Oneiron.open(${JSON.stringify(vault)})
console.log(JSON.stringify({
  both: Array.isArray(first.receipts(1)) && Array.isArray(second.receipts(1)),
}))
`,
      root,
    )
    const payload = JSON.parse(stdout.trim().split("\n").at(-1) ?? "{}")
    expect(payload.both).toBe(true)
  }, 120_000)
})
