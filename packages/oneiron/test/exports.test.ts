/**
 * The public export census (ONE-1441 I6 — closed exports).
 *
 * The package's runtime surface is exactly `Oneiron` and `OneironError`. Every
 * raw native class — `VaultBridge`, `ActorScopedVault`, `NativeClient`,
 * `NapiVault` — is an implementation detail, and a package that leaked one
 * would be promising to keep it working.
 */

import { describe, expect, test } from "bun:test"

import { readdirSync, readFileSync } from "node:fs"

import * as pkg from "../src/index.js"

/** The whole public runtime surface, spelled once. */
const PUBLIC_EXPORTS = ["Oneiron", "OneironError"]

/** Names that must never become reachable from the package entry. */
const FORBIDDEN_EXPORTS = [
  "NativeClient",
  "VaultBridge",
  "ActorScopedVault",
  "NapiVault",
  "Vault",
  "OneironClient",
]

describe("export census", () => {
  test("retired task names are absent", () => {
    // ARCH-0067's 2026-09-22 amendment renamed the four task rows, with no alias.
    const instance = pkg.Oneiron.connect("http://127.0.0.1:9/", "census-unused")
    for (const retired of ["check", "expand", "ack", "cancel"]) {
      expect(instance.tasks).not.toHaveProperty(retired)
    }
    expect(typeof pkg.Oneiron.prototype.describe).toBe("function")
    expect(typeof pkg.Oneiron.prototype.cancel).toBe("function")
  })
})
