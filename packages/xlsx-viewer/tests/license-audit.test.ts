import { describe, expect, it } from "bun:test";
import { auditLicenses, isPermissive } from "../scripts/license-audit";

const PACKAGE_ROOT = new URL("..", import.meta.url).pathname;

describe("acceptance 5: all runtime deps are permissively licensed", () => {
  it("audits the installed tree and finds only Apache/MIT-class licenses", () => {
    const result = auditLicenses(PACKAGE_ROOT);
    if (!result.ok) {
      // Surface the offenders in the failure message.
      throw new Error(
        `non-permissive: ${JSON.stringify(result.violations)}; unknown: ${JSON.stringify(result.unknown)}`,
      );
    }
    expect(result.ok).toBe(true);
    expect(result.violations).toEqual([]);
    expect(result.unknown).toEqual([]);
    expect(result.packages).toBeGreaterThan(50);
  });

  it("SPDX expression evaluation is conservative", () => {
    expect(isPermissive("MIT")).toBe(true);
    expect(isPermissive("Apache-2.0")).toBe(true);
    expect(isPermissive("(MIT OR Apache-2.0)")).toBe(true);
    expect(isPermissive("GPL-3.0")).toBe(false);
    expect(isPermissive("(MIT OR GPL-3.0)")).toBe(false); // no GPL fallback path anywhere
    expect(isPermissive("")).toBe(false);
  });
});
