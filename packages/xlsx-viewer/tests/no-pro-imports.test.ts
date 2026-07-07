import { describe, expect, it } from "bun:test";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const PACKAGE_ROOT = new URL("..", import.meta.url).pathname;

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      walk(full, out);
    } else if (full.endsWith(".ts") || full.endsWith(".tsx")) {
      out.push(full);
    }
  }
  return out;
}

describe("acceptance 4: zero Univer-Pro imports", () => {
  it("no source file imports from @univerjs-pro / univer-pro", () => {
    // Match real import/require specifiers only, not doc-comment mentions of the
    // Pro packages we are deliberately avoiding.
    const proImport =
      /(?:from|import|require)\s*\(?\s*["'](?:@univerjs-pro\/[^"']+|[^"']*univer-pro[^"']*)["']/;
    const offenders: string[] = [];
    for (const file of walk(join(PACKAGE_ROOT, "src"))) {
      if (proImport.test(readFileSync(file, "utf8"))) {
        offenders.push(file);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("package.json declares no Pro packages", () => {
    const pkg = JSON.parse(readFileSync(join(PACKAGE_ROOT, "package.json"), "utf8")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const names = [
      ...Object.keys(pkg.dependencies ?? {}),
      ...Object.keys(pkg.devDependencies ?? {}),
    ];
    expect(names.filter((n) => n.startsWith("@univerjs-pro") || n.includes("univer-pro"))).toEqual([]);
  });

  it("the installed dependency tree contains no @univerjs-pro package", () => {
    expect(existsSync(join(PACKAGE_ROOT, "node_modules", "@univerjs-pro"))).toBe(false);
  });
});
