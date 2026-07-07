/**
 * License audit: walk the installed dependency tree and assert every package is
 * under a permissive (Apache/MIT-class) license. Backs OF-368 D10's in-repo
 * wall and acceptance test #5. Run: `bun run scripts/license-audit.ts`.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

/** SPDX ids we accept as permissive (Apache/MIT-equivalent). */
const PERMISSIVE = new Set([
  "MIT",
  "MIT-0",
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "0BSD",
  "ISC",
  "CC0-1.0",
  "CC-BY-4.0",
  "Unlicense",
  "BlueOak-1.0.0",
  "Python-2.0",
  "WTFPL",
  "Zlib",
]);

export interface LicenseFinding {
  readonly name: string;
  readonly version: string;
  readonly license: string;
}

export interface LicenseAuditResult {
  readonly ok: boolean;
  readonly packages: number;
  readonly violations: LicenseFinding[];
  readonly unknown: LicenseFinding[];
}

interface PackageManifest {
  name?: string;
  version?: string;
  license?: string | { type?: string };
  licenses?: Array<{ type?: string }>;
}

function normalizeLicense(pkg: PackageManifest): string {
  if (typeof pkg.license === "string") {
    return pkg.license;
  }
  if (pkg.license && typeof pkg.license === "object" && pkg.license.type) {
    return pkg.license.type;
  }
  if (Array.isArray(pkg.licenses)) {
    const types = pkg.licenses.map((l) => l.type).filter((t): t is string => Boolean(t));
    if (types.length > 0) {
      return types.join(" OR ");
    }
  }
  return "";
}

/**
 * Some packages ship a LICENSE file but omit the package.json `license` field
 * (e.g. `@univerjs/telemetry`). Infer the SPDX id from the license text header.
 */
function detectLicenseFromFile(dir: string): string {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return "";
  }
  const licenseFile = entries.find((e) => /^licen[cs]e(\.[a-z]+)?$/i.test(e));
  if (!licenseFile) {
    return "";
  }
  let text: string;
  try {
    text = readFileSync(join(dir, licenseFile), "utf8").slice(0, 400);
  } catch {
    return "";
  }
  if (/Apache License\s*\n?\s*Version 2\.0/i.test(text)) {
    return "Apache-2.0";
  }
  if (/\bMIT License\b/i.test(text) || /Permission is hereby granted, free of charge/i.test(text)) {
    return "MIT";
  }
  if (/\bISC License\b/i.test(text)) {
    return "ISC";
  }
  if (/Redistribution and use in source and binary forms/i.test(text)) {
    return /\b3\.|neither the name/i.test(text) ? "BSD-3-Clause" : "BSD-2-Clause";
  }
  return "";
}

/**
 * A SPDX expression is permissive when EVERY id it references is permissive.
 * (Conservative: `(MIT OR GPL-3.0)` fails even though MIT alone would satisfy —
 * we do not want a GPL fallback path anywhere in the tree.)
 */
export function isPermissive(expression: string): boolean {
  const ids = expression
    .replace(/[()]/g, " ")
    .split(/\s+(?:OR|AND|WITH)\s+|\s+/i)
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && s !== "OR" && s !== "AND" && s !== "WITH");
  if (ids.length === 0) {
    return false;
  }
  return ids.every((id) => PERMISSIVE.has(id));
}

function readManifest(dir: string): PackageManifest | null {
  try {
    return JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as PackageManifest;
  } catch {
    return null;
  }
}

/**
 * Every package directory reachable from a `node_modules`, RECURSING into each
 * package's own nested `node_modules` so non-hoisted transitive deps are audited
 * too. `seen` guards against symlink cycles.
 */
function packageDirs(nodeModules: string, seen = new Set<string>(), out: string[] = []): string[] {
  if (seen.has(nodeModules)) {
    return out;
  }
  seen.add(nodeModules);
  let entries: string[];
  try {
    entries = readdirSync(nodeModules);
  } catch {
    return out;
  }
  for (const entry of entries) {
    if (entry === ".bin" || entry === ".cache") {
      continue;
    }
    const full = join(nodeModules, entry);
    if (entry.startsWith("@")) {
      // Scoped: iterate its children.
      let scoped: string[];
      try {
        scoped = readdirSync(full);
      } catch {
        continue;
      }
      for (const child of scoped) {
        collectPackage(join(full, child), seen, out);
      }
    } else {
      collectPackage(full, seen, out);
    }
  }
  return out;
}

function collectPackage(dir: string, seen: Set<string>, out: string[]): void {
  try {
    if (!statSync(dir).isDirectory()) {
      return;
    }
  } catch {
    return;
  }
  out.push(dir);
  const nested = join(dir, "node_modules");
  try {
    if (statSync(nested).isDirectory()) {
      packageDirs(nested, seen, out);
    }
  } catch {
    /* no nested node_modules */
  }
}

export function auditLicenses(packageRoot: string): LicenseAuditResult {
  const dirs = packageDirs(join(packageRoot, "node_modules"));
  const violations: LicenseFinding[] = [];
  const unknown: LicenseFinding[] = [];
  let count = 0;
  for (const dir of dirs) {
    const manifest = readManifest(dir);
    if (!manifest?.name) {
      continue;
    }
    count += 1;
    const license = normalizeLicense(manifest) || detectLicenseFromFile(dir);
    const finding: LicenseFinding = {
      name: manifest.name,
      version: manifest.version ?? "?",
      license: license || "(none)",
    };
    if (license === "") {
      unknown.push(finding);
    } else if (!isPermissive(license)) {
      violations.push(finding);
    }
  }
  return { ok: violations.length === 0 && unknown.length === 0, packages: count, violations, unknown };
}

if (import.meta.main) {
  const root = new URL("..", import.meta.url).pathname;
  const result = auditLicenses(root);
  const sort = (a: LicenseFinding, b: LicenseFinding) => a.name.localeCompare(b.name);
  console.log(`license audit: ${result.packages} packages scanned`);
  if (result.violations.length > 0) {
    console.error(`NON-PERMISSIVE (${result.violations.length}):`);
    for (const v of [...result.violations].sort(sort)) {
      console.error(`  ${v.name}@${v.version}: ${v.license}`);
    }
  }
  if (result.unknown.length > 0) {
    console.error(`UNKNOWN LICENSE (${result.unknown.length}):`);
    for (const u of [...result.unknown].sort(sort)) {
      console.error(`  ${u.name}@${u.version}`);
    }
  }
  if (result.ok) {
    console.log("OK: all dependencies are permissively licensed (Apache/MIT-class).");
    process.exit(0);
  } else {
    process.exit(1);
  }
}
