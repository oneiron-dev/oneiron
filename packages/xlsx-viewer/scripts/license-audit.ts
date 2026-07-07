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

function packageDirs(nodeModules: string): string[] {
  const dirs: string[] = [];
  let entries: string[];
  try {
    entries = readdirSync(nodeModules);
  } catch {
    return dirs;
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
        dirs.push(join(full, child));
      }
    } else {
      try {
        if (statSync(full).isDirectory()) {
          dirs.push(full);
        }
      } catch {
        /* ignore */
      }
    }
  }
  return dirs;
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
