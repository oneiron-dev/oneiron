/**
 * Fleet-only README regression: run with `bun tests/readme-first-steps.e2e.ts`.
 * The install command and first Use example run verbatim in a fresh project.
 * The ONLY substitution is the local package path instead of the registry.
 * Uses the E2E server-start harness and its pinned E2E_BUILD_MANIFEST.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { EngineFixture } from "../../../tests/e2e/support/engine.ts";
import { credentialParts } from "../../../tests/e2e/support/clients.ts";
import { isolatedEnv, redactor, runProcess } from "../../../tests/e2e/support/run.ts";

function firstFence(markdown: string, heading: string, language: string): string {
  const start = markdown.indexOf(`${heading}\n`);
  assert(start >= 0, `Missing README section ${heading}`);
  const next = markdown.indexOf("\n## ", start + heading.length);
  const section = markdown.slice(start, next < 0 ? undefined : next);
  const match = new RegExp("```" + language + "\n([\\s\\S]*?)```").exec(section);
  assert(match, `Missing ${language} example in ${heading}`);
  return match[1]!;
}

const checkout = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const packagePath = join(checkout, "packages/oneiron-client");
const readme = await readFile(join(packagePath, "README.md"), "utf8");
const install = firstFence(readme, "## Install", "bash");
const example = firstFence(readme, "## Use", "ts");
assert.equal(install.split("\n").filter(line => line.trim()).length, 1);
const localInstall = install.replace("@oneiron/client", JSON.stringify(packagePath));
assert.notEqual(localInstall, install, "Install must name @oneiron/client");
const project = await mkdtemp(join(tmpdir(), "oneiron-client-readme-"));
const engine = await EngineFixture.start({ id: "client-readme", profile: "deterministic" });
try {
  const { bearer, seed } = credentialParts(engine.pairedActor.credential);
  const env: Record<string, string> = { ...isolatedEnv(project, engine.build.environment),
    ONEIRON_URL: engine.url, ONEIRON_SECRET: bearer, ONEIRON_BINDING_KEY: seed };
  await mkdir(env.TMPDIR!, { recursive: true });
  await writeFile(join(project, "package.json"), JSON.stringify({ name: "oneiron-client-readme", type: "module", private: true }));
  await writeFile(join(project, "index.ts"), example);
  const installed = await runProcess(["/bin/sh", "-c", localInstall],
    { cwd: project, env, label: "readme-install", artifacts: engine.artifacts }, 120000);
  console.log(`README_INSTALL rc=${installed.exitCode}`);
  assert.equal(installed.exitCode, 0, redactor.text(installed.stderr));
  const ran = await runProcess([process.execPath, "index.ts"],
    { cwd: project, env, label: "readme-example", artifacts: engine.artifacts, privateOutput: true }, 30000);
  console.log(`README_EXAMPLE rc=${ran.exitCode}`);
  assert.equal(ran.exitCode, 0, redactor.text(ran.stderr));
  assert.match(ran.stdout, /items\s*:/, "Example must print the recall result");
  assert.match(install, /^bun add @oneiron\/client\s*$/);
  assert(readme.indexOf("Bun 1.3") < readme.indexOf(install), "Bun requirement must precede install");
  console.log("PASS README first two steps: fresh Bun project reached vault.recall on authenticated E2E server");
} finally {
  await engine.close();
  await rm(project, { recursive: true, force: true });
}
