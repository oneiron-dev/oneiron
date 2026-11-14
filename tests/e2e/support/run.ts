/** Linux-only execution and reporting. Importing this module starts nothing. */
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { AsyncLocalStorage } from "node:async_hooks";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile, rm, mkdtemp, readdir, access } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import type { expect as BunExpect, test as BunTest } from "bun:test";
import { E2E_ROOT, FIXTURE_ROOT, loadFixtures, loadBuildManifest, loadBuildManifestWithVerification, requireAsset, verifyFile } from "./fixtures.ts";
import type { BuildManifest, BuildVerification, Profile, SuitePlan, PlannedFile } from "./fixtures.ts";

export const LIMITS = Object.freeze({ slots: 6, cpuPerSlot: 2, memoryMiBPerSlot: 4096,
  readyMs: 10_000, requestMs: 10_000, flowMs: 30_000, suiteMs: 600_000, stopMs: 2_000 });
export type Outcome = "PASS" | "FAIL" | "BLOCKED" | "SKIPPED";
/** E2E rules v2 (implementation-baseline-v1 #tests-e2e): the runner sets each case's status from a run on the
 * prebuilt artifact set; nobody types it. See caseStatus. */
export type CaseStatus = "PLANNED" | "PROBED" | "WRITTEN" | "PROVEN";
export interface IdResult {
  readonly id: string; readonly outcome: Outcome; readonly durationMs: number; readonly reason?: string;
  readonly cleanupError?: string; readonly harnessError?: string;
  /** expect(...) calls the case body made through the runner's counted expect. */
  readonly assertions?: number;
  /** The case failed on the error a counted expect matcher threw (not a door, deadline, harness or cleanup error). */
  readonly failedAssertion?: boolean;
  readonly status?: CaseStatus;
}
export class BlockedDoor extends Error { override name = "BlockedDoor" }
export class DeadlineError extends Error { override name = "DeadlineError" }
export function assertLinux(): void {
  if (process.platform !== "linux") throw new BlockedDoor("E2E execution is Linux-only; never launch on the coordinator Mac");
}
class FlowLifecycle {
  readonly processes = new Set<ManagedProcess>();
  readonly resources = new Set<() => void | Promise<void>>();
  readonly controller = new AbortController();
  /** Counted expect calls in this flow, and the last error a counted matcher threw. */
  assertions = 0;
  assertionError: unknown = undefined;
  private failure: DeadlineError | undefined;
  constructor(readonly id: string, readonly deadlineAt: number) {}
  assertActive(): void {
    if (!this.failure && performance.now() >= this.deadlineAt) this.expire();
    if (this.failure) throw this.failure;
  }
  expire(): void {
    if (this.failure) return;
    this.failure = new DeadlineError(`${this.id} flow expired`);
    this.controller.abort(this.failure);
    for (const child of this.processes) child.signal("SIGKILL");
  }
  finish(): void {
    this.failure ??= new DeadlineError(`${this.id} flow finished`);
    this.controller.abort(this.failure);
  }
}
const flowStorage = new AsyncLocalStorage<FlowLifecycle>();
export function assertFlowActive(): void { flowStorage.getStore()?.assertActive() }
export function flowAbortSignal(): AbortSignal | undefined { return flowStorage.getStore()?.controller.signal }
export function secretHex(bytes = 32): string { return randomBytes(bytes).toString("hex") }
type ExpectFn = typeof BunExpect;
let bunExpect: ExpectFn | undefined;
// bun:test loads lazily, as in defineFile: importing the suite runner starts no work.
const realExpect = (): ExpectFn => bunExpect ??= (require("bun:test") as typeof import("bun:test")).expect;
function watchMatchers<T extends object>(matchers: T, flow: FlowLifecycle): T {
  return new Proxy(matchers, { get(target, property) {
    const value: unknown = Reflect.get(target, property, target);
    if (typeof value === "function") return (...args: unknown[]): unknown => {
      try {
        const out: unknown = Reflect.apply(value, target, args);
        return out instanceof Promise ? out.catch((error: unknown) => { flow.assertionError = error; throw error }) : out;
      } catch (error) { flow.assertionError = error; throw error }
    };
    return value !== null && typeof value === "object" ? watchMatchers(value, flow) : value;
  } });
}
/** Bun's expect, counted: each expect(...) call in a case is one assertion, and a failing matcher (also under .not,
 * .resolves or .rejects) marks the case's error as an assertion failure. Case files import expect from here, never
 * from bun:test, so the runner can tell a probe (no assertions) from a written case. */
export const expect: ExpectFn = new Proxy(function countedExpect() {} as unknown as ExpectFn, {
  apply(_target, _this, args: unknown[]) {
    const matchers = Reflect.apply(realExpect(), undefined, args) as object;
    const flow = flowStorage.getStore();
    if (!flow) return matchers;
    flow.assertions++;
    return watchMatchers(matchers, flow);
  },
  get(_target, property) {
    const real = realExpect();
    const value: unknown = Reflect.get(real, property);
    return typeof value === "function" ? value.bind(real) : value;
  },
});
/** Runs `body` as one flow and reports what the counted expect saw. The runner's own tests use it. */
export async function observeAssertions(id: string, body: () => unknown): Promise<{ readonly assertions: number; readonly failedAssertion: boolean }> {
  const flow = new FlowLifecycle(id, performance.now() + LIMITS.flowMs);
  return flowStorage.run(flow, async () => {
    try { await body(); return { assertions: flow.assertions, failedAssertion: false } }
    catch (error) { return { assertions: flow.assertions, failedAssertion: error === flow.assertionError } }
    finally { flow.finish() }
  });
}
/** A run's report, as --red-report reads it: the build head and the result rows. */
export interface RedReport { readonly buildHead: string; readonly results: readonly IdResult[] }
/**
 * The case's status from this run (Engine RULING L8-01-L8-03-MECH 5A, 2026-11-14; the F3 ladder: PLANNED, no run
 * yet; PROBED, every step answers and its effect is read back; WRITTEN, the assertions are in; PROVEN, seen red for
 * the right reason, then green):
 * - PROVEN: PASS with at least one assertion, and `red` (the same id in an earlier run on another build head) FAILED
 *   on an assertion, with no harness or cleanup error. A BLOCKED, deadline, door or harness red proves nothing.
 * - WRITTEN: the body made at least one assertion and no such red is on record (green with no red seen, or red now).
 * - PROBED: the body ran to its end (PASS) and made no assertion.
 * - PLANNED: anything less: not registered, todo, skip, pending door, BLOCKED, or a red before any assertion.
 */
export function caseStatus(result: IdResult | undefined, buildHead: string, red?: { readonly buildHead: string; readonly result: IdResult }): CaseStatus {
  if (!result) return "PLANNED";
  const assertions = result.assertions ?? 0;
  if (result.outcome === "PASS" && assertions > 0 && red && red.buildHead !== buildHead && red.result.id === result.id &&
      red.result.outcome === "FAIL" && red.result.failedAssertion === true && !red.result.harnessError && !red.result.cleanupError) return "PROVEN";
  if (assertions > 0 && (result.outcome === "PASS" || result.outcome === "FAIL")) return "WRITTEN";
  if (result.outcome === "PASS") return "PROBED";
  return "PLANNED";
}
/** Each result row with its status, and the count per status. */
export function withStatuses(results: readonly IdResult[], buildHead: string, red?: RedReport): { results: IdResult[]; statusCounts: Record<CaseStatus,number> } {
  const reds = new Map((red?.results ?? []).map(row => [row.id, row] as const));
  const statusCounts: Record<CaseStatus,number> = { PLANNED: 0, PROBED: 0, WRITTEN: 0, PROVEN: 0 };
  const rows = results.map(row => {
    const prior = reds.get(row.id);
    const status = caseStatus(row, buildHead, red && prior ? { buildHead: red.buildHead, result: prior } : undefined);
    statusCounts[status]++;
    return { ...row, status };
  });
  return { results: rows, statusCounts };
}
async function readRedReport(path: string): Promise<RedReport & { readonly sha256: string }> {
  const bytes = await readFile(path);
  const parsed = JSON.parse(bytes.toString("utf8")) as { buildHead?: unknown; results?: unknown };
  if (typeof parsed.buildHead !== "string" || !Array.isArray(parsed.results)) throw new Error("--red-report is not a runner report with buildHead and results");
  return { buildHead: parsed.buildHead, results: parsed.results as IdResult[], sha256: createHash("sha256").update(bytes).digest("hex") };
}
export class Redactor {
  private readonly secrets = new Set<string>();
  add(...values: string[]): void { for (const value of values) if (value) this.secrets.add(value) }
  text(value: string, localSecrets: readonly string[] = []): string {
    let text = value;
    for (const secret of [...this.secrets, ...localSecrets].sort((a,b) => b.length-a.length)) text = text.split(secret).join("[REDACTED]");
    return text
      .replace(/v2\.(?:cred|slip)\.[a-f0-9.]+/gi, "[REDACTED CREDENTIAL]")
      .replace(/(\/pair)#[^\s"'<>]+/g, "$1#[REDACTED]")
      .replace(/((?:authorization|x-oneiron-binding|x-oneiron-mcp-credential|cookie|set-cookie|x-api-key|api-key|binding_key|auth_secret|password|secret|token|credential|seed)["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'[^']*'|[^\n,;]+)/gi, "$1[REDACTED]");
  }
  command(argv: readonly string[]): readonly string[] {
    return argv.map((argument,index) => index > 0 && /^--(?:token|secret|password|credential|binding-key|api-key|seed|private-key)$/.test(argv[index-1]!)
      ? "[REDACTED]" : this.text(argument));
  }
  privateStderr(value: string): unknown {
    try { return JSON.stringify(this.value(JSON.parse(value))).replace(/\b[a-f0-9]{32,}\b/gi,"[REDACTED HEX]") }
    catch { return "[WITHHELD non-JSON private stderr]" }
  }
  value(value: unknown, localSecrets: readonly string[] = []): unknown {
    if (typeof value === "string") return this.text(value, localSecrets);
    if (Array.isArray(value)) return value.map(v => this.value(v, localSecrets));
    if (value && typeof value === "object") {
      if (value instanceof Error) return { name: value.name, message: this.text(value.message, localSecrets) };
      return Object.fromEntries(Object.entries(value).map(([key,val]) => [key,
        /authorization|binding|cookie|password|secret|token|credential|seed|api.?key/i.test(key) ? "[REDACTED]" : this.value(val, localSecrets)]));
    }
    return value;
  }
}
export const redactor = new Redactor();
export async function withDeadline<T>(work: Promise<T>, ms: number, label: string, abort?: () => void): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expiry = new Promise<never>((_,reject) => { timer = setTimeout(() => {
    abort?.(); reject(new DeadlineError(`${label} exceeded ${ms}ms`));
  }, ms) });
  try { return await Promise.race([work, expiry]) } finally { clearTimeout(timer) }
}
export class Artifacts {
  constructor(readonly root: string) {}
  async json(name: string, value: unknown, localSecrets: readonly string[] = []): Promise<void> {
    if (!/^[a-zA-Z0-9_.-]+$/.test(name)) throw new Error("Artifact name must be one path segment");
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    await writeFile(resolve(this.root, name), JSON.stringify(redactor.value(value, localSecrets), null, 2)+"\n", { mode: 0o600 });
  }
}
/** Start records are persisted before the operation, including calls that never return. */
export async function recordStart(kind: "http" | "cli" | "sdk" | "process" | "stage" | "fixture", details: Readonly<Record<string,unknown>>, artifacts?: Artifacts, stepId = secretHex(6)): Promise<string> {
  assertFlowActive();
  const target = artifacts ?? (process.env.E2E_ARTIFACTS_DIR ? new Artifacts(process.env.E2E_ARTIFACTS_DIR) : undefined);
  await target?.json(`request-${stepId}-start.json`, {stepId,phase:"start",kind,startedAt:new Date().toISOString(),...details});
  try { assertFlowActive() }
  catch (error) {
    if (target) await target.json(`request-${stepId}-cancelled.json`, {
      stepId,phase:"cancelled",kind,finishedAt:new Date().toISOString(),...details,
      error:error instanceof Error ? {name:error.name,message:error.message} : String(error),
    }).catch(() => {});
    throw error;
  }
  return stepId;
}
export interface ProcessResult { readonly exitCode: number; readonly signal: string | null; readonly stdout: string; readonly stderr: string }
export interface ProcessOptions {
  readonly cwd: string; readonly env: Readonly<Record<string, string>>;
  readonly input?: string | Uint8Array;
  readonly artifacts?: Artifacts; readonly label: string;
  /** Credential-bearing stdout stays in memory; stderr is redacted before diagnostics. */
  readonly privateOutput?: boolean;
  /** Test-vault diagnostics retain command arguments and redact secrets only. */
  readonly diagnosticOutput?: boolean;
  readonly stepId?: string;
  readonly operation?: {readonly kind:"cli"|"sdk";readonly method:string;readonly path?:string;readonly operations?:readonly string[]};
}
/** Fresh, minimal environment: no inherited ONEIRON_*, model keys or default HOME. */
export function isolatedEnv(home: string, extra: Readonly<Record<string,string>> = {}): Record<string,string> {
  return { ...extra, PATH: extra.PATH ?? "/usr/local/bin:/usr/bin:/bin", HOME: home, XDG_CONFIG_HOME: resolve(home,"config"),
    XDG_DATA_HOME: resolve(home,"data"), XDG_CACHE_HOME: resolve(home,"cache"), XDG_STATE_HOME: resolve(home,"state"),
    TMPDIR: resolve(home,"tmp"), LANG: "C.UTF-8", TZ: "UTC", HF_HUB_OFFLINE: "1", TRANSFORMERS_OFFLINE: "1",
    OMP_NUM_THREADS: "1", OPENBLAS_NUM_THREADS: "1", MKL_NUM_THREADS: "1", RAYON_NUM_THREADS: "1",
    ...(process.env.E2E_OWNERS_DIR ? { E2E_OWNERS_DIR: process.env.E2E_OWNERS_DIR } : {}) };
}
const owned = new Set<ManagedProcess>();
const resources = new Set<() => void | Promise<void>>();
/** Register a provider/socket/fixture for end-of-flow cleanup, including failure paths. */
export function ownResource(close: () => void | Promise<void>): () => void {
  assertFlowActive();
  const owners = flowStorage.getStore()?.resources ?? resources;
  owners.add(close);
  return () => { owners.delete(close) };
}
export async function closeOwnedResources(): Promise<void> {
  const failures: unknown[] = [];
  const owners = flowStorage.getStore()?.resources ?? resources;
  for (const close of [...owners].reverse()) {
    owners.delete(close);
    try { await close() } catch (error) { failures.push(error) }
  }
  await closeOwnedProcesses();
  if (failures.length) throw new AggregateError(failures,"Flow resource cleanup failed");
}
export class ManagedProcess {
  readonly done: Promise<ProcessResult>;
  readonly settled: Promise<void>;
  private stdout = "";
  private stderr = "";
  private readonly truncated = { stdout: false, stderr: false };
  private readonly lines: { stdout: string; stderr: string } = { stdout: "", stderr: "" };
  private readonly ring: string[] = [];
  private constructor(readonly child: ChildProcessWithoutNullStreams, readonly options: ProcessOptions, readonly stepId: string, readonly ownerFile: string | undefined, readonly argv: readonly string[]) {
    const owners = flowStorage.getStore()?.processes ?? owned;
    owners.add(this);
    const collect = (kind: "stdout" | "stderr", chunk: Buffer): void => {
      const output = this[kind]+chunk.toString("utf8");
      if (output.length > 4*1024*1024) this.truncated[kind] = true;
      this[kind] = output.slice(-4*1024*1024);
      if (options.privateOutput) return;
      this.lines[kind] += chunk.toString("utf8");
      const lines = this.lines[kind].split("\n");
      this.lines[kind] = lines.pop() ?? "";
      // Never persist partial chunks: a secret can straddle two reads.
      for (const line of lines) this.ring.push(redactor.text(`${kind}: ${line}`));
      if (this.lines[kind].length > 1024*1024) this.lines[kind] = "[oversized log line discarded]";
      if (this.ring.length > 200) this.ring.splice(0,this.ring.length-200);
    };
    child.stdout.on("data", chunk => collect("stdout", chunk as Buffer));
    child.stderr.on("data", chunk => collect("stderr", chunk as Buffer));
    this.done = new Promise((resolveDone,reject) => {
      child.once("error", reject);
      child.once("close", (exitCode,signal) => resolveDone({ exitCode: exitCode ?? 128, signal, stdout: this.stdout, stderr: this.stderr }));
    });
    this.settled = this.done.then(async result => {
      // Stop remaining members of the group even if writing diagnostics fails.
      this.signal("SIGKILL");
      try {
        if (!options.privateOutput) for (const kind of ["stdout","stderr"] as const)
          if (this.lines[kind]) this.ring.push(redactor.text(`${kind}: ${this.lines[kind]}`));
        await options.artifacts?.json(`${options.label}.json`, { stepId,phase:"complete",finishedAt:new Date().toISOString(),pid: child.pid, exitCode: result.exitCode,
          signal: result.signal, logs: options.privateOutput ? [] : this.ring,
          ...(options.diagnosticOutput ? {argv:redactor.command(this.argv)} : {}),
          stdoutTruncated: this.truncated.stdout, stderrTruncated: this.truncated.stderr,
          stdout: options.privateOutput ? "[WITHHELD credential-bearing stdout]" : this.truncated.stdout ? "[WITHHELD truncated stdout]" : options.diagnosticOutput ? redactor.text(this.stdout) : redactor.text(this.stdout).replace(/\b[a-f0-9]{32,}\b/gi,"[REDACTED HEX]"),
          stderr: this.truncated.stderr ? "[WITHHELD truncated stderr]" : options.diagnosticOutput ? redactor.text(this.stderr) : options.privateOutput ? redactor.privateStderr(this.stderr) : redactor.text(this.stderr).replace(/\b[a-f0-9]{32,}\b/gi,"[REDACTED HEX]") });
      } finally {
        if (ownerFile) await rm(ownerFile,{force:true});
        owners.delete(this);
      }
    });
    // Callers await settled; this handler only prevents an early unhandled rejection.
    void this.settled.catch(() => {});
  }
  static async start(argv: readonly string[], options: ProcessOptions): Promise<ManagedProcess> {
    assertFlowActive();
    assertLinux();
    if (!argv[0]) throw new Error("Empty process argv");
    const stepId = await recordStart(options.operation?.kind ?? "process", {method:options.operation?.method ?? options.label,
      path:options.operation?.path ?? basename(argv[0]),label:options.label,...(options.operation?.operations ? {operations:options.operation.operations} : {})},options.artifacts,options.stepId);
    const child = spawn(argv[0], argv.slice(1), { cwd: options.cwd, env: { ...options.env }, detached: true, stdio: "pipe" });
    const ownerDir = process.env.E2E_OWNERS_DIR;
    const ownerFile = ownerDir && child.pid ? resolve(ownerDir, `${child.pid}.json`) : undefined;
    // Attach readers and exit handlers before the first filesystem await.
    const managed = new ManagedProcess(child, options, stepId, ownerFile, argv);
    try {
      if (ownerFile) {
        await mkdir(ownerDir!, {recursive:true,mode:0o700});
        await writeFile(ownerFile, JSON.stringify({pid: child.pid}), { mode:0o600 });
        if (!managed.running) await rm(ownerFile,{force:true});
      }
      child.stdin.on("error", error => { if ((error as NodeJS.ErrnoException).code !== "EPIPE") child.emit("error",error) });
      child.stdin.end(options.input);
      return managed;
    } catch (error) { await managed.stop(); throw error }
  }
  get pid(): number { if (!this.child.pid) throw new Error("Process has no pid"); return this.child.pid }
  get running(): boolean { return this.child.exitCode === null && this.child.signalCode === null }
  tail(): string { return this.ring.join("\n") }
  /** Negative leak scan over the raw, unredacted stdout and stderr kept in memory. It never persists
   * or returns output. `truncated` means a stream outgrew its window, so absence is unproved. */
  outputHas(values: readonly string[]): { found: boolean; truncated: boolean } {
    if (values.length === 0 || values.some(value => !value)) throw new TypeError("outputHas needs non-empty values");
    return { found: values.some(value => this.stdout.includes(value) || this.stderr.includes(value)),
      truncated: this.truncated.stdout || this.truncated.stderr };
  }
  signal(signal: NodeJS.Signals): void {
    if (!this.child.pid) return;
    try { process.kill(-this.child.pid,signal) } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error }
  }
  async wait(ms: number = LIMITS.requestMs): Promise<ProcessResult> {
    const result=await withDeadline(this.done, ms, this.options.label, () => this.signal("SIGKILL"));
    await this.settled;
    return result;
  }
  async stop(signal: NodeJS.Signals = "SIGTERM"): Promise<void> {
    this.signal(signal);
    try { await this.wait(LIMITS.stopMs) }
    catch (error) {
      this.signal("SIGKILL");
      await this.done.catch(() => {});
      if (!(error instanceof DeadlineError)) throw error;
      await this.settled;
    }
  }
}
export async function runProcess(argv: readonly string[], options: ProcessOptions, ms: number = LIMITS.requestMs): Promise<ProcessResult> {
  return (await ManagedProcess.start(argv, options)).wait(ms);
}
export async function closeOwnedProcesses(): Promise<void> { await Promise.all([...(flowStorage.getStore()?.processes ?? owned)].map(p => p.stop())) }
export async function tempRoot(label: string, base = process.env.E2E_TEMP_ROOT ?? tmpdir()): Promise<string> {
  assertFlowActive();
  assertLinux();
  await mkdir(base, {recursive:true,mode:0o700});
  assertFlowActive();
  const path = await mkdtemp(resolve(base,`oneiron-${label}-`));
  return path;
}

export interface FileDeclaration { readonly profile: Profile; readonly slots: 1 | 2 }
/** A missing door's FIX-LIST row ("FIX <line>") and its "door or delete" date (YYYY-MM-DD, UTC). */
export interface PendingDoor { readonly fix: string; readonly deadline: string }
interface FileDiagnostics {
  readonly file: string; readonly caseId: string; readonly exitCode: number; readonly signal: string | null;
  readonly expectedCases: number; readonly junitPresent: boolean; readonly junitCases: number;
  readonly matchedCases: number; readonly unknownCases: number; readonly duplicateCases: number;
  readonly registrationError: string | null;
}
interface Reporter { test: typeof BunTest }
/** Call once at module scope; pass Bun's test function to avoid importing bun:test in the runner. */
export function defineFile(meta: ImportMeta, declaration: FileDeclaration) {
  // Register only in a Bun test file; importing the suite runner starts no work.
  const { beforeAll } = require("bun:test") as typeof import("bun:test");
  beforeAll(async () => { await loadBuildManifest(declaration.profile) }, LIMITS.suiteMs);
  return caseRegistry(basename(fileURLToPath(meta.url)), declaration);
}
/** The variable the nightly E2E stage (scripts/nightly/nightly_e2e.py) sets to "1" to run nightly budget cases. */
export const NIGHTLY_ENV = "E2E_NIGHTLY";
export const NIGHTLY_REASON = `nightly budget case: runs only when ${NIGHTLY_ENV}=1 (the nightly E2E stage)`;
/** One file's case registrations and results, without defineFile's build-manifest hook. It reads the runner's
 * variables from `env` (process.env in a case file). */
export function caseRegistry(file: string, declaration: FileDeclaration, env: Readonly<Record<string,string|undefined>> = process.env) {
  const results = new Map<string,IdResult>();
  const registrations = new Set<string>();
  const resultPath = env.E2E_RESULT_FILE;
  const selected = new Set((env.E2E_SELECTED_IDS ?? "").split(",").filter(Boolean));
  const flush = async (): Promise<void> => {
    if (resultPath) await new Artifacts(dirname(resultPath)).json(basename(resultPath), { file, declaration, registrations:[...registrations], results:[...results.values()] });
  };
  const register = (id: string): void => {
    if (registrations.has(id)) throw new Error(`Duplicate ID ${id}`);
    registrations.add(id);
  };
  return {
    test(test: Reporter["test"], id: string, name: string, body: () => void | Promise<void>, deadlineMs: number = LIMITS.flowMs): void {
      if (selected.size && !selected.has(id)) return;
      register(id);
      test(`${id} ${name}`, async () => {
        const flow = new FlowLifecycle(id, performance.now() + deadlineMs);
        return flowStorage.run(flow, async () => {
          const started = performance.now();
          try {
            if (env.E2E_PROFILE && env.E2E_PROFILE !== declaration.profile) throw new BlockedDoor("File profile mismatch");
            await withDeadline(Promise.resolve().then(() => { assertFlowActive(); return body() }), deadlineMs, id, () => flow.expire());
            assertFlowActive();
            flow.finish();
            await closeOwnedResources();
            results.set(id, {id,outcome:"PASS",durationMs:performance.now()-started,assertions:flow.assertions});
          } catch (error) {
            results.set(id, {id,outcome:error instanceof BlockedDoor ? "BLOCKED" : "FAIL",durationMs:performance.now()-started,
              reason:redactor.text(error instanceof Error ? error.message : String(error)),
              assertions:flow.assertions,failedAssertion:error === flow.assertionError});
            // Bun must not inspect raw credential-bearing properties such as CliError.result.
            throw new Error(results.get(id)!.reason);
          } finally {
            flow.finish();
            try { await closeOwnedResources() }
            catch (error) {
              const prior = results.get(id);
              const cleanupError = redactor.text(String(error));
              results.set(id,{id,outcome:"FAIL",durationMs:performance.now()-started,reason:prior?.reason ?? cleanupError,cleanupError,
                assertions:flow.assertions});
              throw new Error(cleanupError);
            }
            finally { await flush() }
          }
        });
      }, deadlineMs + LIMITS.stopMs + 1000);
    },
    /** Owner-deferred missing doors are registered but do not fail a run. */
    skip(test: Reporter["test"], id: string, reason: `waits on ${string}`): void {
      if (selected.size && !selected.has(id)) return;
      register(id);
      results.set(id, {id,outcome:"SKIPPED",durationMs:0,reason});
      test.skip(`${id} ${reason}`, () => {});
    },
    /** A case whose door is missing (Engine CORE-FOUR-SKIPS = A, the pending-door filter). It stays
     * registered and in the 242-ID plan, is never run, and reports SKIPPED with its missing door, its
     * FIX row and its deadline, so the PR tier stays green and honest. From the deadline on it FAILS:
     * door or delete. */
    pendingDoor(test: Reporter["test"], id: string, reason: `waits on ${string}`, pending: PendingDoor): void {
      if (selected.size && !selected.has(id)) return;
      if (!/^\d{4}-\d{2}-\d{2}$/.test(pending.deadline) || !/^FIX \d+$/.test(pending.fix)) throw new Error(`Malformed pending door for ${id}`);
      register(id);
      const text = `${reason} [${pending.fix}; pending door until ${pending.deadline}: door or delete]`;
      if (Date.now() >= Date.parse(`${pending.deadline}T00:00:00Z`)) {
        results.set(id, {id,outcome:"FAIL",durationMs:0,reason:`pending-door deadline passed: ${text}`});
        test(`${id} ${text}`, () => { throw new Error(`pending-door deadline passed: ${text}`) });
        return;
      }
      results.set(id, {id,outcome:"SKIPPED",durationMs:0,reason:`PENDING-DOOR ${text}`});
      test.skip(`${id} ${text}`, () => {});
    },
    /** Real test.todo, but also a mandatory BLOCKED row in the independent report. */
    todo(test: Reporter["test"], id: string, reason: `waits on ${string}`): void {
      if (selected.size && !selected.has(id)) return;
      register(id);
      results.set(id, {id,outcome:"BLOCKED",durationMs:0,reason});
      test.todo(`${id} ${reason}`, () => {});
      // Bun afterAll is supplied by the file so registration-only TODO files flush too.
    },
    /** A nightly budget case: a flow longer than the 30 s PR budget (Engine E2E-NIGHTLY-TODO = A). Without
     * E2E_NIGHTLY=1 it is a todo that reports BLOCKED with NIGHTLY_REASON and its body never runs; with it, it
     * runs as suite.test with its own deadline. */
    nightly(test: Reporter["test"], id: string, name: string, body: () => void | Promise<void>, deadlineMs: number): void {
      if (env[NIGHTLY_ENV] === "1") { this.test(test, id, name, body, deadlineMs); return }
      if (selected.size && !selected.has(id)) return;
      register(id);
      results.set(id, {id,outcome:"BLOCKED",durationMs:0,reason:NIGHTLY_REASON});
      test.todo(`${id} ${name} [${NIGHTLY_REASON}]`, () => {});
    },
    flush,
  };
}

export interface Preflight { readonly build: BuildManifest; readonly verification: BuildVerification; readonly plan: SuitePlan; readonly files: readonly PlannedFile[];
  readonly fixturePins:readonly {path:string;sha256:string}[] }
function selectFiles(plan: SuitePlan, profile: Profile, names: readonly string[]): PlannedFile[] {
  const available = plan.files.filter(file => profile === "deterministic" || file.tests.some(test => plan.optionalIds.includes(test.id)));
  for (const name of names) if (!available.some(file => file.file === name)) throw new Error(`Unknown file for ${profile}: ${name}`);
  return available.filter(file => names.length === 0 || names.includes(file.file));
}
// Dispatch estimate of one planned case: its own measured estimatedSeconds when the plan has one,
// else an equal share of its file's estimate. The scheduler starts the longest estimate first.
export function caseEstimateSeconds(file: PlannedFile, planIndex: number): number {
  return file.tests[planIndex]?.estimatedSeconds ?? file.estimatedSeconds/file.tests.length;
}
export async function preflight(profile: Profile, names: readonly string[] = []): Promise<Preflight> {
  assertLinux();
  const catalog = await loadFixtures();
  const plan = await catalog.readJson<SuitePlan>("suite-plan");
  const {build,verification} = await loadBuildManifestWithVerification(profile);
  const files = selectFiles(plan,profile,names);
  if (build.launcher.length === 0 || !build.launcher[0]?.startsWith("/")) throw new BlockedDoor("waits on absolute Linux process launcher");
  if (!Object.values(build.assets).some(asset => asset.path === build.launcher[0])) throw new BlockedDoor("Unpinned process launcher");
  for (const manifest of catalog.manifests) for (const binary of manifest.value.binaries ?? []) {
    if (binary.requiredFor.includes(profile)) {
      // The JS SDK loads the native addon even for pairing; Python is checked only by its consumer.
      if (!["server","cli","bun","node","sdk-js","native-addon"].includes(binary.id) && !build.assets[binary.id]) continue;
      const path = requireAsset(build,binary.id);
      const pin=build.assets[binary.id]!;
      if (!(binary.expectedFacts && typeof binary.expectedFacts === "object" && "sameBuild" in binary.expectedFacts) &&
          binary.source.revision && pin.source.revision!==binary.source.revision) throw new BlockedDoor(`Runtime revision differs: ${binary.id}`);
      if (binary.expectedFacts && typeof binary.expectedFacts === "object" && "sameBuild" in binary.expectedFacts &&
          build.assets[binary.id]?.source.revision !== build.head) throw new BlockedDoor(`Build head differs: ${path}`);
    }
  }
  for (const file of files) await access(resolve(E2E_ROOT,file.file));
  for (const capability of ["linux","fleet-job","slot-accounting"])
    if (!build.capabilities.includes(capability)) throw new BlockedDoor(`waits on ${capability}`);
  if (profile === "real-small-model") {
    const model = build.realModel;
    if (!model || !/^[a-f0-9]{40,64}$/.test(model.revision) || !model.weights.length || !model.tokenizer || !model.config || !Object.keys(model.sampling).length ||
        model.threads < 1 || !Object.values(model.bindings).includes("real")) throw new BlockedDoor("waits on complete real-small-model pin and bindings");
    for (const id of [...model.weights,model.tokenizer,model.config]) requireAsset(build,id);
  }
  // The counts are the plan pin's own facts (fixtures/manifest.json), re-pinned with the plan, never literals here.
  const counts = catalog.expected<{readonly plannedFiles:number;readonly plannedTests:number}>("suite-plan");
  const plannedIds = plan.files.flatMap(f => f.tests.map(t => t.id));
  const allIds = new Set(plannedIds);
  if (allIds.size !== plannedIds.length) throw new Error("Pinned registry plan repeats an ID");
  if (allIds.size !== counts.plannedTests || plan.files.length !== counts.plannedFiles) throw new Error("Pinned registry plan is incomplete");
  for (const file of plan.files) for (const test of file.tests)
    if (test.estimatedSeconds !== undefined && !(Number.isFinite(test.estimatedSeconds) && test.estimatedSeconds > 0))
      throw new Error(`Pinned registry plan has an invalid estimate for ${test.id}`);
  for (const manifest of catalog.manifests) for (const asset of manifest.value.assets) {
    for (const id of asset.scenarios) if (!allIds.has(id)) throw new Error(`Unknown scenario ${id} in ${asset.id}`);
  }
  return { build, verification, plan, files, fixturePins:catalog.manifests.map(m=>({path:m.path,sha256:m.sha256})) };
}
async function reapDirectory(path: string): Promise<void> {
  let entries: string[];
  try { entries = await readdir(path) } catch { return }
  for (const entry of entries) {
    const row = JSON.parse(await readFile(resolve(path,entry),"utf8")) as {pid:number};
    try { process.kill(-row.pid,"SIGKILL") } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error }
    await rm(resolve(path,entry),{force:true});
  }
}
export async function runSuite(profile: Profile, workers = 4, names: readonly string[] = [], redReportPath = ""): Promise<number> {
  assertLinux();
  if (!Number.isInteger(workers) || workers < 1 || workers > LIMITS.slots) throw new Error("Workers must be between one and six slots");
  const red = redReportPath ? await readRedReport(redReportPath) : undefined;
  const redReport = red ? { buildHead: red.buildHead, sha256: red.sha256 } : null;
  const started = performance.now();
  const output = process.env.E2E_REPORT_DIR ?? await tempRoot("report");
  const artifacts = new Artifacts(output);
  await mkdir(output, {recursive:true,mode:0o700});
  // This shared pin remains readable even when an area fragment blocks preflight.
  const shared = JSON.parse(await readFile(resolve(FIXTURE_ROOT,"manifest.json"),"utf8")) as {assets:{id:string;path:string;sha256:string}[]};
  const planPin = shared.assets.find(asset=>asset.id==="suite-plan");
  if (!planPin) throw new Error("Shared suite-plan pin is missing");
  const planPath=resolve(FIXTURE_ROOT,planPin.path);
  await verifyFile(planPath,planPin.sha256);
  const pinnedPlan=JSON.parse(await readFile(planPath,"utf8")) as SuitePlan;
  const selectedFiles = selectFiles(pinnedPlan,profile,names);
  if (selectedFiles.some(file => file.slots > workers)) throw new Error("A selected file needs more slots than --workers");
  const scope = { files: selectedFiles.map(file => file.file), completePlan: profile === "deterministic" && selectedFiles.length === pinnedPlan.files.length };
  let ready: Preflight;
  try { ready = await withDeadline(preflight(profile,names), Math.max(1,LIMITS.suiteMs-(performance.now()-started)), "preflight") }
  catch (error) {
    const plan = pinnedPlan;
    const ids = selectedFiles.flatMap(f => f.tests).filter(t => profile === "deterministic" || plan.optionalIds.includes(t.id));
    const blocked = withStatuses(ids.map(t => ({id:t.id,outcome:"BLOCKED" as const,durationMs:0,reason:String(error)})),"",red);
    await artifacts.json("report.json", {profile,scope,success:false,source:plan.source,redReport,
      statusCounts:blocked.statusCounts,results:blocked.results});
    return 1;
  }
  const {build,plan} = ready;
  // A sibling of the report directory, never an exportable report artifact.
  const verifiedRoot = await tempRoot("verified",dirname(resolve(output)));
  const verifiedPath = resolve(verifiedRoot,"build.json");
  const selectedIds = (file:PlannedFile) => file.tests.filter(t => profile === "deterministic" || plan.optionalIds.includes(t.id)).map(t => t.id);
  const jobs = ready.files.flatMap(file => selectedIds(file).map(id => {
    const planIndex = file.tests.findIndex(test => test.id === id);
    return {file,id,planIndex,estimate:caseEstimateSeconds(file,planIndex)};
  }));
  const pending = jobs.sort((a,b) => b.estimate-a.estimate || a.file.file.localeCompare(b.file.file) || a.planIndex-b.planIndex);
  const running = new Map<string,{file:PlannedFile; id:string; process:ManagedProcess; ownerDir:string; resultFile:string; junitFile:string; fileRoot:string; done:Promise<string>}>();
  const results = new Map<string,IdResult>();
  const fileDiagnostics: FileDiagnostics[] = [];
  const collect = async (name: string): Promise<void> => {
    const job = running.get(name)!;
    running.delete(name);
    const exit = await job.process.done.catch(() => ({exitCode:1,signal:null,stdout:"",stderr:""}));
    let processFailure="";
    try { await job.process.settled } catch(error) { processFailure=redactor.text(String(error)) }
    await reapDirectory(job.ownerDir);
    let rows: IdResult[] = [];
    let registrationError = processFailure;
    const junitOutcomes = new Map<string,string>();
    const diagnostics = {file:job.file.file,caseId:job.id,exitCode:exit.exitCode,signal:exit.signal,
      expectedCases:1,junitPresent:false,junitCases:0,matchedCases:0,unknownCases:0,duplicateCases:0};
    try {
      const payload = JSON.parse(await readFile(job.resultFile,"utf8")) as {declaration:FileDeclaration;registrations:string[];results:IdResult[]};
      rows = payload.results;
      const expected = [job.id];
      if (payload.declaration.slots !== job.file.slots || payload.declaration.profile !== profile ||
          JSON.stringify([...payload.registrations].sort()) !== JSON.stringify(expected)) registrationError = "File declaration/ID registration differs from plan";
      if (new Set(rows.map(r => r.id)).size !== rows.length || rows.some(r => !expected.includes(r.id))) registrationError = "Duplicate or unknown result rows";
      const junit = await readFile(job.junitFile,"utf8");
      await artifacts.json(`${job.file.file}.${job.id}.junit.json`, {format:"junit",source:basename(job.junitFile),
        xml:redactor.text(junit).replace(/\b[a-f0-9]{32,}\b/gi,"[REDACTED HEX]")});
      diagnostics.junitPresent = /<testsuites?\b/.test(junit);
      if (!diagnostics.junitPresent) registrationError = "Bun reports missing JUnit";
      const cases = [...junit.matchAll(/<testcase\b([^>]*?)(?:\/>|>([\s\S]*?)<\/testcase>)/g)];
      diagnostics.junitCases = cases.length;
      for (const match of cases) {
        const name = /\bname="([^"]*)"/.exec(match[1]!)?.[1] ?? "";
        const id = expected.find(id => name.startsWith(id+" "));
        if (!id) { diagnostics.unknownCases++; registrationError = "Bun testcase registry differs from the plan"; continue }
        if (junitOutcomes.has(id)) { diagnostics.duplicateCases++; registrationError = "Bun testcase registry differs from the plan"; continue }
        const body = match[2] ?? "";
        junitOutcomes.set(id,/<failure\b|<error\b/.test(body) ? "FAIL" : /<skipped\b/.test(body) ? "BLOCKED" : "PASS");
      }
      diagnostics.matchedCases = junitOutcomes.size;
      if (cases.length !== expected.length || junitOutcomes.size !== expected.length) registrationError = "Bun testcase registry differs from the plan";
      if (exit.exitCode !== 0 && rows.every(row => row.outcome === "PASS")) registrationError ||= "Bun file process failed outside a reported test";
    } catch { registrationError = "File has no complete result artifact" }
    fileDiagnostics.push({...diagnostics,registrationError:registrationError || null});
    for (const id of [job.id]) {
      const row = rows.find(r => r.id === id);
      if (!row || !["PASS","FAIL","BLOCKED","SKIPPED"].includes(row.outcome) || !Number.isFinite(row.durationMs)) {
        results.set(id,{id,outcome:"FAIL",durationMs:0,reason:registrationError || "ID did not finish"});
      } else if (row.outcome === "SKIPPED") {
        if (registrationError || junitOutcomes.get(id) !== "BLOCKED")
          results.set(id,{...row,outcome:"FAIL",reason:registrationError || "Bun testcase does not confirm recorded SKIPPED"});
        else results.set(id,row);
      } else if (row.outcome === "BLOCKED") results.set(id,row);
      else if (registrationError || (row.outcome === "PASS" && junitOutcomes.get(id) !== "PASS"))
        results.set(id,{...row,outcome:"FAIL",reason:row.reason ?? (registrationError || "Bun testcase outcome differs from recorded PASS"),
          harnessError:registrationError || "Bun testcase outcome differs from recorded PASS"});
      else results.set(id,row);
    }
    let retain=false;
    try { await access(resolve(job.fileRoot,"retain-vaults")); retain=true } catch { /* Retention is explicit only. */ }
    if (!retain) await rm(job.fileRoot,{recursive:true,force:true});
    else await artifacts.json(`${job.file.file}.${job.id}.retained.json`,{protectedLocalRoot:job.fileRoot,uploaded:false});
  };
  let interrupted = false;
  const interrupt = () => { interrupted = true; for (const job of running.values()) job.process.signal("SIGKILL") };
  process.once("SIGINT",interrupt); process.once("SIGTERM",interrupt);
  let schedulerFailure: string | undefined;
  try {
    await writeFile(verifiedPath,JSON.stringify(ready.verification)+"\n",{mode:0o600});
    while ((pending.length || running.size) && !interrupted) {
      const remaining = LIMITS.suiteMs-(performance.now()-started);
      if (remaining <= 0) break;
      let used = [...running.values()].reduce((n,r) => n+r.file.slots,0);
      for (let index=0; index<pending.length;) {
        const {file,id} = pending[index]!;
        if (used+file.slots > workers) { index++; continue }
        pending.splice(index,1); used += file.slots;
        const fileRoot = await tempRoot(`${file.file.replace(".test.ts","")}-${id}`);
        const ownerDir = resolve(fileRoot,"owners");
        const resultFile = resolve(output,`${file.file}.${id}.json`);
        const junitFile = resolve(output,`${file.file}.${id}.junit.xml`);
        const env = isolatedEnv(fileRoot,{...build.environment,E2E_PROFILE:profile,E2E_FILE_SLOTS:String(file.slots),
          E2E_CPU_CREDITS:String(file.slots*LIMITS.cpuPerSlot),E2E_MEMORY_MIB:String(file.slots*LIMITS.memoryMiBPerSlot),
          E2E_OWNERS_DIR:ownerDir,E2E_ARTIFACTS_DIR:resolve(output,file.file),E2E_RESULT_FILE:resultFile,E2E_SELECTED_IDS:id,
          E2E_TEMP_ROOT:fileRoot,E2E_BUILD_VERIFIED:verifiedPath,E2E_BUILD_MANIFEST:process.env.E2E_BUILD_MANIFEST!,E2E_BUILD_MANIFEST_SHA256:process.env.E2E_BUILD_MANIFEST_SHA256!,
          ...(process.env.E2E_MEMORY_RETAIN_VAULT?{E2E_MEMORY_RETAIN_VAULT:process.env.E2E_MEMORY_RETAIN_VAULT}:{}),
          ...(process.env[NIGHTLY_ENV]==="1"?{[NIGHTLY_ENV]:"1"}:{})});
        await mkdir(env.TMPDIR!,{recursive:true,mode:0o700});
        const child = await ManagedProcess.start([...build.launcher,requireAsset(build,"bun"),"test",resolve(E2E_ROOT,file.file),"--timeout",String(LIMITS.suiteMs),"--max-concurrency","1","--reporter=junit","--reporter-outfile",junitFile],
          {cwd:E2E_ROOT,env,label:`process-${file.file}-${id}`,artifacts});
        const key = `${file.file}#${id}`;
        running.set(key,{file,id,process:child,ownerDir,resultFile,junitFile,fileRoot,done:child.done.then(() => key,() => key)});
      }
      if (!running.size) throw new Error("No schedulable file");
      try {
        const name = await withDeadline(Promise.race([...running.values()].map(j => j.done)),Math.max(1,LIMITS.suiteMs-(performance.now()-started)),"whole suite");
        await collect(name);
      } catch (error) { if (error instanceof DeadlineError) break; throw error }
    }
  } catch (error) { schedulerFailure=redactor.text(String(error)) }
  finally {
    try {
      for (const job of running.values()) job.process.signal("SIGKILL");
      for (const name of [...running.keys()]) await collect(name);
      await closeOwnedProcesses();
      process.off("SIGINT",interrupt); process.off("SIGTERM",interrupt);
    } finally { await rm(verifiedRoot,{recursive:true,force:true}) }
  }
  for (const file of ready.files) for (const id of selectedIds(file))
    if (!results.has(id)) results.set(id,{id,outcome:"FAIL",durationMs:0,reason:"Suite deadline/interruption before completion"});
  const durationMs = performance.now()-started;
  const rows = plan.coverage.filter(row => row.tests.some(id => results.has(id))).map(row => ({...row,
    outcome:row.tests.every(id => results.get(id)?.outcome === "PASS") ? "PASS" :
      row.tests.every(id => ["PASS","SKIPPED"].includes(results.get(id)?.outcome ?? "")) ? "SKIPPED" : "BLOCKED"}));
  const success = !schedulerFailure && !interrupted && durationMs <= LIMITS.suiteMs && [...results.values()].every(r => r.outcome === "PASS" || r.outcome === "SKIPPED");
  const statuses = withStatuses([...results.values()].sort((a,b) => a.id.localeCompare(b.id)),build.head,red);
  await artifacts.json("report.json",{profile,scope,success,durationMs,schedulerFailure,source:plan.source,buildManifestSha256:process.env.E2E_BUILD_MANIFEST_SHA256,
    buildHead:build.head,redReport,statusCounts:statuses.statusCounts,fixturePins:ready.fixturePins,realModel:build.realModel,fileDiagnostics,results:statuses.results,coverage:rows,excludedRows:plan.excludedRows});
  return success ? 0 : 1;
}
if (import.meta.main) {
  const args = process.argv.slice(2);
  const value = (flag:string,fallback:string) => {
    const index=args.indexOf(flag);if(index<0) return fallback;
    const next=args[index+1];if(!next||next.startsWith("--")) throw new Error(`Missing ${flag} value`);return next;
  };
  if(args.some(arg=>arg.startsWith("--")&&arg!=="--profile"&&arg!=="--workers"&&arg!=="--files"&&arg!=="--red-report")) throw new Error("Unknown runner option");
  const profile = value("--profile","deterministic");
  const workers = Number(value("--workers","4"));
  if (profile !== "deterministic" && profile !== "real-small-model") throw new Error("Unknown profile");
  const files = value("--files","").split(",").filter(Boolean);
  process.exitCode = await runSuite(profile,workers,files,value("--red-report",""));
}
