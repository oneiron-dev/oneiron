/** Linux-only execution and reporting. Importing this module starts nothing. */
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile, rm, mkdtemp, readdir, access } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import type { test as BunTest } from "bun:test";
import { E2E_ROOT, FIXTURE_ROOT, loadFixtures, loadBuildManifest, requireAsset, verifyFile } from "./fixtures.ts";
import type { BuildManifest, Profile, SuitePlan, PlannedFile } from "./fixtures.ts";

export const LIMITS = Object.freeze({ slots: 4, cpuPerSlot: 2, memoryMiBPerSlot: 4096,
  readyMs: 10_000, requestMs: 10_000, flowMs: 30_000, suiteMs: 600_000, stopMs: 2_000 });
export type Outcome = "PASS" | "FAIL" | "BLOCKED";
export interface IdResult { readonly id: string; readonly outcome: Outcome; readonly durationMs: number; readonly reason?: string }
export class BlockedDoor extends Error { override name = "BlockedDoor" }
export class DeadlineError extends Error { override name = "DeadlineError" }
export function assertLinux(): void {
  if (process.platform !== "linux") throw new BlockedDoor("E2E execution is Linux-only; never launch on the coordinator Mac");
}
export function secretHex(bytes = 32): string { return randomBytes(bytes).toString("hex") }
export class Redactor {
  private readonly secrets = new Set<string>();
  add(...values: string[]): void { for (const value of values) if (value) this.secrets.add(value) }
  text(value: string): string {
    let text = value;
    for (const secret of [...this.secrets].sort((a,b) => b.length-a.length)) text = text.split(secret).join("[REDACTED]");
    return text
      .replace(/v2\.(?:cred|slip)\.[a-f0-9.]+/gi, "[REDACTED CREDENTIAL]")
      .replace(/(\/pair)#[^\s"'<>]+/g, "$1#[REDACTED]")
      .replace(/((?:authorization|x-oneiron-binding|x-oneiron-mcp-credential|cookie|set-cookie|x-api-key|api-key|binding_key|auth_secret|password|secret|token|credential|seed)["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'[^']*'|[^\n,;]+)/gi, "$1[REDACTED]");
  }
  value(value: unknown): unknown {
    if (typeof value === "string") return this.text(value);
    if (Array.isArray(value)) return value.map(v => this.value(v));
    if (value && typeof value === "object") {
      if (value instanceof Error) return { name: value.name, message: this.text(value.message) };
      return Object.fromEntries(Object.entries(value).map(([key,val]) => [key,
        /authorization|binding|cookie|password|secret|token|credential|seed|api.?key/i.test(key) ? "[REDACTED]" : this.value(val)]));
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
  async json(name: string, value: unknown): Promise<void> {
    if (!/^[a-zA-Z0-9_.-]+$/.test(name)) throw new Error("Artifact name must be one path segment");
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    await writeFile(resolve(this.root, name), JSON.stringify(redactor.value(value), null, 2)+"\n", { mode: 0o600 });
  }
}
export interface ProcessResult { readonly exitCode: number; readonly signal: string | null; readonly stdout: string; readonly stderr: string }
export interface ProcessOptions {
  readonly cwd: string; readonly env: Readonly<Record<string, string>>;
  readonly input?: string | Uint8Array;
  readonly artifacts?: Artifacts; readonly label: string;
  /** Pairing/init output stays in memory only; it is never emitted as logs. */
  readonly privateOutput?: boolean;
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
  resources.add(close);
  return () => { resources.delete(close) };
}
export async function closeOwnedResources(): Promise<void> {
  const failures: unknown[] = [];
  for (const close of [...resources].reverse()) {
    resources.delete(close);
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
  private readonly lines: { stdout: string; stderr: string } = { stdout: "", stderr: "" };
  private readonly ring: string[] = [];
  private constructor(readonly child: ChildProcessWithoutNullStreams, readonly options: ProcessOptions, readonly ownerFile?: string) {
    owned.add(this);
    const collect = (kind: "stdout" | "stderr", chunk: Buffer): void => {
      this[kind] = (this[kind]+chunk.toString("utf8")).slice(-4*1024*1024);
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
        await options.artifacts?.json(`${options.label}.json`, { pid: child.pid, exitCode: result.exitCode,
          signal: result.signal, logs: options.privateOutput ? [] : this.ring });
      } finally {
        if (ownerFile) await rm(ownerFile,{force:true});
        owned.delete(this);
      }
    });
    // Callers await settled; this handler only prevents an early unhandled rejection.
    void this.settled.catch(() => {});
  }
  static async start(argv: readonly string[], options: ProcessOptions): Promise<ManagedProcess> {
    assertLinux();
    if (!argv[0]) throw new Error("Empty process argv");
    const child = spawn(argv[0], argv.slice(1), { cwd: options.cwd, env: { ...options.env }, detached: true, stdio: "pipe" });
    const ownerDir = process.env.E2E_OWNERS_DIR;
    const ownerFile = ownerDir && child.pid ? resolve(ownerDir, `${child.pid}.json`) : undefined;
    // Attach readers and exit handlers before the first filesystem await.
    const managed = new ManagedProcess(child, options, ownerFile);
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
export async function closeOwnedProcesses(): Promise<void> { await Promise.all([...owned].map(p => p.stop())) }
export async function tempRoot(label: string): Promise<string> {
  assertLinux();
  const base = process.env.E2E_TEMP_ROOT ?? tmpdir();
  await mkdir(base, {recursive:true,mode:0o700});
  const path = await mkdtemp(resolve(base,`oneiron-${label}-`));
  return path;
}

export interface FileDeclaration { readonly profile: Profile; readonly slots: 1 | 2 }
interface Reporter { test: typeof BunTest }
/** Call once at module scope; pass Bun's test function to avoid importing bun:test in the runner. */
export function defineFile(meta: ImportMeta, declaration: FileDeclaration) {
  const file = basename(fileURLToPath(meta.url));
  const results = new Map<string,IdResult>();
  const registrations = new Set<string>();
  const resultPath = process.env.E2E_RESULT_FILE;
  const selected = new Set((process.env.E2E_SELECTED_IDS ?? "").split(",").filter(Boolean));
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
        const started = performance.now();
        try {
          if (process.env.E2E_PROFILE && process.env.E2E_PROFILE !== declaration.profile) throw new BlockedDoor("File profile mismatch");
          await withDeadline(Promise.resolve().then(body), deadlineMs, id, () => { for (const child of owned) child.signal("SIGKILL") });
          await closeOwnedResources();
          results.set(id, {id,outcome:"PASS",durationMs:performance.now()-started});
        } catch (error) {
          results.set(id, {id,outcome:error instanceof BlockedDoor ? "BLOCKED" : "FAIL",durationMs:performance.now()-started,
            reason:redactor.text(error instanceof Error ? error.message : String(error))});
          throw error;
        } finally {
          try { await closeOwnedResources() }
          catch (error) { results.set(id,{id,outcome:"FAIL",durationMs:performance.now()-started,reason:redactor.text(String(error))}); throw error }
          finally { await flush() }
        }
      }, deadlineMs + LIMITS.stopMs + 1000);
    },
    /** Real test.todo, but also a mandatory BLOCKED row in the independent report. */
    todo(test: Reporter["test"], id: string, reason: `waits on ${string}`): void {
      if (selected.size && !selected.has(id)) return;
      register(id);
      results.set(id, {id,outcome:"BLOCKED",durationMs:0,reason});
      test.todo(`${id} ${reason}`);
      // Bun afterAll is supplied by the file so registration-only TODO files flush too.
    },
    flush,
  };
}

export interface Preflight { readonly build: BuildManifest; readonly plan: SuitePlan; readonly files: readonly PlannedFile[];
  readonly fixturePins:readonly {path:string;sha256:string}[] }
export async function preflight(profile: Profile): Promise<Preflight> {
  assertLinux();
  const catalog = await loadFixtures();
  const plan = await catalog.readJson<SuitePlan>("suite-plan");
  const build = await loadBuildManifest(profile);
  if (build.launcher.length === 0 || !build.launcher[0]?.startsWith("/")) throw new BlockedDoor("waits on absolute Linux containment launcher");
  if (!Object.values(build.assets).some(asset => asset.path === build.launcher[0])) throw new BlockedDoor("Unpinned containment launcher");
  for (const manifest of catalog.manifests) for (const binary of manifest.value.binaries ?? []) {
    if (binary.requiredFor.includes(profile)) {
      const path = requireAsset(build,binary.id);
      const pin=build.assets[binary.id]!;
      if (!(binary.expectedFacts && typeof binary.expectedFacts === "object" && "sameBuild" in binary.expectedFacts) &&
          binary.source.revision && pin.source.revision!==binary.source.revision) throw new BlockedDoor(`Runtime revision differs: ${binary.id}`);
      if (binary.expectedFacts && typeof binary.expectedFacts === "object" && "sameBuild" in binary.expectedFacts &&
          build.assets[binary.id]?.source.revision !== build.head) throw new BlockedDoor(`Build head differs: ${path}`);
    }
  }
  for (const file of plan.files) await access(resolve(E2E_ROOT,file.file));
  for (const capability of ["linux","network-isolated","four-slot-accounting"])
    if (!build.capabilities.includes(capability)) throw new BlockedDoor(`waits on ${capability}`);
  if (profile === "real-small-model") {
    const model = build.realModel;
    if (!model || !/^[a-f0-9]{40,64}$/.test(model.revision) || !model.weights.length || !model.tokenizer || !model.config || !Object.keys(model.sampling).length ||
        model.threads < 1 || !Object.values(model.bindings).includes("real")) throw new BlockedDoor("waits on complete real-small-model pin and bindings");
    for (const id of [...model.weights,model.tokenizer,model.config]) requireAsset(build,id);
  }
  const allIds = new Set(plan.files.flatMap(f => f.tests.map(t => t.id)));
  if (allIds.size !== 242 || plan.files.length !== 29) throw new Error("Pinned registry plan is incomplete");
  for (const manifest of catalog.manifests) for (const asset of manifest.value.assets) {
    for (const id of asset.scenarios) if (!allIds.has(id)) throw new Error(`Unknown scenario ${id} in ${asset.id}`);
    for (const capability of asset.requires) if (!build.capabilities.includes(capability)) throw new BlockedDoor(`waits on ${capability}`);
  }
  const files = plan.files.filter(f => profile === "deterministic" || f.tests.some(t => plan.optionalIds.includes(t.id)));
  return { build, plan, files, fixturePins:catalog.manifests.map(m=>({path:m.path,sha256:m.sha256})) };
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
export async function runSuite(profile: Profile, workers = 4): Promise<number> {
  assertLinux();
  if (workers !== LIMITS.slots) throw new Error("The reference scheduler has exactly four slots");
  const started = performance.now();
  const output = process.env.E2E_REPORT_DIR ?? await tempRoot("report");
  const artifacts = new Artifacts(output);
  // This shared pin remains readable even when an area fragment blocks preflight.
  const shared = JSON.parse(await readFile(resolve(FIXTURE_ROOT,"manifest.json"),"utf8")) as {assets:{id:string;path:string;sha256:string}[]};
  const planPin = shared.assets.find(asset=>asset.id==="suite-plan");
  if (!planPin) throw new Error("Shared suite-plan pin is missing");
  const planPath=resolve(FIXTURE_ROOT,planPin.path);
  await verifyFile(planPath,planPin.sha256);
  const pinnedPlan=JSON.parse(await readFile(planPath,"utf8")) as SuitePlan;
  let ready: Preflight;
  try { ready = await withDeadline(preflight(profile), Math.max(1,LIMITS.suiteMs-(performance.now()-started)), "preflight") }
  catch (error) {
    const plan = pinnedPlan;
    const ids = plan.files.flatMap(f => f.tests).filter(t => profile === "deterministic" || plan.optionalIds.includes(t.id));
    await artifacts.json("report.json", {profile,success:false,source:plan.source,
      results:ids.map(t => ({id:t.id,outcome:"BLOCKED",durationMs:0,reason:String(error)}))});
    return 1;
  }
  const {build,plan} = ready;
  const pending = [...ready.files].sort((a,b) => b.estimatedSeconds-a.estimatedSeconds || a.file.localeCompare(b.file));
  const running = new Map<string,{file:PlannedFile; process:ManagedProcess; ownerDir:string; resultFile:string; fileRoot:string; done:Promise<string>}>();
  const results = new Map<string,IdResult>();
  const selectedIds = (file:PlannedFile) => file.tests.filter(t => profile === "deterministic" || plan.optionalIds.includes(t.id)).map(t => t.id);
  const collect = async (name: string): Promise<void> => {
    const job = running.get(name)!;
    running.delete(name);
    const exit = await job.process.done.catch(() => ({exitCode:1,stdout:"",stderr:""}));
    let processFailure="";
    try { await job.process.settled } catch(error) { processFailure=redactor.text(String(error)) }
    await reapDirectory(job.ownerDir);
    let rows: IdResult[] = [];
    let registrationError = processFailure;
    try {
      const payload = JSON.parse(await readFile(job.resultFile,"utf8")) as {declaration:FileDeclaration;registrations:string[];results:IdResult[]};
      rows = payload.results;
      const expected = selectedIds(job.file).sort();
      if (payload.declaration.slots !== job.file.slots || payload.declaration.profile !== profile ||
          JSON.stringify([...payload.registrations].sort()) !== JSON.stringify(expected)) registrationError = "File declaration/ID registration differs from plan";
      if (new Set(rows.map(r => r.id)).size !== rows.length || rows.some(r => !expected.includes(r.id))) registrationError = "Duplicate or unknown result rows";
      // /dev/stdout is a pipe, not a raw on-disk JUnit artifact (Bun 1.3.4 requires an outfile).
      const junit = exit.stdout+exit.stderr;
      if (!/<testsuites?\b/.test(junit) || /<skipped\b|<failure\b|<error\b/.test(junit)) registrationError = "Bun reports missing JUnit, skipped/TODO or failed tests";
      const cases=[...junit.matchAll(/<testcase\b[^>]*\bname="([^"]*)"/g)].map(match=>match[1]!);
      if (cases.length!==expected.length || cases.some(name=>!expected.some(id=>name.startsWith(id+" ")))) registrationError = "Bun testcase registry differs from the plan";
    } catch { registrationError = "File has no complete result artifact" }
    for (const id of selectedIds(job.file)) {
      const row = rows.find(r => r.id === id);
      if (!row || !["PASS","FAIL","BLOCKED"].includes(row.outcome) || !Number.isFinite(row.durationMs)) {
        results.set(id,{id,outcome:"FAIL",durationMs:0,reason:registrationError || "ID did not finish"});
      } else if (row.outcome === "BLOCKED") results.set(id,row);
      else if (registrationError || (exit.exitCode !== 0 && row.outcome === "PASS"))
        results.set(id,{...row,outcome:"FAIL",reason:registrationError || "Bun file process failed"});
      else results.set(id,row);
    }
    let retain=false;
    try { await access(resolve(job.fileRoot,"retain-vaults")); retain=true } catch { /* Retention is explicit only. */ }
    if (!retain) await rm(job.fileRoot,{recursive:true,force:true});
    else await artifacts.json(`${job.file.file}.retained.json`,{protectedLocalRoot:job.fileRoot,uploaded:false});
  };
  let interrupted = false;
  const interrupt = () => { interrupted = true; for (const job of running.values()) job.process.signal("SIGKILL") };
  process.once("SIGINT",interrupt); process.once("SIGTERM",interrupt);
  let schedulerFailure: string | undefined;
  try {
    while ((pending.length || running.size) && !interrupted) {
      const remaining = LIMITS.suiteMs-(performance.now()-started);
      if (remaining <= 0) break;
      let used = [...running.values()].reduce((n,r) => n+r.file.slots,0);
      for (let index=0; index<pending.length;) {
        const file = pending[index]!;
        if (used+file.slots > workers) { index++; continue }
        pending.splice(index,1); used += file.slots;
        const fileRoot = await tempRoot(file.file.replace(".test.ts",""));
        const ownerDir = resolve(fileRoot,"owners");
        const resultFile = resolve(output,`${file.file}.json`);
        const env = isolatedEnv(fileRoot,{...build.environment,E2E_PROFILE:profile,E2E_FILE_SLOTS:String(file.slots),
          E2E_CPU_CREDITS:String(file.slots*LIMITS.cpuPerSlot),E2E_MEMORY_MIB:String(file.slots*LIMITS.memoryMiBPerSlot),
          E2E_OWNERS_DIR:ownerDir,E2E_ARTIFACTS_DIR:resolve(output,file.file),E2E_RESULT_FILE:resultFile,E2E_SELECTED_IDS:selectedIds(file).join(","),
          E2E_TEMP_ROOT:fileRoot,E2E_BUILD_MANIFEST:process.env.E2E_BUILD_MANIFEST!,E2E_BUILD_MANIFEST_SHA256:process.env.E2E_BUILD_MANIFEST_SHA256!});
        await mkdir(env.TMPDIR!,{recursive:true,mode:0o700});
        const child = await ManagedProcess.start([...build.launcher,requireAsset(build,"bun"),"test",resolve(E2E_ROOT,file.file),"--timeout",String(LIMITS.suiteMs),"--max-concurrency","1","--reporter=junit","--reporter-outfile","/dev/stdout"],
          {cwd:E2E_ROOT,env,label:file.file,artifacts});
        running.set(file.file,{file,process:child,ownerDir,resultFile,fileRoot,done:child.done.then(() => file.file,() => file.file)});
      }
      if (!running.size) throw new Error("No schedulable file");
      try {
        const name = await withDeadline(Promise.race([...running.values()].map(j => j.done)),Math.max(1,LIMITS.suiteMs-(performance.now()-started)),"whole suite");
        await collect(name);
      } catch (error) { if (error instanceof DeadlineError) break; throw error }
    }
  } catch (error) { schedulerFailure=redactor.text(String(error)) }
  finally {
    for (const job of running.values()) job.process.signal("SIGKILL");
    for (const name of [...running.keys()]) await collect(name);
    await closeOwnedProcesses();
    process.off("SIGINT",interrupt); process.off("SIGTERM",interrupt);
  }
  for (const file of ready.files) for (const id of selectedIds(file))
    if (!results.has(id)) results.set(id,{id,outcome:"FAIL",durationMs:0,reason:"Suite deadline/interruption before completion"});
  const durationMs = performance.now()-started;
  const rows = plan.coverage.filter(row => row.tests.some(id => results.has(id))).map(row => ({...row,
    outcome:row.tests.every(id => results.get(id)?.outcome === "PASS") ? "PASS" : "BLOCKED"}));
  const success = !schedulerFailure && !interrupted && durationMs <= LIMITS.suiteMs && [...results.values()].every(r => r.outcome === "PASS");
  await artifacts.json("report.json",{profile,success,durationMs,schedulerFailure,source:plan.source,buildManifestSha256:process.env.E2E_BUILD_MANIFEST_SHA256,
    buildHead:build.head,fixturePins:ready.fixturePins,realModel:build.realModel,results:[...results.values()].sort((a,b) => a.id.localeCompare(b.id)),coverage:rows,excludedRows:plan.excludedRows});
  return success ? 0 : 1;
}
if (import.meta.main) {
  const args = process.argv.slice(2);
  const value = (flag:string,fallback:string) => {
    const index=args.indexOf(flag);if(index<0) return fallback;
    const next=args[index+1];if(!next||next.startsWith("--")) throw new Error(`Missing ${flag} value`);return next;
  };
  if(args.some(arg=>arg.startsWith("--")&&arg!=="--profile"&&arg!=="--workers")) throw new Error("Unknown runner option");
  const profile = value("--profile","deterministic");
  const workers = Number(value("--workers","4"));
  if (profile !== "deterministic" && profile !== "real-small-model") throw new Error("Unknown profile");
  process.exitCode = await runSuite(profile,workers);
}
