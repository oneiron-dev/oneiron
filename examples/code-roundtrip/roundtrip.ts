// One user-run round trip of a real Git repository through Oneiron (FIX 6869,
// G4 PR3): admit a chosen commit, import and seal it, preview and export it,
// clone it with stock Git, run the repo's own native command once, make one
// real signed edit, push it, take it through review and the merge queue, then
// preview, export and re-clone the result and prove every path, mode and raw
// blob byte matches the push.
//
// CONNECTED IN SOURCE, NOT EXECUTED: every call below names a built verb and
// its generated input and result types; nothing here has been run end to
// end. The run needs what this script never provisions: a configured checker
// (a Linux session backend with its pinned image and toolchain, or the
// existing explicit host opt-in). The received proposal needs no review
// unless the owner set a vault review policy (FIX 8268): with none, the
// queue's intake enqueues it into the same checks on its own. Until a
// prerequisite exists, the step that needs it answers `roundtrip_pending`
// and the accepted push stays as it is.
//
// One step per boundary per invocation: run `bun run <this file> --plan
// <absolute plan.json>` again to continue. No default, poll, deadline or
// retry. See README.md beside this file.
import type { FacadeInput, FacadeResult, FacadeVerb } from "../../packages/oneiron-client/src/facade.ts";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { isAbsolute, relative } from "node:path";

/** CALL P: the one plan version this example reads. */
const ROUNDTRIP_PLAN_VERSION = 1;
const STATE_VERSION = 1;

type CredentialEnv = { secret_env: string; binding_key_env: string };
type DeclaredCommand = { argv: [string, ...string[]]; env: Record<string, string> };
type ManifestCatalog = NonNullable<FacadeInput<"vault.code.import">["accept"]>["catalog"];
type ManifestReview = Omit<FacadeInput<"vault.critic.review">, "target_ref">;

type RoundtripPlan = {
  schema_version: 1;
  binary: string;
  base_url: string;
  owner: CredentialEnv;
  run: CredentialEnv;
  live_run_file: string;
  project: string;
  owner_task: string;
  run_task: string;
  source_repo: string;
  source_commit: string;
  source_ref: string;
  served_repo: string;
  default_branch: string;
  ref_name: string;
  endpoint: string;
  owner_checkout: { checkout: string; ttl_seconds: number };
  run_checkout: { checkout: string; ttl_seconds: number };
  clone_dir: string;
  reclone_dir: string;
  state_file: string;
  manifest_catalog: ManifestCatalog;
  manifest_review: ManifestReview | null;
  native_command: DeclaredCommand;
  edit_command: DeclaredCommand;
  commit_message: string;
  git_env: Record<string, string>;
};

/** One effect this script started: finished, or uncertain until a human says. */
type Custody = { status: "started" } | { status: "finished"; exit_code: number };
type Lease = FacadeResult<"vault.code.checkout.claim">;
type Receipt = NonNullable<FacadeResult<"vault.code.checks.get">>;
type Export = FacadeResult<"vault.code.export">;

type RoundtripState = {
  schema_version: typeof STATE_VERSION;
  plan_digest: string;
  registered?: FacadeResult<"vault.code.origin.register">;
  source_push?: Custody;
  admission_receipt?: string;
  source_provenance?: string;
  manifest?: FacadeResult<"vault.code.import">["manifest"];
  owner_lease?: Lease;
  owner_binding?: FacadeResult<"vault.code.checkout.bind">;
  init?: FacadeResult<"vault.code.merge_queue.init">;
  baseline_receipts?: Receipt[];
  baseline_revision?: string;
  manifest_verdict?: string | null;
  promotion_receipt?: string;
  run_lease?: Lease;
  run_binding?: FacadeResult<"vault.repo.checkout.bind">;
  baseline_preview_digest?: string;
  first_export_started?: true;
  first_export?: Export;
  clone_head?: string;
  untracked_after_native?: string[];
  native?: Custody;
  edit?: Custody;
  pushed_commit?: string;
  pushed_tree?: string;
  run_push?: Custody;
  push_publication_receipt?: string;
  push_provenance?: string;
  candidate_ref?: string;
  candidate_proposal?: string;
  candidate_fork_session?: string;
  enqueue_started?: true;
  candidate_batch?: string;
  check_receipts?: Receipt[];
  candidate_revision?: string;
  final_preview_digest?: string;
  final_export_started?: true;
  final_export?: Export;
  final_path_count?: number;
};

type RoundtripComplete = {
  result: "roundtrip_complete";
  served_repo: string; ref_name: string; source_commit: string;
  manifest_ref: string; manifest_digest: string;
  baseline_revision: string; baseline_preview_digest: string;
  first_export: FacadeResult<"vault.code.export">;
  pushed_commit: string; pushed_tree: string; push_publication_receipt: string;
  push_provenance: string;
  candidate_ref: string; candidate_proposal: string; candidate_fork_session: string;
  candidate_batch: string;
  check_receipts: NonNullable<FacadeResult<"vault.code.checks.get">>[];
  candidate_revision: string; final_preview_digest: string;
  final_export: FacadeResult<"vault.code.export">;
  native_command: { argv: string[]; exit_code: 0 };
  edit_command: { argv: string[]; exit_code: 0 };
  path_count: number;
  full_path_mode_byte_equality: true;
  source_is_ancestor: true; pushed_commit_is_ancestor: true;
};

/** A run that cannot go on now: pending (rerun later), stopped (a human decides) or error. */
class Stop extends Error {
  constructor(
    readonly result: "roundtrip_pending" | "roundtrip_stopped" | "roundtrip_error",
    readonly reason: string,
    readonly evidence: unknown = null,
  ) {
    super(reason);
  }
}
const pending = (reason: string, evidence: unknown = null) => new Stop("roundtrip_pending", reason, evidence);
const stopped = (reason: string, evidence: unknown = null) => new Stop("roundtrip_stopped", reason, evidence);

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const HEX40 = /^[0-9a-f]{40}$/;
const HEX32 = /^[0-9a-f]{32}$/;

// ---- plan and state ---------------------------------------------------------

function parse_plan(path: string): { plan: RoundtripPlan; digest: string } {
  if (!isAbsolute(path)) throw stopped("the plan path must be absolute");
  const text = readFileSync(path, "utf8");
  const plan = JSON.parse(text) as RoundtripPlan;
  const fail = (why: string): never => { throw stopped(`plan: ${why}`); };
  if (plan.schema_version !== ROUNDTRIP_PLAN_VERSION) fail(`schema_version must be ${ROUNDTRIP_PLAN_VERSION}`);
  for (const key of ["binary", "live_run_file", "source_repo", "clone_dir", "reclone_dir", "state_file"] as const) {
    if (typeof plan[key] !== "string" || !isAbsolute(plan[key])) fail(`${key} must be an absolute path`);
  }
  for (const dir of [plan.source_repo, plan.clone_dir, plan.reclone_dir]) {
    if (!relative(dir, plan.state_file).startsWith("..")) fail("state_file must sit outside the source and both clones");
  }
  if (!HEX40.test(plan.source_commit)) fail("source_commit must be a full lower-hex commit id");
  const branch = `refs/heads/${plan.default_branch}`;
  if (!plan.default_branch || plan.source_ref !== branch || plan.ref_name !== branch) {
    fail("source_ref and ref_name must both be the full ref of default_branch");
  }
  if (new URL(plan.endpoint).origin !== new URL(plan.base_url).origin) fail("endpoint must be on base_url's origin");
  for (const id of [plan.project, plan.owner_task, plan.run_task, plan.owner_checkout.checkout, plan.run_checkout.checkout]) {
    if (!HEX32.test(id)) fail("ids and checkouts are 32 lower-hex characters");
  }
  for (const ttl of [plan.owner_checkout.ttl_seconds, plan.run_checkout.ttl_seconds]) {
    if (!Number.isInteger(ttl) || ttl <= 0) fail("checkout TTLs are explicit positive seconds");
  }
  for (const command of [plan.native_command, plan.edit_command]) {
    if (!Array.isArray(command.argv) || command.argv.length === 0 || typeof command.env !== "object") {
      fail("each command declares its argv and its whole env");
    }
  }
  if (!plan.commit_message.trim()) fail("commit_message is explicit");
  // Explicit empty lenses permit no review on this import; quorum zero is never chosen here.
  if ((plan.manifest_catalog.lenses.length === 0) !== (plan.manifest_review === null)) {
    fail("manifest_review is null exactly when manifest_catalog names no lenses");
  }
  return { plan, digest: new Bun.CryptoHasher("sha256").update(text).digest("hex") };
}

function load_state(plan: RoundtripPlan, digest: string): RoundtripState {
  if (!existsSync(plan.state_file)) return { schema_version: STATE_VERSION, plan_digest: digest };
  const state = JSON.parse(readFileSync(plan.state_file, "utf8")) as RoundtripState;
  if (state.schema_version !== STATE_VERSION || state.plan_digest !== digest) {
    throw stopped("the state file belongs to another plan; use a new state_file for a changed plan");
  }
  return state;
}

/** Private 0600 state, replaced whole: pins, receipts and custody, never a secret. */
function save_state(plan: RoundtripPlan, state: RoundtripState): void {
  const next = `${plan.state_file}.next`;
  writeFileSync(next, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  renameSync(next, plan.state_file);
}

// ---- transport ----------------------------------------------------------------

type Ran = { code: number; stdout: Uint8Array; stderr: string };

async function spawn_captured(argv: string[], env: Record<string, string>, cwd?: string, stdin?: Uint8Array): Promise<Ran> {
  const child = Bun.spawn(argv, {
    cwd,
    env,
    stdin: stdin === undefined ? "ignore" : new Blob([stdin]),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(child.stdout).arrayBuffer(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { code, stdout: new Uint8Array(stdout), stderr };
}

/** Only the named credential variables and PATH reach the oneiron CLI. */
function credential_env(who: CredentialEnv): Record<string, string> {
  const env: Record<string, string> = { PATH: process.env.PATH ?? "" };
  for (const name of [who.secret_env, who.binding_key_env]) {
    const value = process.env[name];
    if (value !== undefined) env[name] = value;
  }
  return env;
}

/**
 * The one typed boundary: a generated facade input in, its generated result out,
 * through `oneiron api call`, which signs each request afresh. A refusal keeps
 * its typed body and stops; nothing approves, retries or reshapes it.
 */
async function call<V extends FacadeVerb>(plan: RoundtripPlan, who: CredentialEnv, verb: V, input: FacadeInput<V>): Promise<FacadeResult<V>> {
  const ran = await spawn_captured(
    [plan.binary, "api", "--base-url", plan.base_url, "--secret-env", who.secret_env, "--binding-key-env", who.binding_key_env, "call", verb, "--data", "-"],
    credential_env(who),
    undefined,
    encoder.encode(JSON.stringify(input)),
  );
  if (ran.code !== 0) {
    throw stopped(`${verb} refused (exit ${ran.code})`, { body: decoder.decode(ran.stdout), stderr: ran.stderr });
  }
  return JSON.parse(decoder.decode(ran.stdout)) as FacadeResult<V>;
}

/**
 * Stock Git's several smart-HTTP requests, each relayed through
 * `oneiron api raw` with a fresh holder signature: loopback only, an
 * OS-assigned port, one random in-memory prefix per relay, no idle deadline.
 * Only `upstream`'s info/refs and pack routes pass; a failed upstream call is
 * never answered as success. Closed when `use` returns.
 */
async function with_signed_git_relay<T>(plan: RoundtripPlan, who: CredentialEnv, upstream: string, push: boolean, use: (url: string) => Promise<T>): Promise<T> {
  const prefix = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("hex");
  const services = push ? ["git-upload-pack", "git-receive-pack"] : ["git-upload-pack"];
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    idleTimeout: 0,
    async fetch(request) {
      const url = new URL(request.url);
      const head = `/${prefix}/`;
      if (!url.pathname.startsWith(head)) return new Response(null, { status: 404 });
      const rest = url.pathname.slice(head.length);
      let path: string;
      let service: string | null;
      let body: Uint8Array | undefined;
      if (request.method === "GET" && rest === "info/refs") {
        service = url.searchParams.get("service");
        path = `${upstream}/info/refs?service=${service}`;
      } else if (request.method === "POST" && services.includes(rest)) {
        service = rest;
        path = `${upstream}/${rest}`;
        body = new Uint8Array(await request.arrayBuffer());
        if (request.headers.get("content-encoding") === "gzip") body = Bun.gunzipSync(body);
      } else {
        return new Response(null, { status: 404 });
      }
      if (service === null || !services.includes(service)) return new Response(null, { status: 403 });
      const argv = [plan.binary, "api", "--base-url", plan.base_url, "--secret-env", who.secret_env, "--binding-key-env", who.binding_key_env, "raw", request.method, path];
      if (body !== undefined) argv.push("--data", "-", "--content-type", `application/x-${service}-request`);
      const ran = await spawn_captured(argv, credential_env(who), undefined, body);
      if (ran.code !== 0) return new Response("upstream refused", { status: 502 });
      const kind = body === undefined ? "advertisement" : "result";
      return new Response(ran.stdout, { headers: { "content-type": `application/x-${service}-${kind}`, "cache-control": "no-cache" } });
    },
  });
  try {
    return await use(`http://127.0.0.1:${server.port}/${prefix}`);
  } finally {
    server.stop(true);
  }
}

/** Stock Git with the plan's declared non-secret env, never a shell. */
async function git(plan: RoundtripPlan, cwd: string, args: string[]): Promise<string> {
  const ran = await spawn_captured(
    ["git", "-c", "protocol.version=0", "-c", "http.followRedirects=false", "-c", "credential.helper=", ...args],
    plan.git_env,
    cwd,
  );
  if (ran.code !== 0) throw stopped(`git ${args[0]} failed (exit ${ran.code})`, { stderr: ran.stderr });
  return decoder.decode(ran.stdout);
}

async function git_ok(plan: RoundtripPlan, cwd: string, args: string[]): Promise<boolean> {
  const ran = await spawn_captured(["git", ...args], plan.git_env, cwd);
  return ran.code === 0;
}

/** A declared command, exactly once: Started is saved before it spawns. */
async function run_declared_command(plan: RoundtripPlan, state: RoundtripState, slot: "native" | "edit", command: DeclaredCommand, cwd: string): Promise<void> {
  const held = state[slot];
  if (held?.status === "started") throw stopped(`${slot}_command started earlier and never reported; resolve it by hand`);
  if (held?.status === "finished") {
    if (held.exit_code !== 0) throw stopped(`${slot}_command exited ${held.exit_code}`);
    return;
  }
  state[slot] = { status: "started" };
  save_state(plan, state);
  const child = Bun.spawn(command.argv, { cwd, env: command.env, stdin: "ignore", stdout: "inherit", stderr: "inherit" });
  const exit_code = await child.exited;
  state[slot] = { status: "finished", exit_code };
  save_state(plan, state);
  if (exit_code !== 0) throw stopped(`${slot}_command exited ${exit_code}`);
}

// ---- proofs -------------------------------------------------------------------

type TreeEntry = { mode: number; oid: string };

/** The complete committed inventory: `git ls-tree -r -z --full-tree`. */
async function tree_entries(plan: RoundtripPlan, cwd: string, commit: string): Promise<Map<string, TreeEntry>> {
  const out = await git(plan, cwd, ["ls-tree", "-r", "-z", "--full-tree", commit]);
  const entries = new Map<string, TreeEntry>();
  for (const record of out.split("\0").filter(Boolean)) {
    const tab = record.indexOf("\t");
    const [mode, , oid] = record.slice(0, tab).split(" ");
    entries.set(record.slice(tab + 1), { mode: Number.parseInt(mode, 8), oid });
  }
  return entries;
}

async function blob_bytes(plan: RoundtripPlan, cwd: string, oid: string): Promise<Uint8Array> {
  const ran = await spawn_captured(["git", "cat-file", "blob", oid], plan.git_env, cwd);
  if (ran.code !== 0) throw stopped(`git cat-file ${oid} failed`, { stderr: ran.stderr });
  return ran.stdout;
}

const same_bytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((byte, i) => byte === b[i]);

/**
 * The owner's exact preview, every changed side read by its handle. Held is
 * pending with its hold. Before its export, a stale expectation stops (the
 * export's compare-and-swap would refuse); after it, the same pins stay exact.
 */
async function exact_preview(plan: RoundtripPlan, request: FacadeInput<"vault.code.export.preview">, before_export: boolean) {
  const answer = await call(plan, plan.owner, "vault.code.export.preview", request);
  if (answer.state === "held") throw pending("the export preview is held", answer.hold);
  const preview = answer.preview;
  if (before_export && !preview.expected_matches_observed) {
    throw stopped("the ref no longer holds the expected commit; the export's compare-and-swap would refuse", preview.observed_ref_oid);
  }
  const reads = new Map<string, Uint8Array>();
  for (const delta of preview.files) {
    for (const side of [delta.before, delta.after]) {
      if (!side) continue;
      const read = await call(plan, plan.owner, "vault.code.export.preview.read", { preview: request, handle: side.handle });
      if (read.state === "held") throw pending("a preview byte read is held", read.hold);
      reads.set(`${side.handle.side}:${delta.path}`, Uint8Array.from(read.file.bytes));
    }
  }
  return { preview, reads };
}

/** The clone holds exactly the preview's target: root, every path, and each changed after side's raw bytes. */
async function clone_matches_preview(plan: RoundtripPlan, cwd: string, commit: string, exact: Awaited<ReturnType<typeof exact_preview>>): Promise<number> {
  const root = (await git(plan, cwd, ["rev-parse", `${commit}^{tree}`])).trim();
  const entries = await tree_entries(plan, cwd, commit);
  const paths = [...entries.keys()].sort();
  const expected = [...exact.preview.after_paths].sort();
  if (root !== exact.preview.target_tree || paths.join("\0") !== expected.join("\0")) {
    throw stopped("the clone's tree is not the previewed target", { root, target: exact.preview.target_tree });
  }
  for (const delta of exact.preview.files) {
    const after = delta.after;
    const entry = entries.get(delta.path);
    if (!after || !entry) continue;
    const bytes = exact.reads.get(`after:${delta.path}`);
    if (entry.mode !== after.mode || entry.oid !== after.git_oid || !bytes || !same_bytes(bytes, await blob_bytes(plan, cwd, entry.oid))) {
      throw stopped(`${delta.path}: the clone's bytes or mode differ from the preview read`);
    }
  }
  return entries.size;
}

/** One Published publication of `commit` on `ref`, by the owner's lookup; ambiguity stops. */
async function published(plan: RoundtripPlan, ref_name: string, git_commit: string) {
  const view = await call(plan, plan.owner, "vault.code.origin.publications", { repo: plan.served_repo, ref_name, git_commit });
  const rows = view.publications.filter((row) => row.status === "published");
  if (rows.length === 0) throw pending(`no Published publication of ${git_commit} on ${ref_name} yet`, view);
  if (rows.length > 1) throw stopped(`several Published publications of ${git_commit}; choose one by hand`, rows);
  return rows[0];
}

function lease_path(remote_url: string | null | undefined): string {
  if (!remote_url) throw stopped("the run's checkout binding returned no lease remote");
  return new URL(remote_url).pathname.replace(/\/$/, "");
}

// ---- the round trip -----------------------------------------------------------

async function roundtrip(plan: RoundtripPlan, state: RoundtripState): Promise<RoundtripComplete> {
  const save = () => save_state(plan, state);
  const owner = plan.owner;
  const run = plan.run;
  const git_door = new URL(plan.endpoint).pathname.replace(/\/$/, "");

  // 1. An empty served origin, the chosen commit pushed to it once through the
  //    owner's direct door, and its unique Published receive-pack publication.
  state.registered ??= await call(plan, owner, "vault.code.origin.register", { repo: plan.served_repo, default_branch: plan.default_branch });
  save();
  if (state.source_push?.status === "started") throw stopped("the source push started earlier and never reported; read vault.code.origin.publications by hand");
  if (!state.source_push) {
    state.source_push = { status: "started" };
    save();
    await with_signed_git_relay(plan, owner, `${git_door}/${plan.served_repo}.git`, true, (url) =>
      git(plan, plan.source_repo, ["-c", "push.gpgSign=false", "push", "--no-signed", url, `${plan.source_commit}:${plan.source_ref}`]),
    );
    state.source_push = { status: "finished", exit_code: 0 };
    save();
  }
  if (!state.admission_receipt) {
    const row = await published(plan, plan.source_ref, plan.source_commit);
    state.admission_receipt = row.receipt;
    state.source_provenance = row.provenance_receipt;
    save();
  }

  // 2. The import manifest (accept: null), then the owner's checkout of the
  //    imported snapshot (never the served anchor), bound to the door.
  state.manifest ??= (await call(plan, owner, "vault.code.import", {
    repo: plan.served_repo, project: plan.project, source_ref: plan.source_ref,
    source_commit: plan.source_commit, admission_receipt: state.admission_receipt, accept: null,
  })).manifest;
  save();
  const manifest = state.manifest;
  const anchor = manifest.anchor;
  state.owner_lease ??= await call(plan, owner, "vault.code.checkout.claim", {
    checkout: plan.owner_checkout.checkout, repo: anchor.snapshot, task: plan.owner_task,
    task_class: "edit", ttl_seconds: plan.owner_checkout.ttl_seconds, declared_idempotent: false,
  });
  save();
  state.owner_binding ??= await call(plan, owner, "vault.code.checkout.bind", {
    repo: plan.served_repo, checkout: state.owner_lease.checkout, epoch: state.owner_lease.epoch, endpoint: plan.endpoint,
  });
  save();
  const binding = state.owner_binding;

  // 3. Explicit queue init on the served anchor: the engine prepares its own
  //    detached source worktree in the same store. One status read per run.
  state.init ??= await call(plan, owner, "vault.code.merge_queue.init", { repo: anchor.repo, baseline_commit: plan.source_commit, contract_baseline_ref: null });
  save();
  if (!state.baseline_revision) {
    const status = await call(plan, owner, "vault.code.merge_queue.check_status", { repo: anchor.repo, work_ref: state.init.work_ref });
    if (status.status === "needs_configuration") throw pending("the checker needs configuration", status.configuration_keys);
    if (status.status !== "passed" && status.status !== "settled") throw pending(`baseline checks are ${status.status}`, status.hold ?? status.reason);
    const receipts: Receipt[] = [];
    for (const receipt_ref of new Set(status.receipt_refs)) {
      const receipt = await call(plan, owner, "vault.code.checks.get", { repo: anchor.repo, work_ref: status.work_ref, receipt_ref });
      if (!receipt) throw pending(`baseline receipt ${receipt_ref} is not readable yet`);
      receipts.push(receipt);
    }
    const repo = await call(plan, owner, "vault.code.repos.get", { repo: anchor.repo });
    if (!repo?.green_revision || repo.queue?.green_commit !== plan.source_commit) throw pending("no sealed baseline at the source commit yet", repo);
    if (!receipts.every((receipt) => receipt.receipts.every((attempt) => attempt.commit === plan.source_commit))) {
      throw stopped("baseline receipts name another commit than the source", receipts);
    }
    state.baseline_receipts = receipts;
    state.baseline_revision = repo.green_revision;
    save();
  }
  const baseline = state.baseline_revision;

  // 4. The owner-selected manifest review, then the same import accepted:
  //    untouched bytes promoted on this exact Baseline.
  if (state.manifest_verdict === undefined) {
    state.manifest_verdict = plan.manifest_review === null
      ? null
      : (await call(plan, owner, "vault.critic.review", { ...plan.manifest_review, target_ref: manifest.manifest_ref })).verdict_claim_ref;
    save();
  }
  if (!state.promotion_receipt) {
    const accepted = await call(plan, owner, "vault.code.import", {
      repo: plan.served_repo, project: plan.project, source_ref: plan.source_ref,
      source_commit: plan.source_commit, admission_receipt: state.admission_receipt,
      accept: { manifest_digest: manifest.digest, baseline_revision: baseline, catalog: plan.manifest_catalog, review_verdict: state.manifest_verdict },
    });
    if (accepted.state !== "promoted" || accepted.baseline_revision !== baseline || !accepted.promotion_receipt) {
      throw pending(`the import is ${accepted.state}`, accepted);
    }
    state.promotion_receipt = accepted.promotion_receipt;
    save();
  }

  // 5. The run's own checkout of the snapshot, bound through its public repo
  //    door under its live attachment and Grant. Nothing is minted here.
  const live_run = readFileSync(plan.live_run_file, "utf8").trim();
  state.run_lease ??= await call(plan, run, "vault.code.checkout.claim", {
    checkout: plan.run_checkout.checkout, repo: anchor.snapshot, task: plan.run_task,
    task_class: "edit", ttl_seconds: plan.run_checkout.ttl_seconds, declared_idempotent: false,
  });
  save();
  if (!state.run_binding) {
    const bound = await call(plan, run, "vault.repo.checkout.bind", {
      live_run, spec: { repo: anchor.repo, ref: plan.ref_name, checkout: state.run_lease.checkout, epoch: state.run_lease.epoch, endpoint: plan.endpoint },
    });
    if (bound.repo !== anchor.repo || bound.ref !== plan.ref_name || bound.checkout !== state.run_lease.checkout || bound.epoch !== state.run_lease.epoch || !bound.remote_url) {
      throw stopped("the run's checkout binding is not the one requested", bound);
    }
    state.run_binding = bound;
    save();
  }
  const run_door = lease_path(state.run_binding.remote_url);

  // 6. The exact preview of the Baseline export, then that export: P moves
  //    to E0 while the queue's own source stays at the source commit.
  const first_request = {
    repo: plan.served_repo, code_repo: anchor.repo, checkout: binding.checkout, epoch: binding.epoch,
    revision: baseline, ref_name: plan.ref_name, expected_old_oid: plan.source_commit, endpoint: plan.endpoint,
  } satisfies FacadeInput<"vault.code.export.preview">;
  const first = state.clone_head ? null : await exact_preview(plan, first_request, !state.first_export);
  if (first) {
    if (state.baseline_preview_digest && state.baseline_preview_digest !== first.preview.preview_digest) {
      throw stopped("the Baseline preview changed between runs", first.preview.preview_digest);
    }
    state.baseline_preview_digest = first.preview.preview_digest;
    save();
  }
  if (state.first_export_started && !state.first_export) throw stopped("the first export started earlier and never reported; read vault.code.origin.publications by hand");
  if (!state.first_export) {
    state.first_export_started = true;
    save();
    const { code_repo: _selector, ...pins } = first_request;
    state.first_export = await call(plan, owner, "vault.code.export", pins);
    save();
  }
  const e0 = state.first_export;
  if (e0.revision !== baseline || e0.publication.status !== "published" || e0.wire_rejected) throw stopped("the first export did not publish the Baseline", e0);

  // 7. A fresh clone at E0 through the run's lease door, the complete tree
  //    proven against the preview, and the native command run once.
  if (!state.clone_head && first) {
    await published(plan, plan.ref_name, e0.git_commit);
    if (existsSync(plan.clone_dir)) throw stopped("clone_dir must be new");
    await with_signed_git_relay(plan, run, run_door, false, (url) =>
      git(plan, "/", ["clone", "--branch", plan.default_branch, url, plan.clone_dir]),
    );
    const head = (await git(plan, plan.clone_dir, ["rev-parse", "HEAD"])).trim();
    if (head !== e0.git_commit || !(await git_ok(plan, plan.clone_dir, ["merge-base", "--is-ancestor", plan.source_commit, head]))) {
      throw stopped("the clone is not the exported commit over the source", head);
    }
    await clone_matches_preview(plan, plan.clone_dir, head, first);
    state.clone_head = head;
    save();
  }
  await run_declared_command(plan, state, "native", plan.native_command, plan.clone_dir);
  if (!state.untracked_after_native) {
    if ((await git(plan, plan.clone_dir, ["status", "--porcelain", "--untracked-files=no"])).trim()) {
      throw stopped("native_command changed tracked sources; nothing is reset behind you");
    }
    state.untracked_after_native = (await git(plan, plan.clone_dir, ["ls-files", "--others", "--exclude-standard", "-z"])).split("\0").filter(Boolean);
    save();
  }

  // 8. One real edit, signed with the user's own GPG setup, pushed once as an
  //    exact commit through the run's lease door. The accepted push stays.
  await run_declared_command(plan, state, "edit", plan.edit_command, plan.clone_dir);
  if (!state.pushed_commit) {
    const native_outputs = new Set(state.untracked_after_native);
    const added = (await git(plan, plan.clone_dir, ["ls-files", "--others", "--exclude-standard", "-z"])).split("\0").filter((path) => path && !native_outputs.has(path));
    await git(plan, plan.clone_dir, ["add", "-u"]);
    if (added.length > 0) await git(plan, plan.clone_dir, ["--literal-pathspecs", "add", "--", ...added]);
    if (await git_ok(plan, plan.clone_dir, ["diff", "--cached", "--quiet"])) throw stopped("edit_command made no tracked change");
    await git(plan, plan.clone_dir, ["commit", "-S", "-m", plan.commit_message]);
    state.pushed_commit = (await git(plan, plan.clone_dir, ["rev-parse", "HEAD"])).trim();
    state.pushed_tree = (await git(plan, plan.clone_dir, ["rev-parse", "HEAD^{tree}"])).trim();
    save();
  }
  const pushed = state.pushed_commit;
  if (state.run_push?.status === "started") throw stopped("the edit push started earlier and never reported; read vault.code.origin.publications by hand");
  if (!state.run_push) {
    state.run_push = { status: "started" };
    save();
    await with_signed_git_relay(plan, run, run_door, true, (url) =>
      git(plan, plan.clone_dir, ["push", url, `${pushed}:${plan.ref_name}`]),
    );
    state.run_push = { status: "finished", exit_code: 0 };
    save();
  }

  // 9. The accepted push's ingress, its ONE all-files candidate proposal and
  //    durable fork. The bundle names no catalog: the vault's review policy
  //    decides its review, and with none set it needs none (FIX 8268).
  if (!state.push_provenance) {
    const row = await published(plan, plan.ref_name, pushed);
    state.push_publication_receipt = row.receipt;
    state.push_provenance = row.provenance_receipt;
    save();
  }
  const ingress = await call(plan, owner, "vault.code.ingress.get", { repo: anchor.repo, provenance: state.push_provenance, ref_name: plan.ref_name });
  if (!ingress || !ingress.published || ingress.publication !== state.push_publication_receipt || ingress.old_oid !== e0.git_commit || ingress.new_oid !== pushed) {
    throw pending("the accepted push's ingress is not readable as this push yet", ingress);
  }
  const candidate = ingress.candidate;
  if (!candidate || candidate.state === "pending") throw pending("the received push has no matched candidate yet", candidate);
  if (candidate.state.startsWith("held_") || candidate.state === "rejected") {
    throw pending(`the received candidate is ${candidate.state}; the named hold's way out comes first`, candidate);
  }
  if (candidate.proposal_refs.length !== 1 || !candidate.fork_session) throw stopped("one push must be ONE proposal on one fork", candidate);
  state.candidate_ref = candidate.candidate;
  state.candidate_proposal = candidate.proposal_refs[0];
  state.candidate_fork_session = candidate.fork_session;
  save();
  const fork = await call(plan, owner, "vault.code.forks.get", { repo: anchor.repo, fork_session: candidate.fork_session });
  const proposal_view = await call(plan, owner, "vault.code.proposal_view", { proposal_ref: state.candidate_proposal });
  if (!fork || proposal_view?.operation_kind !== "received_files") throw pending("the candidate's fork or proposal is not readable yet", { fork, proposal_view });
  await call(plan, run, "describe", { handle: { kind: "task", task_ref: plan.run_task } });

  // 10. Matching proposes, never approves. With no vault review policy the
  //     queue's intake enqueues the candidate once, into the same checks. With
  //     one set, real reviewers (or the owner's Approve) settle it with the
  //     existing proposal doors, then one owner enqueue. Then the queue's own
  //     checks, landing and seal, read once per run.
  const policy = await call(plan, owner, "vault.code.merge_queue.review_policy.get", {});
  if (policy.mode === "held") throw pending("the vault's review policy does not read; an owner sets it again or clears it first", policy);
  if (policy.mode === "land_on_green" && candidate.batch_refs.length === 0 && !state.candidate_batch) {
    throw pending("no vault review policy: the queue's intake enqueues the received proposal on its next drain", candidate);
  }
  if (policy.mode === "review") {
    const settlement = await call(plan, owner, "vault.code.proposal_settlement", { proposal: state.candidate_proposal });
    if (settlement.status === "Proposed") {
      throw pending("the received proposal awaits review under the vault's policy: vault.code.proposal_review, or vault.code.proposal_settle approve", settlement);
    }
    if (settlement.status !== "Approved" && settlement.status !== "Applied") throw stopped(`the received proposal is ${settlement.status}`, settlement);
  }
  if (policy.mode === "review" && candidate.batch_refs.length === 0 && !state.candidate_batch) {
    if (state.enqueue_started) throw stopped("the enqueue started earlier and never reported; read vault.code.repos.get batch_refs by hand");
    const repo = await call(plan, owner, "vault.code.repos.get", { repo: anchor.repo });
    if (!repo?.queue) throw pending("the queue is not readable yet", repo);
    state.enqueue_started = true;
    save();
    state.candidate_batch = (await call(plan, owner, "vault.code.merge_queue.enqueue", {
      repo: anchor.repo, proposals: [state.candidate_proposal], base_green: repo.queue.green_commit,
    })).batch_ref;
    save();
  }
  state.candidate_batch ??= candidate.batch_refs[0];
  const batch = state.candidate_batch;
  if (!batch) throw stopped("the candidate names no batch and none was enqueued");
  save();
  const observed = await call(plan, owner, "vault.code.merge_queue.observe", { repo: anchor.repo, batches: [batch] });
  const receipts: Receipt[] = [];
  for (const drive of observed.drive) {
    for (const work_ref of new Set(drive.check_work_refs)) {
      const status = await call(plan, owner, "vault.code.merge_queue.check_status", { repo: anchor.repo, work_ref });
      for (const receipt_ref of new Set(status.receipt_refs)) {
        const receipt = await call(plan, owner, "vault.code.checks.get", { repo: anchor.repo, work_ref, receipt_ref });
        if (receipt) receipts.push(receipt);
      }
    }
  }
  state.check_receipts = receipts;
  save();
  const sealed = await call(plan, owner, "vault.code.ingress.get", { repo: anchor.repo, provenance: state.push_provenance, ref_name: plan.ref_name });
  const revision = sealed?.candidate?.revision_refs.at(-1);
  if (!revision) throw pending("the candidate is not sealed yet", { drive: observed.drive, candidate: sealed?.candidate });
  const repo = await call(plan, owner, "vault.code.repos.get", { repo: anchor.repo });
  if (repo?.green_revision !== revision) throw pending("the queue's current green is not the candidate's seal", repo);
  state.candidate_revision = revision;
  save();

  // 11. The exact preview of that seal against the push, then the queue's own
  //     export of its current green. Its result must be the previewed seal;
  //     drift is disclosed and stops. Then a fresh re-clone proves the tree.
  const final_request = {
    repo: plan.served_repo, code_repo: anchor.repo, checkout: binding.checkout, epoch: binding.epoch,
    revision, ref_name: plan.ref_name, expected_old_oid: pushed, endpoint: plan.endpoint,
  } satisfies FacadeInput<"vault.code.export.preview">;
  const last = await exact_preview(plan, final_request, !state.final_export);
  if (last.preview.target_tree !== state.pushed_tree) throw stopped("the sealed tree is not the pushed tree", last.preview.target_tree);
  state.final_preview_digest = last.preview.preview_digest;
  if (state.final_export_started && !state.final_export) throw stopped("export_green started earlier and never reported; read vault.code.origin.publications by hand");
  if (!state.final_export) {
    const current = await call(plan, owner, "vault.code.repos.get", { repo: anchor.repo });
    if (current?.green_revision !== revision) throw stopped("the green moved after the preview; preview again", current);
    state.final_export_started = true;
    save();
    state.final_export = await call(plan, owner, "vault.code.merge_queue.export_green", {
      repo: anchor.repo, served_repo: plan.served_repo, checkout: binding.checkout, epoch: binding.epoch,
      ref_name: plan.ref_name, expected_old_oid: pushed, endpoint: plan.endpoint,
    });
    save();
  }
  const e1 = state.final_export;
  if (e1.revision !== revision || e1.publication.status !== "published" || e1.wire_rejected) {
    throw stopped("export_green published another revision than the previewed seal", e1);
  }
  if (!state.final_path_count) {
    await published(plan, plan.ref_name, e1.git_commit);
    if (existsSync(plan.reclone_dir)) throw stopped("reclone_dir must be new");
    await with_signed_git_relay(plan, run, run_door, false, (url) =>
      git(plan, "/", ["clone", "--branch", plan.default_branch, url, plan.reclone_dir]),
    );
    const head = (await git(plan, plan.reclone_dir, ["rev-parse", "HEAD"])).trim();
    if (head !== e1.git_commit) throw stopped("the re-clone is not the exported commit", head);
    const exported = await tree_entries(plan, plan.reclone_dir, head);
    const original = await tree_entries(plan, plan.clone_dir, pushed);
    const same = exported.size === original.size && [...original].every(([path, entry]) => {
      const other = exported.get(path);
      return other !== undefined && other.mode === entry.mode && other.oid === entry.oid;
    });
    for (const [path, entry] of original) {
      const other = exported.get(path);
      if (!other || !same_bytes(await blob_bytes(plan, plan.clone_dir, entry.oid), await blob_bytes(plan, plan.reclone_dir, other.oid))) {
        throw stopped(`${path}: the re-export's raw bytes differ from the push`);
      }
    }
    if (!same || (await clone_matches_preview(plan, plan.reclone_dir, head, last)) !== original.size) {
      throw stopped("the re-export's paths or modes differ from the push");
    }
    for (const ancestor of [plan.source_commit, pushed]) {
      if (!(await git_ok(plan, plan.reclone_dir, ["merge-base", "--is-ancestor", ancestor, head]))) {
        throw stopped(`${ancestor} is not an ancestor of the re-export`);
      }
    }
    state.final_path_count = original.size;
    save();
  }
  return finish_roundtrip(plan, state);
}

/** The one completion value, only once every proof above has passed. */
function finish_roundtrip(plan: RoundtripPlan, state: RoundtripState): RoundtripComplete {
  const need = <T>(value: T | undefined | null, name: string): T => {
    if (value === undefined || value === null) throw stopped(`state lacks ${name}`);
    return value;
  };
  const manifest = need(state.manifest, "manifest");
  return {
    result: "roundtrip_complete",
    served_repo: plan.served_repo, ref_name: plan.ref_name, source_commit: plan.source_commit,
    manifest_ref: manifest.manifest_ref, manifest_digest: manifest.digest,
    baseline_revision: need(state.baseline_revision, "baseline_revision"),
    baseline_preview_digest: need(state.baseline_preview_digest, "baseline_preview_digest"),
    first_export: need(state.first_export, "first_export"),
    pushed_commit: need(state.pushed_commit, "pushed_commit"),
    pushed_tree: need(state.pushed_tree, "pushed_tree"),
    push_publication_receipt: need(state.push_publication_receipt, "push_publication_receipt"),
    push_provenance: need(state.push_provenance, "push_provenance"),
    candidate_ref: need(state.candidate_ref, "candidate_ref"),
    candidate_proposal: need(state.candidate_proposal, "candidate_proposal"),
    candidate_fork_session: need(state.candidate_fork_session, "candidate_fork_session"),
    candidate_batch: need(state.candidate_batch, "candidate_batch"),
    check_receipts: need(state.check_receipts, "check_receipts"),
    candidate_revision: need(state.candidate_revision, "candidate_revision"),
    final_preview_digest: need(state.final_preview_digest, "final_preview_digest"),
    final_export: need(state.final_export, "final_export"),
    native_command: { argv: plan.native_command.argv, exit_code: 0 },
    edit_command: { argv: plan.edit_command.argv, exit_code: 0 },
    path_count: need(state.final_path_count, "final_path_count"),
    full_path_mode_byte_equality: true,
    source_is_ancestor: true, pushed_commit_is_ancestor: true,
  };
}

async function main(): Promise<void> {
  const at = process.argv.indexOf("--plan");
  if (at < 0 || !process.argv[at + 1]) throw stopped("usage: bun run roundtrip.ts --plan <absolute plan.json>");
  const { plan, digest } = parse_plan(process.argv[at + 1]);
  const state = load_state(plan, digest);
  try {
    console.log(JSON.stringify(await roundtrip(plan, state), null, 2));
  } finally {
    save_state(plan, state);
  }
}

main().catch((error: unknown) => {
  const stop = error instanceof Stop ? error : new Stop("roundtrip_error", String(error));
  console.log(JSON.stringify({ result: stop.result, reason: stop.reason, evidence: stop.evidence }, null, 2));
  process.exitCode = stop.result === "roundtrip_pending" ? 3 : 1;
});
